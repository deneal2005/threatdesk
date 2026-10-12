"""SSRF-safe outbound fetching, defanging, and input validation.

Every fetch of a URL that came from a user or from the internet must use safe_fetch():
- http/https only, ports 80/443/8080/8443 only
- the host is resolved and EVERY address must be public (no private, loopback, link-local, metadata, reserved)
- the connection is pinned to the validated IP (prevents DNS-rebinding between check and connect)
- redirects are followed manually, re-validating every hop, max 3 hops
- the body is read up to a byte cap (200 KB pages, 1 MB images) and is never executed or rendered
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlunparse

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

PAGE_MAX_BYTES = 200 * 1024
IMAGE_MAX_BYTES = 1024 * 1024
PAGE_TIMEOUT = 8.0
MAX_REDIRECTS = 3
ALLOWED_PORTS = {80, 443, 8080, 8443}
USER_AGENT = "ThreatDesk/1.0 (brand-protection research; +https://example.invalid/bot)"
NAT64 = ipaddress.ip_network("64:ff9b::/96")
METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data"}


class UnsafeURL(Exception):
    pass


class InvalidInput(ValueError):
    pass


# ------------------------------------------------------------------ IP policy
def ip_is_blocked(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if isinstance(a, ipaddress.IPv6Address):
        if a.ipv4_mapped:
            a = a.ipv4_mapped
        elif a in NAT64:                      # DNS64: judge the embedded IPv4 address
            a = ipaddress.IPv4Address(int(a) & 0xFFFFFFFF)
    return (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast
            or a.is_unspecified or not a.is_global)


def dns_servers() -> tuple[str, ...]:
    from threatdesk.config import get_settings      # lazy: keeps this module importable on its own
    return get_settings().dns_servers


def dns_resolver(servers: tuple[str, ...] | None = None) -> dns.asyncresolver.Resolver:
    """Resolver on the configured servers (DNS_SERVERS); the OS resolver when none are configured."""
    servers = dns_servers() if servers is None else servers
    if servers:
        r = dns.asyncresolver.Resolver(configure=False)
        r.nameservers = list(servers)
    else:
        r = dns.asyncresolver.Resolver()
    r.lifetime = 4.0
    return r


async def resolve_host(host: str, port: int) -> list[str]:
    """Resolve to IP strings via the configured DNS servers, then the OS resolver if they give no answer.
    NXDOMAIN from the configured servers is final. Tests monkeypatch this to stay offline."""
    if dns_servers():
        res = dns_resolver()
        for rdtype in ("A", "AAAA"):
            try:
                return list(dict.fromkeys(r.to_text() for r in await res.resolve(host, rdtype)))
            except dns.resolver.NXDOMAIN:
                raise OSError(f"{host}: NXDOMAIN")
            except dns.exception.DNSException:
                continue
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(i[4][0] for i in infos))


async def check_url(url: str) -> tuple[str, str]:
    """Validate url; return (url, pinned_ip). Raises UnsafeURL."""
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise UnsafeURL("only http/https allowed")
    host = (p.hostname or "").rstrip(".").lower()
    if not host:
        raise UnsafeURL("missing host")
    if host in METADATA_HOSTS:
        raise UnsafeURL("metadata host refused")
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        raise UnsafeURL("bad port")
    if port not in ALLOWED_PORTS:
        raise UnsafeURL(f"port {port} not allowed")
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        try:
            ips = await resolve_host(host, port)
        except OSError:
            raise UnsafeURL("host does not resolve")
    if not ips:
        raise UnsafeURL("host does not resolve")
    for ip in ips:
        if ip_is_blocked(ip):
            raise UnsafeURL("host resolves to a non-public address")
    return url, ips[0]


async def resolve_public_ip(host: str, port: int = 443) -> str:
    _, ip = await check_url(f"https://{host}:{port}/" if port != 443 else f"https://{host}/")
    return ip


# ------------------------------------------------------------------ fetching
@dataclass
class FetchResult:
    status_code: int
    url: str                 # final URL
    body: bytes
    truncated: bool
    chain: list[dict] = field(default_factory=list)    # [{"url","status","ip"}] every hop
    headers: dict = field(default_factory=dict)
    tls_verified: bool = True

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


KEEP_HEADERS = ("server", "content-type", "content-length", "location", "x-powered-by", "set-cookie",
                "strict-transport-security", "content-security-policy", "last-modified", "date")


def _pinned(url: str, ip: str) -> tuple[str, dict, dict]:
    p = urlparse(url)
    netloc = f"[{ip}]" if ":" in ip else ip
    if p.port:
        netloc += f":{p.port}"
    target = urlunparse(p._replace(netloc=netloc))
    host_header = p.netloc.rsplit("@", 1)[-1]
    ext = {"sni_hostname": p.hostname} if p.scheme == "https" else {}
    return target, {"Host": host_header}, ext


async def _one_hop(client: httpx.AsyncClient, url: str, ip: str, timeout: float, max_bytes: int,
                   headers: dict) -> tuple[httpx.Response, bytes, bool]:
    target, extra, ext = _pinned(url, ip)
    req = client.build_request("GET", target, headers={"User-Agent": USER_AGENT, **headers, **extra},
                               timeout=timeout, extensions=ext)
    resp = await client.send(req, stream=True, follow_redirects=False)
    try:
        buf = bytearray()
        truncated = False
        if resp.status_code not in (301, 302, 303, 307, 308):
            async for chunk in resp.aiter_bytes():
                buf += chunk
                if len(buf) >= max_bytes:
                    truncated = True
                    del buf[max_bytes:]
                    break
        return resp, bytes(buf), truncated
    finally:
        await resp.aclose()


async def safe_fetch(client: httpx.AsyncClient, url: str, *, timeout: float = PAGE_TIMEOUT,
                     max_bytes: int = PAGE_MAX_BYTES, max_redirects: int = MAX_REDIRECTS,
                     headers: dict | None = None, allow_insecure_tls: bool = False) -> FetchResult:
    chain: list[dict] = []
    current = url
    tls_verified = True
    insecure: httpx.AsyncClient | None = None
    try:
        for _ in range(max_redirects + 1):
            current, ip = await check_url(current)
            use = insecure or client
            try:
                resp, body, truncated = await _one_hop(use, current, ip, timeout, max_bytes, headers or {})
            except httpx.ConnectError as e:
                if not (allow_insecure_tls and "SSL" in str(e).upper() and insecure is None):
                    raise
                insecure = httpx.AsyncClient(verify=False)
                tls_verified = False
                resp, body, truncated = await _one_hop(insecure, current, ip, timeout, max_bytes, headers or {})
            chain.append({"url": current, "status": resp.status_code, "ip": ip})
            loc = resp.headers.get("location")
            if resp.status_code in (301, 302, 303, 307, 308) and loc:
                current = urljoin(current, loc)
                continue
            kept = {k: v[:300] for k, v in resp.headers.items() if k.lower() in KEEP_HEADERS}
            return FetchResult(resp.status_code, current, body, truncated, chain, kept, tls_verified)
        raise UnsafeURL(f"more than {max_redirects} redirects")
    finally:
        if insecure is not None:
            await insecure.aclose()


# ------------------------------------------------------------------ display
def defang(value: str | None) -> str:
    """hxxps://evil[.]com/path - for display only, never clickable."""
    if not value:
        return ""
    s = re.sub(r"^http", "hxxp", str(value), flags=re.I)
    m = re.match(r"^(hxxps?://)?([^/?#]+)(.*)$", s, flags=re.S)
    if not m:
        return s.replace(".", "[.]")
    scheme, host, rest = m.group(1) or "", m.group(2), m.group(3)
    return scheme + host.replace(".", "[.]") + rest


_DOMAINISH = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]+))\b", re.I)


def defang_text(value) -> str:
    """Defang every URL/domain inside free text or JSON (display only)."""
    s = re.sub(r"\bhttp(s?)://", r"hxxp\1://", str(value or ""), flags=re.I)
    return _DOMAINISH.sub(lambda m: m.group(1).replace(".", "[.]"), s)


# ------------------------------------------------------------------ validation
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})$")
HANDLE_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,24}$")


def clean_text(raw: str | None, limit: int, required: bool = False, label: str = "Value") -> str:
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", (raw or "")).strip()
    if required and not s:
        raise InvalidInput(f"{label} is required.")
    if len(s) > limit:
        raise InvalidInput(f"{label} is too long (max {limit} characters).")
    return s


def clean_domain(raw: str) -> str:
    s = (raw or "").strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = re.split(r"[/?#]", s, maxsplit=1)[0].split("@")[-1].split(":")[0].strip(".")
    if s.startswith("www."):
        s = s[4:]
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError:
        raise InvalidInput(f"'{raw[:60]}' is not a valid domain.")
    if not DOMAIN_RE.match(s):
        raise InvalidInput(f"'{raw[:60]}' is not a valid domain (e.g. example.com).")
    return s


def clean_handle(raw: str) -> str:
    s = re.sub(r"^https?://[^/]+/", "", (raw or "").strip(), flags=re.I)
    s = s.split("?")[0].strip("/").lstrip("@")
    if not HANDLE_RE.match(s):
        raise InvalidInput(f"Handle '{s[:40]}' is invalid (2-64 letters, digits, . _ -).")
    return s


def clean_list(raw: str, cleaner, max_items: int = 20, names: bool = False) -> list[str]:
    """Split on commas and whitespace; names=True splits on commas, semicolons and new lines only
    (company names contain spaces)."""
    parts = [p.strip() for p in re.split(r"[,;\n]+" if names else r"[,\s]+", raw or "") if p.strip()]
    if len(parts) > max_items:
        raise InvalidInput(f"At most {max_items} values allowed.")
    out: list[str] = []
    for p in parts:
        v = cleaner(p)
        if v.lower() not in {o.lower() for o in out}:
            out.append(v)
    return out


def clean_email(raw: str) -> str:
    s = (raw or "").strip().lower()
    if len(s) > 254 or not EMAIL_RE.match(s):
        raise InvalidInput("Enter a valid email address.")
    return s
