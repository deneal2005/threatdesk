"""RDAP for the domain (age, registrar, redaction, registrar abuse contact) and for the IP (hosting + abuse), ASN."""
from __future__ import annotations

import ipaddress
import json
import re
import time

import dns.exception

from threatdesk.checks.base import Ctx, EvidenceItem, get_json
from threatdesk.checks.domain import _is_ip, registrable_domain
from threatdesk.db import utcnow
from threatdesk.safety import UnsafeURL, dns_resolver, ip_is_blocked, safe_fetch
from threatdesk.scoring_helpers import parse_date

REDACT_RE = re.compile(r"redact|privacy|private|withheld|data protected|not disclosed|gdpr|proxy", re.I)


def vcard(entity: dict) -> dict:
    out: dict = {}
    arr = (entity or {}).get("vcardArray")
    if not (isinstance(arr, list) and len(arr) > 1 and isinstance(arr[1], list)):
        return out
    for item in arr[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        key, val = item[0], item[3]
        if isinstance(val, list):
            val = " ".join(str(v) for v in val if v)
        val = str(val or "").strip()
        if key in ("fn", "org", "email", "tel", "kind") and val and key not in out:
            out[key] = val.removeprefix("tel:").removeprefix("mailto:")[:200]
    return out


def _walk(entities: list, depth: int = 0):
    for e in entities or []:
        if isinstance(e, dict):
            yield e
            if depth < 2:
                yield from _walk(e.get("entities"), depth + 1)


def _remarks(data: dict) -> str:
    return " ".join(" ".join(r.get("description") or []) for r in data.get("remarks") or [] if isinstance(r, dict))


def parse_domain_rdap(data: dict) -> dict:
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events") or [] if isinstance(e, dict)}
    registrar = registrant = abuse = None
    for e in _walk(data.get("entities")):
        roles = e.get("roles") or []
        if "registrar" in roles and registrar is None:
            registrar = e
        if "registrant" in roles and registrant is None:
            registrant = e
        if "abuse" in roles and abuse is None:
            abuse = e
    rv = vcard(registrar) if registrar else {}
    av = vcard(abuse) if abuse else {}
    gv = vcard(registrant) if registrant else {}
    iana = next((p.get("identifier") for p in (registrar or {}).get("publicIds") or []
                 if isinstance(p, dict) and "IANA" in str(p.get("type", ""))), None)
    redacted = bool(data.get("redacted")) or not (gv.get("fn") or gv.get("org")) or \
        bool(REDACT_RE.search(" ".join(gv.values()))) or bool(REDACT_RE.search(_remarks(registrant or {})))
    return {
        "domain": (data.get("ldhName") or "").lower(), "registered": events.get("registration"),
        "expires": events.get("expiration"), "changed": events.get("last changed"),
        "registrar": rv.get("fn") or rv.get("org") or (registrar or {}).get("handle"), "registrar_iana": iana,
        "abuse_email": av.get("email"), "abuse_phone": av.get("tel"), "abuse_name": av.get("fn"),
        "registrant": None if redacted else (gv.get("org") or gv.get("fn")), "redacted": redacted,
        "status": list(data.get("status") or [])[:8],
        "nameservers": [(n.get("ldhName") or "").lower() for n in data.get("nameservers") or []
                        if isinstance(n, dict)][:6],
    }


def parse_ip_rdap(data: dict) -> dict:
    org = abuse = None
    for e in _walk(data.get("entities")):
        roles = e.get("roles") or []
        if org is None and ("registrant" in roles or "administrative" in roles):
            org = vcard(e)
        if abuse is None and "abuse" in roles:
            abuse = vcard(e)
    start, end = data.get("startAddress"), data.get("endAddress")
    return {"name": data.get("name"), "handle": data.get("handle"), "country": data.get("country"),
            "range": f"{start} - {end}" if start and end else None, "org": (org or {}).get("fn") or
            (org or {}).get("org"), "abuse_email": (abuse or {}).get("email"), "abuse_phone": (abuse or {}).get("tel")}


IANA_BOOTSTRAP = {"domain": "https://data.iana.org/rdap/dns.json", "ipv4": "https://data.iana.org/rdap/ipv4.json",
                  "ipv6": "https://data.iana.org/rdap/ipv6.json"}
BOOTSTRAP_TTL = 24 * 3600
BOOTSTRAP_RETRY = 600
_bootstrap: dict[str, tuple[float, list]] = {}


async def _services(ctx: Ctx, kind: str) -> list:
    cached = _bootstrap.get(kind)
    now = time.monotonic()
    if cached and now < cached[0]:
        return cached[1]
    try:
        status, data = await get_json(ctx.client, IANA_BOOTSTRAP[kind], timeout=15)
        services = data.get("services") if status == 200 and isinstance(data, dict) else None
    except Exception:  # noqa: BLE001 - rdap.org is the fallback
        services = None
    _bootstrap[kind] = (now + (BOOTSTRAP_TTL if services else BOOTSTRAP_RETRY), services or [])
    return services or []


def _pick(urls: list) -> str | None:
    urls = [u for u in urls or [] if isinstance(u, str)]
    best = next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
    return (best if best.endswith("/") else best + "/") if best else None


def server_for_domain(services: list, domain: str) -> str | None:
    best, best_len = None, -1
    for entry in services:
        if not (isinstance(entry, list) and len(entry) >= 2):
            continue
        for key in entry[0]:
            key = str(key).lower()
            if (domain == key or domain.endswith("." + key)) and len(key) > best_len:
                best, best_len = _pick(entry[1]), len(key)
    return best


def server_for_ip(services: list, ip: str) -> str | None:
    addr = ipaddress.ip_address(ip)
    best, best_len = None, -1
    for entry in services:
        if not (isinstance(entry, list) and len(entry) >= 2):
            continue
        for key in entry[0]:
            try:
                net = ipaddress.ip_network(key, strict=False)
            except ValueError:
                continue
            if net.version == addr.version and addr in net and net.prefixlen > best_len:
                best, best_len = _pick(entry[1]), net.prefixlen
    return best


async def _fetch(ctx: Ctx, url: str) -> tuple[int, dict | None]:
    res = await safe_fetch(ctx.client, url, headers={"Accept": "application/rdap+json"}, timeout=10,
                           max_bytes=512 * 1024)
    try:
        data = json.loads(res.body.decode("utf-8", errors="replace")) if res.status_code == 200 else None
    except ValueError:
        data = None
    return res.status_code, data if isinstance(data, dict) else None


async def rdap_lookup(ctx: Ctx, kind: str, value: str) -> tuple[int, dict | None, str]:
    """(status, data, source url): the authoritative server from the IANA bootstrap, then rdap.org."""
    path = "domain" if kind == "domain" else "ip"
    services = await _services(ctx, "domain" if kind == "domain" else
                               ("ipv6" if ":" in value else "ipv4"))
    server = server_for_domain(services, value) if kind == "domain" else server_for_ip(services, value)
    if server:
        url = f"{server}{path}/{value}"
        try:
            status, data = await _fetch(ctx, url)
            if status == 200 and data or status == 404:
                return status, data, url
        except Exception:  # noqa: BLE001 - try the public redirector next
            pass
    url = f"https://rdap.org/{path}/{value}"
    try:
        status, data = await _fetch(ctx, url)
    except UnsafeURL:
        return 0, None, url
    return status, data, url


async def check_rdap_domain(ctx: Ctx):
    if _is_ip(ctx.link.host):
        return ctx.not_possible("rdap_domain", "the link uses an IP address, not a domain")
    dom = registrable_domain(ctx.link.host)
    status, data, src = await rdap_lookup(ctx, "domain", dom)
    if status == 404:
        return ctx.not_possible("rdap_domain", "no RDAP record (unregistered domain or TLD without RDAP)")
    if status == 429:
        return ctx.not_possible("rdap_domain", "rate limited by RDAP server")
    if status != 200 or not data:
        return ctx.not_possible("rdap_domain", f"RDAP answered HTTP {status}" if status else "RDAP server unreachable")
    info = parse_domain_rdap(data)
    reg = parse_date(info["registered"])
    info["age_days"] = (utcnow() - reg).days if reg else None
    info["source"] = src
    ctx.facts["rdap_domain"] = info
    if not ctx.brand.is_official_host(ctx.link.host):
        if reg and info["age_days"] < 30:
            ctx.card.add("domain_age_lt_30d", f"{dom} registered {reg.date().isoformat()} ({info['age_days']} days ago)")
        elif reg and info["age_days"] < 180:
            ctx.card.add("domain_age_lt_180d", f"{dom} registered {reg.date().isoformat()} ({info['age_days']} days ago)")
        if info["redacted"]:
            ctx.card.add("registrant_redacted", f"{dom}: registrant details are redacted or private")
    ctx.evidence.append(ctx_ev("rdap_domain", {"source": src, "parsed": info, "raw": data}))
    return ctx.ran("rdap_domain", **info)


async def _asn(ip: str) -> dict:
    """Team Cymru IP-to-ASN over DNS TXT (IPv4 only)."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return {}
        res = dns_resolver()
        rev = ".".join(reversed(ip.split(".")))
        txt = (await res.resolve(f"{rev}.origin.asn.cymru.com", "TXT", lifetime=4))[0].to_text().strip('"')
        asn, prefix, country = [p.strip() for p in txt.split("|")[:3]]
        asn = asn.split()[0]
        name = ""
        try:
            info = (await res.resolve(f"AS{asn}.asn.cymru.com", "TXT", lifetime=4))[0].to_text().strip('"')
            name = info.split("|")[-1].strip()
        except dns.exception.DNSException:
            pass
        return {"asn": asn, "prefix": prefix, "country": country, "name": name}
    except (dns.exception.DNSException, ValueError, IndexError):
        return {}


async def check_rdap_ip(ctx: Ctx):
    ips = [ip for ip in (ctx.facts.get("dns") or {}).get("ips", []) if not ip_is_blocked(ip)]
    if not ips:
        return ctx.not_possible("rdap_ip", "no public IP resolved for the host")
    ip = ips[0]
    asn = await _asn(ip)
    if asn.get("asn"):
        ctx.indicator("asn", asn["asn"])
    status, data, src = await rdap_lookup(ctx, "ip", ip)
    if status != 200 or not data:
        return ctx.not_possible("rdap_ip", f"IP RDAP answered HTTP {status}", ip=ip, asn=asn)
    info = {"ip": ip, **parse_ip_rdap(data), "asn": asn, "source": src}
    ctx.facts["rdap_ip"] = info
    ctx.evidence.append(ctx_ev("rdap_ip", {"source": src, "parsed": info, "raw": data}))
    return ctx.ran("rdap_ip", **info)


def ctx_ev(kind: str, content: dict) -> EvidenceItem:
    return EvidenceItem(kind, content)
