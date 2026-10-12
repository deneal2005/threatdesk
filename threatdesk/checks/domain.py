"""DNS, registrable-domain helpers, Wayback availability."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from datetime import datetime

import dns.asyncresolver
import dns.exception
import dns.resolver

from threatdesk.checks.base import Ctx, get_json
from threatdesk.db import utcnow
from threatdesk.safety import dns_resolver, dns_servers

MULTI_SUFFIXES = {
    "co.in", "net.in", "org.in", "bank.in", "fin.in", "firm.in", "gen.in", "ind.in", "ac.in", "gov.in", "edu.in",
    "res.in", "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.za", "com.br",
    "com.sg", "com.my", "co.id", "com.pk", "com.bd", "com.np", "com.lk", "co.jp", "com.cn", "com.hk", "com.tw",
    "co.kr", "com.mx", "com.ar", "com.tr", "com.sa", "com.ng", "co.ke", "com.ph", "com.vn",
}


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registrable_domain(host: str) -> str:
    """Last 2 labels, or 3 when the last 2 are a known multi-label suffix (co.in, com.au...)."""
    host = (host or "").lower().rstrip(".")
    if _is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def resolver() -> dns.asyncresolver.Resolver:
    return dns_resolver()


async def _resolve_a(host: str, res: dns.asyncresolver.Resolver, lifetime: float) -> tuple[str, list[str]]:
    try:
        ans = await res.resolve(host, "A", lifetime=lifetime)
        return "resolved", list(dict.fromkeys(r.to_text() for r in ans))
    except dns.resolver.NXDOMAIN:
        return "nxdomain", []
    except dns.resolver.NoAnswer:
        try:
            ans = await res.resolve(host, "AAAA", lifetime=lifetime)
            return "resolved", list(dict.fromkeys(r.to_text() for r in ans))
        except dns.resolver.NoAnswer:
            return "noanswer", []
        except dns.exception.Timeout:
            return "timeout", []
        except dns.exception.DNSException:
            return "noanswer", []
    except dns.exception.Timeout:
        return "timeout", []
    except dns.exception.DNSException:
        return "error", []


async def resolve_a(host: str, res: dns.asyncresolver.Resolver | None = None,
                    lifetime: float = 4.0) -> tuple[str, list[str]]:
    """(state, ips): resolved | nxdomain | noanswer | timeout | error. The configured servers first; when they time
    out or fail, the OS resolver gets one try."""
    if _is_ip(host):
        return "resolved", [host]
    state, ips = await _resolve_a(host, res or resolver(), lifetime)
    if state in ("timeout", "error") and dns_servers():
        try:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM), lifetime)
            got = list(dict.fromkeys(i[4][0] for i in infos))
            if got:
                return "resolved", got
        except (OSError, asyncio.TimeoutError):
            pass
    return state, ips


async def check_dns(ctx: Ctx):
    host = ctx.link.host
    state, ips = await resolve_a(host)
    ctx.facts["dns"] = {"state": state, "ips": ips}
    if state == "timeout":
        return ctx.not_possible("dns", "DNS lookup timed out")
    if state == "error":
        return ctx.not_possible("dns", "DNS servers failed")
    for ip in ips[:4]:
        ctx.indicator("ip", ip)
    ctx.indicator("domain", registrable_domain(host))
    return ctx.ran("dns", state=state, ips=ips)


def _parse_wayback_ts(ts: str) -> datetime | None:
    try:
        return datetime.strptime(str(ts)[:14].ljust(14, "0"), "%Y%m%d%H%M%S")
    except ValueError:
        return None


async def _cdx_first(ctx: Ctx, host: str) -> tuple[bool, datetime | None]:
    """(answered, first capture). The CDX index confirms "never archived" (the availability API is unreliable)."""
    status, data = await get_json(ctx.client, "https://web.archive.org/cdx/search/cdx",
                                  params={"url": host, "limit": "1", "fl": "timestamp", "output": "json"}, timeout=20)
    ctx.facts["_cdx_status"] = status
    if status != 200 or not isinstance(data, list):
        return False, None
    rows = [r for r in data[1:] if r] if data and data[0] == ["timestamp"] else [r for r in data if r]
    return True, (_parse_wayback_ts(rows[0][0]) if rows else None)


async def check_wayback(ctx: Ctx):
    host = registrable_domain(ctx.link.host)
    official = ctx.brand.is_official_host(ctx.link.host)
    first, source = None, "availability"
    try:
        status, data = await get_json(ctx.client, "https://archive.org/wayback/available",
                                      params={"url": host, "timestamp": "19960101"}, timeout=12)
        snap = ((data or {}).get("archived_snapshots") or {}).get("closest") if status == 200 and \
            isinstance(data, dict) else None
        if snap and snap.get("available") is not False and snap.get("timestamp"):
            first = _parse_wayback_ts(snap["timestamp"])
    except Exception:  # noqa: BLE001 - the CDX index below is the confirmation
        pass
    if first is None:
        source = "cdx"
        answered, first = await _cdx_first(ctx, host)
        if not answered:
            if ctx.facts.get("_cdx_status") == 429:
                return ctx.not_possible("wayback", "rate limited by archive.org")
            return ctx.not_possible("wayback", "archive.org gave no reliable answer")
    detail = {"domain": host, "first_snapshot": first.isoformat() if first else None, "source": source}
    ctx.facts["wayback"] = detail
    if not official:
        if first is None:
            ctx.card.add("no_archive_history", f"{host} has no Wayback Machine snapshots")
        elif (utcnow() - first).days < 30:
            ctx.card.add("archive_recent", f"{host} first archived {first.date().isoformat()}")
    return ctx.ran("wayback", **detail)
