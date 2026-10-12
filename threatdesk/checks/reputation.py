"""Optional reputation lookups. Each runs only when its key exists; otherwise not_configured."""
from __future__ import annotations

import asyncio
import base64
import time
from urllib.parse import urlsplit

from threatdesk.checks.base import NOT_CONFIGURED, CheckOutcome, Ctx, get_json

THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


def _urls(ctx: Ctx) -> list[str]:
    page = ctx.facts.get("page") or {}
    return list(dict.fromkeys(u for u in (ctx.link.url, page.get("final_url")) if u))


async def check_safe_browsing(ctx: Ctx):
    key = ctx.settings.safe_browsing_api_key
    if not key:
        return ctx.not_configured("safe_browsing", "SAFE_BROWSING_API_KEY")
    body = {"client": {"clientId": "threatdesk", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": THREAT_TYPES, "platformTypes": ["ANY_PLATFORM"],
                           "threatEntryTypes": ["URL"], "threatEntries": [{"url": u} for u in _urls(ctx)]}}
    status, data = await get_json(ctx.client, "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                                  params={"key": key}, method="POST", json_body=body)
    if status != 200:
        return ctx.not_possible("safe_browsing", f"Safe Browsing answered HTTP {status}")
    threats = sorted({m.get("threatType", "") for m in (data or {}).get("matches", [])} - {""})
    if threats:
        ctx.card.add("safe_browsing_hit", f"Google Safe Browsing: {', '.join(threats)}")
    return ctx.ran("safe_browsing", listed=bool(threats), threats=threats)


class _VTLimiter:
    """Process-wide spacing for the free VirusTotal API (4 lookups/minute)."""
    SPACING = 15.0
    MAX_WAIT = 20.0
    _next = 0.0

    @classmethod
    async def wait(cls) -> bool:
        now = time.monotonic()
        slot = max(now, cls._next)
        if slot - now > cls.MAX_WAIT:
            return False
        cls._next = slot + cls.SPACING
        await asyncio.sleep(slot - now)
        return True


async def check_virustotal(ctx: Ctx):
    key = ctx.settings.vt_api_key
    if not key:
        return ctx.not_configured("virustotal", "VT_API_KEY")
    if not await _VTLimiter.wait():
        return ctx.not_possible("virustotal", "VirusTotal lookups are spaced 15 s apart; too many waiting")
    url_id = base64.urlsafe_b64encode(ctx.link.url.encode()).decode().rstrip("=")
    status, data = await get_json(ctx.client, f"https://www.virustotal.com/api/v3/urls/{url_id}",
                                  headers={"x-apikey": key}, timeout=15)
    if status == 404:
        return ctx.ran("virustotal", known=False)          # lookup only: URLs are never submitted
    if status == 429:
        return ctx.not_possible("virustotal", "VirusTotal rate limit reached")
    if status != 200:
        return ctx.not_possible("virustotal", f"VirusTotal answered HTTP {status}")
    stats = ((data or {}).get("data") or {}).get("attributes", {}).get("last_analysis_stats") or {}
    mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    engines = sum(int(v) for v in stats.values() if isinstance(v, int))
    if mal >= 2:
        ctx.card.add("virustotal_malicious", f"{mal} of {engines} engines say malicious")
    elif mal + sus >= 1:
        ctx.card.add("virustotal_suspicious", f"{mal + sus} of {engines} engines flag it")
    return ctx.ran("virustotal", known=True, malicious=mal, suspicious=sus, engines=engines)


async def check_urlhaus(ctx: Ctx):
    key = ctx.settings.urlhaus_auth_key
    if not key:
        return ctx.not_configured("urlhaus", "URLHAUS_AUTH_KEY")
    status, data = await get_json(ctx.client, "https://urlhaus-api.abuse.ch/v1/url/", method="POST",
                                  data={"url": ctx.link.url}, headers={"Auth-Key": key})
    if status != 200 or not isinstance(data, dict):
        return ctx.not_possible("urlhaus", f"URLhaus answered HTTP {status}")
    q = data.get("query_status")
    if q == "ok":
        threat = data.get("threat") or "malware"
        ctx.card.add("urlhaus_listed", f"URLhaus: {threat} ({data.get('url_status', 'unknown status')})")
        return ctx.ran("urlhaus", listed=True, threats=[threat], url_status=data.get("url_status"))
    if q == "no_results":
        return ctx.ran("urlhaus", listed=False)
    return ctx.not_possible("urlhaus", f"URLhaus answered {q}")


async def check_scam_lists(ctx: Ctx):
    if not ctx.settings.scam_lists:
        return CheckOutcome("scam_lists", NOT_CONFIGURED, {"reason": "turned off (SCAM_LISTS=off)"})
    from threatdesk.scamlists import STATE
    if not STATE.ready():
        return ctx.not_possible("scam_lists", "lists are still downloading")
    page = ctx.facts.get("page") or {}
    hosts = [ctx.link.host] + [(urlsplit(h.get("url", "")).hostname or "") for h in page.get("redirect_chain", [])]
    hosts.append(page.get("final_host") or "")
    for h in dict.fromkeys(x.lower() for x in hosts if x):
        matched, sources = STATE.lookup(h)
        if matched:
            ctx.card.add("scam_list_hit", f"{matched} is on: {', '.join(sources)}")
            return ctx.ran("scam_lists", hit=matched, sources=sources, total=STATE.total())
    return ctx.ran("scam_lists", hit=None, sources=[], total=STATE.total())


async def check_phishtank(ctx: Ctx):
    s = ctx.settings
    headers = {"User-Agent": f"phishtank/{s.phishtank_username}"}
    found = {"in_database": False, "verified_phish": False}
    for u in _urls(ctx):
        form = {"url": u, "format": "json", **({"app_key": s.phishtank_app_key} if s.phishtank_app_key else {})}
        status, data = await get_json(ctx.client, "https://checkurl.phishtank.com/checkurl/", method="POST",
                                      data=form, headers=headers, timeout=15)
        if status in (429, 509):
            return ctx.not_possible("phishtank", "rate limited by PhishTank")
        if status != 200 or not isinstance(data, dict):
            return ctx.not_possible("phishtank", f"PhishTank answered HTTP {status}")
        r = data.get("results") or {}
        if r.get("in_database"):
            found["in_database"] = True
            if r.get("verified") and r.get("valid"):
                found["verified_phish"] = True
                ctx.card.add("phishtank_verified", f"PhishTank verified phish (id {r.get('phish_id')}): {u[:120]}")
                break
    return ctx.ran("phishtank", checked=_urls(ctx), **found)
