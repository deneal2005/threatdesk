"""Third-party website trust report from the Apify actor lofomachines/website-trust-scam-checker (optional, paid).

Off unless APIFY_TOKEN is set and APIFY_WEBSITE_TRUST=true. About $0.02 per site on Apify's free tier, so it only
runs for sites that already claim the brand, at most APIFY_TRUST_DAILY_LIMIT times per day per process, with one
result cached per domain for a day and a hard per-run charge cap.

The report is shown as labelled context and adds NO points: in testing its AI verdict called an unreachable domain
"phishing" from the name alone, which is exactly what ThreatDesk's own rules refuse to do. Its plain facts
(reachability, mail setup, policy pages) duplicate checks ThreatDesk already runs itself.
"""
from __future__ import annotations

import time
from datetime import date

from threatdesk.checks.base import Ctx, EvidenceItem, get_json
from threatdesk.checks.domain import registrable_domain
from threatdesk.scoring import BRAND_CLAIMS

ACTOR = "lofomachines~website-trust-scam-checker"
API = f"https://api.apify.com/v2/acts/{ACTOR}/run-sync-get-dataset-items"
MAX_CHARGE_USD = 0.03
RUN_TIMEOUT = 45
CACHE_TTL = 24 * 3600
_cache: dict[str, tuple[float, tuple[str, dict | None]]] = {}
_spent: dict[str, int] = {}                 # runs per day (this process)


def _budget_left(limit: int) -> bool:
    return _spent.get(date.today().isoformat(), 0) < limit


def _charge() -> None:
    today = date.today().isoformat()
    for k in [k for k in _spent if k != today]:
        del _spent[k]
    _spent[today] = _spent.get(today, 0) + 1


def summarise(item: dict) -> dict:
    flags = item.get("flags") or {}
    ai = item.get("aiInsights") or {}
    return {"trust_score": item.get("trustScore"), "risk_level": item.get("riskLevel"),
            "site_status": item.get("status"), "verdict": (item.get("verdict") or "")[:300],
            "confidence": item.get("confidence"), "negative_flags": (flags.get("negative") or [])[:8],
            "warnings": (flags.get("warnings") or [])[:8], "positive_flags": (flags.get("positive") or [])[:8],
            "ai_category": ai.get("category"), "ai_summary": (ai.get("summary") or "")[:400]}


async def _run(ctx: Ctx, domain: str) -> tuple[str, dict | None]:
    hit = _cache.get(domain)
    if hit and hit[0] > time.monotonic():
        return hit[1]
    if not _budget_left(ctx.settings.apify_trust_daily_limit):
        return "daily limit reached", None
    _charge()
    status, data = await get_json(
        ctx.client, API, params={"timeout": RUN_TIMEOUT, "maxTotalChargeUsd": MAX_CHARGE_USD},
        headers={"Authorization": f"Bearer {ctx.settings.apify_token}"}, method="POST",
        json_body={"websites": [domain], "enableAiInsights": True}, timeout=RUN_TIMEOUT + 15, retries=0)
    if status in (401, 403):
        result = ("token rejected", None)
    elif status == 402:
        result = ("Apify credits used up", None)
    elif status == 429:
        result = ("rate limited by Apify", None)
    elif status not in (200, 201) or not isinstance(data, list):
        result = (f"HTTP {status}", None)
    elif not data:
        result = ("no report returned", None)
    else:
        result = ("ok", data[0])
    if result[0] == "ok":
        _cache[domain] = (time.monotonic() + CACHE_TTL, result)
    return result


async def check_trust(ctx: Ctx):
    s = ctx.settings
    if not (s.apify_token and s.apify_website_trust):
        return ctx.not_configured("third_party_trust", "APIFY_TOKEN + APIFY_WEBSITE_TRUST=true")
    if not any(sig.code in BRAND_CLAIMS for sig in ctx.card.signals):
        return ctx.not_possible("third_party_trust", "skipped: nothing on this site claims the brand, so no paid "
                                                     "lookup was made")
    domain = registrable_domain(ctx.link.host)
    status, item = await _run(ctx, domain)
    if item is None:
        return ctx.not_possible("third_party_trust", f"Apify trust checker: {status}")
    out = summarise(item)
    ctx.evidence.append(EvidenceItem("third_party_trust", {"actor": ACTOR, "domain": domain, **out}))
    return ctx.ran("third_party_trust", informational=True, source="Apify: website-trust-scam-checker (third party, "
                   "not scored)", domain=domain, **out)
