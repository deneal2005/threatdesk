"""Shared app checks: impersonation, icon vs logo, developer website age/archive, description signals."""
from __future__ import annotations

from threatdesk import images
from threatdesk.checks.base import Ctx, EvidenceItem, get_json
from threatdesk.checks.content import text_signals
from threatdesk.checks.domain import _parse_wayback_ts, registrable_domain
from threatdesk.checks.rdap import parse_domain_rdap, rdap_lookup
from threatdesk.db import utcnow
from threatdesk.indicators import host_of
from threatdesk.safety import IMAGE_MAX_BYTES, InvalidInput, safe_fetch
from threatdesk.scoring import Scorecard
from threatdesk.scoring_helpers import name_similarity, parse_date

ICON_FORMATS = {"PNG", "JPEG", "WEBP", "GIF"}


def impersonation(card: Scorecard, ctx_brand, title: str, app_id: str, kind: str, developer: str,
                  official_publisher: str | None = None) -> dict:
    if not ctx_brand.name:
        return {"note": "No brand selected: no impersonation check"}
    if official_publisher or ctx_brand.is_official_asset(kind, app_id):
        return {"official": True}
    t = (title or "").lower()
    for term in ctx_brand.terms():
        if name_similarity(title, term) >= 80 or (len(term) >= 3 and term in t):
            card.add("app_impersonation", f"'{title}' by {developer or 'unknown developer'} resembles "
                                          f"{ctx_brand.name} but is not one of its apps")
            return {"similar_to": term}
    return {}


async def check_icon(ctx: Ctx, icon_url: str | None, kind: str, app_id: str):
    if not ctx.brand.logo_phash:
        return ctx.not_possible("icon_vs_logo", "no brand logo uploaded (Brand settings)")
    if not icon_url:
        return ctx.not_possible("icon_vs_logo", "the listing has no icon")
    res = await safe_fetch(ctx.client, icon_url, max_bytes=IMAGE_MAX_BYTES + 1, timeout=8)
    if res.status_code != 200 or res.truncated:
        return ctx.not_possible("icon_vs_logo", f"icon could not be downloaded (HTTP {res.status_code})")
    try:
        ph = images.phash_hex(images.decode(res.body, allowed=ICON_FORMATS))
    except InvalidInput as e:
        return ctx.not_possible("icon_vs_logo", str(e))
    dist = images.distance(ph, ctx.brand.logo_phash)
    ctx.indicator("icon_hash", ph)
    official = ctx.brand.is_official_asset(kind, app_id) or bool(ctx.facts.get("official_publisher"))
    match = dist is not None and dist <= images.PHASH_MATCH_DISTANCE
    if match and not official:
        ctx.card.add("icon_matches_logo", f"app icon matches the brand logo (perceptual distance {dist})")
    return ctx.ran("icon_vs_logo", distance=dist, match=match, phash=ph, official=official)


async def check_dev_website(ctx: Ctx, website: str | None):
    if not website:
        return ctx.not_possible("developer_website", "the listing names no developer website")
    host = host_of(website)
    if not host:
        return ctx.not_possible("developer_website", "developer website is not a valid address")
    dom = registrable_domain(host)
    ctx.indicator("domain", dom)
    official = ctx.brand.is_official_host(host)
    status, data, _src = await rdap_lookup(ctx, "domain", dom)
    info = parse_domain_rdap(data) if status == 200 and data else {}
    reg = parse_date(info.get("registered"))
    first = None
    try:
        st, wb = await get_json(ctx.client, "https://archive.org/wayback/available",
                                params={"url": dom, "timestamp": "19960101"}, timeout=12)
        snap = ((wb or {}).get("archived_snapshots") or {}).get("closest") if st == 200 and isinstance(wb, dict) else None
        first = _parse_wayback_ts(snap["timestamp"]) if snap and snap.get("timestamp") else None
    except Exception:  # noqa: BLE001 - the archive date is extra context only
        pass
    age = (utcnow() - reg).days if reg else None
    if age is not None and age < 180 and not official:
        ctx.card.add("app_dev_site_new", f"developer website {dom} registered {reg.date().isoformat()}")
    return ctx.ran("developer_website", domain=dom, registered=info.get("registered"), age_days=age,
                   registrar=info.get("registrar"), archived_first=first.isoformat() if first else None,
                   note=None if reg else f"{dom}: no registration date (RDAP HTTP {status})")


def description_signals(ctx: Ctx, description: str, kind: str, app_id: str) -> dict:
    if ctx.brand.is_official_asset(kind, app_id) or ctx.facts.get("official_publisher"):
        return {"official": True, "signals": []}
    found = text_signals(ctx.card, description or "", ctx.brand, official_context=True)
    return {"signals": list(found)}


def store_evidence(ctx: Ctx, kind: str, data: dict) -> None:
    ctx.evidence.append(EvidenceItem(kind, data))
