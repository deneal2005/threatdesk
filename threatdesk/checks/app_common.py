"""Shared app checks: impersonation, icon vs logo, developer website age/archive, description signals."""
from __future__ import annotations

from threatdesk import images
from threatdesk.brands import publisher_key
from threatdesk.checks.base import Ctx, EvidenceItem, get_json
from threatdesk.checks.content import text_signals
from threatdesk.checks.domain import _parse_wayback_ts, registrable_domain
from threatdesk.checks.rdap import parse_domain_rdap, rdap_lookup
from threatdesk.db import utcnow
from threatdesk.indicators import host_of
from threatdesk.lookalike import best_match, best_title_match
from threatdesk.safety import IMAGE_MAX_BYTES, InvalidInput, safe_fetch
from threatdesk.scoring import Scorecard
from threatdesk.scoring_helpers import parse_date

ICON_FORMATS = {"PNG", "JPEG", "WEBP", "GIF"}


GENERIC_PACKAGE_PARTS = {"com", "org", "net", "in", "co", "io", "app", "apps", "android", "mobile", "ios", "www",
                         "official", "release", "prod", "client", "main", "application"}


def package_lookalike(brand, package: str, kind: str) -> str | None:
    """Why a package/bundle id imitates the brand: an official app's namespace or a brand-like segment."""
    pkg = (package or "").lower()
    if not pkg or "." not in pkg:
        return None
    official = brand.official_apps.get("android" if kind == "android" else "ios_bundles", []) or []
    for off in official:
        parts = off.lower().split(".")
        if len(parts) >= 2 and len(parts[1]) >= 4 and parts[1] not in GENERIC_PACKAGE_PARTS:
            ns = ".".join(parts[:2])
            if pkg.startswith(ns + ".") and pkg != off.lower():
                return f"uses the namespace {ns} of official app {off}"
    refs = brand.name_references()
    for seg in (p for p in pkg.split(".") if p not in GENERIC_PACKAGE_PARTS):
        hit = best_match(seg, refs)
        if hit and hit[0].strong(brand.lookalike_threshold):
            return f"segment '{seg}' imitates {hit[1]} ({hit[0].explain()})"
    return None


def impersonation(card: Scorecard, ctx_brand, title: str, app_id: str, kind: str, developer: str,
                  official_publisher: str | None = None, package: str = "") -> dict:
    """Identity signals for a store listing: title, developer name and package id compared with the brand.

    A different publisher alone is not a signal (resellers, banks' partners and unrelated apps all have one);
    it is reported as context in the evidence of a title match."""
    if not ctx_brand.name:
        return {"note": "No brand selected: no impersonation check"}
    if official_publisher or ctx_brand.is_official_asset(kind, app_id):
        return {"official": True}
    out: dict = {}
    th = ctx_brand.lookalike_threshold
    hit = best_title_match(title or "", ctx_brand.name_references())
    if hit and hit[0].strong(th):
        m, label = hit
        card.add("app_impersonation", f"'{title}' resembles {label} ({m.explain()}); published by "
                                      f"{developer or 'an unknown developer'}, which is not an official publisher")
        out["similar_to"], out["title_match"] = m.reference, m.as_dict()
    elif hit:
        out["title_mentions"] = hit[0].as_dict()
    if developer:
        refs = ctx_brand.name_references() | {p.lower(): f"listed publisher '{p}'"
                                              for p in ctx_brand.official_publishers()}
        dev = best_match(developer, refs)
        if dev is None and publisher_key(developer):
            dev = best_match(publisher_key(developer), {publisher_key(r) or r: lb for r, lb in refs.items()})
        if dev and dev[0].strong(th):
            card.add("app_publisher_lookalike", f"developer '{developer}' resembles {dev[1]} ({dev[0].explain()}) "
                                                f"but is not one of the brand's publishers")
            out["publisher_match"] = dev[0].as_dict()
    if why := package_lookalike(ctx_brand, package or app_id, kind):
        card.add("app_package_lookalike", f"{package or app_id}: {why}")
        out["package_lookalike"] = why
    return out


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
