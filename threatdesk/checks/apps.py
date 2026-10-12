"""Google Play (unofficial google-play-scraper, 15 s thread timeout) and App Store (iTunes lookup) checks."""
from __future__ import annotations

import asyncio

from threatdesk import constants as C
from threatdesk.brands import publisher_key
from threatdesk.checks.app_common import (
    check_dev_website, check_icon, description_signals, impersonation, store_evidence,
)
from threatdesk.checks.base import RAN, Ctx, get_json, run_check
from threatdesk.db import utcnow
from threatdesk.scoring_helpers import parse_date

PLAY_TIMEOUT = 15.0


def _play_fetch(app_id: str) -> tuple[dict, dict | None]:
    from google_play_scraper import app, permissions
    details = app(app_id, lang="en", country="in")
    try:
        perms = permissions(app_id, lang="en", country="in")
    except Exception:  # noqa: BLE001 - permissions are a separate, flaky endpoint
        perms = None
    return details, perms


def dangerous_from_play(perms: dict | None) -> list[str]:
    texts = " | ".join(str(t).lower() for group in (perms or {}).values() for t in (group or []))
    texts += " | " + " | ".join(str(k).lower() for k in (perms or {}))
    found = [const for hint, const in C.PERMISSION_TEXT_HINTS.items() if hint in texts]
    return list(dict.fromkeys(found))


def app_age_signals(ctx: Ctx, released, ratings, official: bool) -> dict:
    rel = parse_date(released)
    age = (utcnow() - rel).days if rel else None
    if not official:
        if age is not None and age < 90:
            ctx.card.add("app_new", f"released {rel.date().isoformat()} ({age} days ago)")
        if ratings is not None and int(ratings) < 50:
            ctx.card.add("app_low_ratings", f"{int(ratings)} ratings")
    return {"released": rel.isoformat() if rel else None, "age_days": age, "ratings": ratings}


def _desc_check(description: str, kind: str, app_id: str):
    async def run(ctx: Ctx):
        return ctx.ran("description_signals", **description_signals(ctx, description, kind, app_id))
    return run


async def run_play(ctx: Ctx) -> None:
    pkg = ctx.link.ident

    async def play_details(c: Ctx):
        from google_play_scraper.exceptions import NotFoundError
        try:
            d, perms = await asyncio.wait_for(asyncio.to_thread(_play_fetch, pkg), PLAY_TIMEOUT)
        except NotFoundError:
            return c.not_possible("play_details", "app not found on Google Play (removed, or never published)")
        except asyncio.TimeoutError:
            return c.not_possible("play_details", f"Google Play did not answer in {int(PLAY_TIMEOUT)} s")
        c.facts["play"] = {"details": d, "perms": perms}
        dev, email, website = d.get("developer") or "", d.get("developerEmail") or "", d.get("developerWebsite") or ""
        pub = c.brand.official_publisher(dev, website, email)
        if pub:
            c.facts["official_publisher"] = pub
        official = bool(pub) or c.brand.is_official_asset("android", pkg)
        imp = impersonation(c.card, c.brand, d.get("title") or "", pkg, "android", dev, pub)
        if not official:
            if email and email.rsplit("@", 1)[-1].lower() in C.FREE_EMAIL_PROVIDERS:
                c.card.add("app_dev_free_email", f"developer email {email}")
            if not d.get("privacyPolicy"):
                c.card.add("app_no_privacy_policy", "the listing has no privacy policy link")
        age = app_age_signals(c, d.get("released"), d.get("ratings"), official)
        c.indicator("developer", dev)
        c.indicator("email", email.lower())
        store_evidence(c, "play_listing", {k: d.get(k) for k in (
            "title", "developer", "developerEmail", "developerWebsite", "developerAddress", "privacyPolicy",
            "installs", "released", "updated", "score", "ratings", "genre", "icon", "url")}
            | {"description": (d.get("description") or "")[:3000], "permissions": perms})
        return c.ran("play_details", title=d.get("title"), developer=dev, email=email, website=website,
                     installs=d.get("installs"), score=d.get("score"), genre=d.get("genre"),
                     official_publisher=pub, **age, **imp)

    first = await run_check("play_details", play_details, ctx, timeout=20)
    if first.status != RAN:
        return
    d, perms = ctx.facts["play"]["details"], ctx.facts["play"]["perms"]

    async def play_permissions(c: Ctx):
        if perms is None:
            return c.not_possible("play_permissions", "Google Play did not return the permission list")
        dangerous = dangerous_from_play(perms)
        official = bool(c.facts.get("official_publisher")) or c.brand.is_official_asset("android", pkg)
        if dangerous and not official:
            c.card.add("app_dangerous_permissions", ", ".join(C.DANGEROUS_PERMISSIONS.get(x, x) for x in dangerous))
        return c.ran("play_permissions", dangerous=[C.DANGEROUS_PERMISSIONS.get(x, x) for x in dangerous],
                     groups=sorted(perms)[:20])

    await asyncio.gather(
        run_check("play_permissions", play_permissions, ctx),
        run_check("icon_vs_logo", lambda c: check_icon(c, d.get("icon"), "android", pkg), ctx),
        run_check("developer_website", lambda c: check_dev_website(c, d.get("developerWebsite")), ctx),
        run_check("description_signals", _desc_check(d.get("description") or "", "android", pkg), ctx))


def _seller_official(brand, seller: str) -> str | None:
    """App Store seller names are verified by Apple: equal to the brand, or extending a listed publisher."""
    key = publisher_key(seller)
    if key and key == publisher_key(brand.name):
        return f"App Store seller {seller}"
    for p in brand.official_publishers():
        pk = publisher_key(p)
        if key and pk and key.startswith(pk):
            return f"App Store seller {seller} (listed publisher {p})"
    return None


async def run_ios(ctx: Ctx) -> None:
    app_id = ctx.link.ident

    async def ios_details(c: Ctx):
        status, results = 0, []
        for params in ({"id": app_id, "country": "in"}, {"id": app_id}):
            status, data = await get_json(c.client, "https://itunes.apple.com/lookup", params=params)
            results = (data or {}).get("results") if status == 200 and isinstance(data, dict) else []
            if results:
                break
        if status != 200:
            return c.not_possible("ios_details", f"App Store answered HTTP {status}")
        if not results:
            return c.not_possible("ios_details", "app not found on the App Store")
        r = results[0]
        seller, dev, website = r.get("sellerName") or "", r.get("artistName") or "", r.get("sellerUrl") or ""
        bundle = r.get("bundleId") or ""
        pub = _seller_official(c.brand, seller) or c.brand.official_publisher(dev, website)
        if not pub and bundle and bundle in (c.brand.official_apps.get("ios_bundles") or []):
            pub = f"official bundle id {bundle}"
        if pub:
            c.facts["official_publisher"] = pub
        official = bool(pub) or c.brand.is_official_asset("ios", app_id)
        imp = impersonation(c.card, c.brand, r.get("trackName") or "", app_id, "ios", seller or dev, pub)
        age = app_age_signals(c, r.get("releaseDate"), r.get("userRatingCount"), official)
        c.facts["ios"] = r
        c.indicator("developer", seller or dev)
        store_evidence(c, "appstore_listing", {k: r.get(k) for k in (
            "trackName", "sellerName", "artistName", "sellerUrl", "bundleId", "releaseDate", "version",
            "userRatingCount", "averageUserRating", "primaryGenreName", "trackViewUrl", "artworkUrl512")}
            | {"description": (r.get("description") or "")[:3000]})
        return c.ran("ios_details", title=r.get("trackName"), seller=seller, developer=dev, website=website,
                     bundle_id=bundle, official_publisher=pub, **age, **imp)

    first = await run_check("ios_details", ios_details, ctx)
    if first.status != RAN:
        return
    r = ctx.facts["ios"]
    icon = r.get("artworkUrl512") or r.get("artworkUrl100")
    await asyncio.gather(
        run_check("icon_vs_logo", lambda c: check_icon(c, icon, "ios", app_id), ctx),
        run_check("developer_website", lambda c: check_dev_website(c, r.get("sellerUrl")), ctx),
        run_check("description_signals", _desc_check(r.get("description") or "", "ios", app_id), ctx))
