"""Instagram / TikTok / Facebook profiles through Apify (optional, paid per profile; off unless APIFY_TOKEN is set)."""
from __future__ import annotations

import time
from datetime import datetime, timezone

try:
    from datetime import UTC
except ImportError:
    UTC = timezone.utc

from threatdesk.checks.base import Ctx, EvidenceItem, get_json
from threatdesk.checks.social import social_signals
from threatdesk.indicators import extract

API = "https://api.apify.com/v2/acts/{actor}/run-sync-get-dataset-items"
MAX_CHARGE_USD = 0.05
RUN_TIMEOUT = 90
CACHE_TTL = 24 * 3600
ACTORS = {"instagram": "apify~instagram-profile-scraper", "tiktok": "clockworks~tiktok-profile-scraper",
          "facebook": "apify~facebook-pages-scraper"}
_cache: dict[tuple[str, str], tuple[float, tuple[str, dict | None]]] = {}


def _input(platform: str, handle: str, url: str, about: bool) -> dict:
    if platform == "instagram":
        return {"usernames": [handle], "includeAboutSection": about}
    if platform == "tiktok":
        return {"profiles": [handle], "resultsPerPage": 1, "shouldDownloadVideos": False,
                "shouldDownloadCovers": False, "shouldDownloadAvatars": False, "shouldDownloadSubtitles": False}
    return {"startUrls": [{"url": url}]}


def _epoch(v) -> str | None:
    if isinstance(v, (int, float)) and v > 0:
        return datetime.fromtimestamp(v / 1000 if v > 1e11 else v, UTC).replace(tzinfo=None).isoformat()
    return str(v) if v else None


def normalise(platform: str, item: dict) -> dict:
    """One profile shape for every actor: handle, name, bio, followers, posts, created, verified, private, links."""
    if platform == "instagram":
        about = item.get("about") or {}
        return {"handle": item.get("username"), "name": item.get("fullName"), "bio": item.get("biography"),
                "followers": item.get("followersCount"), "posts": item.get("postsCount"),
                "created": about.get("dateJoined") or None, "verified": item.get("verified"),
                "private": item.get("private"), "links": [u for u in [item.get("externalUrl")] if u],
                "contacts": [c for c in (item.get("businessEmail"), item.get("businessPhoneNumber")) if c],
                "joined_recently": bool(item.get("joinedRecently"))}
    if platform == "tiktok":
        a = item.get("authorMeta") or item
        return {"handle": a.get("name") or a.get("uniqueId"), "name": a.get("nickName") or a.get("nickname"),
                "bio": a.get("signature"), "followers": a.get("fans"), "posts": a.get("video"),
                "created": _epoch(a.get("createTime")), "verified": a.get("verified"), "private": a.get("privateAccount"),
                "links": [u for u in [a.get("bioLink")] if u], "contacts": []}
    return {"handle": item.get("pageName") or item.get("pageId"), "name": item.get("title") or item.get("name"),
            "bio": item.get("intro") or item.get("info"), "followers": item.get("followers") or item.get("likes"),
            "posts": None, "created": item.get("creation_date") or item.get("pageCreated"),
            "verified": item.get("verified"), "private": False,
            "links": [u for u in [item.get("website")] if u],
            "contacts": [c for c in (item.get("email"), item.get("phone")) if c]}


async def _run(ctx: Ctx, platform: str, handle: str) -> tuple[str, dict | None]:
    key = (platform, handle.lower())
    hit = _cache.get(key)
    if hit and hit[0] > time.monotonic():
        return hit[1]
    status, data = await get_json(
        ctx.client, API.format(actor=ACTORS[platform]),
        params={"timeout": RUN_TIMEOUT, "maxItems": 1, "maxTotalChargeUsd": MAX_CHARGE_USD},
        headers={"Authorization": f"Bearer {ctx.settings.apify_token}"}, method="POST",
        json_body=_input(platform, handle, ctx.link.url, ctx.settings.apify_instagram_about),
        timeout=RUN_TIMEOUT + 15, retries=0)
    if status in (401, 403):
        result = ("token rejected", None)
    elif status == 402:
        result = ("credits used up", None)
    elif status not in (200, 201) or not isinstance(data, list):
        result = (f"HTTP {status}", None)
    elif not data or data[0].get("error"):
        result = ("profile not found", None)
    else:
        result = ("ok", data[0])
    if result[0] in ("ok", "profile not found"):
        _cache[key] = (time.monotonic() + CACHE_TTL, result)
    return result


async def check_apify_profile(ctx: Ctx):
    if not ctx.settings.apify_token:
        return ctx.not_configured("social_profile", "APIFY_TOKEN")
    platform, handle = ctx.link.platform, ctx.link.ident
    if platform not in ACTORS:
        return ctx.not_possible("social_profile", f"{platform} profiles are not supported by the profile reader")
    if not handle:
        return ctx.not_possible("social_profile", "the link does not name a profile")
    status, item = await _run(ctx, platform, handle)
    if item is None:
        return ctx.not_possible("social_profile", f"Apify: {status}")
    prof = normalise(platform, item)
    det = social_signals(ctx.card, ctx.brand, platform, prof["handle"] or handle, prof["name"] or "",
                         prof["bio"] or "", prof["created"],
                         prof["followers"] if isinstance(prof["followers"], int) else None,
                         verified=bool(prof.get("verified")), links=prof["links"])
    if platform == "instagram" and prof.get("joined_recently") and not prof["created"] and \
            ("similar_to" in det or det.get("name_similar")):
        ctx.card.add("account_lt_90d", "Instagram shows 'joined recently' on a profile that resembles the brand")
    for u in prof["links"]:
        ctx.indicator("url", u)
    found = extract(" ".join(str(c) for c in prof["contacts"]) + " " + (prof["bio"] or ""))
    for t in ("email", "phone", "upi"):
        for v in found[t][:10]:
            ctx.indicator(t, v)
    ctx.evidence.append(EvidenceItem("social_profile", {"platform": platform, "profile": prof, "raw": item}))
    return ctx.ran("social_profile", **{k: v for k, v in prof.items() if k != "contacts"}, **det)
