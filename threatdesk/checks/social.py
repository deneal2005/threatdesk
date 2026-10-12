"""Social checks: YouTube (Data API), Telegram (t.me heuristic), Bluesky (public API), closed platforms."""
from __future__ import annotations

import re

from rapidfuzz import fuzz

from threatdesk.brands import BrandContext
from threatdesk.checks.base import Ctx, EvidenceItem, get_json
from threatdesk.checks.content import text_signals
from threatdesk.db import utcnow
from threatdesk.pageparse import parse
from threatdesk.safety import UnsafeURL, safe_fetch
from threatdesk.scoring import Scorecard
from threatdesk.scoring_helpers import handle_similarity, norm, parse_date

YT = "https://www.googleapis.com/youtube/v3"
OG_RE = re.compile(r"^(telegram: contact @|telegram messenger$|telegram – a new era of messaging)", re.I)
TG_EXTRA_RE = re.compile(r'class="tgme_page_extra"[^>]*>([^<]{1,80})<', re.I)
LOGIN_WALL = re.compile(r"^(instagram|facebook|x|tiktok|log ?in|login • instagram|facebook – log in or sign up|"
                        r"page not found|sorry, this page isn't available\.?)$", re.I)


from threatdesk.lookalike import find_lookalike


def social_signals(card: Scorecard, brand: BrandContext, platform: str, handle: str, name: str, bio: str,
                   created=None, followers: int | None = None, prefix: str = "") -> dict:
    if not brand.name:
        return {"note": "No brand selected: no look-alike check"}
    hkey = (handle or "").lstrip("@").lower()
    if hkey and brand.is_official_asset(platform, hkey):
        return {"official": True}
    out: dict = {}

    # 1. Handle look-alike classification against official handles and brand terms
    eligible_handles = [h for h in brand.all_handles() if h and not h.startswith("uc")]
    handle_match = find_lookalike(hkey, targets=brand.terms(), official_targets=eligible_handles)
    if handle_match:
        card.add("handle_similar",
                 f"{prefix}@{handle} resembles official @{handle_match.target} · {handle_match.label}: {handle_match.explanation}")
        out["similar_to"] = handle_match.target
        out["handle_lookalike"] = handle_match.as_dict()
    else:
        sims = [(handle_similarity(hkey, h), h) for h in eligible_handles]
        if sims and hkey:
            sim, best = max(sims)
            if sim >= 80 and norm(hkey) != norm(best):
                card.add("handle_similar", f"{prefix}@{handle} resembles official @{best} ({int(sim)}%)")
                out["similar_to"] = best

    # 2. Display name look-alike classification
    name_match = find_lookalike(name, targets=brand.terms()) if name else None
    if name_match:
        card.add("name_similar",
                 f"{prefix}Display name '{name[:80]}' resembles {brand.name} · {name_match.label}: {name_match.explanation}")
        out["name_similar"] = True
        out["name_lookalike"] = name_match.as_dict()
    elif name:
        for term in brand.terms():
            if fuzz.token_set_ratio(name.lower(), term) >= 85:
                card.add("name_similar", f"{prefix}display name '{name[:80]}' resembles {brand.name}")
                out["name_similar"] = True
                break
    born = parse_date(created)
    if born:
        days = (utcnow() - born).days
        if days < 90:
            card.add("account_lt_90d", f"{prefix}account created {born.date().isoformat()} ({days} days ago)")
        elif days < 365:
            card.add("account_lt_365d", f"{prefix}account created {born.date().isoformat()}")
    scratch = Scorecard()                       # text rules on name + bio, evidence prefixed (USER-SUPPLIED...)
    found = text_signals(scratch, f"{name or ''}\n{bio or ''}", brand, brand_mentions=False)
    for s in scratch.signals:
        card.add(s.code, f"{prefix}{s.evidence}")
    out["text_signals"] = list(found)
    claims = "claims_official" in found or "similar_to" in out
    if followers is not None and followers < 100 and claims:
        card.add("low_followers", f"{prefix}{followers} followers")
    return out


async def check_youtube(ctx: Ctx):
    key = ctx.settings.youtube_api_key
    if not key:
        return ctx.not_configured("youtube_channel", "YOUTUBE_API_KEY")
    link = ctx.link
    params = {"part": "snippet,statistics", "key": key}
    by = link.extra.get("by")
    if by == "video":
        status, data = await get_json(ctx.client, f"{YT}/videos", params={"part": "snippet", "key": key,
                                                                           "id": link.extra.get("video_id", "")})
        items = (data or {}).get("items") if status == 200 and isinstance(data, dict) else None
        if status == 403:
            return ctx.not_possible("youtube_channel", "YouTube API quota or key problem (HTTP 403)")
        if not items:
            return ctx.not_possible("youtube_channel", "video not found")
        params["id"] = items[0]["snippet"]["channelId"]
    elif by == "id":
        params["id"] = link.ident
    elif by == "legacy":
        params["forUsername"] = link.ident
    else:
        params["forHandle"] = link.ident if link.ident.startswith("@") else f"@{link.ident}"
    status, data = await get_json(ctx.client, f"{YT}/channels", params=params)
    if status == 403:
        return ctx.not_possible("youtube_channel", "YouTube API quota or key problem (HTTP 403)")
    if status != 200 or not isinstance(data, dict):
        return ctx.not_possible("youtube_channel", f"YouTube answered HTTP {status}")
    if not data.get("items"):
        return ctx.not_possible("youtube_channel", "channel not found")
    ch = data["items"][0]
    sn, st = ch.get("snippet", {}), ch.get("statistics", {})
    handle = (sn.get("customUrl") or link.ident or "").lstrip("@")
    subs = None if st.get("hiddenSubscriberCount") else int(st.get("subscriberCount") or 0)
    if ctx.brand.is_official_asset("youtube", ch.get("id", "")):
        det = {"official": True}
    else:
        det = social_signals(ctx.card, ctx.brand, "youtube", handle, sn.get("title", ""), sn.get("description", ""),
                             sn.get("publishedAt"), subs)
    ctx.indicator("handle", handle.lower())
    ctx.evidence.append(EvidenceItem("youtube_channel", {"id": ch.get("id"), "snippet": sn, "statistics": st}))
    return ctx.ran("youtube_channel", channel_id=ch.get("id"), title=sn.get("title"), handle=f"@{handle}",
                   created=sn.get("publishedAt"), followers=subs if subs is not None else "hidden",
                   videos=st.get("videoCount"), description=(sn.get("description") or "")[:300], **det)


def parse_telegram(page: str, handle: str) -> dict | None:
    """Telegram serves a generic page for any name; only a real title/description suggests the handle exists."""
    p = parse(page, f"https://t.me/{handle}")
    title = (p["meta"].get("og:title") or p["title"] or "").strip()
    desc = (p["meta"].get("og:description") or "").strip()
    generic_desc = not desc or desc.lower().startswith(f"if you have telegram, you can contact @{handle.lower()}")
    if (not title or OG_RE.match(title)) and generic_desc:
        return None
    m = TG_EXTRA_RE.search(page or "")
    return {"title": title, "description": desc[:500], "extra": m.group(1).strip() if m else None}


async def fetch_telegram(client, handle: str) -> tuple[str, dict | None]:
    for base in ("https://t.me/", "https://telegram.me/"):
        try:
            res = await safe_fetch(client, f"{base}{handle}", timeout=6)
        except (UnsafeURL, OSError, Exception):  # noqa: BLE001 - some networks block t.me; try the mirror
            continue
        if res.status_code == 200:
            return "ok", parse_telegram(res.text, handle)
    return "unreachable", None


async def check_telegram(ctx: Ctx):
    handle = ctx.link.ident
    status, data = await fetch_telegram(ctx.client, handle)
    if status == "unreachable":
        return ctx.not_possible("telegram_page", "t.me and telegram.me could not be reached")
    if data is None:
        return ctx.ran("telegram_page", exists=False, heuristic=True, handle=handle,
                       note="No public page: the handle may not exist (heuristic, unverified)")
    det = social_signals(ctx.card, ctx.brand, "telegram", handle, data["title"], data["description"])
    ctx.indicator("handle", handle.lower())
    ctx.evidence.append(EvidenceItem("telegram_page", {"handle": handle, **data}))
    return ctx.ran("telegram_page", exists=True, heuristic=True, handle=handle, title=data["title"],
                   members=data["extra"], description=data["description"][:300], **det)


async def check_bluesky(ctx: Ctx):
    status, data = await get_json(ctx.client, "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile",
                                  params={"actor": ctx.link.ident})
    if status == 400:
        return ctx.not_possible("bluesky_profile", "profile not found")
    if status != 200 or not isinstance(data, dict):
        return ctx.not_possible("bluesky_profile", f"Bluesky answered HTTP {status}")
    handle = data.get("handle") or ctx.link.ident
    short = handle[: -len(".bsky.social")] if handle.endswith(".bsky.social") else handle
    det = social_signals(ctx.card, ctx.brand, "bluesky", short, data.get("displayName") or "",
                         data.get("description") or "", data.get("createdAt"), data.get("followersCount"))
    ctx.indicator("handle", short.lower())
    ctx.evidence.append(EvidenceItem("bluesky_profile", data))
    return ctx.ran("bluesky_profile", handle=handle, display_name=data.get("displayName"),
                   followers=data.get("followersCount"), created=data.get("createdAt"), did=data.get("did"), **det)


async def check_closed_social(ctx: Ctx):
    """Instagram/X/Facebook/TikTok hide profiles; read only the public preview tags, never log in."""
    if not ctx.link.ident:
        return ctx.not_possible("public_og_tags", "the link does not name a profile")
    try:
        res = await safe_fetch(ctx.client, ctx.link.url, timeout=6)
    except UnsafeURL as e:
        return ctx.not_possible("public_og_tags", f"refused by SSRF guard: {e}")
    p = parse(res.text, res.url)
    title = (p["meta"].get("og:title") or "").strip()
    desc = (p["meta"].get("og:description") or "").strip()
    if res.status_code != 200 or not title or LOGIN_WALL.match(title):
        return ctx.not_possible("public_og_tags", "login wall or generic page: the platform hides this profile")
    det = social_signals(ctx.card, ctx.brand, ctx.link.platform, ctx.link.ident, title, desc)
    ctx.evidence.append(EvidenceItem("public_og_tags", {"url": res.url, "title": title, "description": desc}))
    return ctx.ran("public_og_tags", title=title, description=desc[:300], handle=ctx.link.ident, **det)
