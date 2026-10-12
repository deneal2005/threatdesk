"""Social checks: YouTube (Data API), Telegram (t.me heuristic), Bluesky (public API), closed platforms."""
from __future__ import annotations

import re


from threatdesk.brands import BrandContext
from threatdesk.checks.base import Ctx, EvidenceItem, get_json
from threatdesk.checks.content import text_signals
from threatdesk.checks.domain import registrable_domain
from threatdesk.db import utcnow
from threatdesk.indicators import extract, host_of, is_shortener
from threatdesk.lookalike import basic, best_match
from threatdesk.pageparse import parse
from threatdesk.safety import UnsafeURL, safe_fetch
from threatdesk.scoring import Scorecard
from threatdesk.scoring_helpers import parse_date

YT = "https://www.googleapis.com/youtube/v3"
OG_RE = re.compile(r"^(telegram: contact @|telegram messenger$|telegram – a new era of messaging)", re.I)
TG_EXTRA_RE = re.compile(r'class="tgme_page_extra"[^>]*>([^<]{1,80})<', re.I)
LOGIN_WALL = re.compile(r"^(instagram|facebook|x|tiktok|log ?in|login • instagram|facebook – log in or sign up|"
                        r"page not found|sorry, this page isn't available\.?)$", re.I)


# Link wrappers the platform itself adds to every link in a profile (X rewrites all links to t.co). They say nothing
# about the account, so they are not "links hidden behind a shortener".
PLATFORM_WRAPPERS = {"x": ("t.co",), "linkedin": ("lnkd.in",), "youtube": ("youtu.be",)}
BARE_DOMAIN_RE = re.compile(r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)


def _bio_links(card: Scorecard, brand: BrandContext, bio: str, links, prefix: str, out: dict) -> list[str]:
    """Links in the profile that point at a non-official site whose name imitates the brand. The brand's exact name
    on another TLD (amazon.work, amazon.shop) is usually the brand's own: recorded, not scored."""
    found: list[str] = []
    refs = brand.name_references() | {registrable_domain(d).split(".")[0]: f"official site {d}"
                                      for d in brand.official_domains}
    bare = [m.group(0) for m in BARE_DOMAIN_RE.finditer(bio or "")]
    for u in list(dict.fromkeys([*(links or []), *extract(bio or "")["url"], *bare]))[:10]:
        host = host_of(u)
        if not host or brand.is_official_host(host) or is_shortener(u):
            continue
        hit = best_match(registrable_domain(host).split(".")[0], refs)
        if hit and hit[0].score == 100 and hit[0].techniques == ["identical name"]:
            out.setdefault("same_name_links", []).append(host)
            continue
        if hit and hit[0].strong(brand.lookalike_threshold):
            card.add("bio_link_lookalike", f"{prefix}profile links to {host}, which imitates {hit[1]} "
                                           f"({hit[0].explain()})")
            found.append(host)
    return found


def _unwrap(platform: str, text: str) -> str:
    hosts = PLATFORM_WRAPPERS.get(platform)
    if not hosts:
        return text
    rx = "|".join(re.escape(h) for h in hosts)
    return re.sub(rf"(?:https?://)?(?:www\.)?(?:{rx})/[\w-]+", " ", text, flags=re.I)


def social_signals(card: Scorecard, brand: BrandContext, platform: str, handle: str, name: str, bio: str,
                   created=None, followers: int | None = None, prefix: str = "", verified: bool | None = None,
                   links=()) -> dict:
    """Signals for one account. Identity (handle/name look-alike) is kept apart from context (age, audience,
    badge) and behaviour (bio text, links) so scoring can tell "named like the brand" from "acts like a scam"."""
    if not brand.name:
        return {"note": "No brand selected: no look-alike check"}
    hkey = (handle or "").lstrip("@").lower()
    if hkey and brand.is_official_asset(platform, hkey):
        return {"official": True}
    out: dict = {}
    th = brand.lookalike_threshold
    if hkey:
        hit = best_match(hkey, brand.reference_handles() | brand.name_references())
        if hit and hit[0].strong(th):
            m, label = hit
            same = basic(hkey) == basic(m.reference) and m.reference in brand.reference_handles()
            why = ("same handle as an official account on another platform; add it to the brand if it is yours"
                   if same else m.explain())
            card.add("handle_similar", f"{prefix}@{handle} resembles {label} ({why}; similarity {m.score}%)")
            out["similar_to"], out["handle_match"] = m.reference, m.as_dict()
        elif hit:
            out["handle_mentions"] = hit[0].as_dict()
    if name:
        hit = best_match(name, brand.name_references())
        if hit and hit[0].strong(th):
            card.add("name_similar", f"{prefix}display name '{name[:80]}' resembles {hit[1]} ({hit[0].explain()})")
            out["name_similar"], out["name_match"] = True, hit[0].as_dict()
    born = parse_date(created)
    days = (utcnow() - born).days if born else None
    if days is not None and days < 90:
        card.add("account_lt_90d", f"{prefix}account created {born.date().isoformat()} ({days} days ago)")
    elif days is not None and days < 365:
        card.add("account_lt_365d", f"{prefix}account created {born.date().isoformat()}")
    scratch = Scorecard()                       # text rules on name + bio, evidence prefixed (USER-SUPPLIED...)
    found = text_signals(scratch, _unwrap(platform, f"{name or ''}\n{bio or ''}"), brand, brand_mentions=False)
    for s in scratch.signals:
        card.add(s.code, f"{prefix}{s.evidence}")
    out["text_signals"] = list(found)
    if lookalike_links := _bio_links(card, brand, bio, links, prefix, out):
        out["lookalike_links"] = lookalike_links
    resembles = "similar_to" in out or bool(out.get("name_similar"))
    if followers is not None and followers < 100 and ("claims_official" in found or resembles):
        card.add("low_followers", f"{prefix}{followers} followers")
    if verified and resembles:
        card.add("platform_verified", f"{prefix}the platform shows a verified badge on this account")
    if days is not None and days >= 730 and followers is not None and followers >= 10_000:
        card.add("established_account", f"{prefix}account since {born.date().isoformat()} with {followers:,} followers")
    return out


async def _affiliation(ctx: Ctx, platform: str, handle: str, name: str, bio: str = "", links=(),
                       verified: bool | None = None) -> dict:
    """Evidence that a brand-named account is the brand's own (linked from its site, regional naming...).
    Runs once per investigation: the public preview and the profile reader may both read the same account."""
    from threatdesk import affiliation
    if "affiliation" in ctx.facts or det_official(ctx, platform, handle):
        return {}
    found = [*links, *extract(bio or "")["url"], *[m.group(0) for m in BARE_DOMAIN_RE.finditer(bio or "")]]
    out = await affiliation.assess(ctx.client, ctx.card, ctx.brand, platform, handle, name, found, verified)
    if out:
        ctx.facts["affiliation"] = out
        return {"affiliation": out}
    return {}


def det_official(ctx: Ctx, platform: str, handle: str) -> bool:
    return ctx.brand.is_official_asset(platform, (handle or "").lstrip("@").lower())


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
        det.update(await _affiliation(ctx, "youtube", handle, sn.get("title", ""), sn.get("description", "")))
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
    det.update(await _affiliation(ctx, "telegram", handle, data["title"], data["description"]))
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
    det.update(await _affiliation(ctx, "bluesky", short, data.get("displayName") or "", data.get("description") or ""))
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
    det.update(await _affiliation(ctx, ctx.link.platform, ctx.link.ident, title, desc))
    ctx.evidence.append(EvidenceItem("public_og_tags", {"url": res.url, "title": title, "description": desc}))
    return ctx.ran("public_og_tags", title=title, description=desc[:300], handle=ctx.link.ident, **det)
