"""Network reads used by verification. Each returns plain data or raises; tests replace these functions."""
from __future__ import annotations

import asyncio
import json

import dns.exception
import dns.resolver
import httpx

from threatdesk.assets.platforms import label
from threatdesk.checks.base import get_json
from threatdesk.pageparse import parse
from threatdesk.safety import UnsafeURL, dns_resolver, safe_fetch

YT = "https://www.googleapis.com/youtube/v3"


class Unavailable(Exception):
    """The source could not answer (network, missing key, platform closed): the check is inconclusive."""


async def txt_records(name: str) -> list[str]:
    try:
        ans = await dns_resolver().resolve(name, "TXT", lifetime=6)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as e:
        raise Unavailable(f"DNS lookup failed ({type(e).__name__})")
    return ["".join(s.decode("utf-8", "replace") for s in r.strings) for r in ans]


async def fetch_page(client: httpx.AsyncClient, url: str) -> tuple[str, str]:
    try:
        res = await safe_fetch(client, url, timeout=8)
    except (UnsafeURL, httpx.HTTPError, OSError) as e:
        raise Unavailable(f"{url} could not be fetched ({type(e).__name__})")
    if res.status_code != 200:
        raise Unavailable(f"{url} answered HTTP {res.status_code}")
    return res.url, res.text


def page_links(html: str, base: str) -> list[str]:
    return [ln["href"] for ln in parse(html, base)["links"]]


async def fetch_json_file(client: httpx.AsyncClient, url: str) -> object | None:
    try:
        res = await safe_fetch(client, url, timeout=8, max_bytes=256 * 1024)
    except (UnsafeURL, httpx.HTTPError, OSError) as e:
        raise Unavailable(f"{url} could not be fetched ({type(e).__name__})")
    if res.status_code != 200:
        return None
    try:
        return json.loads(res.body.decode("utf-8", "replace"))
    except ValueError:
        return None


async def read_profile(client: httpx.AsyncClient, settings, platform: str, handle: str, platform_id: str | None,
                       profile_url: str, allow_paid: bool) -> dict:
    """{"name", "bio", "links", "id"} for a profile, or Unavailable."""
    if platform == "youtube":
        if not settings.youtube_api_key:
            raise Unavailable("reading YouTube channels needs YOUTUBE_API_KEY")
        params = {"part": "snippet", "key": settings.youtube_api_key}
        params |= {"id": platform_id} if platform_id else {"forHandle": f"@{handle.lstrip('@')}"}
        status, data = await get_json(client, f"{YT}/channels", params=params)
        items = (data or {}).get("items") if status == 200 and isinstance(data, dict) else None
        if not items:
            raise Unavailable(f"YouTube channel not found (HTTP {status})")
        sn = items[0].get("snippet", {})
        return {"name": sn.get("title"), "bio": sn.get("description", ""), "links": [], "id": items[0].get("id")}
    if platform == "bluesky":
        actor = handle if "." in handle or handle.startswith("did:") else f"{handle}.bsky.social"
        status, data = await get_json(client, "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile",
                                      params={"actor": actor})
        if status != 200 or not isinstance(data, dict):
            raise Unavailable(f"Bluesky answered HTTP {status}")
        return {"name": data.get("displayName"), "bio": data.get("description", ""), "links": [], "id": data.get("did"),
                "handle": data.get("handle")}
    if platform == "github":
        status, data = await get_json(client, f"https://api.github.com/users/{handle}",
                                      headers={"Accept": "application/vnd.github+json"})
        if status != 200 or not isinstance(data, dict):
            raise Unavailable(f"GitHub answered HTTP {status}")
        return {"name": data.get("name"), "bio": data.get("bio") or "", "links": [u for u in [data.get("blog")] if u],
                "id": str(data.get("id") or "")}
    if platform == "telegram":
        from threatdesk.checks.social import fetch_telegram
        status, page = await fetch_telegram(client, handle)
        if status != "ok":
            raise Unavailable("t.me could not be reached")
        return {"name": (page or {}).get("title"), "bio": (page or {}).get("description", ""), "links": [], "id": None}
    if platform in ("instagram", "tiktok", "facebook"):
        return await _read_apify(client, settings, platform, handle, profile_url, allow_paid)
    raise Unavailable(f"ThreatDesk can't read {label(platform)} profiles automatically (the platform needs a login "
                      f"or a paid API)")


async def _read_apify(client, settings, platform: str, handle: str, profile_url: str, allow_paid: bool) -> dict:
    if not settings.apify_token:
        raise Unavailable(f"reading {label(platform)} bios needs the Apify integration (APIFY_TOKEN)")
    if not allow_paid:
        raise Unavailable(f"{label(platform)} bios are read only by a single Check (paid per profile)")
    from threatdesk.checks import apify
    from threatdesk.checks.base import Ctx
    from threatdesk.linkdetect import detect
    ctx = Ctx(client=client, link=detect(profile_url), brand=None, settings=settings)  # type: ignore[arg-type]
    status, item = await apify._run(ctx, platform, handle)
    if item is None:
        raise Unavailable(f"Apify: {status}")
    prof = apify.normalise(platform, item)
    return {"name": prof.get("name"), "bio": prof.get("bio") or "", "links": prof.get("links") or [], "id": None}


def _play(pkg: str) -> dict:
    from google_play_scraper import app
    d = app(pkg, lang="en", country="us")
    return {"name": d.get("title"), "developer": d.get("developer"), "website": d.get("developerWebsite"),
            "bundle_id": None}


async def read_store(client: httpx.AsyncClient, platform: str, store_id: str, market: str = "") -> dict:
    if platform == "android":
        try:
            return await asyncio.wait_for(asyncio.to_thread(_play, store_id), 15)
        except Exception as e:  # noqa: BLE001 - the scraper raises many kinds of errors
            raise Unavailable(f"Google Play listing could not be read ({type(e).__name__})")
    for cc in [c for c in (market.lower(), "us", "in") if c]:
        status, data = await get_json(client, "https://itunes.apple.com/lookup", params={"id": store_id, "country": cc})
        results = (data or {}).get("results") if status == 200 and isinstance(data, dict) else None
        if results:
            r = results[0]
            return {"name": r.get("trackName"), "developer": r.get("sellerName"), "website": r.get("sellerUrl"),
                    "bundle_id": r.get("bundleId")}
    raise Unavailable("App Store listing not found")
