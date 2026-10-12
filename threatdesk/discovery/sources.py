"""Discovery sources. Each returns (status_text, [candidate URLs]). Exceptions are caught by the scan runner."""
from __future__ import annotations

import asyncio
import time
from collections import Counter

from rapidfuzz import fuzz

from threatdesk.brands import BrandContext
from threatdesk.checks.base import get_json
from threatdesk.checks.domain import resolve_a
from threatdesk.checks.social import fetch_telegram
from threatdesk.config import Settings
from threatdesk.discovery.permutations import all_domain_candidates, telegram_candidates
from threatdesk.safety import DOMAIN_RE
from threatdesk.scoring_helpers import handle_similarity

DNS_CONCURRENCY = 30
MAX_DOMAIN_JOBS = 60
MAX_CT_JOBS = 40
MAX_PER_SOURCE = 25


def relevant(brand: BrandContext, *texts: str) -> bool:
    blob = " ".join(t or "" for t in texts).lower()
    if any(term in blob for term in brand.terms() if len(term) >= 3):
        return True
    return any(fuzz.token_set_ratio(brand.name.lower(), (t or "").lower()) >= 80 for t in texts if t)


async def resolve_many(hosts: list[str]) -> tuple[list[str], dict]:
    sem = asyncio.Semaphore(DNS_CONCURRENCY)
    stats: Counter = Counter()
    ok: list[str] = []

    async def one(h: str) -> None:
        async with sem:
            state, ips = await resolve_a(h, lifetime=3.0)
        stats[state] += 1
        if state == "resolved" and ips:
            ok.append(h)

    await asyncio.gather(*(one(h) for h in hosts))
    order = {h: i for i, h in enumerate(hosts)}
    return sorted(ok, key=order.get), dict(stats)


def _keep(brand: BrandContext, host: str) -> bool:
    return not brand.is_official_host(host) and not brand.is_whitelisted("domain", host)


async def src_domains(client, brand: BrandContext, settings: Settings):
    if not brand.official_domains:
        return "not possible: the brand has no official websites yet", []
    cands = all_domain_candidates(brand.official_domains)
    ok, stats = await resolve_many(cands)
    keep = [h for h in ok if _keep(brand, h)]
    urls = [f"https://{h}/" for h in keep[:MAX_DOMAIN_JOBS]]
    misc = ", ".join(f"{k} {v}" for k, v in stats.items() if k != "resolved")
    return (f"ok: {len(cands)} candidates, {len(ok)} resolve{f' ({misc})' if misc else ''}; "
            f"investigating first {len(urls)}"), urls


async def src_crtsh(client, brand: BrandContext, settings: Settings):
    terms = [t.replace(" ", "") for t in brand.terms() if len(t.replace(" ", "")) >= 4][:3]
    if not terms:
        return "not possible: no brand term of 4+ letters", []
    names: set[str] = set()
    for term in terms:
        status, data = await get_json(client, "https://crt.sh/", params={"q": f"%{term}%", "output": "json"},
                                      timeout=20, retries=0)
        if status != 200 or not isinstance(data, list):
            return f"failed: crt.sh answered HTTP {status}", []
        for row in data[:5000]:
            for n in str(row.get("name_value") or "").split("\n"):
                n = n.strip().lower().removeprefix("*.")
                if term in n.replace("-", "") and DOMAIN_RE.match(n):
                    names.add(n)
    cands = [n for n in sorted(names) if _keep(brand, n)][:300]
    ok, _ = await resolve_many(cands)
    return f"ok: {len(names)} certificate names, {len(ok)} resolve", [f"https://{h}/" for h in ok[:MAX_CT_JOBS]]


async def src_ios(client, brand: BrandContext, settings: Settings):
    urls: list[str] = []
    official = {a.lower() for a in brand.official_apps.get("ios", [])}
    for term in brand.terms()[:3]:
        status, data = await get_json(client, "https://itunes.apple.com/search",
                                      params={"term": term, "entity": "software", "country": "in", "limit": 25})
        if status != 200 or not isinstance(data, dict):
            return f"failed: App Store search answered HTTP {status}", urls
        for r in data.get("results", []):
            if str(r.get("trackId")) in official or not relevant(brand, r.get("trackName"), r.get("sellerName")):
                continue
            u = f"https://apps.apple.com/app/id{r.get('trackId')}"
            if u not in urls:
                urls.append(u)
    return f"ok: {len(urls)} non-official apps resemble the brand", urls[:MAX_PER_SOURCE]


def _play_search(term: str) -> list[dict]:
    from google_play_scraper import search
    return search(term, lang="en", country="in", n_hits=20)


async def src_android(client, brand: BrandContext, settings: Settings):
    urls: list[str] = []
    no_id = 0
    official = {a.lower() for a in brand.official_apps.get("android", [])}
    for term in brand.terms()[:3]:
        hits = await asyncio.wait_for(asyncio.to_thread(_play_search, term), 15)
        for h in hits:
            app_id = h.get("appId")
            if not app_id:
                no_id += 1
                continue
            if app_id.lower() in official or not relevant(brand, h.get("title"), h.get("developer")):
                continue
            u = f"https://play.google.com/store/apps/details?id={app_id}"
            if u not in urls:
                urls.append(u)
    note = f"; {no_id} results had no app id (scraper limitation)" if no_id else ""
    return f"ok: {len(urls)} non-official apps resemble the brand{note}", urls[:MAX_PER_SOURCE]


async def src_youtube(client, brand: BrandContext, settings: Settings):
    if not settings.youtube_api_key:
        return "not configured (YOUTUBE_API_KEY)", []
    status, data = await get_json(client, "https://www.googleapis.com/youtube/v3/search",
                                  params={"part": "snippet", "type": "channel", "q": brand.name, "maxResults": 15,
                                          "key": settings.youtube_api_key})
    if status != 200 or not isinstance(data, dict):
        return f"failed: YouTube search answered HTTP {status}", []
    urls = []
    for it in data.get("items", []):
        cid = (it.get("id") or {}).get("channelId") or (it.get("snippet") or {}).get("channelId")
        title = (it.get("snippet") or {}).get("title", "")
        if cid and not brand.is_official_asset("youtube", cid) and relevant(brand, title):
            urls.append(f"https://www.youtube.com/channel/{cid}")
    return f"ok: {len(urls)} channels resemble the brand", urls[:MAX_PER_SOURCE]


async def src_bluesky(client, brand: BrandContext, settings: Settings):
    status, data = await get_json(client, "https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors",
                                  params={"q": brand.name, "limit": 25})
    if status != 200 or not isinstance(data, dict):
        return f"failed: Bluesky search answered HTTP {status}", []
    official = brand.official_handles.get("bluesky", [])
    urls = []
    for a in data.get("actors", []):
        handle = a.get("handle", "")
        short = handle.removesuffix(".bsky.social")
        if brand.is_official_asset("bluesky", short) or brand.is_official_asset("bluesky", handle):
            continue
        similar = any(handle_similarity(short, h) >= 80 for h in official)
        if similar or relevant(brand, a.get("displayName"), short):
            urls.append(f"https://bsky.app/profile/{handle}")
    return f"ok: {len(urls)} accounts resemble the brand", urls[:MAX_PER_SOURCE]


async def src_telegram(client, brand: BrandContext, settings: Settings, deadline: float):
    handles = [h for h in brand.official_handles.get("telegram", []) if h]
    if not handles:
        return "not possible: the brand has no official Telegram handle", []
    cands = list(dict.fromkeys(c for h in handles for c in telegram_candidates(h)))
    found: list[str] = []
    probed = 0
    for i in range(0, len(cands), 5):
        if time.monotonic() > deadline - 5 or len(found) >= MAX_PER_SOURCE:
            break
        batch = cands[i:i + 5]
        results = await asyncio.gather(*(fetch_telegram(client, c) for c in batch), return_exceptions=True)
        probed += len(batch)
        for c, res in zip(batch, results):
            if isinstance(res, tuple) and res[0] == "ok" and res[1]:
                found.append(f"https://t.me/{c}")
        await asyncio.sleep(0.5)
    return (f"ok: probed {probed}/{len(cands)} lookalike handles, {len(found)} appear to exist "
            f"(heuristic, unverified)"), found[:MAX_PER_SOURCE]
