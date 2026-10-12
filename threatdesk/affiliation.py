"""Is a social account that is named like the brand actually the brand's (a regional, language or product account),
or an impostor? Evidence, strongest first:

  1. An official website links to the account (fetched from the brand's own domains, redirects followed safely).
     The brand put it there, so it is affiliated. Scans drop such leads.
  2. The account is named "<brand> + region/language/product" (YouTube India, YouTube Brasil, AmazonNews) AND the
     platform shows a verified badge, it is long established, or a link in its profile resolves to an official
     domain. Likely the brand's own: labelled for review, never "suspicious" on the name alone.
  3. Regional naming with nothing else: unconfirmed, needs review (a look-alike name is not evidence of abuse).

A profile link that resolves to the official site is NOT proof on its own: impostors link to the real site to look
genuine. It only counts next to other evidence, and abuse signals (scam phrases, look-alike links...) always win.
"""
from __future__ import annotations

import asyncio
import re
import time

import httpx

from threatdesk.brands import BrandContext
from threatdesk.lookalike import basic
from threatdesk.scoring import Scorecard

CACHE_TTL = 6 * 3600
MAX_SITES = 3
MAX_LINKS = 3
FETCH_TIMEOUT = 8

# Countries, regions and languages brands name their local accounts after (lower case, letters only).
REGIONS = {
    "india", "ind", "in", "bharat", "hindi", "tamil", "telugu", "bangla", "bangladesh", "pakistan", "pk", "nepal",
    "srilanka", "lanka", "usa", "us", "america", "uk", "gb", "britain", "ireland", "ie", "canada", "ca", "mexico",
    "mx", "latam", "latino", "latinoamerica", "brasil", "brazil", "br", "argentina", "ar", "chile", "cl", "colombia",
    "co", "peru", "pe", "venezuela", "espana", "spain", "es", "espanol", "francais", "france", "fr", "deutsch",
    "deutschland", "germany", "de", "dach", "austria", "at", "schweiz", "suisse", "swiss", "ch", "italia", "italy",
    "it", "italiano", "portugal", "pt", "portugues", "nederland", "netherlands", "nl", "belgie", "belgique", "belgium",
    "be", "nordic", "nordics", "sverige", "sweden", "se", "norge", "norway", "no", "danmark", "denmark", "dk", "suomi",
    "finland", "fi", "polska", "poland", "pl", "cesko", "czech", "cz", "turkiye", "turkey", "tr", "turkce", "russia",
    "ru", "ukraine", "ua", "greece", "gr", "hellas", "romania", "ro", "hungary", "hu", "israel", "il", "arabia",
    "arabic", "arab", "mena", "ksa", "saudi", "uae", "emirates", "egypt", "eg", "maroc", "morocco", "africa", "za",
    "southafrica", "nigeria", "ng", "kenya", "ke", "ghana", "japan", "jp", "nihon", "korea", "kr", "china", "cn",
    "taiwan", "tw", "hongkong", "hk", "asia", "apac", "emea", "europe", "eu", "sea", "singapore", "sg", "malaysia",
    "my", "indonesia", "id", "philippines", "ph", "pilipinas", "thailand", "th", "vietnam", "vn", "australia", "au",
    "aus", "nz", "newzealand", "anz", "global", "intl", "international", "worldwide", "en", "english",
}
# Product, audience and function accounts brands commonly run. Deliberately NOT "support", "help", "care",
# "official", "rewards", "refund"...: impostors use exactly those, so they get no benefit of the doubt.
AFFILIATES = {
    "creators", "creator", "music", "kids", "gaming", "games", "tv", "originals", "shorts", "studio", "studios",
    "news", "newsroom", "press", "dev", "devs", "developers", "developer", "careers", "jobs", "life", "business",
    "ads", "advertising", "marketing", "design", "engineering", "eng", "tech", "security", "status", "events",
    "podcast", "learn", "learning", "academy", "education", "edu", "research", "labs", "ai", "cloud", "foundation",
    "sports", "movies", "films", "fashion", "beauty", "food", "travel", "prime", "pay",
}
SPLIT_RE = re.compile(r"[\s_.\-|·•:/]+")

_site_cache: dict[tuple, tuple[float, set[tuple[str, str]]]] = {}


def _brand_refs(brand: BrandContext) -> list[str]:
    refs = {basic(brand.name)} | {basic(k) for k in brand.keywords} | {basic(h) for h in brand.all_handles()}
    return sorted((r for r in refs if len(r) >= 3), key=len, reverse=True)


# In a squashed handle two-letter codes are ambiguous ("appleid" is not Apple Indonesia): only whole words count.
_SQUASHED = sorted((w for w in REGIONS | AFFILIATES if len(w) >= 3), key=len, reverse=True)


def _remainder_words(rest: str) -> list[str] | None:
    """Split a squashed remainder ('brasilmusic') into known words, longest first; None if any part is unknown."""
    if not rest:
        return []
    for w in _SQUASHED:
        if rest.startswith(w):
            tail = _remainder_words(rest[len(w):])
            if tail is not None:
                return [w, *tail]
    return None


def variant_of(brand: BrandContext, handle: str, name: str = "") -> dict | None:
    """{'kind': 'regional'|'affiliate', 'words': [...], 'ref': brand reference} when the handle (or display name) is
    a brand reference plus only region, language or product words: 'YouTubeIndia', 'youtube_brasil', 'AmazonNews'."""
    refs = _brand_refs(brand)
    for raw in (handle or "", name or ""):
        tokens = [basic(t) for t in SPLIT_RE.split(raw) if basic(t)]
        for i in range(1, len(tokens)):                     # separated words: "youtube_in", "YouTube Brasil"
            head, tail = "".join(tokens[:i]), tokens[i:]
            if head in refs and all(t in REGIONS or t in AFFILIATES for t in tail):
                kind = "regional" if any(t in REGIONS for t in tail) else "affiliate"
                return {"kind": kind, "words": tail, "ref": head}
        cb = basic(raw)
        for ref in refs:
            for rest in ([cb[len(ref):]] if cb.startswith(ref) else []) + \
                        ([cb[:-len(ref)]] if cb.endswith(ref) and cb != ref else []):
                words = _remainder_words(rest)
                if words:
                    kind = "regional" if any(w in REGIONS for w in words) else "affiliate"
                    return {"kind": kind, "words": words, "ref": ref}
    return None


async def official_site_profiles(client: httpx.AsyncClient, brand: BrandContext) -> set[tuple[str, str]]:
    """(platform, handle_key) of every social profile linked from the brand's official home pages. Fetched through
    the SSRF-guarded fetcher (redirects followed and re-checked), cached for a few hours per brand."""
    from threatdesk.assets import sources
    from threatdesk.assets.platforms import parse_profile
    from threatdesk.safety import InvalidInput
    domains = tuple(brand.official_domains[:MAX_SITES])
    if not domains:
        return set()
    key = (brand.id, brand.name, domains)
    hit = _site_cache.get(key)
    if hit and hit[0] > time.monotonic():
        return hit[1]

    async def one(domain: str) -> list[str]:
        try:
            final, html = await asyncio.wait_for(sources.fetch_page(client, f"https://{domain}/"), FETCH_TIMEOUT + 2)
            return sources.page_links(html, final)
        except (sources.Unavailable, asyncio.TimeoutError):
            return []
    found: set[tuple[str, str]] = set()
    pages = await asyncio.gather(*(one(d) for d in domains))
    for links in pages:
        for href in links:
            try:
                p = parse_profile(href)
            except InvalidInput:
                continue
            if p.platform != "other":
                found.add((p.platform, p.handle_key))
                if p.platform_id:
                    found.add((p.platform, p.platform_id.lower()))
    if any(pages):                              # don't cache a total failure: try again next time
        _site_cache[key] = (time.monotonic() + CACHE_TTL, found)
    return found


async def resolve_official_links(client: httpx.AsyncClient, brand: BrandContext, links) -> list[str]:
    """Profile links whose final destination (after redirects, e.g. t.co or bit.ly) is an official domain."""
    from threatdesk.indicators import host_of
    from threatdesk.safety import UnsafeURL, safe_fetch
    out = []
    for u in list(dict.fromkeys(links or []))[:MAX_LINKS]:
        url = u if "://" in u else f"https://{u}"
        host = host_of(url)
        if host and brand.is_official_host(host):
            out.append(host)
            continue
        try:
            res = await safe_fetch(client, url, timeout=FETCH_TIMEOUT, max_bytes=64 * 1024)
        except (UnsafeURL, httpx.HTTPError, OSError):
            continue
        final = host_of(res.url)
        if final and brand.is_official_host(final):
            out.append(f"{host} → {final}")
    return out


def apply(card: Scorecard, brand: BrandContext, platform: str, handle: str, name: str = "", *,
          linked_from_site: bool = False, official_links: list[str] = (), verified: bool | None = None,
          prefix: str = "") -> dict:
    """Add the affiliation signals for one account and return the classification with its confidence (0-100) and
    the evidence behind it. Call after social.social_signals() so abuse signals already on the card are seen."""
    from threatdesk.scoring import AFFILIATION_ABUSE
    hkey = (handle or "").lstrip("@").lower()
    variant = variant_of(brand, hkey, name)
    cross = sorted(p for p, hs in brand.official_handles.items() if p != platform and hkey in [h.lower() for h in hs])
    abuse = sorted({s.code for s in card.signals} & AFFILIATION_ABUSE)
    evidence: list[str] = []
    confidence = 0
    if linked_from_site:
        card.add("linked_from_official_site", f"{prefix}an official website of {brand.name} links to this account")
        evidence.append("linked from the brand's official website")
        confidence = 90
    if official_links:
        card.add("links_to_official_site", f"{prefix}profile link resolves to an official domain "
                                           f"({', '.join(official_links)[:200]})")
        evidence.append("its profile links to an official domain")
        confidence += 15
    if variant:
        words = " + ".join(variant["words"])
        what = "a region or language" if variant["kind"] == "regional" else "a product or team"
        card.add("regional_variant", f"{prefix}named as the brand plus {what} ({words}), the way brands name "
                                     f"their own local or product accounts")
        evidence.append(f"named like a {variant['kind']} account ({words})")
        confidence += 10
    if cross:
        evidence.append(f"the same handle is an official {', '.join(cross)} account")
        confidence += 20
    if verified:
        evidence.append("the platform shows a verified badge")
        confidence += 25
    if card.has("established_account"):
        evidence.append("long-established account with a large audience")
        confidence += 20
    confidence = min(95, confidence)
    if linked_from_site and not abuse:
        status = "affiliated"
    elif abuse:
        status, confidence = "suspicious", min(confidence, 30)
    elif (variant or cross) and confidence >= 35:
        status = "likely_affiliated"
    elif variant or cross:
        status = "needs_review"
    else:
        status = "unverified"
    return {"status": status, "confidence": confidence, "evidence": evidence, "abuse": abuse,
            **({"variant": variant} if variant else {})}


async def assess(client: httpx.AsyncClient, card: Scorecard, brand: BrandContext, platform: str, handle: str,
                 name: str = "", links=(), verified: bool | None = None, prefix: str = "") -> dict:
    """Gather the network evidence (only for accounts that resemble the brand) and apply it."""
    if not brand.name:
        return {}
    resembles = card.has("handle_similar") or card.has("name_similar") or variant_of(brand, handle, name)
    if not resembles:
        return {}
    hkey = (handle or "").lstrip("@").lower()
    # A Bluesky handle on an official domain can only be set by whoever controls that domain's DNS or web server.
    linked = platform == "bluesky" and "." in hkey and brand.is_official_host(hkey)
    if not linked:
        try:
            linked = (platform, hkey) in await official_site_profiles(client, brand)
        except Exception:  # noqa: BLE001 - evidence gathering must never break the check
            linked = False
    try:
        official = await resolve_official_links(client, brand, links)
    except Exception:  # noqa: BLE001
        official = []
    return apply(card, brand, platform, hkey, name, linked_from_site=linked, official_links=official,
                 verified=verified, prefix=prefix)
