"""Optional web-search discovery of PUBLIC profile pages on closed platforms.

Instagram, Facebook and X hide profiles from automated checks, but search engines index their public pages.
A search result that already shows look-alike signals becomes a finding labelled "FROM SEARCH RESULTS".
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx

from threatdesk.brands import BrandContext
from threatdesk.checks.base import EvidenceItem, get_json
from threatdesk.checks.social import social_signals
from threatdesk.config import Settings
from threatdesk.investigator import Report, exclusion
from threatdesk.linkdetect import detect
from threatdesk.safety import InvalidInput
from threatdesk.scoring import Scorecard, assess, severity, verdict

SITES = ["instagram.com", "facebook.com", "x.com"]
PREFIX = "FROM SEARCH RESULTS: "


@dataclass
class Hit:
    title: str
    url: str
    snippet: str


class GoogleCSE:
    name = "google"

    def __init__(self, key: str, cx: str):
        self.key, self.cx = key, cx

    async def search(self, client: httpx.AsyncClient, q: str) -> list[Hit]:
        status, data = await get_json(client, "https://www.googleapis.com/customsearch/v1",
                                      params={"key": self.key, "cx": self.cx, "q": q, "num": 10})
        if status != 200 or not isinstance(data, dict):
            raise RuntimeError(f"Google Custom Search answered HTTP {status}")
        return [Hit(i.get("title", ""), i.get("link", ""), i.get("snippet", "")) for i in data.get("items", [])]


class BraveSearch:
    name = "brave"

    def __init__(self, key: str):
        self.key = key

    async def search(self, client: httpx.AsyncClient, q: str) -> list[Hit]:
        status, data = await get_json(client, "https://api.search.brave.com/res/v1/web/search",
                                      params={"q": q, "count": 10},
                                      headers={"X-Subscription-Token": self.key, "Accept": "application/json"})
        if status != 200 or not isinstance(data, dict):
            raise RuntimeError(f"Brave Search answered HTTP {status}")
        return [Hit(i.get("title", ""), i.get("url", ""), i.get("description", ""))
                for i in (data.get("web") or {}).get("results", [])]


def providers(settings: Settings) -> list:
    out: list = []
    if settings.google_cse_key and settings.google_cse_cx:
        out.append(GoogleCSE(settings.google_cse_key, settings.google_cse_cx))
    if settings.brave_api_key:
        out.append(BraveSearch(settings.brave_api_key))
    return out


def queries(brand: BrandContext) -> list[str]:
    return [f'site:{s} "{brand.name}" (official OR support OR care OR helpline)' for s in SITES]


def hit_to_report(hit: Hit, brand: BrandContext, provider: str) -> Report | None:
    try:
        link = detect(hit.url)
    except InvalidInput:
        return None
    if link.kind != "closed_social" or not link.ident or exclusion(link, brand):
        return None
    card = Scorecard()
    det = social_signals(card, brand, link.platform, link.ident, hit.title, hit.snippet, prefix=PREFIX)
    if not card.signals:
        return None
    score = assess(card.signals, "social_profile").score
    detail = {"provider": provider, "title": hit.title[:200], "snippet": hit.snippet[:500], **det}
    return Report(url=link.url, kind="social_profile",
                  link={"kind": link.kind, "host": link.host, "ident": link.ident, "platform": link.platform},
                  display_name=f"{link.host.removeprefix('www.')}/{link.ident}", dedupe_key=link.dedupe_key,
                  checks=[{"check": "public_og_tags", "status": "ran", "detail": {**detail, "source": "search"}}],
                  signals=[s.as_dict() for s in card.signals], score=score, severity=severity(score),
                  verdict=verdict(score, 1, False, "social_profile"), checks_ran=1,
                  indicators=[("handle", link.ident.lower())],
                  evidence=[EvidenceItem("public_og_tags", {"from": "search results", "url": hit.url, **detail})],
                  ai={"status": "not used"})


async def src_websearch(client: httpx.AsyncClient, brand: BrandContext, settings: Settings):
    provs = providers(settings)
    if not provs:
        return "not configured (GOOGLE_CSE_KEY+GOOGLE_CSE_CX or BRAVE_API_KEY)", []
    reports: dict[str, Report] = {}
    hits = 0
    errors = []
    for p in provs:
        for q in queries(brand):
            try:
                found = await p.search(client, q)
            except (RuntimeError, httpx.HTTPError) as e:
                errors.append(str(e)[:80])
                break
            hits += len(found)
            for h in found:
                r = hit_to_report(h, brand, p.name)
                if r and r.dedupe_key not in reports:
                    reports[r.dedupe_key] = r
    if errors and not hits:
        return f"failed: {errors[0]}", []
    return f"ok: {hits} results, {len(reports)} look-alike profiles", list(reports.values())
