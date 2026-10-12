"""Investigator: detect the link type, run the right checks, score, verdict, optional AI. Returns a Report."""
from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field

import httpx

from threatdesk import llm
from threatdesk.brands import BrandContext
from threatdesk.checks import content, ct, domain, page, rdap, reputation, tls
from threatdesk.checks.base import RAN, CheckOutcome, Ctx, EvidenceItem, run_check
from threatdesk.config import Settings, get_settings
from threatdesk.linkdetect import Link, detect
from threatdesk.scoring import MIN_CHECKS, RULES, severity, verdict

KIND_MAP = {"website": "website", "android_app": "android_app", "ios_app": "ios_app", "youtube": "youtube",
            "telegram": "telegram", "bluesky": "bluesky", "closed_social": "social_profile"}


@dataclass
class Report:
    url: str
    kind: str
    link: dict
    display_name: str
    dedupe_key: str
    checks: list[dict] = field(default_factory=list)
    signals: list[dict] = field(default_factory=list)
    score: int = 0
    severity: str = "Low"
    verdict: str = "Insufficient data"
    checks_ran: int = 0
    indicators: list[tuple[str, str]] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    ai: dict = field(default_factory=dict)
    excluded_reason: str | None = None
    facts: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence"] = [{"kind": e.kind, "sha256": e.sha256} for e in self.evidence]
        return d


def _social_handle(link: Link) -> str:
    h = link.ident.lstrip("@").lower()
    return h[: -len(".bsky.social")] if link.kind == "bluesky" and h.endswith(".bsky.social") else h


def exclusion(link: Link, brand: BrandContext) -> str | None:
    """Why this link is one of the brand's own or allowed assets (checks still run; the score is forced to 0)."""
    if brand.is_whitelisted("dedupe_key", link.dedupe_key):
        return "on the brand's allow list"
    if link.kind == "website":
        if brand.is_official_host(link.host):
            return f"official domain of {brand.name}"
        if brand.is_whitelisted("domain", link.host):
            return "domain on the brand's allow list"
    elif link.kind in ("android_app", "ios_app"):
        kind = "android" if link.kind == "android_app" else "ios"
        if brand.is_official_asset(kind, link.ident):
            return f"official app of {brand.name}"
        if brand.is_whitelisted(kind, link.ident):
            return "app on the brand's allow list"
    elif link.ident:
        handle = _social_handle(link)
        if brand.is_official_asset(link.platform, handle):
            return f"official {link.platform} account of {brand.name}"
        if brand.is_whitelisted("handle", handle):
            return "account on the brand's allow list"
    return None


async def _website(ctx: Ctx) -> None:
    await run_check("dns", domain.check_dns, ctx)
    await asyncio.gather(
        run_check("domain_name", content.check_domain_name, ctx),
        run_check("rdap_domain", rdap.check_rdap_domain, ctx),
        run_check("rdap_ip", rdap.check_rdap_ip, ctx),
        run_check("tls", tls.check_tls, ctx),
        run_check("wayback", domain.check_wayback, ctx),
        run_check("page_fetch", page.check_page, ctx),
        run_check("safe_browsing", reputation.check_safe_browsing, ctx),
        run_check("virustotal", reputation.check_virustotal, ctx, timeout=40),
        run_check("urlhaus", reputation.check_urlhaus, ctx))
    await run_check("content_signals", content.check_content, ctx)
    await asyncio.gather(                                                 # after page_fetch: see the final URL
        run_check("scam_lists", reputation.check_scam_lists, ctx),
        run_check("phishtank", reputation.check_phishtank, ctx),
        run_check("ct_history", ct.check_ct, ctx))                        # after rdap_domain: age fallback
    content.independent_site(ctx)                                         # needs page, rdap and ct results


async def _run_kind(ctx: Ctx) -> None:
    kind = ctx.link.kind
    if kind == "website":
        await _website(ctx)
    elif kind == "android_app":
        from threatdesk.checks import apps
        await apps.run_play(ctx)
    elif kind == "ios_app":
        from threatdesk.checks import apps
        await apps.run_ios(ctx)
    else:
        from threatdesk.checks import apify, social
        if kind == "youtube":
            await run_check("youtube_channel", social.check_youtube, ctx)
        elif kind == "telegram":
            await run_check("telegram_page", social.check_telegram, ctx)
        elif kind == "bluesky":
            await run_check("bluesky_profile", social.check_bluesky, ctx)
        else:
            await asyncio.gather(run_check("public_og_tags", social.check_closed_social, ctx),
                                 run_check("social_profile", apify.check_apify_profile, ctx, timeout=110))


def display_name(link: Link, outcomes: list[CheckOutcome]) -> str:
    ran = {o.check: o.detail for o in outcomes if o.status == RAN}
    if link.kind in ("android_app", "ios_app"):
        d = ran.get("play_details") or ran.get("ios_details") or {}
        return f"{d['title']} ({link.ident})" if d.get("title") else link.ident
    if link.kind == "youtube":
        d = ran.get("youtube_channel") or {}
        who = d.get("handle") or link.ident or d.get("title") or "video"
        return f"youtube.com/{who}"
    if link.kind in ("telegram", "bluesky", "closed_social") and link.ident:
        base = {"telegram": "t.me", "bluesky": "bsky.app/profile"}.get(link.kind, link.host.removeprefix("www."))
        return f"{base}/{link.ident}"
    return link.host


def ai_facts(ctx: Ctx, brand: BrandContext) -> dict:
    return {
        "brand": brand.name or None, "official_domains": brand.official_domains[:10],
        "kind": KIND_MAP[ctx.link.kind], "host": ctx.link.host, "url": ctx.link.url,
        "checks": [{"check": o.check, "status": o.status, "detail": {k: v for k, v in o.detail.items()
                                                                       if k not in ("raw", "generic")}}
                   for o in ctx.outcomes],
        "signals": [{"rule": RULES[s.code][1], "points": s.points, "evidence": s.evidence} for s in ctx.card.signals],
        "indicators": sorted(ctx.indicators)[:40],
    }


HARD_EVIDENCE = {"safe_browsing_hit", "virustotal_malicious", "urlhaus_listed", "phishtank_verified", "scam_list_hit",
                 "hosting_abuse_block", "idn_homograph", "brand_domain_embedded"}
BRAND_CLAIMS = {"claims_official", "brand_mention_unofficial", "known_brand_unofficial", "domain_lookalike",
                "domain_has_brand", "app_impersonation", "handle_similar", "name_similar"}
ENFORCEMENT_WORDS = ("block", "report", "takedown", "take down", "take-down", "blacklist", "blocklist", "suspend")


def hard_evidence(codes: set[str]) -> bool:
    return bool(codes & HARD_EVIDENCE) or ("asks_credentials" in codes and bool(codes & BRAND_CLAIMS))


def temper_ai(ai: dict, codes: set[str]) -> dict:
    """Without hard evidence the AI may not recommend enforcement: a wrong takedown request hurts someone."""
    if hard_evidence(codes):
        return ai
    steps = [s for s in ai.get("next_steps", []) if not any(w in s.lower() for w in ENFORCEMENT_WORDS)]
    lead = "Confirm who owns this site before any takedown request: the evidence is not conclusive."
    return {**ai, "next_steps": [lead, *steps][:5], "advice_limited": True}


async def investigate(url: str, brand: BrandContext | None = None, settings: Settings | None = None,
                      client: httpx.AsyncClient | None = None, use_ai: bool = True) -> Report:
    brand = brand or BrandContext()
    settings = settings or get_settings()
    link = detect(url)
    own = client is None
    client = client or httpx.AsyncClient(limits=httpx.Limits(max_connections=20))
    try:
        ctx = Ctx(client=client, link=link, brand=brand, settings=settings)
        excluded = exclusion(link, brand)
        await _run_kind(ctx)
        if not excluded and ctx.facts.get("official_publisher"):      # an app by the brand or a listed group company
            excluded = f"official publisher: {ctx.facts['official_publisher']}"
        ran = sum(1 for o in ctx.outcomes if o.status == RAN)
        ai = {"status": llm.UNAVAILABLE}
        if use_ai and settings.gemini_api_key and not excluded:
            res = await llm.assess(client, ai_facts(ctx, brand), thin=ran < MIN_CHECKS)
            if res:
                ai = {"status": "ok", **res}
                independent = any(s.code == "independent_site" for s in ctx.card.signals)
                if res["scam_likelihood"] >= 0.7 and ran >= MIN_CHECKS and not independent:
                    ctx.card.add("ai_assessment", f"AI: {res['category']} (likelihood {res['scam_likelihood']})")
                ai = temper_ai(ai, {s.code for s in ctx.card.signals})
    finally:
        if own:
            await client.aclose()
    score = 0 if excluded else ctx.card.score
    return Report(url=link.url, kind=KIND_MAP[link.kind], link={"kind": link.kind, "host": link.host,
                  "ident": link.ident, "platform": link.platform, **link.extra},
                  display_name=display_name(link, ctx.outcomes), dedupe_key=link.dedupe_key,
                  checks=[{"check": o.check, "status": o.status, "detail": o.detail} for o in ctx.outcomes],
                  signals=[s.as_dict() for s in ctx.card.signals] if not excluded else [],
                  score=score, severity=severity(score), verdict=verdict(score, ran, bool(excluded), KIND_MAP[link.kind]), checks_ran=ran,
                  indicators=sorted(ctx.indicators), evidence=ctx.evidence, ai=ai, excluded_reason=excluded,
                  facts={k: ctx.facts[k] for k in ("dns", "rdap_domain", "rdap_ip", "tls", "wayback") if k in ctx.facts}
                  | ({"redirect_chain": ctx.facts["page"]["redirect_chain"],
                      "final_url": ctx.facts["page"]["final_url"]} if "page" in ctx.facts else {}))
