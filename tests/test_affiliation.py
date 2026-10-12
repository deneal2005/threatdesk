"""Official regional / product accounts are not flagged as impostors on their name alone; evidence decides."""
import asyncio

import httpx

from threatdesk import affiliation
from threatdesk.brands import BrandContext
from threatdesk.checks.social import social_signals
from threatdesk.discovery.websearch import Hit, hit_to_report
from threatdesk.riskview import TIERS, classify
from threatdesk.scoring import Scorecard, assess

YT = BrandContext(id=7, name="YouTube", official_domains=["youtube.com"],
                  official_handles={"x": ["youtube"], "instagram": ["youtube"]})


def _codes(card):
    return {s.code for s in card.signals}


def test_regional_and_product_names_are_recognised():
    assert affiliation.variant_of(YT, "YouTubeIndia")["words"] == ["india"]
    assert affiliation.variant_of(YT, "youtube_brasil")["kind"] == "regional"
    assert affiliation.variant_of(YT, "YTB", "YouTube Brasil")["words"] == ["brasil"]
    assert affiliation.variant_of(YT, "youtube_in")["words"] == ["in"]            # separated codes are fine
    assert affiliation.variant_of(YT, "YouTubeCreators")["kind"] == "affiliate"
    assert affiliation.variant_of(YT, "youtubemusicjapan")["words"] == ["music", "japan"]
    # words impostors use get no benefit of the doubt, and squashed two-letter codes are ambiguous
    for h in ("YouTubeSupport", "youtubehelpdesk", "youtube_official", "youtubeid", "youtubeclaimreward"):
        assert affiliation.variant_of(YT, h) is None, h


def test_regional_name_alone_is_review_not_suspicious():
    card = Scorecard()
    social_signals(card, YT, "x", "YouTubeIndia", "YouTube India", "Official YouTube India channel updates")
    out = affiliation.apply(card, YT, "x", "YouTubeIndia", "YouTube India")
    assert out["status"] == "needs_review" and "regional_variant" in _codes(card)
    score = assess(card.signals, "social_profile").score
    assert score < 40
    assert classify("new", "No strong signals", _codes(card), score) == "regional_review"
    assert TIERS["regional_review"][0] == "Regional or product name, unconfirmed"


def test_supporting_evidence_makes_it_likely_affiliated():
    card = Scorecard()
    social_signals(card, YT, "x", "YouTubeBrasil", "YouTube Brasil", "", verified=True)
    out = affiliation.apply(card, YT, "x", "YouTubeBrasil", "YouTube Brasil", verified=True,
                            official_links=["youtube.com"])
    assert out["status"] == "likely_affiliated" and out["confidence"] >= 35
    assert {"platform_verified", "links_to_official_site", "regional_variant"} <= _codes(card)
    score = assess(card.signals, "social_profile").score
    assert classify("new", "No strong signals", _codes(card), score) == "affiliated"


def test_linked_from_official_site_is_affiliated_and_dropped_by_scans():
    card = Scorecard()
    social_signals(card, YT, "x", "YouTubeIndia", "YouTube India", "")
    out = affiliation.apply(card, YT, "x", "YouTubeIndia", "YouTube India", linked_from_site=True)
    assert out["status"] == "affiliated" and out["confidence"] >= 90
    hit = Hit("YouTube India (@YouTubeIndia) / X", "https://x.com/YouTubeIndia", "Official account. Customer care")
    assert hit_to_report(hit, YT, "brave", {("x", "youtubeindia")}) is None
    r = hit_to_report(hit, YT, "brave", set())
    assert r is not None and any(s["code"] == "regional_variant" for s in r.signals)


def test_impostor_with_regional_name_still_flagged():
    card = Scorecard()
    social_signals(card, YT, "x", "YouTubeIndia", "YouTube India",
                   "Official YouTube India customer care. Claim your reward, contact us on WhatsApp +91 98765 43210")
    out = affiliation.apply(card, YT, "x", "YouTubeIndia", "YouTube India", official_links=["youtube.com"])
    assert out["status"] == "suspicious" and out["abuse"]
    assert classify("new", "Medium risk", _codes(card), 45) == "suspicious"


def test_official_site_links_are_read_with_redirects_and_cached():
    calls = []

    def handler(request: httpx.Request):
        calls.append(str(request.url))
        if request.headers.get("host") == "youtube.com":
            return httpx.Response(301, headers={"location": "https://www.youtube.com/"})
        return httpx.Response(200, html='<a href="https://x.com/YouTubeIndia">India</a>'
                                        '<a href="https://www.instagram.com/youtube/">IG</a>')

    from threatdesk import safety

    async def resolve(h, port):
        return ["93.184.216.34"]

    async def run():
        orig = safety.resolve_host
        safety.resolve_host = resolve
        try:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
                first = await affiliation.official_site_profiles(c, YT)
                again = await affiliation.official_site_profiles(c, YT)
                return first, again
        finally:
            safety.resolve_host = orig
    first, again = asyncio.run(run())
    assert ("x", "youtubeindia") in first and ("instagram", "youtube") in first and again == first
    assert len(calls) == 2                                                    # redirect followed once, then cached


def test_assess_skips_accounts_that_do_not_resemble_the_brand():
    card = Scorecard()
    social_signals(card, YT, "x", "catvideos", "Cat videos", "")

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500))) as c:
            return await affiliation.assess(c, card, YT, "x", "catvideos", "Cat videos")
    assert asyncio.run(run()) == {}


def test_platform_link_wrappers_are_not_contact_bait():
    """Real case: X rewrites every link to t.co, which made @YouTubeBrasil look like a scam account."""
    title = "Ajuda do YouTube: Para suporte, conte com o @TeamYouTube aqui no X ou acesse a Central de Ajuda"
    snippet = title + ": https://t.co/OqfdUQ4ySq"
    r = hit_to_report(Hit(title, "https://x.com/YouTubeBrasil", snippet), YT, "brave", set())
    codes = {s["code"] for s in r.signals}
    assert "contact_bait" not in codes and "regional_variant" in codes and r.score <= 35
    assert classify("new", r.verdict, codes, r.score) == "regional_review"
    card = Scorecard()                                   # a real shortener elsewhere still counts
    social_signals(card, YT, "instagram", "youtube_help_desk", "YouTube help", "DM us https://bit.ly/x1y2z3")
    assert card.has("contact_bait")
