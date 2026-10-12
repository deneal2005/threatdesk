"""Social detection with synthetic profiles: official exclusion, look-alikes, evidence gating, counter-evidence,
brand-profile changes and source failures (Bluesky/Telegram via httpx.MockTransport, no network)."""
import dataclasses

import httpx

from threatdesk import config
from threatdesk.brands import SENSITIVITY, BrandContext
from threatdesk.checks.social import social_signals
from threatdesk.investigator import investigate
from threatdesk.scoring import Scorecard, assess, verdict

ACME = BrandContext(id=1, name="Acme Bank", official_domains=["acmebank.com"], keywords=["acme"],
                    official_handles={"instagram": ["acmebank"], "bluesky": ["acmebank.com"],
                                      "youtube": ["ucabcdefghijklmnopqrstuv"], "telegram": ["acmebank"]})


def signals(handle, name="", bio="", brand=ACME, **kw) -> tuple[Scorecard, dict]:
    card = Scorecard()
    out = social_signals(card, brand, kw.pop("platform", "tiktok"), handle, name, bio, **kw)
    return card, out


def final(card) -> tuple[int, str]:
    a = assess(card.signals, "social_profile")
    return a.score, verdict(a.score, 1, False, "social_profile")


def test_official_accounts_are_excluded():
    card, out = signals("AcmeBank", "Acme Bank", "Official account", platform="instagram")
    assert out == {"official": True} and card.signals == []


def test_name_similarity_alone_is_not_medium_risk():
    card, out = signals("acmeb4nk", "Acme Bank")
    assert {s.code for s in card.signals} == {"handle_similar", "name_similar"}
    assert "character substitution: 4→a" in card.signals[0].evidence
    score, v = final(card)
    assert sum(s.points for s in card.signals) == 45 and score == 35 and v == "No strong signals"


def test_corroborated_impersonation_reaches_high():
    card, _ = signals("acmebank_help", "Acme Bank Customer Care",
                      "Official helpline. WhatsApp +91 98765 43210 or visit acmebank-kyc.xyz", followers=42,
                      created="2026-09-30")
    found = {s.code for s in card.signals}
    assert {"handle_similar", "name_similar", "claims_official", "contact_bait", "bio_link_lookalike",
            "account_lt_90d", "low_followers"} <= found
    assert final(card) == (100, "High risk")


def test_unrelated_legitimate_names_get_nothing():
    for handle, name in (("johnsmith", "John Smith"), ("acmeplumbing", "Acme Plumbing Co"),
                         ("ucbank", "UC Bank"), ("bankstatements", "Bank Statements")):
        card, _ = signals(handle, name)
        assert card.signals == [], (handle, [s.code for s in card.signals])


def test_counter_evidence_for_established_or_verified_accounts():
    card, _ = signals("acmebankfans", "Acme Bank Fans", created="2019-01-01", followers=52000, verified=True)
    found = {s.code: s.points for s in card.signals}
    assert found["established_account"] == -15 and found["platform_verified"] == -10
    assert final(card)[1] == "No strong signals"


def test_cross_platform_same_handle_is_explained_not_scored_high():
    card, out = signals("acmebank", "Acme Bank", platform="x")
    assert "same handle as an official account on another platform" in card.signals[0].evidence
    assert final(card)[0] <= 35


def test_brand_profile_changes_affect_detection():
    plain = BrandContext(id=1, name="Acme Bank", official_domains=["acmebank.com"])
    assert {s.code for s in signals("acmepay_support", brand=plain)[0].signals} == set()
    with_kw = dataclasses.replace(plain, keywords=["acmepay"])
    assert "handle_similar" in {s.code for s in signals("acmepay_support", brand=with_kw)[0].signals}
    listed = dataclasses.replace(with_kw, official_handles={"tiktok": ["acmepay_support"]})
    assert signals("acmepay_support", brand=listed)[1] == {"official": True}
    strict = dataclasses.replace(plain, lookalike_threshold=SENSITIVITY["strict"])
    assert "handle_similar" in {s.code for s in signals("acmebnak_help", brand=plain)[0].signals}
    assert "handle_similar" not in {s.code for s in signals("acmebnak_help", brand=strict)[0].signals}


def bsky(handler):
    async def run(url):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await investigate(url, brand=ACME, client=c, use_ai=False)
    return run


async def test_bluesky_profile_missing_fields_and_failures():
    config.override(scam_lists=False)
    r = await bsky(lambda req: httpx.Response(200, json={"handle": "acme-bank-help.bsky.social"}))(
        "https://bsky.app/profile/acme-bank-help.bsky.social")
    assert r.checks[0]["status"] == "ran" and "handle_similar" in {s["code"] for s in r.signals}
    assert r.score <= 35                                   # name only, no profile data: never above Low
    r = await bsky(lambda req: httpx.Response(503))("https://bsky.app/profile/acme-help.bsky.social")
    assert r.checks[0]["status"] == "not_possible" and "HTTP 503" in r.checks[0]["detail"]["reason"]
    assert r.verdict == "Insufficient data"
    r = await bsky(lambda req: httpx.Response(200, content=b"not json"))("https://bsky.app/profile/x.bsky.social")
    assert r.checks[0]["status"] == "not_possible"


async def test_official_bluesky_account_is_excluded():
    r = await bsky(lambda req: httpx.Response(200, json={"handle": "acmebank.com", "displayName": "Acme Bank"}))(
        "https://bsky.app/profile/acmebank.com")
    assert r.verdict == "Official/whitelisted asset" and r.score == 0


async def test_telegram_unreachable_is_explicit(monkeypatch):
    from threatdesk.checks import social

    async def down(client, handle):
        return "unreachable", None
    monkeypatch.setattr(social, "fetch_telegram", down)
    r = await bsky(lambda req: httpx.Response(404))("https://t.me/acmebank_support")
    assert r.checks[0]["status"] == "not_possible" and "could not be reached" in r.checks[0]["detail"]["reason"]


def test_handle_dedupe_key_is_case_insensitive():
    from threatdesk.linkdetect import detect
    keys = {detect(u).dedupe_key for u in ("https://www.instagram.com/AcmeBank_Help/", "instagram.com/acmebank_help",
                                           "https://instagram.com/acmebank_help?igshid=abc")}
    assert keys == {"instagram:acmebank_help"}


def test_claims_official_does_not_corroborate_on_verified_or_established_accounts():
    from threatdesk.scoring import Scorecard as Card
    for counter in ("platform_verified", "established_account"):          # the live @amazoninofficial case
        card = Card()
        for code in ("handle_similar", "name_similar", "claims_official", counter):
            card.add(code, "x")
        assert assess(card.signals, "social_profile").score <= 35
    card = Card()
    for code in ("handle_similar", "name_similar", "claims_official"):     # an unverified "official" account
        card.add(code, "x")
    assert assess(card.signals, "social_profile").score == 60


def test_bio_link_to_the_brand_name_on_another_tld_is_context_not_evidence():
    card, out = signals("amazonvestlife", "Amazon Vest Life", "Visit atoz.amazon.work",
                        brand=BrandContext(id=2, name="amazon", official_domains=["amazon.com"]))
    assert "bio_link_lookalike" not in {s.code for s in card.signals} and out["same_name_links"] == ["atoz.amazon.work"]
    card, _ = signals("acmebank_help", "Acme", "Visit acmebank-kyc.xyz")
    assert "bio_link_lookalike" in {s.code for s in card.signals}         # an imitation still counts
