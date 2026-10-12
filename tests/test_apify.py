import json

import httpx

from threatdesk import config
from threatdesk.brands import BrandContext
from threatdesk.checks import apify
from threatdesk.checks.base import Ctx
from threatdesk.linkdetect import detect

ACME = BrandContext(name="Acme Bank", official_domains=["acmebank.com"], keywords=["acme"],
                    official_handles={"instagram": ["acmebank"]})


def _ctx(url: str, handler) -> Ctx:
    return Ctx(client=httpx.AsyncClient(transport=httpx.MockTransport(handler)), link=detect(url), brand=ACME,
               settings=config.get_settings())


def test_tiktok_links_are_social_profiles():
    link = detect("https://www.tiktok.com/@acmebank_care?lang=en")
    assert (link.kind, link.platform, link.ident) == ("closed_social", "tiktok", "acmebank_care")


async def test_instagram_lookalike_flagged_and_cached():
    config.override(apify_token="apify-test-token")
    apify._cache.clear()
    calls = []

    def handler(req: httpx.Request):
        calls.append(json.loads(req.content))
        assert req.headers["authorization"] == "Bearer apify-test-token" and "maxTotalChargeUsd=0.05" in str(req.url)
        return httpx.Response(201, json=[{"username": "acmebank_help", "fullName": "Acme Bank Customer Care",
                                          "biography": "Official helpline. WhatsApp +91 98765 43210",
                                          "followersCount": 42, "verified": False, "private": False}])
    ctx = _ctx("https://www.instagram.com/acmebank_help/", handler)
    out = await apify.check_apify_profile(ctx)
    assert out.status == "ran" and out.detail["followers"] == 42
    codes = {s.code for s in ctx.card.signals}
    assert {"handle_similar", "name_similar", "claims_official", "contact_bait", "low_followers"} <= codes
    assert ("phone", "9876543210") in ctx.indicators and calls[0] == {"usernames": ["acmebank_help"],
                                                                      "includeAboutSection": False}
    again = _ctx("https://www.instagram.com/AcmeBank_Help/", handler)
    await apify.check_apify_profile(again)
    assert len(calls) == 1                                           # cached for 24 h, case-insensitive


async def test_errors_become_not_possible_and_unsupported():
    config.override(apify_token="t")
    apify._cache.clear()
    for status, why in ((401, "token rejected"), (402, "credits used up"), (500, "HTTP 500")):
        out = await apify.check_apify_profile(_ctx(f"https://www.instagram.com/x{status}/",
                                                   lambda r, s=status: httpx.Response(s)))
        assert out.status == "not_possible" and why in out.detail["reason"]
    out = await apify.check_apify_profile(_ctx("https://x.com/acme", lambda r: httpx.Response(200)))
    assert out.status == "not_possible" and "not supported" in out.detail["reason"]


async def test_not_configured_without_token():
    out = await apify.check_apify_profile(_ctx("https://www.instagram.com/acme/", lambda r: httpx.Response(200)))
    assert out.status == "not_configured" and out.detail["reason"] == "APIFY_TOKEN not set"


def test_normalisation_shapes():
    tt = apify.normalise("tiktok", {"authorMeta": {"name": "acme", "nickName": "Acme", "signature": "hi", "fans": 5,
                                                   "createTime": 1700000000}})
    assert tt["handle"] == "acme" and tt["followers"] == 5 and tt["created"].startswith("2023-11-14")
    fb = apify.normalise("facebook", {"pageName": "acmebank", "title": "Acme", "followers": 10, "email": "a@b.co"})
    assert fb["contacts"] == ["a@b.co"] and fb["name"] == "Acme"
