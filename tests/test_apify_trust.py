"""Apify website trust report: opt-in, only for brand-claiming sites, cached, budget-capped, never scored."""
import json

import httpx

from threatdesk import config
from threatdesk.brands import BrandContext
from threatdesk.checks import apify_trust
from threatdesk.checks.base import Ctx
from threatdesk.linkdetect import detect
from threatdesk.scoring import Scorecard

ACME = BrandContext(name="Acme Bank", official_domains=["acmebank.com"], keywords=["acme"])
REPORT = {"domain": "acmebank-kyc.xyz", "status": "reachable", "trustScore": 12, "riskLevel": "very high",
          "verdict": "Do not trust", "confidence": "medium",
          "flags": {"negative": ["Domain registered 3 days ago"], "warnings": [], "positive": []},
          "aiInsights": {"category": "phishing site", "summary": "Imitates Acme Bank"}}


def _ctx(handler, claims=True) -> Ctx:
    card = Scorecard()
    if claims:
        card.add("domain_has_brand", "acmebank-kyc.xyz contains 'acmebank'")
    return Ctx(client=httpx.AsyncClient(transport=httpx.MockTransport(handler)), link=detect("https://acmebank-kyc.xyz/"),
               brand=ACME, settings=config.get_settings(), card=card)


def _reset():
    apify_trust._cache.clear()
    apify_trust._spent.clear()


async def test_off_by_default_and_skips_sites_without_brand_claims():
    _reset()
    out = await apify_trust.check_trust(_ctx(lambda r: httpx.Response(500)))
    assert out.status == "not_configured"
    config.override(apify_token="t", apify_website_trust=True)
    out = await apify_trust.check_trust(_ctx(lambda r: (_ for _ in ()).throw(AssertionError("paid call")), claims=False))
    assert out.status == "not_possible" and "no paid lookup" in out.detail["reason"]


async def test_report_is_context_only_cached_and_capped():
    _reset()
    config.override(apify_token="apify-test-token", apify_website_trust=True, apify_trust_daily_limit=1)
    calls = []

    def handler(req: httpx.Request):
        calls.append(json.loads(req.content))
        assert req.headers["authorization"] == "Bearer apify-test-token"
        assert "maxTotalChargeUsd=0.03" in str(req.url) and "website-trust-scam-checker" in str(req.url)
        return httpx.Response(201, json=[REPORT])
    ctx = _ctx(handler)
    before = [s.code for s in ctx.card.signals]
    out = await apify_trust.check_trust(ctx)
    assert out.status == "ran" and out.detail["informational"] and out.detail["trust_score"] == 12
    assert [s.code for s in ctx.card.signals] == before                       # adds no points
    assert calls == [{"websites": ["acmebank-kyc.xyz"], "enableAiInsights": True}]
    assert (await apify_trust.check_trust(_ctx(handler))).status == "ran" and len(calls) == 1   # cached per domain
    other = _ctx(handler)
    other.link = detect("https://acme-bank.top/")
    out = await apify_trust.check_trust(other)
    assert out.status == "not_possible" and "daily limit" in out.detail["reason"] and len(calls) == 1


async def test_failures_are_reported_plainly():
    config.override(apify_token="t", apify_website_trust=True)
    for code, words in ((402, "credits used up"), (429, "rate limited"), (401, "token rejected"), (502, "HTTP 502")):
        _reset()
        out = await apify_trust.check_trust(_ctx(lambda r, c=code: httpx.Response(c, json={})))
        assert out.status == "not_possible" and words in out.detail["reason"]
