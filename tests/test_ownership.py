"""Defensive registrations (the amazonlogin.com case): a look-alike domain the brand owns must not be reported as a
scam, while a real phishing look-alike stays High risk. Offline fixtures only."""
import asyncio
import dataclasses

import pytest
from sqlalchemy import select

from threatdesk import config, db
from threatdesk.brands import BrandContext
from threatdesk.checks.ownership import protection_registrar, registrant_matches, shared_dns
from threatdesk.investigator import investigate
from threatdesk.models import Finding
from threatdesk.persistence import save_report
from threatdesk.riskview import classify
from tests.brandhelp import make_brand
from tests.helpers import make_client, signup
from tests.netfixtures import offline  # noqa: F401

ACME = BrandContext(id=1, name="Acme Bank", official_domains=["acmebank.com"], keywords=["acme"])


@pytest.fixture(autouse=True)
def _no_lists():
    config.override(scam_lists=False)


def codes(r) -> set[str]:
    return {s["code"] for s in r.signals}


async def test_defensive_registration_is_not_a_scam(offline):
    async with offline() as c:
        r = await investigate("https://acmebanklogin.com/", brand=ACME, client=c, use_ai=False)
    page = next(x for x in r.checks if x["check"] == "page_fetch")
    assert page["status"] == "ran" and "plain HTTP" in page["detail"]["fallback"]
    assert page["detail"]["final_host"] == "www.acmebank.com"
    assert {"redirects_to_official", "brand_protection_registrar"} <= codes(r)
    assert "domain_lookalike" not in codes(r) or "domain_has_brand" not in codes(r)       # counted once
    assert r.score < 40 and r.verdict == "No strong signals"
    assert classify("new", r.verdict, codes(r), r.score) == "brand_owned"


async def test_real_phishing_lookalike_stays_high(offline):
    async with offline() as c:
        r = await investigate("https://acmebank-kyc.xyz/login", brand=ACME, client=c, use_ai=False)
    assert r.verdict == "High risk" and not codes(r) & {"brand_protection_registrar", "redirects_to_official"}
    assert classify("new", r.verdict, codes(r), r.score) == "malicious"


async def test_name_only_website_is_capped(offline):
    """A look-alike name with nothing else (page unreachable, old registration) is not High risk any more."""
    async with offline() as c:
        r = await investigate("https://acmebank-secure-login.com/", brand=ACME, client=c, use_ai=False)
    assert {"domain_has_brand", "phishing_words_in_domain"} <= codes(r)
    assert r.score <= 35


async def test_shared_private_nameservers_are_ownership_evidence(monkeypatch):
    import httpx

    from threatdesk.checks import ownership
    from threatdesk.checks.base import Ctx
    from threatdesk.linkdetect import detect
    from threatdesk.scoring import Scorecard
    ns = {"acmebank.com": ["ns1.acmedns.net", "ns2.acmedns.net"], "acme-pay.net": ["ns2.acmedns.net"],
          "acme-shop.net": ["kim.ns.cloudflare.com"], "acme-deals.net": ["ns1.markmonitor.com"]}

    async def fake_ns(domain):
        return ns.get(domain, [])
    monkeypatch.setattr(ownership, "nameservers", fake_ns)

    async def run(host, rdap=None):
        ctx = Ctx(client=httpx.AsyncClient(), link=detect(f"https://{host}/"), brand=ACME,
                  settings=config.get_settings(), card=Scorecard(), facts={"rdap_domain": rdap} if rdap else {})
        out = await ownership.check_ownership(ctx)
        return out, {s.code for s in ctx.card.signals}

    out, found = await run("acme-pay.net")
    assert found == {"shares_official_nameservers"} and out.detail["shares_nameservers_with"] == "acmebank.com"
    assert (await run("acme-shop.net"))[1] == set()            # Cloudflare is shared by millions: no evidence
    assert (await run("acme-deals.net"))[1] == set()           # MarkMonitor NS are shared by all its clients
    young = {"registrar": "MarkMonitor Inc.", "registered": "2026-09-01", "age_days": 40, "nameservers": []}
    assert (await run("acme-new.net", young))[1] == set()      # brand-protection registrar needs a year of age
    owned = {"registrar": "GoDaddy", "registrant": "Acme Bank Ltd", "age_days": 900, "nameservers": []}
    assert (await run("acme-old.net", owned))[1] == {"registrant_is_brand"}


def test_ownership_helpers():
    assert protection_registrar("MarkMonitor Inc.", []) == "MarkMonitor Inc."
    assert protection_registrar("Nom-iq Ltd. dba COM LAUDE", []) and protection_registrar("x", ["ns1.markmonitor.com"])
    assert protection_registrar("NameCheap, Inc.", ["dns1.registrar-servers.com"]) is None
    brand = dataclasses.replace(ACME, official_apps={"publishers": ["Acme Holdings Ltd"]})
    assert registrant_matches("Acme Bank Limited", brand) == "Acme Bank"
    assert registrant_matches("ACME HOLDINGS PVT LTD", brand) == "Acme Holdings Ltd"
    assert registrant_matches("Totally Different LLC", brand) is None and registrant_matches(None, brand) is None
    assert shared_dns("ns-12.awsdns-01.org") and shared_dns("kim.ns.cloudflare.com")
    assert not shared_dns("ns1.amzndns.com") and not shared_dns("ns1.acmedns.net")


def test_well_known_brand_gets_its_built_in_official_domains():
    amazon = BrandContext(name="amazon", official_domains=["amazon.com"])
    assert amazon.known_brand == "Amazon" and amazon.is_official_host("www.amazon.in")
    assert "built-in list" in amazon.official_reason("amazon.co.uk")
    assert amazon.official_reason("amazon.com") == "official domain of amazon"
    github = BrandContext(name="GitHub", official_domains=["github.com"])      # on Microsoft's list, not Microsoft
    assert github.known_brand is None and not github.is_official_host("microsoft.com")
    stranger = BrandContext(name="Amazon Plumbing", official_domains=["amazonplumbing.com"])
    assert stranger.known_brand is None and not stranger.is_official_host("amazon.in")


def test_scan_drops_brand_owned_leads_and_closes_open_findings(monkeypatch):
    from threatdesk import handlers
    from threatdesk.investigator import Report
    c = make_client()
    signup(c)
    from tests.brandhelp import org_of
    oid = org_of("a@example.com")
    bid = make_brand(oid)
    owned = Report(url="https://acmebanklogin.com/", kind="website", link={}, display_name="acmebanklogin.com",
                   dedupe_key="host:acmebanklogin.com", verdict="No strong signals", score=5, checks_ran=8,
                   checks=[{"check": "dns", "status": "ran", "detail": {}}],
                   signals=[{"code": "domain_has_brand", "points": 20, "evidence": "contains the brand"},
                            {"code": "brand_protection_registrar", "points": -20,
                             "evidence": "acmebanklogin.com was registered 2007-01-01 through MarkMonitor Inc."},
                            {"code": "redirects_to_official", "points": -30,
                             "evidence": "acmebanklogin.com redirects to official www.acmebank.com"}])
    with db.session_scope() as s:                       # opened by an earlier scan, before the fix
        old = dataclasses.replace(owned, score=75, verdict="High risk", signals=owned.signals[:1])
        fid = save_report(s, oid, bid, old, "discovery:domains")[0].id

    async def fake(url, brand=None, **kw):
        return owned
    monkeypatch.setattr(handlers, "investigate", fake)
    res = asyncio.run(handlers.handle_investigate(1, {"url": owned.url, "brand_id": bid,
                                                      "source": "discovery:domains"}, oid))
    assert res["skipped"].startswith("likely brand-owned") and res["closed_existing"] is True
    with db.session_scope() as s:
        f = s.get(Finding, fid)
        assert f.status == "false_positive" and f.score == 5 and f.verdict == "No strong signals"
        assert len(s.scalars(select(Finding)).all()) == 1
    res = asyncio.run(handlers.handle_investigate(1, {"url": owned.url, "brand_id": bid, "source": "investigate"},
                                                  oid))
    assert "finding_id" in res                             # a manual investigation still shows the full report


def test_reputation_hit_on_a_brand_protected_domain_is_conflicting_not_malicious():
    owned = {"domain_has_brand", "virustotal_malicious", "redirects_to_official", "brand_protection_registrar"}
    assert classify("new", "No strong signals", owned, 25) == "conflicting"
    assert classify("new", "High risk", {"domain_has_brand", "virustotal_malicious"}, 60) == "malicious"


def test_timeouts_count_towards_a_network_outage():
    from threatdesk.handlers import network_outage
    from threatdesk.investigator import Report
    checks = [{"check": c, "status": "ran", "detail": {}} for c in ("dns", "domain_name", "ownership")]
    checks += [{"check": c, "status": "not_possible", "detail": {"reason": "network error (ConnectTimeout)"}}
               for c in ("rdap_domain", "page_fetch")]
    checks += [{"check": c, "status": "not_possible", "detail": {"reason": "timed out after 25s"}}
               for c in ("wayback", "phishtank", "ct_history")]
    r = Report(url="https://x.com/", kind="website", link={}, display_name="x", dedupe_key="host:x.com",
               checks=checks, verdict="Insufficient data")
    assert network_outage(r)                  # 5 of 8 attempted checks failed for network reasons: retry later


def test_one_virustotal_engine_does_not_corroborate_a_name():
    from threatdesk.scoring import Scorecard, assess
    card = Scorecard()
    for code in ("domain_lookalike", "virustotal_suspicious", "registrant_redacted"):   # the live mazon.com case
        card.add(code, "x")
    a = assess(card.signals, "website")
    assert a.raw == 45 and a.score == 35 and a.capped
    card.add("domain_age_lt_30d", "registered last week")                                # real corroboration
    assert assess(card.signals, "website").score == 75
