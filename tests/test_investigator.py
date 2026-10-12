import httpx
import pytest

from threatdesk import config
from threatdesk.brands import BrandContext
from threatdesk.checks.domain import registrable_domain
from threatdesk.checks.rdap import parse_domain_rdap, server_for_domain, server_for_ip
from threatdesk.handlers import network_outage
from threatdesk.investigator import exclusion, hard_evidence, investigate, temper_ai
from threatdesk.linkdetect import detect
from threatdesk.pageparse import input_kinds, parse
from threatdesk.scoring import VERDICT_INSUFFICIENT
from tests.netfixtures import PHISH_HTML, _rdap_domain, offline  # noqa: F401

ACME = BrandContext(id=1, name="Acme Bank", official_domains=["acmebank.com"], keywords=["acme"],
                    official_handles={"instagram": ["acmebank"]}, official_apps={"android": ["com.acme.bank"]})


@pytest.fixture(autouse=True)
def _no_lists():
    config.override(scam_lists=False)


async def test_phishing_site_end_to_end(offline):
    async with offline() as c:
        r = await investigate("hxxps://acmebank-kyc[.]xyz/login", brand=ACME, client=c, use_ai=False)
    codes = {s["code"] for s in r.signals}
    assert {"domain_has_brand", "domain_age_lt_30d", "asks_credentials", "urgency", "scam_phrases", "contact_bait",
            "claims_official", "no_archive_history", "registrant_redacted"} <= codes
    assert r.verdict == "High risk" and r.score == 100 and r.severity == "High"
    assert r.checks_ran >= 8 and r.dedupe_key == "host:acmebank-kyc.xyz"
    assert ("phone", "9876543210") in r.indicators and ("upi", "acmekyc@ybl") in r.indicators
    kinds = {e.kind for e in r.evidence}
    assert {"page_capture", "rdap_domain", "rdap_ip", "ct_certs"} <= kinds
    page = next(e for e in r.evidence if e.kind == "page_capture")
    assert len(page.sha256) == 64 and r.facts["final_url"].startswith("https://acmebank-kyc.xyz")
    assert "safe" not in r.verdict.lower()


async def test_official_domain_is_excluded(offline):
    async with offline() as c:
        r = await investigate("https://acmebank.com/", brand=ACME, client=c, use_ai=False)
    assert r.verdict == "Official/whitelisted asset" and r.score == 0 and r.signals == []
    assert r.checks_ran >= 4                      # checks still ran and are shown


async def test_independent_site_counter_evidence(offline):
    async with offline() as c:
        r = await investigate("https://old-bakery.com/", brand=ACME, client=c, use_ai=False)
    codes = {s["code"] for s in r.signals}
    assert "independent_site" in codes and r.verdict == "No strong signals"


async def test_outage_is_insufficient_and_detected(monkeypatch):
    from threatdesk import safety
    from threatdesk.checks import domain

    async def dead(*a, **k):
        raise httpx.ConnectError("offline")

    async def dns_timeout(h, res=None, lifetime=4.0):
        return "timeout", []

    monkeypatch.setattr(domain, "resolve_a", dns_timeout)
    monkeypatch.setattr(safety, "resolve_host", dead)

    def boom(request):
        raise httpx.ConnectError("offline")

    async with httpx.AsyncClient(transport=httpx.MockTransport(boom)) as c:
        r = await investigate("https://somewhere-else.xyz/", brand=ACME, client=c, use_ai=False)
    assert r.verdict == VERDICT_INSUFFICIENT
    assert network_outage(r)


async def test_check_crash_becomes_not_possible(offline, monkeypatch):
    from threatdesk.checks import content

    async def crash(ctx):
        raise ZeroDivisionError

    monkeypatch.setattr(content, "check_domain_name", crash)
    async with offline() as c:
        r = await investigate("https://acmebank-kyc.xyz/", brand=ACME, client=c, use_ai=False)
    dn = next(x for x in r.checks if x["check"] == "domain_name")
    assert dn["status"] == "not_possible" and "internal error (ZeroDivisionError)" in dn["detail"]["reason"]


async def test_ai_bonus_and_temper(offline, monkeypatch):
    from threatdesk import llm
    config.override(gemini_api_key="test-key", scam_lists=False)

    async def fake(client, facts, thin):
        return {"scam_likelihood": 0.9, "category": "phishing", "summary": "Looks like phishing.",
                "next_steps": ["Report the domain to the registrar", "Warn customers"]}

    monkeypatch.setattr(llm, "assess", fake)
    async with offline() as c:
        r = await investigate("https://old-bakery.com/", brand=ACME, client=c)
    assert r.ai["status"] == "ok" and "ai_assessment" not in {s["code"] for s in r.signals}   # independent site
    assert r.ai["advice_limited"] and not any("registrar" in s for s in r.ai["next_steps"][1:])
    async with offline() as c:
        r = await investigate("https://acmebank-kyc.xyz/", brand=ACME, client=c)
    assert "ai_assessment" in {s["code"] for s in r.signals}
    assert "advice_limited" not in r.ai                 # credentials + brand claim = hard evidence


def test_temper_rules():
    ai = {"next_steps": ["Block the site", "Check who owns it"]}
    soft = temper_ai(ai, {"urgency"})
    assert soft["advice_limited"] and soft["next_steps"][1:] == ["Check who owns it"]
    assert hard_evidence({"scam_list_hit"}) and hard_evidence({"asks_credentials", "domain_has_brand"})
    assert not hard_evidence({"asks_credentials"})
    assert temper_ai(ai, {"safe_browsing_hit"}) == ai


def test_page_parse_and_input_kinds():
    p = parse(PHISH_HTML, "https://acmebank-kyc.xyz/")
    assert p["title"] == "Acme Bank KYC Update" and p["meta"]["description"].startswith("Official")
    assert input_kinds(p["forms"]) == {"password", "otp"}
    assert any(ln["href"] == "https://wa.me/919876543210" for ln in p["links"])
    assert "wa.me" in p["outbound_domains"]


def test_rdap_parsers_and_bootstrap():
    info = parse_domain_rdap(_rdap_domain("acmebank-kyc.xyz", 5))
    assert info["registrar"] == "Cheap Names Inc" and info["abuse_email"] == "abuse@cheapnames.example"
    assert info["redacted"] and info["nameservers"] == ["ns1.cheapnames.example"]
    services = [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]], [["xyz"], ["http://a/", "https://b/x"]]]
    assert server_for_domain(services, "evil.com") == "https://rdap.verisign.com/com/v1/"
    assert server_for_domain(services, "a.b.xyz") == "https://b/x/"
    assert server_for_domain(services, "x.org") is None
    ip_services = [[["93.0.0.0/8"], ["https://rdap.ripe.net/"]], [["93.184.0.0/16"], ["https://rdap.arin.net/registry/"]]]
    assert server_for_ip(ip_services, "93.184.216.34") == "https://rdap.arin.net/registry/"


def test_registrable_domain():
    assert registrable_domain("a.b.acmebank.com") == "acmebank.com"
    assert registrable_domain("www.acme.co.in") == "acme.co.in"
    assert registrable_domain("hdfc.bank.in") == "hdfc.bank.in"
    assert registrable_domain("1.2.3.4") == "1.2.3.4"


def test_exclusion_rules():
    wl = BrandContext(name="Acme", official_domains=["acmebank.com"], whitelist=[("domain", "partner.com"),
                                                                                  ("handle", "acmereseller")])
    assert exclusion(detect("https://login.acmebank.com/x"), wl)
    assert exclusion(detect("https://shop.partner.com/"), wl)
    assert exclusion(detect("https://www.instagram.com/acmereseller/"), wl)
    assert exclusion(detect("https://acmebank.co/"), wl) is None
    assert exclusion(detect("https://play.google.com/store/apps/details?id=com.acme.bank"), ACME)
