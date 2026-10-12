import asyncio

from sqlalchemy import select

from threatdesk import config, db
from threatdesk.brands import BrandContext
from threatdesk.discovery import scan, sources
from threatdesk.discovery.permutations import all_domain_candidates, domain_candidates, telegram_candidates
from threatdesk.discovery.websearch import Hit, hit_to_report
from threatdesk.models import Brand, Finding, Job
from tests.brandhelp import make_brand
from tests.test_monitoring import _org

ACME = BrandContext(id=1, name="Acme Bank", official_domains=["acmebank.com"], keywords=["acme"],
                    official_handles={"instagram": ["acmebank"], "telegram": ["acmebank"]})


def test_domain_candidates_categories_validity_cap():
    c = domain_candidates("acmebank.com")
    assert len(c) == 400 and "acmebank.com" not in c and len(set(c)) == 400
    assert {"acmbank.com", "acmeabnk.com", "acmebank.in", "acme-bank.com", "acmebank-login.com"} <= set(c)
    assert all(x.split(".")[0][0] != "-" and x.split(".")[0][-1] != "-" for x in c)
    both = all_domain_candidates(["acmebank.com", "acmebank.in"], cap=50)
    assert len(both) == 50 and "acmebank.in" not in both and "acmebank.com" not in both


def test_telegram_candidates():
    t = telegram_candidates("acmebank")
    assert "acmebank_official" in t and "acmebank" not in t and len(t) <= 40


def test_websearch_hits_become_unverified_reports():
    good = hit_to_report(Hit("Acme Bank Customer Care (@acmebank.care)", "https://www.instagram.com/acmebank.care/",
                             "Official helpline 24x7. DM for KYC update"), ACME, "brave")
    assert good and good.checks_ran == 1 and good.kind == "social_profile"
    assert all(s["evidence"].startswith("FROM SEARCH RESULTS: ") for s in good.signals)
    assert hit_to_report(Hit("Acme", "https://www.instagram.com/acmebank/", ""), ACME, "brave") is None   # official
    assert hit_to_report(Hit("Cats", "https://www.instagram.com/p/xyz/", ""), ACME, "brave") is None


def test_scan_isolates_failing_sources_and_enqueues(monkeypatch):
    oid = _org()
    bid = make_brand(oid)

    async def ok_domains(client, brand, settings):
        return "ok: 2 candidates", ["https://acmebank.co/", "https://acme-bank.com/"]

    async def boom(*a, **k):
        raise RuntimeError("crt.sh down")

    async def empty(*a, **k):
        return "not configured (YOUTUBE_API_KEY)", []

    monkeypatch.setattr(sources, "src_domains", ok_domains)
    monkeypatch.setattr(sources, "src_crtsh", boom)
    for name in ("src_ios", "src_android", "src_youtube", "src_bluesky", "src_telegram"):
        monkeypatch.setattr(sources, name, empty)

    async def search(client, brand, settings):
        return "ok: 1 results", [hit_to_report(Hit("Acme Bank Help", "https://www.instagram.com/acme.bank.help/",
                                                  "official support"), brand, "brave")]
    monkeypatch.setattr(scan, "src_websearch", search)
    res = asyncio.run(scan.run_scan(1, oid, bid))
    by = {s["name"]: s for s in res["sources"]}
    assert by["certificate_transparency"]["status"] == "failed: RuntimeError" and by["domains"]["candidates"] == 2
    assert res["enqueued"] == 2 and res["search_findings_new"] == 1
    with db.session_scope() as s:
        payloads = [j.payload for j in s.scalars(select(Job).where(Job.type == "investigate"))]
        assert {p["source"] for p in payloads} == {"discovery:domains"} and all(p["in_triage"] for p in payloads)
        f = s.scalar(select(Finding))
        assert f.source == "discovery:websearch" and s.get(Brand, bid).last_scan_at is not None


def test_discovery_skips_official_results(monkeypatch):
    from threatdesk import handlers
    from threatdesk.investigator import Report

    async def official(url, brand=None, **kw):
        return Report(url=url, kind="website", link={}, display_name="acmebank.com", dedupe_key="host:acmebank.com",
                      verdict="Official/whitelisted asset", excluded_reason="official domain")
    monkeypatch.setattr(handlers, "investigate", official)
    oid = _org()
    bid = make_brand(oid)
    res = asyncio.run(handlers.handle_investigate(1, {"url": "https://acmebank.com", "brand_id": bid,
                                                      "source": "discovery:domains"}, oid))
    assert res == {"skipped": "official domain", "verdict": "Official/whitelisted asset", "closed_existing": False}
    with db.session_scope() as s:
        assert s.scalar(select(Finding)) is None
    assert config.get_settings()
