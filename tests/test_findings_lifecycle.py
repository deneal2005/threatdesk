"""Findings over time: dedupe, persistence, gated rescoring, classification in UI/API/CSV, auto-closing assets that
became official, and the additive column migration."""
import asyncio

from sqlalchemy import create_engine, inspect, select, text

from threatdesk import db
from threatdesk.investigator import Report
from threatdesk.models import CaseEvent, Evidence, Finding, Signal
from threatdesk.persistence import rescore, save_report
from threatdesk.riskview import classify, confidence
from tests.brandhelp import make_brand, org_of
from tests.helpers import csrf, make_client, signup


def lookalike_report(**kw) -> Report:
    sig = [{"code": "handle_similar", "points": 25, "evidence": "@acmeb4nk resembles official @acmebank"},
           {"code": "name_similar", "points": 20, "evidence": "display name 'Acme Bank' resembles the brand"}]
    base = dict(url="https://www.instagram.com/acmeb4nk/", kind="social_profile",
                link={"kind": "closed_social", "platform": "instagram", "ident": "acmeb4nk"},
                display_name="instagram.com/acmeb4nk", dedupe_key="instagram:acmeb4nk", signals=sig, score=35,
                severity="Low", verdict="No strong signals", checks_ran=1,
                checks=[{"check": "public_og_tags", "status": "ran", "detail": {"title": "Acme Bank"}}])
    return Report(**(base | kw))


def _setup():
    c = make_client()
    signup(c)
    oid = org_of("a@example.com")
    return c, oid, make_brand(oid)


def test_duplicates_update_one_finding_and_evidence_is_kept():
    _, oid, bid = _setup()
    from threatdesk.checks.base import EvidenceItem
    with db.session_scope() as s:
        f1, created1 = save_report(s, oid, bid, lookalike_report(evidence=[EvidenceItem("public_og_tags", {"v": 1})]),
                                   "discovery:websearch")
        f2, created2 = save_report(s, oid, bid, lookalike_report(evidence=[EvidenceItem("public_og_tags", {"v": 2})]),
                                   "discovery:websearch")
        assert created1 and not created2 and f1.id == f2.id
        assert s.scalar(select(Finding).where(Finding.org_id == oid)).id == f1.id
        assert len(s.scalars(select(Evidence).where(Evidence.finding_id == f1.id)).all()) == 2   # append-only
        assert len(s.scalars(select(Signal).where(Signal.finding_id == f1.id)).all()) == 2       # latest run only


def test_rescore_applies_the_identity_gate():
    _, oid, bid = _setup()
    with db.session_scope() as s:
        f, _ = save_report(s, oid, bid, lookalike_report(), "investigate")
        f.score = 45                                     # e.g. stored before the gate existed
        rescore(s, f)
        assert (f.score, f.verdict) == (35, "No strong signals")
        s.add(Signal(org_id=oid, finding_id=f.id, code="account_lt_90d", points=20, evidence="created last week"))
        s.flush()
        rescore(s, f)
        assert (f.score, f.verdict) == (65, "Medium risk")


def test_classification_tiers_and_confidence():
    assert classify("new", "No strong signals", {"handle_similar"}, 35) == "lookalike"
    assert classify("new", "Medium risk", {"handle_similar", "account_lt_90d"}, 65) == "suspicious"
    assert classify("new", "High risk", {"scam_list_hit"}, 40) == "malicious"
    assert classify("confirmed", "Medium risk", set(), 50) == "confirmed"
    assert classify("false_positive", "High risk", {"scam_list_hit"}, 90) == "false_positive"
    assert classify("new", "Official/whitelisted asset", set(), 0) == "official"
    assert classify("new", "No strong signals", set(), 0) == "none"
    sig = [Signal(code="handle_similar", points=25, evidence="x")]
    assert confidence(sig, 1, "social_profile")[0] == "Low"
    sig.append(Signal(code="account_lt_90d", points=20, evidence="x"))
    sig.append(Signal(code="contact_bait", points=10, evidence="x"))
    assert confidence(sig, 1, "social_profile") == ("High", "2 independent kinds of evidence")
    sig.append(Signal(code="name_similar", points=20, evidence="USER-SUPPLIED UNVERIFIED: name"))
    assert confidence(sig, 1, "social_profile")[0] == "Low"


def test_report_page_list_api_and_csv_show_the_classification():
    c, oid, bid = _setup()
    with db.session_scope() as s:
        f, _ = save_report(s, oid, bid, lookalike_report(), "discovery:websearch")
        fid = f.id
    page = c.get(f"/findings/{fid}").text
    assert "Look-alike, unconfirmed" in page and "Evidence confidence" in page and "Name similarity" in page
    listing = c.get("/findings").text
    assert "Look-alike, unconfirmed" in listing
    assert "acmeb4nk" in c.get("/findings?tier=lookalike").text
    assert "acmeb4nk" not in c.get("/findings?tier=suspicious").text
    assert c.get("/reports/findings.csv").text.splitlines()[1].endswith(',"Look-alike, unconfirmed"')


def test_adding_an_official_account_closes_its_open_finding():
    c, oid, bid = _setup()
    with db.session_scope() as s:
        f, _ = save_report(s, oid, bid, lookalike_report(url="https://www.instagram.com/acmebank_careers/",
                                                         dedupe_key="instagram:acmebank_careers"), "discovery:x")
        fid = f.id
    r = c.post(f"/brands/{bid}/social", data={"platform": "instagram", "handle": "acmebank_careers",
                                              "csrf_token": csrf(c, f"/brands/{bid}?tab=social")})
    assert r.status_code == 303
    with db.session_scope() as s:
        f = s.get(Finding, fid)
        assert (f.status, f.verdict, f.score) == ("false_positive", "Official/whitelisted asset", 0)
        ev = s.scalar(select(CaseEvent).where(CaseEvent.finding_id == fid))
        assert ev.user_id is None and "closed automatically" in ev.body and "official instagram account" in ev.body


def test_confirmed_findings_are_never_auto_closed():
    from threatdesk.reconcile import close_as_official
    _, oid, bid = _setup()
    with db.session_scope() as s:
        f, _ = save_report(s, oid, bid, lookalike_report(), "investigate")
        f.status = "confirmed"
        assert close_as_official(s, f, "now official") is False and f.status == "confirmed"


def test_scan_closes_existing_finding_when_lead_became_official(monkeypatch):
    from threatdesk import handlers

    async def official(url, brand=None, **kw):
        return lookalike_report(verdict="Official/whitelisted asset", score=0, signals=[],
                                excluded_reason="official instagram account of Acme Bank")
    _, oid, bid = _setup()
    with db.session_scope() as s:
        fid = save_report(s, oid, bid, lookalike_report(), "discovery:websearch")[0].id
    monkeypatch.setattr(handlers, "investigate", official)
    res = asyncio.run(handlers.handle_investigate(1, {"url": "https://www.instagram.com/acmeb4nk/", "brand_id": bid,
                                                      "source": "discovery:websearch"}, oid))
    assert res["closed_existing"] is True
    with db.session_scope() as s:
        assert s.get(Finding, fid).status == "false_positive"


def test_brand_sensitivity_is_validated_saved_and_used():
    from threatdesk.handlers import load_brand_ctx
    c, oid, bid = _setup()
    tok = csrf(c, f"/brands/{bid}/edit")
    r = c.post(f"/brands/{bid}", data={"name": "Acme Bank", "sensitivity": "extreme", "csrf_token": tok})
    assert r.status_code == 400 and "strict, balanced or broad" in r.text
    r = c.post(f"/brands/{bid}", data={"name": "Acme Bank", "sensitivity": "strict", "csrf_token": tok})
    assert r.status_code == 303
    assert load_brand_ctx(oid, bid).lookalike_threshold == 90
    assert 'value="strict" selected' in c.get(f"/brands/{bid}/edit").text


def test_missing_nullable_columns_are_added(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as conn:                     # a brands table from before the "detection" column existed
        conn.execute(text("CREATE TABLE brands (id INTEGER PRIMARY KEY, org_id INTEGER, name VARCHAR(80))"))
    added = db.add_missing_columns(engine)
    assert "brands.detection" in added
    assert "detection" in {c["name"] for c in inspect(engine).get_columns("brands")}
    assert db.add_missing_columns(engine) == []      # idempotent
