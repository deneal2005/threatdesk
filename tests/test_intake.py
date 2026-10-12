import asyncio

from sqlalchemy import select

from threatdesk import db
from threatdesk.brands import BrandContext
from threatdesk.intake import analyze_text, run_text_intake
from threatdesk.models import Brand, Finding, Job, ReportIntake
from tests.brandhelp import make_brand
from tests.helpers import make_client

MSG = ("Dear customer your Acme account will be blocked today. Update KYC immediately at bit.ly/acme-kyc or "
       "WhatsApp +91 98765 43210. Contact @acmebank_care for help.")


def _token(bid: int) -> str:
    with db.session_scope() as s:
        return s.get(Brand, bid).report_token


def _org() -> int:
    from threatdesk.models import Org
    with db.session_scope() as s:
        o = Org(name="Acme Org")
        s.add(o)
        s.flush()
        return o.id


def test_public_form_without_login_and_bad_token():
    c = make_client()
    bid = make_brand(_org())
    r = c.get(f"/report/{_token(bid)}")
    assert r.status_code == 200 and "Report a scam using our name" in r.text and "Acme Bank" in r.text
    assert c.get("/report/not-a-real-token-123").status_code == 404


def test_link_and_text_report_create_intake_and_two_jobs():
    c = make_client()
    bid = make_brand(_org())
    tok = _token(bid)
    page = c.get(f"/report/{tok}").text
    import re
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    r = c.post(f"/report/{tok}", data={"url": "hxxps://acmebank-kyc[.]xyz", "text": MSG, "contact": "me@x.com",
                                       "csrf_token": csrf})
    assert r.status_code == 200 and "Report received" in r.text and "R-1" in r.text
    with db.session_scope() as s:
        intake = s.scalar(select(ReportIntake))
        assert intake.url == "https://acmebank-kyc.xyz/" and intake.reporter_contact == "me@x.com"
        jobs = {j.type: j.payload for j in s.scalars(select(Job))}
    assert jobs["investigate"]["user_submitted"] and jobs["investigate"]["intake_id"] == intake.id
    assert jobs["intake_text"] == {"intake_id": intake.id, "link_finding": False}


def test_honeypot_validation_and_rate_limit():
    import re
    c = make_client()
    bid = make_brand(_org())
    tok = _token(bid)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', c.get(f"/report/{tok}").text).group(1)
    r = c.post(f"/report/{tok}", data={"text": "hi", "website": "http://spam.example", "csrf_token": csrf})
    assert r.status_code == 200 and "Report received" in r.text
    with db.session_scope() as s:
        assert s.scalar(select(ReportIntake)) is None                 # honeypot: nothing stored
    r = c.post(f"/report/{tok}", data={"csrf_token": csrf})
    assert r.status_code == 400 and "Paste the suspicious link, the message text, or both." in r.text
    codes = [c.post(f"/report/{tok}", data={"text": f"scam {i}", "csrf_token": csrf}).status_code for i in range(5)]
    assert codes[-1] == 429


def test_text_rules_and_indicators():
    brand = BrandContext(name="Acme Bank", official_domains=["acmebank.com"], keywords=["acme"],
                         official_handles={"instagram": ["acmebank"]})
    r = analyze_text(MSG, brand, None, ["https://acmebank-kyc.xyz/"])
    codes = {s["code"] for s in r.signals}
    assert {"urgency", "scam_phrases", "contact_bait", "handle_similar"} <= codes
    assert ("phone", "9876543210") in r.indicators and ("domain", "acmebank-kyc.xyz") in r.indicators
    assert r.kind == "other" and r.dedupe_key.startswith("text:") and r.display_name.startswith("Reported text:")
    assert analyze_text(MSG.upper(), brand, None).dedupe_key == r.dedupe_key        # normalised text


def test_text_report_becomes_flagged_finding():
    oid = _org()
    bid = make_brand(oid)
    with db.session_scope() as s:
        intake = ReportIntake(org_id=oid, brand_id=bid, text=MSG)
        s.add(intake)
        s.flush()
        iid = intake.id
    res = asyncio.run(run_text_intake(oid, iid, link_finding=True))
    with db.session_scope() as s:
        f = s.get(Finding, res["finding_id"])
        assert f.source == "intake" and f.is_user_submitted and f.in_triage and f.score > 0
        assert s.get(ReportIntake, iid).finding_id == f.id


def test_text_report_with_signals_gets_a_verdict_without_ai():
    brand = BrandContext(name="Acme Bank", official_domains=["acmebank.com"], official_handles={"instagram": ["acmebank"]})
    r = analyze_text(MSG, brand, None)
    assert r.score >= 40 and r.verdict in ("Medium risk", "High risk")
