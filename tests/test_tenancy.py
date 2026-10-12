import re

from sqlalchemy import select

from threatdesk import db
from threatdesk.models import Brand, CheckResult, Evidence, Finding, Job, Notification, Signal
from tests.brandhelp import make_brand, org_of
from tests.helpers import csrf, make_client, post, signup


def test_api_keys_and_users_isolated():
    a, b = make_client(), make_client()
    signup(a, "a@example.com", "A")
    signup(b, "b@example.com", "B")
    post(a, "/settings/users", {"email": "ana@example.com", "password": "teammate pass 1", "role": "analyst"})
    post(a, "/settings/api-keys", {"label": "A key"})
    page_b = b.get("/settings").text
    assert "ana@example.com" not in page_b and "A key" not in page_b
    key_id = re.search(r"/settings/api-keys/(\d+)/revoke", a.get("/settings").text).group(1)
    assert post(b, f"/settings/api-keys/{key_id}/revoke").status_code == 404


def test_profile_details_are_labeled_unverified_and_queue_bio_link():
    c = make_client()
    signup(c)
    oid = org_of("a@example.com")
    bid = make_brand(oid)
    with db.session_scope() as s:
        f = Finding(org_id=oid, brand_id=bid, source="investigate", kind="social_profile",
                    dedupe_key="instagram:acmebank_care", scope_key=f"{bid}:instagram:acmebank_care",
                    display_name="instagram.com/acmebank_care", url="https://www.instagram.com/acmebank_care/",
                    verdict="Insufficient data", checks_ran=0, in_triage=True)
        s.add(f)
        s.flush()
        fid = f.id
    page = c.get(f"/findings/{fid}").text
    assert "User-supplied, unverified" in page and "Add profile details" in page
    r = c.post(f"/findings/{fid}/profile-details", data={
        "display_name": "Acme Bank Customer Care", "joined": "2026-09-30", "bio": "Official helpline, DM for KYC",
        "followers": "37", "link_in_bio": "hxxps://acmebank-kyc[.]xyz", "verified_badge": "no",
        "csrf_token": csrf(c, f"/findings/{fid}")})
    assert r.status_code == 303 and "m=details" in r.headers["location"]
    with db.session_scope() as s:
        sigs = s.scalars(select(Signal).where(Signal.finding_id == fid)).all()
        assert sigs and all(x.evidence.startswith("USER-SUPPLIED UNVERIFIED: ") for x in sigs)
        assert {"handle_similar", "name_similar", "account_lt_90d", "claims_official"} <= {x.code for x in sigs}
        ev = s.scalar(select(Evidence).where(Evidence.finding_id == fid))
        assert ev.kind == "user_supplied_profile" and ev.content_json["entered_by"] == "a@example.com"
        assert s.scalar(select(CheckResult).where(CheckResult.finding_id == fid)).check == "user_profile_details"
        job = s.scalar(select(Job))
        assert job.payload["source"] == "link_in_bio" and job.payload["url"] == "https://acmebank-kyc.xyz/"
        f = s.get(Finding, fid)
        assert f.score > 0 and f.checks_ran == 1 and f.verdict != "Insufficient data"
    assert "profile details recorded (user-supplied, unverified)" in c.get(f"/findings/{fid}").text


def test_brand_settings_edit_keeps_assets():
    c = make_client()
    signup(c)
    tok = csrf(c, "/brands/new")
    r = c.post("/brands", data={"name": "Acme", "websites": "acme.example", "csrf_token": tok})
    bid = int(r.headers["location"].split("/")[2].split("?")[0])
    page = c.get(f"/brands/{bid}/edit").text
    assert "Brand settings" in page and "Official websites" not in page
    r = c.post(f"/brands/{bid}", data={"name": "Acme Bank", "keywords": "acme, acmepay", "scan_interval_hours": "12",
                                       "publishers": "Acme Insurance Ltd", "csrf_token": tok})
    assert r.status_code == 303
    with db.session_scope() as s:
        b = s.get(Brand, bid)
        assert (b.name, b.keywords, b.scan_interval_hours) == ("Acme Bank", ["acme", "acmepay"], 12)
        assert b.official_apps["publishers"] == ["Acme Insurance Ltd"] and b.official_domains == ["acme.example"]


def test_alerts_page_and_mark_read():
    c = make_client()
    signup(c)
    oid = org_of("a@example.com")
    with db.session_scope() as s:
        s.add(Notification(org_id=oid, text="New High finding (Scan): evil.example - High risk, score 90"))
    page = c.get("/notifications").text
    assert "1 unread" in page and "evil[.]example" in page
    assert '<span class="count" title="1 unread">1</span>' in c.get("/").text
    c.post("/notifications/read", data={"csrf_token": csrf(c, "/notifications")})
    assert "All read" in c.get("/notifications").text
