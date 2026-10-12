from datetime import timedelta

from sqlalchemy import select

from threatdesk import db
from threatdesk.cases import whitelist_value
from threatdesk.metrics import dashboard_metrics
from threatdesk.models import AssetWhitelist, CaseEvent, Finding
from tests.brandhelp import make_brand, make_user, org_of
from tests.helpers import csrf, make_client, signup


def _finding(org_id: int, brand_id: int | None = None, key: str = "host:evil.example", **kw) -> int:
    with db.session_scope() as s:
        f = Finding(org_id=org_id, brand_id=brand_id, source=kw.get("source", "discovery:domains"), kind="website",
                    dedupe_key=key, scope_key=f"{brand_id or 0}:{key}", display_name=key.split(":", 1)[1],
                    url=f"https://{key.split(':', 1)[1]}/", score=kw.get("score", 60), severity=kw.get("sev", "Medium"),
                    verdict="Medium risk", status="new", in_triage=True)
        s.add(f)
        s.flush()
        return f.id


def test_status_flow_and_audit_trail():
    c = make_client()
    signup(c)
    fid = _finding(org_of("a@example.com"))
    tok = csrf(c, f"/findings/{fid}")
    r = c.post(f"/findings/{fid}/status", data={"to": "confirmed", "reason": "", "csrf_token": tok})
    assert r.status_code == 400 and "Reason is required." in r.text
    r = c.post(f"/findings/{fid}/status", data={"to": "taken_down", "reason": "x", "csrf_token": tok})
    assert r.status_code == 400 and "Cannot move a finding from &#39;new&#39; to &#39;taken_down&#39;" in r.text
    for to in ("investigating", "confirmed", "takedown_requested"):
        r = c.post(f"/findings/{fid}/status", data={"to": to, "reason": f"because {to}", "csrf_token": tok})
        assert r.status_code == 303
    with db.session_scope() as s:
        assert s.get(Finding, fid).status == "takedown_requested"
        evs = s.scalars(select(CaseEvent).where(CaseEvent.finding_id == fid).order_by(CaseEvent.id)).all()
        assert [e.to_status for e in evs] == ["investigating", "confirmed", "takedown_requested"]
        assert evs[0].body == "new -> investigating: because investigating"
    page = c.get(f"/findings/{fid}").text
    assert "Investigating → Confirmed" not in page and "confirmed → takedown_requested" in page


def test_assign_and_comment_and_other_org_assignee_refused():
    c = make_client()
    signup(c)
    fid = _finding(org_of("a@example.com"))
    tok = csrf(c, f"/findings/{fid}")
    with db.session_scope() as s:
        from threatdesk.models import User
        me = s.scalar(select(User.id).where(User.email == "a@example.com"))
    stranger = make_user("x@example.com")
    assert c.post(f"/findings/{fid}/assign", data={"assignee_id": str(me), "csrf_token": tok}).status_code == 303
    assert c.post(f"/findings/{fid}/assign", data={"assignee_id": str(stranger), "csrf_token": tok}).status_code == 400
    assert c.post(f"/findings/{fid}/comment", data={"body": "looks bad", "csrf_token": tok}).status_code == 303
    assert c.post(f"/findings/{fid}/comment", data={"body": " ", "csrf_token": tok}).status_code == 400
    page = c.get(f"/findings/{fid}").text
    assert "looks bad" in page and "assigned to a@example.com" in page


def test_bulk_false_positive_with_allow_list_and_isolation():
    c = make_client()
    signup(c)
    oid = org_of("a@example.com")
    bid = make_brand(oid)
    f1, f2 = _finding(oid, bid, "host:partner.example"), _finding(oid, bid, "instagram:acme_reseller")
    stranger = make_user("x@example.com")
    with db.session_scope() as s:
        from threatdesk.models import User
        other = s.get(User, stranger).org_id
    foreign = _finding(other, None, "host:foreign.example")
    tok = csrf(c, "/findings")
    r = c.post("/findings/bulk", data={"ids": [str(f1), str(f2), str(foreign)], "reason": "our partners",
                                       "whitelist": "1", "csrf_token": tok})
    assert r.status_code == 303
    with db.session_scope() as s:
        assert {s.get(Finding, i).status for i in (f1, f2)} == {"false_positive"}
        assert s.get(Finding, foreign).status == "new"
        wl = {(w.type, w.value) for w in s.scalars(select(AssetWhitelist))}
    assert wl == {("domain", "partner.example"), ("handle", "acme_reseller")}


def test_whitelist_value_mapping():
    def f(key):
        return Finding(dedupe_key=key)
    assert whitelist_value(f("host:evil.com")) == ("domain", "evil.com")
    assert whitelist_value(f("android:com.x.y")) == ("android", "com.x.y")
    assert whitelist_value(f("ios:123456")) == ("ios", "123456")
    assert whitelist_value(f("youtube:@acme")) == ("handle", "acme")
    assert whitelist_value(f("text:abcdef")) == ("dedupe_key", "text:abcdef")


def test_dashboard_metrics_and_new_since_visit():
    c = make_client()
    signup(c)
    oid = org_of("a@example.com")
    a, b = _finding(oid, key="host:a.example", sev="High"), _finding(oid, key="host:b.example")
    tok = csrf(c, f"/findings/{a}")
    with db.session_scope() as s:
        s.get(Finding, a).first_seen -= timedelta(hours=10)
    c.post(f"/findings/{a}/status", data={"to": "confirmed", "reason": "phish", "csrf_token": tok})
    c.post(f"/findings/{b}/status", data={"to": "false_positive", "reason": "ours", "csrf_token": tok})
    with db.session_scope() as s:
        m = dashboard_metrics(s, oid)
    assert m["open"] == {"High": 1, "Medium": 0, "Low": 0} and m["precision"] == "50%" and m["precision_n"] == 2
    assert m["detect_confirm"].endswith(" h") and m["detect_confirm_n"] == 1
    assert "1 High" not in c.get("/").text
    c.get("/findings")                                          # records the visit
    _finding(oid, key="host:c.example")
    page = c.get("/findings?since=1&view=all").text
    assert "c[.]example" in page and "a[.]example" not in page


def test_finding_routes_isolated():
    a, b = make_client(), make_client()
    signup(a, "a@example.com", "A")
    signup(b, "b@example.com", "B")
    fid = _finding(org_of("a@example.com"))
    tok = csrf(b, "/findings")
    assert b.get(f"/findings/{fid}").status_code == 404
    for path in ("save", "status", "assign", "comment", "profile-details"):
        assert b.post(f"/findings/{fid}/{path}", data={"to": "confirmed", "reason": "x", "body": "x",
                                                        "csrf_token": tok}).status_code == 404


def test_findings_empty_state_with_scan_cta():
    c = make_client()
    signup(c, "fresh@example.com", "Fresh Org")
    oid = org_of("fresh@example.com")

    # 1. Zero brands registered yet
    page_nobrands = c.get("/findings").text
    assert "No brands registered yet" in page_nobrands
    assert "/brands/new" in page_nobrands

    # 2. Brand registered, zero findings -> shows scan CTA
    bid = make_brand(oid, "Fresh Brand")
    page_empty = c.get("/findings").text
    assert "No findings yet" in page_empty
    assert f"/brands/{bid}/scan" in page_empty
    assert "Run First Brand Discovery Scan (Fresh Brand)" in page_empty

    # 3. Post scan CTA via existing authorized route
    tok = csrf(c, "/findings")
    res = c.post(f"/brands/{bid}/scan", data={"csrf_token": tok})
    assert res.status_code == 303 and f"/brands/{bid}?m=queued" in res.headers["location"]

    with db.session_scope() as s:
        from threatdesk.models import Job
        job = s.scalar(select(Job).where(Job.org_id == oid, Job.type == "scan"))
        assert job is not None and job.payload["brand_id"] == bid

