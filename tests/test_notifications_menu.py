"""The bell opens a dropdown of recent alerts with read state; items open the finding and mark it read."""
from sqlalchemy import select

from threatdesk import db
from threatdesk.models import Notification
from threatdesk.persistence import save_report
from tests.brandhelp import make_user, org_of
from tests.helpers import csrf, make_client, signup


def _alert(org, text="New High finding: acmebank-kyc[.]xyz", with_finding=True):
    from tests.test_jobs import _fake_report
    with db.session_scope() as s:
        fid = None
        if with_finding:
            f, _ = save_report(s, org, None, _fake_report(), "discovery:domains",
                               in_triage=True)
            fid = f.id
        n = Notification(org_id=org, finding_id=fid, text=text)
        s.add(n)
        s.flush()
        return n.id, fid


def test_bell_is_a_dropdown_with_unread_badge():
    c = make_client()
    signup(c)
    org = org_of("a@example.com")
    page = c.get("/").text
    assert 'id="notif-menu"' in page and 'href="/notifications" class="topbar-btn"' not in page
    assert 'class="topbar-count is-empty"' in page                                 # no badge without alerts
    menu = c.get("/notifications/menu").text
    assert "all caught up" in menu and "View all alerts" in menu
    _alert(org)
    _alert(org, "Second alert", with_finding=False)
    page = c.get("/").text
    assert '<span aria-hidden="true">2</span>' in page and "2 unread alerts" in page
    menu = c.get("/notifications/menu").text
    assert menu.count("is-unread") == 2 and "Mark all as read" in menu and "2 unread" in menu
    assert 'hx-swap-oob="true"' in menu                                            # keeps the bell's badge in step
    assert "every 60s" in c.get("/notifications/badge").text


def test_open_marks_read_and_goes_to_the_finding():
    c = make_client()
    signup(c)
    org = org_of("a@example.com")
    nid, fid = _alert(org)
    r = c.get(f"/notifications/{nid}/open")
    assert r.status_code == 303 and r.headers["location"] == f"/findings/{fid}"
    with db.session_scope() as s:
        assert s.get(Notification, nid).read
    nid2, _ = _alert(org, "No finding", with_finding=False)
    assert c.get(f"/notifications/{nid2}/open").headers["location"] == "/notifications"
    assert "alert_gone" in c.get("/notifications/99999/open").headers["location"]


def test_mark_one_and_all_read_from_the_dropdown():
    c = make_client()
    signup(c)
    org = org_of("a@example.com")
    a, _ = _alert(org)
    b, _ = _alert(org, "Other", with_finding=False)
    tok = csrf(c, "/")
    r = c.post(f"/notifications/{a}/read", headers={"HX-Request": "true", "X-CSRF-Token": tok})
    assert r.status_code == 200 and r.text.count("is-unread") == 1 and "1 unread" in r.text
    r = c.post("/notifications/read", headers={"HX-Request": "true", "X-CSRF-Token": tok})
    assert "is-unread" not in r.text and "All read" in r.text and 'class="topbar-count is-empty"' in r.text
    with db.session_scope() as s:
        assert all(n.read for n in s.scalars(select(Notification)))
    assert c.post("/notifications/read", data={"csrf_token": tok}).headers["location"] == "/notifications?m=all_read"


def test_alerts_are_private_to_the_org():
    c = make_client()
    signup(c)
    make_user("b@example.com")
    nid, _ = _alert(org_of("b@example.com"), "Other org alert", with_finding=False)
    assert "Other org alert" not in c.get("/notifications/menu").text
    assert "alert_gone" in c.get(f"/notifications/{nid}/open").headers["location"]
    c.post(f"/notifications/{nid}/read", headers={"HX-Request": "true", "X-CSRF-Token": csrf(c, "/")})
    with db.session_scope() as s:
        assert not s.get(Notification, nid).read
