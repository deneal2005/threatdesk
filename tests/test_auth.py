from fastapi.routing import APIRoute
from sqlalchemy import select

from threatdesk import db
from threatdesk.models import Org, User
from threatdesk.web import CSRF_EXEMPT, CSRF_EXEMPT_PREFIXES
from threatdesk.web.deps import csrf_protect
from tests.helpers import csrf, make_client, post, signup


def test_signup_creates_org_and_admin_and_logs_in():
    c = make_client()
    signup(c, "boss@example.com", "Acme Org")
    with db.session_scope() as s:
        u = s.scalar(select(User).where(User.email == "boss@example.com"))
        assert u.role == "admin"
        assert s.get(Org, u.org_id).name == "Acme Org"
    r = c.get("/")
    assert r.status_code == 200
    assert "boss@example.com" in r.text and "Start by adding the brand you protect" in r.text


def test_requires_login():
    c = make_client()
    r = c.get("/")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r = c.get("/brands", headers={"HX-Request": "true"})
    assert r.status_code == 401 and r.headers["HX-Redirect"] == "/login"


def test_login_logout_and_wrong_password():
    c = make_client()
    signup(c, "a@example.com")
    r = c.post("/logout", data={"csrf_token": csrf(c, "/")})
    assert r.status_code == 303 and "loggedout" in r.headers["location"]
    c.cookies.delete("td_session")
    assert c.get("/").status_code == 303
    tok = csrf(c, "/login")
    r = c.post("/login", data={"email": "a@example.com", "password": "wrong password!", "csrf_token": tok})
    assert r.status_code == 400 and "Wrong email or password." in r.text and 'value="a@example.com"' in r.text
    r = c.post("/login", data={"email": "A@example.com", "password": "correct horse 1", "csrf_token": tok})
    assert r.status_code == 303 and r.headers["location"] == "/?m=welcome"
    assert c.get("/").status_code == 200


def test_login_rate_limit_5_per_minute():
    c = make_client()
    tok = csrf(c, "/login")
    codes = [c.post("/login", data={"email": "x@example.com", "password": "nope nope nope",
                                    "csrf_token": tok}).status_code for _ in range(6)]
    assert codes[:5] == [400] * 5 and codes[5] == 429


def test_post_without_csrf_rejected():
    c = make_client()
    c.get("/login")
    r = c.post("/login", data={"email": "a@example.com", "password": "correct horse 1"})
    assert r.status_code == 403
    r = c.post("/login", data={"email": "a@example.com", "password": "x", "csrf_token": "forged"})
    assert r.status_code == 403


def test_every_post_route_has_csrf_or_documented_exemption():
    from threatdesk.main import create_app
    missing = []
    for route in create_app().routes:
        if not isinstance(route, APIRoute) or "POST" not in route.methods:
            continue
        if route.path in CSRF_EXEMPT or route.path.startswith(CSRF_EXEMPT_PREFIXES):
            continue
        calls = {d.call for d in route.dependant.dependencies}
        if csrf_protect not in calls:
            missing.append(route.path)
    assert not missing, f"POST routes without CSRF: {missing}"


def test_security_headers():
    r = make_client().get("/login")
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "script-src 'self' https://unpkg.com" in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "td_csrf" in r.headers.get("set-cookie", "")
    assert "style=\"" not in r.text and "<script>" not in r.text


def test_duplicate_email_and_weak_password():
    c = make_client()
    signup(c, "a@example.com")
    c.cookies.clear()
    tok = csrf(c, "/signup")
    r = c.post("/signup", data={"org_name": "B", "email": "a@example.com", "password": "correct horse 2",
                                "csrf_token": tok})
    assert r.status_code == 400 and "already registered" in r.text
    r = c.post("/signup", data={"org_name": "B", "email": "b@example.com", "password": "short", "csrf_token": tok})
    assert r.status_code == 400 and "10-200 characters" in r.text and 'value="b@example.com"' in r.text


def test_teammate_added_by_admin_only():
    c = make_client()
    signup(c, "admin@example.com")
    r = post(c, "/settings/users", {"email": "ana@example.com", "password": "teammate pass 1", "role": "analyst"},
             page="/")
    assert r.status_code == 303
    c.cookies.clear()
    tok = csrf(c, "/login")
    c.post("/login", data={"email": "ana@example.com", "password": "teammate pass 1", "csrf_token": tok})
    r = post(c, "/settings/users", {"email": "x@example.com", "password": "teammate pass 2"}, page="/")
    assert r.status_code == 403


def test_welcome_login_page_and_assets():
    c = make_client()
    r = c.get("/login")
    assert r.status_code == 200
    assert "Sign in to ThreatDesk" in r.text and 'id="loaderOverlay"' in r.text
    assert 'name="csrf_token"' in r.text and 'action="/login"' in r.text and 'href="/signup"' in r.text
    for path, kind in (("/static/welcome/welcome.css", "text/css"), ("/static/welcome/welcome.js", "javascript"),
                       ("/static/welcome/logo.png", "image/png"), ("/static/welcome/mountains.jpg", "image/jpeg"),
                       ("/static/welcome/loader.mp4", "video/mp4")):
        a = c.get(path)
        assert a.status_code == 200 and kind in a.headers["content-type"], path


def test_welcome_intro_skipped_after_failed_login():
    c = make_client()
    tok = csrf(c, "/login")
    r = c.post("/login", data={"email": "nobody@example.com", "password": "wrong password!", "csrf_token": tok})
    assert r.status_code == 400 and "Wrong email or password." in r.text
    assert 'id="loaderOverlay"' not in r.text and 'class="container loaded"' in r.text


def test_logged_out_message_on_welcome_page():
    r = make_client().get("/login?m=loggedout")
    assert "You're logged out." in r.text or "You&#39;re logged out." in r.text
