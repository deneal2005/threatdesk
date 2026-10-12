import logging
from pathlib import Path

from tests.helpers import csrf, make_client, signup

PKG = Path(__file__).resolve().parent.parent / "threatdesk"


def test_body_limit_413():
    c = make_client()
    r = c.post("/login", content=b"x" * (3 * 1024 * 1024 + 10), headers={"content-type": "application/octet-stream"})
    assert r.status_code == 413 and r.json() == {"error": "request body too large"}


def test_friendly_404_and_json_for_api():
    c = make_client()
    signup(c)
    r = c.get("/findings/999999")
    assert r.status_code == 404 and "Not found" in r.text and "Go to overview" in r.text
    r = c.get("/api/v1/findings")
    assert r.status_code == 401 and r.json()["error"] == "invalid or missing API key"


def test_logs_never_contain_passwords_or_keys(caplog):
    from threatdesk import config
    config.override(gemini_api_key="AIza-SECRET-KEY-123", vt_api_key="vt-SECRET-456")
    caplog.set_level(logging.DEBUG)
    c = make_client()
    signup(c, pw="super secret password 9")
    c.post("/login", data={"email": "a@example.com", "password": "super secret password 9",
                           "csrf_token": csrf(c, "/login")})
    c.get("/settings")
    text = caplog.text + repr(config.get_settings())
    for secret in ("super secret password 9", "AIza-SECRET-KEY-123", "vt-SECRET-456"):
        assert secret not in text


def test_modules_stay_small():
    big = {str(p.relative_to(PKG)): n for p in PKG.rglob("*.py")
           if (n := len(p.read_text(encoding="utf-8").splitlines())) >= 300}
    assert not big, f"modules over 300 lines: {big}"
