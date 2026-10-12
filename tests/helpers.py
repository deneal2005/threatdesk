"""Test helpers: app client, login, CSRF token extraction."""
from __future__ import annotations

import re

from fastapi.testclient import TestClient

from threatdesk.security import limiter

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def make_client() -> TestClient:
    from threatdesk.main import create_app
    limiter.reset()
    return TestClient(create_app(), follow_redirects=False)


def csrf(client: TestClient, path: str = "/login") -> str:
    r = client.get(path)
    m = CSRF_RE.search(r.text)
    assert m, f"no csrf token on {path}"
    return m.group(1)


def signup(client: TestClient, email: str = "a@example.com", org: str = "Org A", pw: str = "correct horse 1") -> None:
    tok = csrf(client, "/signup")
    r = client.post("/signup", data={"org_name": org, "email": email, "password": pw, "csrf_token": tok})
    assert r.status_code == 303, r.text[:500]


def post(client: TestClient, path: str, data: dict | None = None, files=None, page: str = "/settings"):
    d = dict(data or {})
    d["csrf_token"] = csrf(client, page)
    return client.post(path, data=d, files=files)
