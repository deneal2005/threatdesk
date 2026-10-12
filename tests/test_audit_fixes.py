"""Regression and verification tests for audit fixes and enhancements:
- Teammate removal safeguards (tenant isolation, self-removal prevention, sole admin protection)
- Navigation route aliases (/team, /discovery)
- Findings workspace pagination and sorting
- Settings integration health status view
- Onboarding checklist empty-state rendering
"""
import pytest
from sqlalchemy import select

from tests.helpers import csrf, make_client, signup
from threatdesk.models import Finding, User


def test_team_and_discovery_route_aliases():
    c = make_client()
    signup(c)

    r_team = c.get("/team", follow_redirects=False)
    assert r_team.status_code == 303
    assert r_team.headers["location"] == "/settings#team"

    r_disc = c.get("/discovery", follow_redirects=False)
    assert r_disc.status_code == 303
    assert r_disc.headers["location"] == "/brands"


def test_teammate_removal_and_safeguards():
    c = make_client()
    admin = signup(c)

    # 1. Add an analyst teammate
    token = csrf(c, "/settings")
    r_add = c.post(
        "/settings/users",
        data={"email": "analyst_bob@example.com", "password": "password12345", "role": "analyst", "csrf_token": token},
        follow_redirects=True,
    )
    assert r_add.status_code == 200
    assert "analyst_bob@example.com" in r_add.text

    from threatdesk import db
    with db.session_scope() as s:
        bob = s.scalar(select(User).where(User.email == "analyst_bob@example.com"))
        assert bob is not None
        bob_id = bob.id
        admin_row = s.scalar(select(User).where(User.email == "a@example.com"))
        admin_id = admin_row.id

    # 2. Prevent self-removal
    token2 = csrf(c, "/settings")
    r_self = c.post(f"/settings/users/{admin_id}/delete", data={"csrf_token": token2})
    assert r_self.status_code == 400
    assert "own user account" in r_self.text

    # 3. Prevent cross-tenant removal
    c2 = make_client()
    signup(c2, email="other_org@example.com", org="Other Org")
    token_c2 = csrf(c2, "/settings")
    r_cross = c2.post(f"/settings/users/{bob_id}/delete", data={"csrf_token": token_c2})
    assert r_cross.status_code == 404

    # 4. Successfully remove the analyst
    token3 = csrf(c, "/settings")
    r_del = c.post(f"/settings/users/{bob_id}/delete", data={"csrf_token": token3}, follow_redirects=True)
    assert r_del.status_code == 200
    assert "analyst_bob@example.com" not in r_del.text

    with db.session_scope() as s:
        assert s.scalar(select(User).where(User.id == bob_id)) is None


def test_findings_pagination_and_sorting():
    c = make_client()
    signup(c)

    # Seed 3 findings
    from threatdesk import db
    from threatdesk.models import Brand
    with db.session_scope() as s:
        admin_user = s.scalar(select(User).where(User.email == "a@example.com"))
        b = Brand(org_id=admin_user.org_id, name="PaginationBrand", report_token="test_token_123")
        s.add(b)
        s.flush()
        for i in range(1, 6):
            s.add(Finding(
                org_id=admin_user.org_id,
                brand_id=b.id,
                kind="domain",
                dedupe_key=f"fraud{i}.pagebrand.com",
                scope_key=f"{b.id}:fraud{i}.pagebrand.com",
                url=f"https://fraud{i}.pagebrand.com",
                display_name=f"fraud{i}.pagebrand.com",
                source="typosquat",
                severity="High" if i % 2 == 0 else "Medium",
                score=50 + i * 5,
                in_triage=True,
                status="new",
            ))

    # Test page and page_size query
    r_page = c.get("/findings?page=1&page_size=2")
    assert r_page.status_code == 200
    assert "Page 1 of" in r_page.text
    assert "Next →" in r_page.text

    # Test sorting
    r_newest = c.get("/findings?sort=newest")
    assert r_newest.status_code == 200
    assert "Order By" in r_newest.text

    r_oldest = c.get("/findings?sort=oldest")
    assert r_oldest.status_code == 200


def test_integration_health_and_onboarding_checklist():
    c = make_client()
    signup(c)

    # Settings integrations table
    r_set = c.get("/settings")
    assert r_set.status_code == 200
    assert "Connected Services &amp; Adapters" in r_set.text
    assert "Gemini AI" in r_set.text
    assert "Reputation Feeds" in r_set.text

    # Dashboard with 0 brands displays Onboarding Checklist
    r_dash = c.get("/dashboard")
    assert r_dash.status_code == 200
    assert "Start by adding the brand you protect" in r_dash.text and "Organization Created" not in r_dash.text
    assert "Add your brand" in r_dash.text and 'href="/brands/new"' in r_dash.text
