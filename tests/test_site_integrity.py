"""Site integrity, route aliases, redirects, and UX robustness tests."""
from tests.helpers import csrf, make_client, signup


def test_route_aliases_and_redirects():
    c = make_client()
    signup(c)

    # 1. /dashboard alias
    r_dash = c.get("/dashboard")
    assert r_dash.status_code == 200
    assert "Digital Risk Overview" in r_dash.text or "ThreatDesk" in r_dash.text

    # 2. /assets redirect to /brands
    r_assets = c.get("/assets", follow_redirects=False)
    assert r_assets.status_code == 303
    assert r_assets.headers["location"] == "/brands"

    # 3. /takedown redirect to /findings?status=takedown_requested
    r_take = c.get("/takedown", follow_redirects=False)
    assert r_take.status_code == 303
    assert r_take.headers["location"] == "/findings?status=takedown_requested"

    # 4. /intake redirect to /brands
    r_intake = c.get("/intake", follow_redirects=False)
    assert r_intake.status_code == 303
    assert r_intake.headers["location"] == "/brands"


def test_investigate_url_query_prefill():
    c = make_client()
    signup(c)

    target_url = "https://phishing-paypal-security.com/login"
    r = c.get(f"/investigate?url={target_url}")
    assert r.status_code == 200
    assert target_url in r.text


def test_findings_search_and_severity_normalization():
    c = make_client()
    signup(c)

    # Severity normalization (lowercase high and critical)
    r_high = c.get("/findings?severity=high")
    assert r_high.status_code == 200

    r_crit = c.get("/findings?severity=critical")
    assert r_crit.status_code == 200
    # The panel preselects the canonical value, so applying another filter keeps the severity
    for r in (r_high, r_crit):
        assert '<option value="High" selected>' in r.text
        assert "&amp;severity=High" in r.text

    # An unknown severity is not counted or carried as an active filter
    r_bad = c.get("/findings?severity=bogus")
    assert "severity=bogus" not in r_bad.text and 'aria-label="Filter Options,' not in r_bad.text

    # Search parameter q
    r_q = c.get("/findings?q=paypal")
    assert r_q.status_code == 200
    assert "paypal" in r_q.text.lower()


def test_bulk_form_csp_compliance():
    c = make_client()
    signup(c)

    r = c.get("/findings")
    assert r.status_code == 200
    # Strict CSP: no inline onsubmit attribute in HTML
    assert "onsubmit=" not in r.text
