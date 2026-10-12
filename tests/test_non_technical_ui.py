"""Tests for non-technical user-friendly UI upgrade.

Verifies:
1. Dashboard welcome, explanation, summary cards, activity feed, and empty states.
2. Plain-English 7-part threat report structure on findings (what, severity, why, evidence, next steps, confidence, technical details).
3. Severity communication with accessible icons, text, and descriptions.
4. Search and filtering on findings triage queue.
5. Case workflow actions and technical details disclosure.
"""
from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from threatdesk import db
from threatdesk.main import app
from threatdesk.models import Brand, CaseEvent, Finding, Org, User
from tests.test_cases import _finding, csrf, make_brand, make_client, org_of, signup


def test_dashboard_non_technical_elements():
    """Verify modern dashboard welcome, KPI cards, and how-it-works banner."""
    c = make_client()
    signup(c, "analyst@example.com", "Test Corp")
    oid = org_of("analyst@example.com")
    bid = make_brand(oid, "Test Bank")
    fid = _finding(oid, bid=bid, key="host:fake-testbank.xyz", sev="High", score=90)

    res = c.get("/")
    assert res.status_code == 200
    html = res.text

    # 1. Platform explanation & welcome
    assert "Digital Safety Dashboard" in html
    assert "ThreatDesk monitors the internet to protect your organization" in html
    assert "Continuous Discovery" in html
    assert "Plain-English Analysis" in html
    assert "Coordinated Response" in html

    # 2. KPI Summary cards
    assert "Total Threats Found" in html
    assert "High-Priority Threats" in html
    assert "Awaiting Triage" in html
    assert "Monitored Assets" in html

    # 3. Prioritized findings table
    assert "Prioritized Findings Requiring Attention" in html
    assert "fake-testbank[.]xyz" in html
    assert "Review →" in html

    # 4. Efficiency & Glossary metrics
    assert "Response &amp; Efficiency" in html
    assert "Quick Security Glossary" in html


def test_plain_english_threat_report_seven_parts():
    """Verify that threat details render the required 7-part structure in plain English."""
    c = make_client()
    signup(c, "secops@example.com", "SecOps Corp")
    oid = org_of("secops@example.com")
    bid = make_brand(oid, "SafePay")
    fid = _finding(oid, brand_id=bid, key="host:safepay-verify.xyz", sev="High", score=95)

    res = c.get(f"/findings/{fid}")
    assert res.status_code == 200
    html = res.text

    # Part 1: What did we find?
    assert "1. What did we find?" in html
    assert "Target Asset" in html
    assert "safepay-verify[.]xyz" in html
    assert "Protected Brand" in html
    assert "SafePay" in html

    # Part 2: How serious is it?
    assert "2. How serious is it?" in html
    assert "/ 100 Risk Score" in html
    assert "Score 70–100:" in html

    # Part 3: Why should I care?
    assert "3. Why should I care?" in html
    assert "Potential Risks &amp; Harms:" in html

    # Part 4: What evidence supports this?
    assert "4. What evidence supports this?" in html
    assert "Why it was flagged" in html

    # Part 5: What should I do next?
    assert "5. What should I do next?" in html

    # Part 6: How confident is the finding?
    assert "6. How confident is the finding?" in html
    assert "Confidence evaluated separately from severity" in html

    # Part 7: Technical details (collapsible)
    assert "7. Technical Details &amp; Raw Signals (For Analysts)" in html
    assert "<details class=\"tech-accordion" in html
    assert "Automated Checks Executed" in html


def test_findings_search_and_filters():
    """Verify search filter and severity filtering in findings triage."""
    c = make_client()
    signup(c, "triage@example.com", "Triage Corp")
    oid = org_of("triage@example.com")
    bid = make_brand(oid, "Acme Brand")

    f1 = _finding(oid, brand_id=bid, key="host:alpha-impersonator.com", sev="High", score=85)
    f2 = _finding(oid, brand_id=bid, key="host:beta-partner.org", sev="Low", score=20)

    # Search for alpha
    res_search = c.get("/findings?q=alpha")
    assert res_search.status_code == 200
    assert "alpha-impersonator[.]com" in res_search.text
    assert "beta-partner[.]org" not in res_search.text

    # Search for beta
    res_search_b = c.get("/findings?q=beta")
    assert res_search_b.status_code == 200
    assert "beta-partner[.]org" in res_search_b.text
    assert "alpha-impersonator[.]com" not in res_search_b.text

    # Filter by High severity
    res_high = c.get("/findings?severity=High")
    assert res_high.status_code == 200
    assert "alpha-impersonator[.]com" in res_high.text
    assert "beta-partner[.]org" not in res_high.text

    # Filter by Low severity
    res_low = c.get("/findings?severity=Low")
    assert res_low.status_code == 200
    assert "beta-partner[.]org" in res_low.text
    assert "alpha-impersonator[.]com" not in res_low.text


def test_accessible_severity_badges():
    """Verify that severity badges render text label, icon, and accessible title."""
    c = make_client()
    signup(c, "user@example.com", "Access Corp")
    oid = org_of("user@example.com")
    fid = _finding(oid, key="host:threat.example", sev="High", score=90)

    res = c.get(f"/findings/{fid}")
    assert res.status_code == 200
    html = res.text

    # Accessible badge attributes
    assert 'role="status"' in html
    assert 'aria-label="Risk level:' in html
    assert 'sev-icon' in html
    assert 'sev-text' in html
