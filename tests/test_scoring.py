import pytest

from threatdesk.brands import BrandContext
from threatdesk.checks.content import domain_name_signals, missing_policy_pages, text_signals
from threatdesk.scoring import (
    CATEGORY_LABELS, CONTENT, IDENTITY, REPUTATION, RULES, VERDICTS, Scorecard, category, severity, verdict,
)
from threatdesk.web.present import rail

BRAND = BrandContext(name="Acme Bank", official_domains=["acmebank.com"], keywords=["acme"])


def test_every_rule_has_points_and_description():
    assert len(RULES) == 63
    for code, (points, desc) in RULES.items():
        assert isinstance(points, int) and points != 0 and desc and "safe" not in desc.split()
        assert category(code, points) in CATEGORY_LABELS
    assert all(code in RULES for code in IDENTITY | REPUTATION | CONTENT)


def test_cap_floor_and_dedupe():
    c = Scorecard()
    for code in ("safe_browsing_hit", "urlhaus_listed", "scam_list_hit"):
        c.add(code, "x")
    assert c.score == 100
    assert not c.add("urlhaus_listed", "again")
    neg = Scorecard()
    neg.add("redirects_to_official")
    assert neg.score == 0
    with pytest.raises(KeyError):
        c.add("no_such_rule")


def test_severity_and_verdicts_never_safe():
    assert [severity(s) for s in (0, 39, 40, 69, 70, 100)] == ["Low", "Low", "Medium", "Medium", "High", "High"]
    assert verdict(90, 2, False) == "Insufficient data"
    assert verdict(90, 1, False, "telegram") == "High risk"
    assert verdict(45, 5, False) == "Medium risk" and verdict(10, 5, False) == "No strong signals"
    assert verdict(90, 9, True) == "Official/whitelisted asset"
    assert all("safe" not in v.lower() for v in VERDICTS)


def test_text_rules_positive_and_negated():
    c = Scorecard()
    found = text_signals(c, "URGENT: share your OTP now to claim refund. Pay via UPI only, flat 90% off!", BRAND)
    assert {"asks_credentials", "urgency", "payment_only_risky", "big_discount"} <= set(found)
    c2 = Scorecard()
    found2 = text_signals(c2, "Acme Bank will never ask you to share your OTP or password.", BRAND,
                          official_context=True)
    assert "asks_credentials" not in found2


def test_missing_policy_pages():
    assert missing_policy_pages([{"href": "/contact-us", "text": "Contact"}]) == ["privacy", "refund"]
    assert len(missing_policy_pages([])) == 3


def test_domain_name_rules():
    c = Scorecard()
    d = domain_name_signals(c, "acmebank.co", BRAND)
    codes = {s.code for s in c.signals}
    assert d["lookalike_of"] == "acmebank.com" and "domain_has_brand" in codes
    assert "domain_lookalike" not in codes                    # the same fact ("contains acmebank") counts once
    c4 = Scorecard()
    domain_name_signals(c4, "acmbank.com", BRAND)             # a typo of the name is its own signal
    assert {s.code for s in c4.signals} == {"domain_lookalike"}
    c2 = Scorecard()
    assert domain_name_signals(c2, "login.acmebank.com", BRAND)["official"] and not c2.signals
    c3 = Scorecard()
    assert "No brand selected" in domain_name_signals(c3, "paypal-login.xyz", BrandContext())["note"]
    assert {s.code for s in c3.signals} >= {"known_brand_unofficial", "phishing_words_in_domain"}


def test_rail_trims_for_negative_signals():
    class S:
        def __init__(self, code, points):
            self.code, self.points = code, points
    segs = rail([S("a", 40), S("b", 25), S("c", -30)], 35)
    assert sum(s["w"] for s in segs) == 35 and segs[0]["tone"] == "t1"
    assert sum(s["w"] for s in rail([S("a", 60), S("b", 60)], 100)) == 100
