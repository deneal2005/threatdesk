"""What a finding is, in plain words: classification, evidence confidence and the score breakdown.

The score says how many warning signs fired. The classification says what the desk knows: an analyst confirmed it,
reputation sources list it, several independent signals point at it, or only its name resembles the brand.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select

from threatdesk.models import Signal
from threatdesk.scoring import (
    CATEGORY_LABELS, MIN_CHECKS, MIN_CHECKS_BY_KIND, VERDICT_EXCLUDED, VERDICT_INSUFFICIENT, Assessment, assess,
    STRONG_OWNERSHIP, category, hard_evidence, ownership_evidence,
)

ANALYST_CONFIRMED = ("confirmed", "takedown_requested", "taken_down")
# key: (label, explanation, css tone)
TIERS = {
    "confirmed": ("Verified threat", "An analyst confirmed it impersonates the brand.", "high"),
    "malicious": ("Malicious indicators", "A reputation source lists it, or it asks for credentials while posing as "
                                          "the brand. Confirm it, then act.", "high"),
    "conflicting": ("Conflicting evidence", "A reputation source flags it, but its registration or redirect points to "
                                            "the brand owning it. Engines often flag a brand's own defensive domains "
                                            "by their name: check the listing before acting.", "med"),
    "suspicious": ("Suspicious", "Several independent warning signs. Needs an analyst to confirm.", "med"),
    "brand_owned": ("Likely brand-owned", "It redirects to an official site or is registered like the brand's own "
                                          "domains (a defensive registration), and nothing on it looks abusive. If "
                                          "it is yours, add it to the brand's websites.", "off"),
    "lookalike": ("Look-alike, unconfirmed", "Its name resembles the brand, but nothing else points to abuse. "
                                             "Name similarity alone is not evidence.", "low"),
    "none": ("No strong signals", "The checks that ran found little. That is not proof it is genuine.", "low"),
    "insufficient": ("Insufficient data", "Too few checks could run to judge it.", "low"),
    "false_positive": ("False positive", "An analyst decided it is not a threat.", "off"),
    "official": ("Official asset", "One of the brand's own or allowed assets.", "off"),
}
UNVERIFIED_PREFIXES = ("USER-SUPPLIED", "FROM SEARCH RESULTS")


@dataclass
class RiskView:
    tier: str
    label: str
    explanation: str
    tone: str
    confidence: str
    confidence_reason: str
    assessment: Assessment
    breakdown: list[tuple[str, int]]


def classify(status: str, verdict: str, codes: set[str], score: int) -> str:
    if status in ANALYST_CONFIRMED:
        return "confirmed"
    if status == "false_positive":
        return "false_positive"
    if verdict == VERDICT_EXCLUDED:
        return "official"
    if hard_evidence(codes):
        return "conflicting" if codes & STRONG_OWNERSHIP else "malicious"
    if ownership_evidence(codes) and score < 40:
        return "brand_owned"
    if verdict == VERDICT_INSUFFICIENT:
        return "insufficient"
    if score >= 40:
        return "suspicious"
    if any(category(c) == "identity" for c in codes):
        return "lookalike"
    return "none"


def confidence(signals, checks_ran: int, kind: str | None) -> tuple[str, str]:
    """How much the evidence can be trusted: independent kinds of evidence, data provenance, coverage."""
    positive = [s for s in signals if s.points > 0]
    if any(str(s.evidence).startswith(UNVERIFIED_PREFIXES) for s in positive):
        return "Low", "part of the evidence is user-supplied or from search results and was not verified"
    if checks_ran < MIN_CHECKS_BY_KIND.get(kind or "", MIN_CHECKS):
        return "Low", f"only {checks_ran} check(s) could run"
    if hard_evidence({s.code for s in positive}):
        return "High", "a reputation source or credential phishing on a brand look-alike"
    kinds = {category(s.code) for s in positive} - {"identity", "ai"}
    if len(kinds) >= 2:
        return "High", f"{len(kinds)} independent kinds of evidence"
    if kinds:
        return "Medium", "one kind of evidence besides the name"
    return "Low", "no evidence besides the name" if positive else "nothing fired"


def risk_view(f, signals) -> RiskView:
    a = assess(signals, f.kind)
    codes = {s.code for s in signals}
    tier = classify(f.status, f.verdict, codes, f.score)
    label, text, tone = TIERS[tier]
    conf, why = confidence(signals, f.checks_ran or 0, f.kind)
    breakdown = [(label, a.categories[c]) for c, label in CATEGORY_LABELS.items() if a.categories.get(c)]
    return RiskView(tier, label, text, tone, conf, why, a, breakdown)


def tiers_for(db, findings) -> dict[int, str]:
    """{finding id: classification key} for many findings with one query."""
    ids = [f.id for f in findings]
    codes: dict[int, set[str]] = {}
    for fid, code in db.execute(select(Signal.finding_id, Signal.code).where(Signal.finding_id.in_(ids or [-1]))):
        codes.setdefault(fid, set()).add(code)
    return {f.id: classify(f.status, f.verdict, codes.get(f.id, set()), f.score) for f in findings}
