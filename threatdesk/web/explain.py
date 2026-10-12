"""Plain-English threat explanations for non-technical users and cybersecurity professionals."""
from __future__ import annotations

from typing import Any

from threatdesk.safety import defang_text
from threatdesk.scoring import RULES, VERDICT_EXCLUDED, VERDICT_INSUFFICIENT, VERDICT_NONE
from threatdesk.web.explain_data import (
    BENIGN_RULES, GLOSSARY, INFRA_RULES, MALICIOUS_RULES, STATUS_ICON, SUSPICIOUS_RULES,
    EvidenceItem, NextStep, ThreatExplanation, asset_kind_name, sev_badge, status_icon,
)


def _headline_and_summary(
    f: Any, brand_name: str | None, defanged_name: str, sig_codes: set[str],
    is_excluded: bool, is_insufficient: bool, is_clean: bool,
) -> tuple[str, str]:
    kind = getattr(f, "kind", "website")
    score = getattr(f, "score", 0)
    has_malicious = bool(sig_codes & MALICIOUS_RULES)
    has_creds = "asks_credentials" in sig_codes or "scam_phrases" in sig_codes
    has_lookalike = bool(sig_codes & {"domain_lookalike", "domain_has_brand", "idn_homograph",
                                       "handle_similar", "name_similar", "app_impersonation"})

    if is_excluded:
        return (f"Official Brand Asset ({brand_name or 'Protected'})",
                f"This {asset_kind_name(kind).lower()} is officially registered or approved on your allowlist. "
                f"It is excluded from risk scoring so genuine services are never mistaken for threats.")
    if is_insufficient:
        return ("Inconclusive Finding: Limited Data Available",
                f"ThreatDesk was unable to complete enough automated verification tests on {defanged_name} "
                f"to reach a definitive conclusion. The site may be offline or blocking scanners.")
    if is_clean and score == 0:
        return ("Low-Risk Finding: No Warning Signs Detected",
                f"Automated checks evaluated {defanged_name} and did not identify deceptive patterns, "
                f"phishing forms, or blacklist entries. Continued monitoring is active.")
    if kind in ("android_app", "ios_app"):
        if has_lookalike:
            return (f"Unofficial Mobile App Imitating {brand_name or 'Your Organization'}",
                    f"An unauthorized mobile app titled '{defanged_name}' was found using branding very similar to "
                    f"{brand_name or 'your brand'}, published by an unverified developer.")
        return ("Potentially Suspicious Mobile Application",
                f"Mobile application '{defanged_name}' was flagged for unverified permissions or low ratings.")
    if kind in ("social_profile", "youtube", "telegram", "bluesky"):
        if has_lookalike:
            return (f"Suspicious Social Account Impersonating {brand_name or 'Your Organization'}",
                    f"A social account ({defanged_name}) closely resembles {brand_name or 'your official profile'}. "
                    f"It is not part of your official registered accounts.")
        return ("Unverified Social Profile Under Investigation",
                f"Social account ({defanged_name}) was flagged due to recent creation or trademark similarity.")
    if kind == "other":
        return ("Reported Scam Message Soliciting Sensitive Information",
                f"A reported suspicious message uses your organization's name to demand urgent action or OTP codes.")
    # Website / Domain
    if has_malicious:
        return (f"Active Malicious Phishing Site Targeting {brand_name or 'Your Organization'}",
                f"Website at {defanged_name} is confirmed on global threat lists as an active phishing attack.")
    if has_creds:
        return (f"Deceptive Website Requesting Customer Credentials",
                f"Website at {defanged_name} imitates {brand_name or 'your brand'} and actively requests login or banking details.")
    if has_lookalike:
        return (f"Look-Alike Website Mimicking {brand_name or 'Your Organization'}",
                f"Look-alike web address ({defanged_name}) closely copies {brand_name or 'your brand'} outside your authorized infrastructure.")
    return ("Suspicious Web Property Flagged for Review",
            f"The website at {defanged_name} exhibited warning signals such as recent registration or private records.")


def _severity_info(f: Any, score: int, sev: str, is_excluded: bool, is_insufficient: bool,
                   is_clean: bool, has_malicious: bool, has_creds: bool) -> tuple[str, str, str, str, str]:
    if is_excluded:
        return ("Verified Asset", "excluded", "shield-check",
                "This asset is confirmed as an authorized digital property of the organization.",
                "Score: 0/100 (Official assets excluded from threat scoring).")
    if is_insufficient:
        return ("Inconclusive", "info", "help-circle",
                "Insufficient technical data to reach a definitive verdict. Manual verification advised.",
                f"Score: {score}/100 (Preliminary baseline; incomplete evidence).")
    if is_clean and score == 0:
        return ("No Strong Signals", "clean", "check-circle",
                "All completed tests passed cleanly without triggering any warning rules.",
                "Score: 0/100 — No risk signals detected.")
    if has_malicious or (score >= 85 and has_creds):
        return ("Critical Threat", "critical", "alert-octagon",
                "Immediate threat to customers or staff. Verified by threat databases or active credential harvesting.",
                f"Score: {score}/100 — Critical risk tier (Threshold: 70+).")
    if score >= 70 or sev == "High":
        return ("High Risk", "high", "alert-triangle",
                "Substantial risk of brand impersonation or customer deception. Multiple warning signals corroborate danger.",
                f"Score: {score}/100 — High risk tier (Threshold: 70+).")
    if score >= 40 or sev == "Medium":
        return ("Medium Risk", "medium", "alert-circle",
                "Moderate risk with suspicious indicators present. Warrants review by your team.",
                f"Score: {score}/100 — Medium risk tier (Threshold: 40–69).")
    return ("Low Risk", "low", "info",
            "Minor technical anomalies observed. Unlikely to present immediate danger today.",
            f"Score: {score}/100 — Low risk tier (Threshold: 1–39).")


def _harms_and_why(brand_name: str | None, sig_codes: set[str], is_excluded: bool,
                   is_insufficient: bool, is_clean: bool, has_creds: bool, has_malicious: bool) -> tuple[str, list[str]]:
    if is_excluded:
        return ("Knowing which assets are genuine allows security teams to focus on real threats.", ["None (Authorized brand asset)."])
    if is_insufficient:
        return ("Attackers sometimes configure sites to block automated scanners.", ["Unmonitored look-alike could turn malicious at any moment."])
    if is_clean and not sig_codes:
        return ("Continuous monitoring ensures dormant look-alikes do not secretly turn into fraud portals.", ["No immediate harm detected today."])

    harms = []
    if has_creds:
        harms.append("Customer Account Takeover: Visitors could enter usernames, passwords, or bank PINs.")
        harms.append("OTP Interception: Attackers may intercept one-time verification codes.")
    if "payment_only_risky" in sig_codes or "contact_bait" in sig_codes:
        harms.append("Direct Financial Loss: Unofficial UPI IDs, crypto, or WhatsApp contacts trick users into irreversible payments.")
    if bool(sig_codes & {"domain_lookalike", "handle_similar", "name_similar"}):
        harms.append("Brand Reputation Harm: Misled customers will associate fraud with your brand.")
        harms.append("Support Desk Strain: Customer support will face complaints from victims of external fraud.")
    if not harms:
        harms.append("Customer Confusion: Unofficial branding causes doubt about legitimate channels.")

    if has_creds or has_malicious:
        why = f"Customers could be tricked into sharing private passwords or financial details believing they interact with {brand_name or 'your team'}."
    else:
        why = f"Deceptive accounts and websites take advantage of customer trust in {brand_name or 'your brand'} to siphon inquiries or prepare attacks."
    return why, harms


def _recommendations(score: int, is_excluded: bool, has_malicious: bool, defanged_name: str) -> list[NextStep]:
    if is_excluded:
        return [NextStep(1, "No Action Needed", "This asset is recognized as official and safely allowed.", "optional")]
    if has_malicious or score >= 70:
        return [
            NextStep(1, "Verify Content", "Confirm this asset does not belong to an internal team or authorized affiliate.", "immediate"),
            NextStep(2, "Issue Takedown Request", "Download ThreatDesk's Takedown Packet and submit to the registrar or web host.", "immediate", "takedown"),
            NextStep(3, "Alert Customer Support", f"Notify frontline staff that look-alike site {defanged_name} may be contacting customers.", "soon", "notify"),
            NextStep(4, "Update Case Status", "Move case to 'Confirmed' or 'Takedown requested' to track resolution.", "soon"),
        ]
    if score >= 40:
        return [
            NextStep(1, "Review Live Content", "Check the captured evidence to verify if deceptive content is published.", "soon"),
            NextStep(2, "Allowlist if Legitimate", "If this belongs to an approved partner, mark as False Positive to allowlist.", "soon", "allowlist"),
            NextStep(3, "Monitor for Changes", "Set status to 'Monitoring' if currently parked or dormant.", "optional"),
        ]
    return [NextStep(1, "Review Baseline", "No immediate danger detected today. Keep in archives or monitoring.", "optional")]


def explain_finding(
    f: Any, brand: Any | None, signals: list[Any], checks: list[Any],
    counts: dict[str, int], evidence: list[Any] | None = None,
    indicators: dict[str, list[str]] | None = None,
) -> ThreatExplanation:
    """Generate a structured, plain-English 7-part threat report."""
    brand_name = brand.name if brand else None
    score = getattr(f, "score", 0)
    sev = getattr(f, "severity", "Low")
    verdict_text = getattr(f, "verdict", "")
    defanged_name = defang_text(getattr(f, "display_name", ""))
    signals, checks, evidence = signals or [], checks or [], evidence or []
    sig_codes = {s.code for s in signals}

    is_excluded = verdict_text == VERDICT_EXCLUDED
    is_insufficient = verdict_text == VERDICT_INSUFFICIENT
    is_clean = verdict_text == VERDICT_NONE
    has_malicious = bool(sig_codes & MALICIOUS_RULES)
    has_creds = "asks_credentials" in sig_codes or "scam_phrases" in sig_codes

    headline, summary = _headline_and_summary(f, brand_name, defanged_name, sig_codes, is_excluded, is_insufficient, is_clean)
    sev_lvl, sev_cls, sev_ico, sev_exp, score_meaning = _severity_info(f, score, sev, is_excluded, is_insufficient, is_clean, has_malicious, has_creds)
    why_it_matters, potential_harms = _harms_and_why(brand_name, sig_codes, is_excluded, is_insufficient, is_clean, has_creds, has_malicious)

    evidence_items = []
    for s in signals:
        desc = RULES.get(s.code, (0, s.code))[1].capitalize()
        cat, badge, b_cls = ("malicious", "Verified Threat", "bad") if s.code in MALICIOUS_RULES else \
                            ("suspicious", "Warning Signal", "warn") if s.code in SUSPICIOUS_RULES else \
                            ("observation", "Confirmed Fact", "fact") if s.code in INFRA_RULES else \
                            ("observation", "Legitimate Signal", "info")
        evidence_items.append(EvidenceItem(cat, badge, b_cls, desc, s.evidence or "", s.code, s.points))

    if not evidence_items:
        evidence_items.append(EvidenceItem("observation", "No Alerts", "info", "All check rules passed cleanly",
                                           f"Completed {counts.get('ran', 0)} checks without discovering warning signals."))

    ran_cnt, tot_cnt = counts.get("ran", 0), counts.get("total", 0)
    if is_excluded:
        conf_lvl, conf_cls, conf_exp = "Verified Record", "conf-high", "Confirmed directly against official asset database."
    elif has_malicious or (ran_cnt >= 7 and len(signals) >= 3):
        conf_lvl, conf_cls, conf_exp = "High Confidence", "conf-high", f"Corroborated across {ran_cnt} independent technical checks and multiple distinct signals."
    elif ran_cnt >= 4 or len(signals) >= 1:
        conf_lvl, conf_cls, conf_exp = "Moderate Confidence", "conf-med", f"Supported by {ran_cnt} completed checks with single or heuristic indicators."
    else:
        conf_lvl, conf_cls, conf_exp = "Preliminary Assessment", "conf-low", f"Limited evidence: only {ran_cnt} of {tot_cnt} checks were able to execute."

    ai_json = getattr(f, "ai_json", None)
    ai_note = ("Note on AI Insights: AI-generated summaries are advisory heuristic readings to assist human analysts. "
               "They explain context in plain English but DO NOT calculate or overwrite the objective rule-based threat score.") if (ai_json and ai_json.get("status") == "ok") else None

    return ThreatExplanation(
        headline=headline, summary=summary, asset_kind_label=asset_kind_name(getattr(f, "kind", "website")),
        display_target=defanged_name, brand_name=brand_name, severity_level=sev_lvl, severity_class=sev_cls,
        severity_icon=sev_ico, severity_explanation=sev_exp, score=score, score_meaning=score_meaning,
        why_it_matters=why_it_matters, potential_harms=potential_harms, evidence_items=evidence_items,
        evidence_count=len(evidence_items), has_captures=bool(evidence),
        recommendations=_recommendations(score, is_excluded, has_malicious, defanged_name),
        confidence_level=conf_lvl, confidence_class=conf_cls, confidence_explanation=conf_exp,
        checks_ran=ran_cnt, checks_total=tot_cnt, ai_note=ai_note, signal_codes=sorted(sig_codes),
        raw_signals=[{"code": s.code, "points": s.points, "evidence": s.evidence} for s in signals],
    )
