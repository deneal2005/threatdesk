"""Explainable scoring: signals (code, points, evidence) -> score 0-100 -> severity and verdict.

Every rule has a fixed number of points and a plain description. A rule counts once per investigation.
The words "safe" and "clean" are never produced: the lowest verdicts are "No strong signals" and "Insufficient data".
"""
from __future__ import annotations

from dataclasses import dataclass, field

MIN_CHECKS = 4
VERDICT_EXCLUDED = "Official/whitelisted asset"
VERDICT_INSUFFICIENT = "Insufficient data"
VERDICT_NONE = "No strong signals"
VERDICTS = (VERDICT_EXCLUDED, VERDICT_INSUFFICIENT, "High risk", "Medium risk", VERDICT_NONE)

RULES: dict[str, tuple[int, str]] = {
    # registration and infrastructure
    "domain_age_lt_30d": (30, "domain registered less than 30 days ago"),
    "domain_age_lt_180d": (15, "domain registered less than 180 days ago"),
    "first_cert_recent": (15, "first TLS certificate issued less than 30 days ago (used when RDAP has no date)"),
    "domain_lookalike": (25, "domain looks like an official domain"),
    "domain_has_brand": (20, "domain contains the brand name but is not official"),
    "idn_homograph": (30, "internationalised domain that imitates the brand (homograph)"),
    "registrant_redacted": (5, "registrant details redacted/private"),
    "tls_invalid": (10, "TLS certificate failed verification"),
    "tls_new_cert": (5, "TLS certificate issued in the last 14 days"),
    "no_archive_history": (10, "no Wayback Machine history"),
    "archive_recent": (10, "first archived less than 30 days ago"),
    "redirect_offsite": (5, "redirects to a different, non-official host"),
    "independent_site": (-30, "established site (2+ years) whose page never mentions the brand"),
    "redirects_to_official": (-30, "redirects to an official brand domain (often a defensive registration)"),
    # page content
    "asks_credentials": (25, "page asks for password/OTP/PIN/card details"),
    "payment_only_risky": (20, "payment only via UPI/crypto/gift card"),
    "urgency": (10, "urgency language"),
    "big_discount": (15, "discounts above 70%"),
    "earn_loan_claims": (20, "guaranteed returns / earn-from-home / instant loan claims"),
    "missing_policy_pages": (10, "no contact, privacy or refund page links"),
    "claims_official": (15, "claims to be official / customer care"),
    "brand_mention_unofficial": (15, "mentions the brand on a non-official domain"),
    "scam_phrases": (20, "known scam phrases"),
    "contact_bait": (10, "WhatsApp/Telegram links, phone numbers or UPI ids for contact"),
    # brand-independent website rules
    "known_brand_unofficial": (25, "uses a well-known brand's name (domain or page title) off that brand's domains"),
    "brand_domain_embedded": (20, "hostname embeds the brand's real domain (roblox.com.bi, paypal.com-login.xyz)"),
    "url_shortener": (10, "link goes through a URL shortener that hides the destination"),
    "free_hosting": (15, "on a free hosting / tunnel / dynamic-DNS subdomain anyone can create"),
    "server_hostname": (15, "bare IP address or a hosting provider's default server name"),
    "phishing_words_in_domain": (10, "domain name contains login/verify/account-style words"),
    "lure_title": (15, "page title is a common phishing lure (voice mail, PDF viewer, verification...)"),
    "hosting_abuse_block": (40, "the hosting provider has blocked this site for phishing/malware"),
    # reputation
    "safe_browsing_hit": (40, "listed by Google Safe Browsing"),
    "virustotal_malicious": (40, "flagged malicious by 2+ VirusTotal engines"),
    "virustotal_suspicious": (15, "flagged by 1 VirusTotal engine"),
    "urlhaus_listed": (40, "listed on URLhaus"),
    "phishtank_verified": (40, "verified, still-online phish on PhishTank"),
    "scam_list_hit": (40, "listed on a public scam/phishing list (OpenPhish, Phishing.Database, community lists)"),
    # apps
    "app_impersonation": (30, "app title resembles the brand but developer/package is not official"),
    "app_dev_free_email": (15, "developer email on a free mail provider"),
    "app_dangerous_permissions": (20, "requests high-risk permissions (SMS, accessibility, overlay...)"),
    "app_new": (15, "app released less than 90 days ago"),
    "app_low_ratings": (10, "fewer than 50 ratings"),
    "app_no_privacy_policy": (10, "no privacy policy link"),
    "app_dev_site_new": (15, "developer website registered less than 180 days ago"),
    "icon_matches_logo": (30, "icon/photo visually matches the brand logo but is not official"),
    # social
    "handle_similar": (25, "handle similar to an official handle"),
    "name_similar": (20, "display name similar to the brand"),
    "account_lt_90d": (20, "account created less than 90 days ago"),
    "account_lt_365d": (10, "account created less than a year ago"),
    "low_followers": (5, "very small audience for a brand account"),
    # AI (bounded, labelled)
    "ai_assessment": (15, "AI assessment: likely scam (labeled AI, rules decide)"),
}


@dataclass
class SignalHit:
    code: str
    points: int
    evidence: str

    def as_dict(self) -> dict:
        return {"code": self.code, "points": self.points, "evidence": self.evidence}


@dataclass
class Scorecard:
    signals: list[SignalHit] = field(default_factory=list)

    def add(self, code: str, evidence: str = "") -> bool:
        """Record a rule hit. Unknown codes raise KeyError; a rule that already fired is ignored."""
        points = RULES[code][0]
        if any(s.code == code for s in self.signals):
            return False
        self.signals.append(SignalHit(code, points, str(evidence or "")[:500]))
        return True

    def has(self, code: str) -> bool:
        return any(s.code == code for s in self.signals)

    @property
    def score(self) -> int:
        return max(0, min(100, sum(s.points for s in self.signals)))


def severity(score: int) -> str:
    return "High" if score >= 70 else "Medium" if score >= 40 else "Low"


MIN_CHECKS_BY_KIND = {"youtube": 1, "telegram": 1, "bluesky": 1, "social_profile": 1}


def verdict(score: int, checks_ran: int, excluded: bool, kind: str | None = None) -> str:
    if excluded:
        return VERDICT_EXCLUDED
    if checks_ran < MIN_CHECKS_BY_KIND.get(kind or "", MIN_CHECKS):
        return VERDICT_INSUFFICIENT
    if score >= 70:
        return "High risk"
    if score >= 40:
        return "Medium risk"
    return VERDICT_NONE
