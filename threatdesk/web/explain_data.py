"""Data models, glossary, rule classifications, and metadata for threat explanations."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Terminology glossary for non-technical users
GLOSSARY = {
    "triage": "The review queue where incoming potential threats are prioritized and decided on.",
    "lookalike": "A deceptive web address, account name, or app designed to resemble a trusted brand so people are misled.",
    "phishing": "A deceptive attempt to steal passwords, credit card numbers, or one-time codes by pretending to be a legitimate organization.",
    "typosquat": "A domain name registered with a deliberate misspelling of a popular brand (e.g. acme-bnak.com).",
    "homograph": "A domain using look-alike letters from different alphabets (e.g. Cyrillic 'a') to trick the human eye.",
    "takedown": "A formal abuse complaint requesting that a domain registrar, web host, or platform take down an unauthorized asset.",
    "allowlist": "An approved list of official or authorized partner assets that ThreatDesk skips during threat detection.",
    "rdap": "Registration Data Access Protocol: official records showing when a domain was registered and which registrar manages it.",
    "tls": "Transport Layer Security certificate: provides encryption (HTTPS) and indicates who issued the certificate.",
    "defanged": "A modified web address (e.g. hxxps://site[.]com) that cannot be accidentally clicked, keeping analysts safe.",
    "sha256": "A cryptographic fingerprint proving stored evidence has not been altered or tampered with since capture.",
    "otp": "One-Time Password: a temporary verification code sent via SMS or app to authenticate transactions.",
}

STATUS_ICON = {
    "new": "•", "investigating": "◐", "confirmed": "■",
    "takedown_requested": "⚑", "taken_down": "✓", "false_positive": "⊘",
    "monitoring": "◎",
}

SEVERITY_META = {
    "Critical": {
        "label": "Critical", "class": "critical", "icon": "■",
        "explanation": "Immediate threat: verified malicious activity, credential theft, or active phishing.",
    },
    "High": {
        "label": "High Risk", "class": "high", "icon": "▲",
        "explanation": "High risk: strong look-alike impersonation or multiple deceptive signals detected.",
    },
    "Medium": {
        "label": "Medium Risk", "class": "medium", "icon": "◆",
        "explanation": "Suspicious indicators found: warrants human review before action.",
    },
    "Low": {
        "label": "Low Risk", "class": "low", "icon": "●",
        "explanation": "Minor technical anomalies; low probability of immediate danger.",
    },
    "Informational": {
        "label": "Informational", "class": "clean", "icon": "○",
        "explanation": "No warning signs detected across automated checks.",
    },
}

INFRA_RULES = {
    "domain_age_lt_30d", "domain_age_lt_180d", "first_cert_recent", "registrant_redacted",
    "tls_invalid", "tls_new_cert", "no_archive_history", "archive_recent", "redirect_offsite",
    "free_hosting", "server_hostname", "app_dev_free_email", "app_new", "app_dev_site_new",
    "account_lt_90d", "account_lt_365d", "low_followers",
}

SUSPICIOUS_RULES = {
    "domain_lookalike", "domain_has_brand", "idn_homograph", "phishing_words_in_domain",
    "brand_domain_embedded", "url_shortener", "lure_title", "asks_credentials", "payment_only_risky",
    "urgency", "big_discount", "earn_loan_claims", "missing_policy_pages", "claims_official",
    "brand_mention_unofficial", "scam_phrases", "contact_bait", "known_brand_unofficial",
    "app_impersonation", "app_dangerous_permissions", "app_low_ratings", "app_no_privacy_policy",
    "icon_matches_logo", "handle_similar", "name_similar", "ai_assessment",
}

MALICIOUS_RULES = {
    "safe_browsing_hit", "virustotal_malicious", "urlhaus_listed", "phishtank_verified",
    "scam_list_hit", "hosting_abuse_block",
}

BENIGN_RULES = {"independent_site", "redirects_to_official"}


def sev_badge(s: str | None, score: int = 0) -> dict[str, str]:
    if s == "High" and score >= 85:
        return SEVERITY_META["Critical"]
    return SEVERITY_META.get(s or "", {
        "label": s or "Low Risk", "class": (s or "low").lower(), "icon": "ℹ",
        "explanation": "Evaluation based on completed detection rules.",
    })


def status_icon(s: str | None) -> str:
    return STATUS_ICON.get(s or "", "•")


def asset_kind_name(kind: str | None) -> str:
    mapping = {
        "website": "Web Address / Site", "domain": "Domain Name", "android_app": "Android Mobile App",
        "ios_app": "iOS App Store App", "youtube": "YouTube Channel", "telegram": "Telegram Channel",
        "bluesky": "Bluesky Account", "social_profile": "Social Media Profile", "other": "Reported Message",
    }
    return mapping.get(kind or "", "Digital Property")


@dataclass
class EvidenceItem:
    category: str
    badge_label: str
    badge_class: str
    title: str
    detail: str
    raw_code: str | None = None
    points: int = 0


@dataclass
class NextStep:
    order: int
    title: str
    action: str
    urgency: str
    action_type: str = "review"


@dataclass
class ThreatExplanation:
    headline: str
    summary: str
    asset_kind_label: str
    display_target: str
    brand_name: str | None
    severity_level: str
    severity_class: str
    severity_icon: str
    severity_explanation: str
    score: int
    score_meaning: str
    why_it_matters: str
    potential_harms: list[str]
    evidence_items: list[EvidenceItem]
    evidence_count: int
    has_captures: bool
    recommendations: list[NextStep]
    confidence_level: str
    confidence_class: str
    confidence_explanation: str
    checks_ran: int
    checks_total: int
    ai_note: str | None = None
    signal_codes: list[str] = field(default_factory=list)
    raw_signals: list[dict[str, Any]] = field(default_factory=list)
