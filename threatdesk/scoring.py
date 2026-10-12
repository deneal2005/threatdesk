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
    "brand_protection_registrar": (-20, "registered over a year ago through a corporate brand-protection registrar "
                                        "(typical of the brand's own defensive registrations)"),
    "registrant_is_brand": (-30, "the registrant organisation is the brand or one of its listed publishers"),
    "shares_official_nameservers": (-25, "uses the same private nameservers as an official brand domain"),
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
    "app_publisher_lookalike": (15, "developer name imitates the brand or a listed publisher but is not an official publisher"),
    "app_package_lookalike": (15, "package/bundle id imitates the brand or an official app's namespace"),
    "icon_matches_logo": (30, "icon/photo visually matches the brand logo but is not official"),
    # social
    "handle_similar": (25, "handle similar to an official handle"),
    "name_similar": (20, "display name similar to the brand"),
    "account_lt_90d": (20, "account created less than 90 days ago"),
    "account_lt_365d": (10, "account created less than a year ago"),
    "low_followers": (5, "very small audience for a brand account"),
    "bio_link_lookalike": (20, "profile links to a non-official site whose name imitates the brand"),
    "platform_verified": (-10, "the platform shows a verified badge (often an unlisted official or partner account)"),
    "established_account": (-15, "established account: 2+ years old with 10,000+ followers"),
    "linked_from_official_site": (-50, "an official brand website links to this account (the brand published it)"),
    "links_to_official_site": (-10, "a link in the profile resolves to an official brand domain (weak on its own: "
                                    "impostors link to the real site too)"),
    "regional_variant": (-5, "named as the brand plus a region, language or product, the way brands name their own "
                             "local and product accounts"),
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


# Every rule belongs to one kind of evidence. "identity" means "the name looks like the brand": on its own that is
# not evidence of abuse (fan pages, resellers, unrelated businesses share names).
IDENTITY = {"handle_similar", "name_similar", "app_impersonation", "app_publisher_lookalike", "app_package_lookalike",
            "domain_lookalike", "domain_has_brand", "known_brand_unofficial", "phishing_words_in_domain"}
OWNERSHIP = {"redirects_to_official", "brand_protection_registrar", "registrant_is_brand", "shares_official_nameservers",
             "linked_from_official_site"}
REPUTATION = {"safe_browsing_hit", "virustotal_malicious", "virustotal_suspicious", "urlhaus_listed",
              "phishtank_verified", "scam_list_hit", "hosting_abuse_block"}
CONTENT = {"asks_credentials", "payment_only_risky", "urgency", "big_discount", "earn_loan_claims",
           "missing_policy_pages", "claims_official", "brand_mention_unofficial", "scam_phrases", "contact_bait",
           "lure_title", "app_dangerous_permissions", "bio_link_lookalike"}
CATEGORY_LABELS = {"identity": "Name similarity", "visual": "Copied branding", "content": "Content and behaviour",
                   "reputation": "Reputation lists", "context": "Account and registration context",
                   "counter": "Counter-evidence", "ai": "AI (bounded)"}


def category(code: str, points: int = 0) -> str:
    if points < 0:
        return "counter"
    if code in IDENTITY:
        return "identity"
    if code == "icon_matches_logo" or code == "idn_homograph" or code == "brand_domain_embedded":
        return "visual"
    if code in REPUTATION:
        return "reputation"
    if code in CONTENT:
        return "content"
    return "ai" if code == "ai_assessment" else "context"


HARD_EVIDENCE = {"safe_browsing_hit", "virustotal_malicious", "urlhaus_listed", "phishtank_verified", "scam_list_hit",
                 "hosting_abuse_block", "idn_homograph", "brand_domain_embedded"}
BRAND_CLAIMS = {"claims_official", "brand_mention_unofficial", "known_brand_unofficial", "domain_lookalike",
                "domain_has_brand", "app_impersonation", "handle_similar", "name_similar"}
# Name similarity alone stays below Medium for every kind of asset: brands register their own look-alike domains
# (amazonlogin.com), fans name pages after brands, and unrelated businesses share names.
GATED_KINDS = {"youtube", "telegram", "bluesky", "social_profile", "android_app", "ios_app", "website"}
IDENTITY_ONLY_CAP = 35
CORROBORATION_MIN = 10
# Absence of data, or facts just as common on a brand's own parked domains: they add points but never corroborate a
# name match on their own (a defensive registration has no archive, a redacted registrant and often no TLS).
# Real brand accounts call themselves "official": on a platform-verified or long-established account that claim
# no longer corroborates a look-alike name.
# A regional or product name (YouTube India) is how real accounts are named, and real accounts call themselves official.
LEGITIMACY = {"platform_verified", "established_account", "regional_variant", "links_to_official_site"}
LEGITIMACY_WEAKENS = {"claims_official"}
# A single VirusTotal engine (of ~90) is noise: it adds its points but never corroborates a name match alone.
WEAK_CONTEXT = {"no_archive_history", "registrant_redacted", "tls_invalid", "tls_new_cert", "redirect_offsite",
                "missing_policy_pages", "low_followers", "virustotal_suspicious"}


def hard_evidence(codes: set[str]) -> bool:
    return bool(codes & HARD_EVIDENCE) or ("asks_credentials" in codes and bool(codes & BRAND_CLAIMS))


STRONG_OWNERSHIP = {"brand_protection_registrar", "registrant_is_brand", "shares_official_nameservers",
                    "linked_from_official_site"}
# Evidence that a brand-named account is one of the brand's regional or product accounts (affiliation.py).
AFFILIATION_SUPPORT = {"platform_verified", "established_account", "links_to_official_site"}
ABUSE = HARD_EVIDENCE | {"asks_credentials", "scam_phrases", "payment_only_risky", "earn_loan_claims", "lure_title",
                         "contact_bait", "claims_official"}


# What rules out "the brand's own regional account". Calling itself official is normal for a real account, so
# claims_official alone does not; scam text, contact bait, look-alike links or a brand-new account do.
AFFILIATION_ABUSE = (ABUSE - {"claims_official"}) | {"bio_link_lookalike", "account_lt_90d"}


def ownership_evidence(codes: set[str], strong_only: bool = False) -> bool:
    """The brand probably owns it (defensive registration) and nothing on it looks abusive. A redirect to the
    official site alone is weaker (it can be cloaking), so scans only drop leads with registration/DNS evidence."""
    owned = bool(codes & STRONG_OWNERSHIP) or (not strong_only and "redirects_to_official" in codes)
    return owned and not codes & ABUSE


@dataclass
class Assessment:
    score: int
    raw: int
    capped: bool
    note: str | None
    categories: dict[str, int]


def assess(signals, kind: str | None = None) -> Assessment:
    """Final score from signals (SignalHit or stored Signal rows) with a per-category breakdown.

    For accounts and apps, when everything that fired is name similarity (corroborating evidence under
    CORROBORATION_MIN points; the bounded AI read and WEAK_CONTEXT do not count), the score is capped at IDENTITY_ONLY_CAP and the note says why."""
    raw = max(0, min(100, sum(s.points for s in signals)))
    cats: dict[str, int] = {}
    for s in signals:
        c = category(s.code, s.points)
        cats[c] = cats.get(c, 0) + s.points
    weak = WEAK_CONTEXT | (LEGITIMACY_WEAKENS if {s.code for s in signals} & LEGITIMACY else set())
    corroborating = sum(s.points for s in signals if s.points > 0 and s.code not in weak
                        and category(s.code) not in ("identity", "ai"))
    if kind in GATED_KINDS and cats.get("identity", 0) > 0 and corroborating < CORROBORATION_MIN             and raw > IDENTITY_ONLY_CAP:
        note = (f"Capped at {IDENTITY_ONLY_CAP} (from {raw}): the name resembles the brand, but nothing else "
                f"corroborates abuse. Name similarity alone is not evidence of impersonation.")
        return Assessment(IDENTITY_ONLY_CAP, raw, True, note, cats)
    return Assessment(raw, raw, False, None, cats)


def severity(score: int) -> str:
    return "High" if score >= 70 else "Medium" if score >= 40 else "Low"


# A store listing that was read is the main evidence; icon and developer-site checks often can't run (no brand logo,
# no website on the listing), which must not turn every app into "Insufficient data".
# A reported message is judged on its own text (at most 3 checks exist, one of them the optional AI).
MIN_CHECKS_BY_KIND = {"youtube": 1, "telegram": 1, "bluesky": 1, "social_profile": 1, "android_app": 2, "ios_app": 2,
                      "other": 1}


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
