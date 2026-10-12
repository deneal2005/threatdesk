"""Reproducible Brand-Impersonation Feature Extraction & Multi-Model Classifier Pipeline.

Demonstrates feature extraction and classification across brand impersonation candidates,
comparing:
  1. Majority-class baseline
  2. Deterministic heuristic baseline (rule-based scorer)
  3. Logistic Regression Pipeline
  4. Random Forest
  5. Gradient Boosted Trees
  6. Support Vector Machine (calibrated)
  7. K-Nearest Neighbours
  8. Soft Voting Ensemble (best models combined)
using brand-separated evaluation splits to prevent train/test data leakage.

Safety invariant:
  Official brand assets are ALWAYS excluded via a deterministic pre-inference gate.
  This gate cannot be overridden by any model.
"""
from __future__ import annotations

import math
import os
import pickle
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from threatdesk.lookalike import (
    CATEGORY_ADDED_TERMS,
    CATEGORY_HOMOGLYPH,
    CATEGORY_INSERTION,
    CATEGORY_SPACING,
    CATEGORY_SUBSTITUTION,
    CATEGORY_SWAP,
    CATEGORY_DELETION,
    CATEGORY_SIMILARITY,
    find_lookalike,
)

try:
    import numpy as np
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.ensemble import (
        GradientBoostingClassifier,
        RandomForestClassifier,
        VotingClassifier,
    )
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
    )
    from sklearn.model_selection import GridSearchCV, GroupKFold, cross_val_score
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import SVC

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# ---------------------------------------------------------------------------
# Data schema
# ---------------------------------------------------------------------------


@dataclass
class ProfileRecord:
    brand_name: str
    official_handle: str
    candidate_handle: str
    candidate_name: str
    followers: int
    following: int
    has_bio: bool
    bio_text: str
    ground_truth_label: int  # 1 = Impersonation, 0 = Legitimate / Benign
    provenance: str = "SYNTHETIC_RESEARCH_BENCHMARK"
    labeling_rationale: str = ""


# ---------------------------------------------------------------------------
# Feature engineering — 18 target-relative features
# ---------------------------------------------------------------------------

FEATURE_NAMES = (
    # --- Original 10 features ---
    "is_swap",
    "is_spacing",
    "is_added_term",
    "is_homoglyph",
    "is_name_similar",
    "low_followers",
    "digit_ratio",
    "log_followers",
    "following_ratio",
    "bio_phishing",
    # --- 8 new features for deeper signal capture ---
    "handle_length_ratio",       # len(candidate_handle) / len(official_handle)
    "has_underscore_or_hyphen",  # structural separators indicate impersonation handles
    "name_edit_distance",        # Damerau-Levenshtein distance between candidate name and brand
    "handle_edit_distance",      # raw DL distance between candidate handle and official handle
    "bio_urgency",               # urgent action words (verify, immediately, suspend, freeze)
    "is_deletion",               # single character deletion from brand name
    "is_substitution",           # single character substitution
    "fuzzy_similarity",          # rapidfuzz ratio (0-1 scale) between handle and official
)

# Phishing lure terms (expanded)
_PHISH_TERMS = frozenset({
    "support", "help", "care", "assistance", "kyc", "airdrop", "bonus",
    "wallet", "recover", "claim", "2fa", "verify", "verification",
    "secure", "security", "update", "login", "password", "reset",
    "official", "customer", "service", "desk", "team", "portal",
    "reward", "prize", "giveaway", "cashback", "refund",
})

# Urgency terms (separate signal from general phishing terms)
_URGENCY_TERMS = frozenset({
    "urgent", "immediately", "suspend", "freeze", "blocked", "locked",
    "expir", "within 24", "action required", "verify now", "confirm now",
    "limited time", "act now", "warning", "alert", "restricted",
})


def extract_features(rec: ProfileRecord) -> dict[str, float]:
    """Extract 18 target-relative brand impersonation features."""
    if not (rec.candidate_handle or "").strip():
        return {k: 0.0 for k in ("is_exact_official",) + FEATURE_NAMES}

    # --- Official asset gate ---
    is_exact_official = 1.0 if rec.candidate_handle.lower() == rec.official_handle.lower() else 0.0

    # --- Lookalike detection via the production module ---
    brand_keywords = [
        rec.brand_name,
        rec.brand_name.split()[0].lower(),
        rec.brand_name.replace(" ", "").lower(),
    ]
    m = find_lookalike(
        rec.candidate_handle,
        targets=brand_keywords,
        official_targets=[rec.official_handle],
    )

    # Categorical lookalike flags
    is_swap = 1.0 if m and m.category in (CATEGORY_SWAP, CATEGORY_INSERTION) else 0.0
    is_spacing = 1.0 if m and m.category == CATEGORY_SPACING else 0.0
    is_added_term = 1.0 if m and m.category == CATEGORY_ADDED_TERMS else 0.0
    is_homoglyph = 1.0 if m and m.category in (CATEGORY_HOMOGLYPH, CATEGORY_SUBSTITUTION) else 0.0
    is_deletion = 1.0 if m and m.category == CATEGORY_DELETION else 0.0
    is_substitution = 1.0 if m and m.category == CATEGORY_SUBSTITUTION else 0.0

    # --- Display name similarity ---
    m_name = find_lookalike(
        rec.candidate_name,
        targets=brand_keywords,
        official_targets=[rec.brand_name],
    )
    is_name_similar = 1.0 if (m_name is not None or rec.brand_name.lower() in rec.candidate_name.lower()) else 0.0

    # --- Audience and behaviour features ---
    digits = sum(c.isdigit() for c in rec.candidate_handle)
    digit_ratio = digits / max(1, len(rec.candidate_handle))
    log_followers = math.log10(rec.followers + 1)
    following_ratio = rec.following / max(1, rec.followers)
    low_followers = 1.0 if rec.followers < 200 else 0.0

    # --- Bio content analysis ---
    bio_lower = rec.bio_text.lower()
    bio_phishing = 1.0 if any(w in bio_lower for w in _PHISH_TERMS) else 0.0
    bio_urgency = 1.0 if any(w in bio_lower for w in _URGENCY_TERMS) else 0.0

    # --- Structural features ---
    handle_length_ratio = len(rec.candidate_handle) / max(1, len(rec.official_handle))
    has_underscore_or_hyphen = 1.0 if bool(re.search(r"[-_]", rec.candidate_handle)) else 0.0

    # Edit distances
    try:
        from rapidfuzz.distance import DamerauLevenshtein
        from rapidfuzz import fuzz
        brand_norm = re.sub(r"[^a-z0-9]", "", rec.brand_name.lower())
        cand_name_norm = re.sub(r"[^a-z0-9]", "", rec.candidate_name.lower())
        cand_handle_norm = re.sub(r"[^a-z0-9]", "", rec.candidate_handle.lower())
        official_norm = re.sub(r"[^a-z0-9]", "", rec.official_handle.lower())

        name_edit_distance = float(DamerauLevenshtein.distance(cand_name_norm, brand_norm))
        handle_edit_distance = float(DamerauLevenshtein.distance(cand_handle_norm, official_norm))
        fuzzy_similarity = fuzz.ratio(cand_handle_norm, official_norm) / 100.0
    except ImportError:
        name_edit_distance = 0.0
        handle_edit_distance = 0.0
        fuzzy_similarity = 0.0

    return {
        "is_exact_official": is_exact_official,
        "is_swap": is_swap,
        "is_spacing": is_spacing,
        "is_added_term": is_added_term,
        "is_homoglyph": is_homoglyph,
        "is_name_similar": is_name_similar,
        "low_followers": low_followers,
        "digit_ratio": digit_ratio,
        "log_followers": log_followers,
        "following_ratio": following_ratio,
        "bio_phishing": bio_phishing,
        "handle_length_ratio": handle_length_ratio,
        "has_underscore_or_hyphen": has_underscore_or_hyphen,
        "name_edit_distance": name_edit_distance,
        "handle_edit_distance": handle_edit_distance,
        "bio_urgency": bio_urgency,
        "is_deletion": is_deletion,
        "is_substitution": is_substitution,
        "fuzzy_similarity": fuzzy_similarity,
    }


# ---------------------------------------------------------------------------
# Brand-separated synthetic evaluation dataset — 90 samples across 8 brands
#
# Train brands: Acme Bank, Apex Crypto, Nova Insurance, Stellar Pay, Zenith Health (57 samples)
# Test brands:  Metro Bank, Omega Finance, Bright Energy (33 samples)
# ---------------------------------------------------------------------------

TRAIN_SET: list[ProfileRecord] = [
    # =========================================================================
    # Brand: Acme Bank (Official handle: acmebank)
    # =========================================================================
    ProfileRecord("Acme Bank", "acmebank", "acmebank", "Acme Bank Official", 85000, 120, True,
                  "Official profile of Acme Bank.", 0,
                  labeling_rationale="Official brand account"),
    ProfileRecord("Acme Bank", "acmebank", "amcebank", "Acme Bank Helpline", 42, 650, True,
                  "24/7 customer support. DM for urgent assistance.", 1,
                  labeling_rationale="Adjacent swap: amce→acme"),
    ProfileRecord("Acme Bank", "acmebank", "acme_support", "Acme Support Desk", 15, 340, True,
                  "Official customer care team.", 1,
                  labeling_rationale="Added term: support"),
    ProfileRecord("Acme Bank", "acmebank", "ac-mebank", "Acme Bank Updates", 88, 1200, True,
                  "Exclusive rewards and cashback.", 1,
                  labeling_rationale="Hyphen spacing variation"),
    ProfileRecord("Acme Bank", "acmebank", "acmebnk", "Acme Bank Portal", 60, 400, True,
                  "Login to your account.", 1,
                  labeling_rationale="Deletion: acmebnk→acmebank"),
    ProfileRecord("Acme Bank", "acmebank", "acmebamk", "Acme Bank Verify", 28, 780, True,
                  "Verify your KYC immediately to avoid account freeze.", 1,
                  labeling_rationale="Swap + urgency lure"),
    ProfileRecord("Acme Bank", "acmebank", "acme_bank_official", "Acme Bank Official Page", 75, 500, True,
                  "The real Acme Bank page. DM for support.", 1,
                  labeling_rationale="Added term: official (fake claim)"),
    ProfileRecord("Acme Bank", "acmebank", "acmebank_help", "Acme Helpdesk", 19, 890, True,
                  "Reset your password. Contact us urgently.", 1,
                  labeling_rationale="Added term: help"),
    ProfileRecord("Acme Bank", "acmebank", "john_doe_99", "John Doe", 320, 410, True,
                  "Photographer and coffee lover.", 0,
                  labeling_rationale="Unrelated personal user"),
    ProfileRecord("Acme Bank", "acmebank", "acme_cafe", "Acme Cafe & Bakery", 1200, 800, True,
                  "Artisan bakery downtown.", 0,
                  labeling_rationale="Unrelated local business sharing dictionary word"),
    ProfileRecord("Acme Bank", "acmebank", "acme_bank_fanclub", "Acme Bank Community", 450, 200, True,
                  "Community discussions about Acme Bank products.", 0,
                  labeling_rationale="Benign community fan page"),
    ProfileRecord("Acme Bank", "acmebank", "the_banking_guy", "Banking Tips Daily", 3400, 500, True,
                  "Personal finance tips for everyone.", 0,
                  labeling_rationale="Unrelated finance influencer"),
    ProfileRecord("Acme Bank", "acmebank", "acme_tools_shop", "Acme Tools", 5600, 300, True,
                  "Professional power tools and equipment.", 0,
                  labeling_rationale="Unrelated business sharing Acme brand name"),

    # =========================================================================
    # Brand: Apex Crypto (Official handle: apexcrypto)
    # =========================================================================
    ProfileRecord("Apex Crypto", "apexcrypto", "apexcrypto", "Apex Crypto Exchange", 250000, 45, True,
                  "Leading crypto asset exchange.", 0,
                  labeling_rationale="Official brand account"),
    ProfileRecord("Apex Crypto", "apexcrypto", "apex_crypto_help", "Apex Support Team", 110, 2400, True,
                  "Recover locked wallets and reset 2FA.", 1,
                  labeling_rationale="Added term: help"),
    ProfileRecord("Apex Crypto", "apexcrypto", "apexcrypt0", "Apex Rewards", 65, 890, True,
                  "Claim your 100 USDT airdrop bonus.", 1,
                  labeling_rationale="Homoglyph: o→0"),
    ProfileRecord("Apex Crypto", "apexcrypto", "apexx_crypto", "Apex Crypto Verify", 90, 750, True,
                  "Verify account credentials immediately.", 1,
                  labeling_rationale="Insertion: apexx→apex"),
    ProfileRecord("Apex Crypto", "apexcrypto", "apexcrypt", "Apex Exchange", 35, 1100, True,
                  "Your account will be suspended. Verify now.", 1,
                  labeling_rationale="Deletion: apexcrypt→apexcrypto"),
    ProfileRecord("Apex Crypto", "apexcrypto", "apex_crypto_official", "Apex Official Desk", 44, 920, True,
                  "Exclusive airdrop. Act now, limited time.", 1,
                  labeling_rationale="Added term: official, urgency lure"),
    ProfileRecord("Apex Crypto", "apexcrypto", "apexcrypto_team", "Apex Team Support", 58, 640, True,
                  "DM us for wallet recovery assistance.", 1,
                  labeling_rationale="Added term: team"),
    ProfileRecord("Apex Crypto", "apexcrypto", "apex_mechanics", "Apex Auto Repairs", 950, 400, True,
                  "Car repair and maintenance.", 0,
                  labeling_rationale="Unrelated auto repair business"),
    ProfileRecord("Apex Crypto", "apexcrypto", "crypto_dan_apex", "Dan | Crypto Enthusiast", 180, 310, True,
                  "Just a crypto hobbyist sharing ideas.", 0,
                  labeling_rationale="Small personal enthusiast"),
    ProfileRecord("Apex Crypto", "apexcrypto", "apex_daily_news", "Daily Fintech News", 35000, 150, True,
                  "Curating crypto market news.", 0,
                  labeling_rationale="Established news curator"),
    ProfileRecord("Apex Crypto", "apexcrypto", "crypto_market_hub", "Crypto Market Hub", 28000, 600, True,
                  "Independent crypto market analysis.", 0,
                  labeling_rationale="Unrelated crypto news aggregator"),

    # =========================================================================
    # Brand: Nova Insurance (Official handle: novainsurance)
    # =========================================================================
    ProfileRecord("Nova Insurance", "novainsurance", "novainsurance", "Nova Insurance Group", 62000, 200, True,
                  "Protecting what matters. Official Nova Insurance.", 0,
                  labeling_rationale="Official brand account"),
    ProfileRecord("Nova Insurance", "novainsurance", "novainsuranc3", "Nova Insurance Claims", 22, 560, True,
                  "File your claim here. DM with policy number.", 1,
                  labeling_rationale="Homoglyph: e→3"),
    ProfileRecord("Nova Insurance", "novainsurance", "nova_insurance_care", "Nova Care Team", 38, 870, True,
                  "Immediate assistance for policy holders.", 1,
                  labeling_rationale="Added term: care"),
    ProfileRecord("Nova Insurance", "novainsurance", "novainsruance", "Nova Insurance Help", 16, 430, True,
                  "Need help with your insurance? DM us.", 1,
                  labeling_rationale="Adjacent swap: insruance→insurance"),
    ProfileRecord("Nova Insurance", "novainsurance", "nova_insurance_verify", "Nova Verification Desk", 11, 720, True,
                  "Verify your identity to process your refund.", 1,
                  labeling_rationale="Added term: verify + refund lure"),
    ProfileRecord("Nova Insurance", "novainsurance", "n0vainsurance", "Nova Insurance Portal", 29, 310, True,
                  "Login to manage your policy. Update details now.", 1,
                  labeling_rationale="Homoglyph: o→0"),
    ProfileRecord("Nova Insurance", "novainsurance", "novainsurance_service", "Nova Service Center", 48, 1100, True,
                  "Customer service. Reset password here.", 1,
                  labeling_rationale="Added term: service"),
    ProfileRecord("Nova Insurance", "novainsurance", "nova_stargazers", "Nova Astronomy Club", 4200, 300, True,
                  "Amateur astronomy nights and telescope reviews.", 0,
                  labeling_rationale="Unrelated astronomy club sharing 'Nova'"),
    ProfileRecord("Nova Insurance", "novainsurance", "nova_cars_ltd", "Nova Cars Dealership", 7800, 250, True,
                  "New and pre-owned vehicles. Test drive today.", 0,
                  labeling_rationale="Unrelated auto dealership sharing 'Nova'"),
    ProfileRecord("Nova Insurance", "novainsurance", "insurance_tips_daily", "Insurance Tips", 12000, 400, True,
                  "Compare quotes and save on premiums.", 0,
                  labeling_rationale="Generic insurance advice, not brand specific"),
    ProfileRecord("Nova Insurance", "novainsurance", "nova_insurance_reviews", "Nova User Reviews", 580, 180, True,
                  "Unofficial community reviews of Nova products.", 0,
                  labeling_rationale="Benign community review forum"),

    # =========================================================================
    # Brand: Stellar Pay (Official handle: stellarpay)
    # =========================================================================
    ProfileRecord("Stellar Pay", "stellarpay", "stellarpay", "Stellar Pay Official", 145000, 80, True,
                  "Send and receive money instantly. Official Stellar Pay.", 0,
                  labeling_rationale="Official brand account"),
    ProfileRecord("Stellar Pay", "stellarpay", "stel1arpay", "Stellar Pay Support", 32, 670, True,
                  "Account locked? DM us for immediate help.", 1,
                  labeling_rationale="Homoglyph: l→1"),
    ProfileRecord("Stellar Pay", "stellarpay", "stellar_pay_help", "Stellar Help Desk", 45, 920, True,
                  "Reset 2FA. Recover your wallet immediately.", 1,
                  labeling_rationale="Added term: help"),
    ProfileRecord("Stellar Pay", "stellarpay", "stellarpya", "Stellar Pay Portal", 18, 540, True,
                  "Exclusive cashback rewards. Claim now.", 1,
                  labeling_rationale="Adjacent swap: pya→pay"),
    ProfileRecord("Stellar Pay", "stellarpay", "stellarpa", "Stellar Payments", 27, 810, True,
                  "Your transaction is pending. Verify identity now.", 1,
                  labeling_rationale="Deletion: stellarpa→stellarpay"),
    ProfileRecord("Stellar Pay", "stellarpay", "stellar_pay_official", "Stellar Official Account", 61, 430, True,
                  "Prize giveaway! Send 0.1 ETH to receive 1 ETH.", 1,
                  labeling_rationale="Added term: official + giveaway scam"),
    ProfileRecord("Stellar Pay", "stellarpay", "stellarpay_verify", "Stellar Verification", 39, 780, True,
                  "Your account will be frozen within 24 hours. Verify now.", 1,
                  labeling_rationale="Added term: verify + frozen urgency"),
    ProfileRecord("Stellar Pay", "stellarpay", "stellar_photography", "Stellar Photo Studio", 8900, 350, True,
                  "Professional photography and video production.", 0,
                  labeling_rationale="Unrelated photo studio sharing 'Stellar'"),
    ProfileRecord("Stellar Pay", "stellarpay", "stellarspace_edu", "Stellar Space Education", 22000, 180, True,
                  "Space science education for kids.", 0,
                  labeling_rationale="Unrelated educational initiative"),
    ProfileRecord("Stellar Pay", "stellarpay", "paytech_reviews", "PayTech Reviews", 6500, 420, True,
                  "Independent payment technology comparisons.", 0,
                  labeling_rationale="Unrelated fintech review site"),
    ProfileRecord("Stellar Pay", "stellarpay", "stellar_pay_users", "Stellar Pay Community", 720, 160, True,
                  "Unofficial user community for Stellar Pay discussions.", 0,
                  labeling_rationale="Benign user community"),

    # =========================================================================
    # Brand: Zenith Health (Official handle: zenithhealth)
    # =========================================================================
    ProfileRecord("Zenith Health", "zenithhealth", "zenithhealth", "Zenith Health Official", 95000, 150, True,
                  "Your health, our mission. Official Zenith Health.", 0,
                  labeling_rationale="Official brand account"),
    ProfileRecord("Zenith Health", "zenithhealth", "zenithh3alth", "Zenith Health Portal", 19, 580, True,
                  "Verify insurance eligibility. Login now.", 1,
                  labeling_rationale="Homoglyph: e→3"),
    ProfileRecord("Zenith Health", "zenithhealth", "zenith_health_support", "Zenith Support", 33, 760, True,
                  "Need help with your prescription? DM us.", 1,
                  labeling_rationale="Added term: support"),
    ProfileRecord("Zenith Health", "zenithhealth", "zenihtHealth", "Zenith Health Help", 14, 420, True,
                  "Claim your free health check. Limited spots.", 1,
                  labeling_rationale="Adjacent swap: zeniht→zenith"),
    ProfileRecord("Zenith Health", "zenithhealth", "zenith_health_care", "Zenith Care Desk", 41, 930, True,
                  "Account suspended. Verify identity immediately.", 1,
                  labeling_rationale="Added term: care + urgency lure"),
    ProfileRecord("Zenith Health", "zenithhealth", "zenithhealt", "Zenith Health Services", 26, 670, True,
                  "Update your health profile to continue.", 1,
                  labeling_rationale="Deletion: zenithhealt→zenithhealth"),
    ProfileRecord("Zenith Health", "zenithhealth", "zenithhealth_verify", "Zenith Verification", 50, 440, True,
                  "Action required: confirm your prescription refill.", 1,
                  labeling_rationale="Added term: verify + action required"),
    ProfileRecord("Zenith Health", "zenithhealth", "zenith_fitness_club", "Zenith Fitness", 11000, 280, True,
                  "Gym memberships and personal training.", 0,
                  labeling_rationale="Unrelated fitness brand sharing 'Zenith'"),
    ProfileRecord("Zenith Health", "zenithhealth", "health_tips_daily", "Daily Health Tips", 45000, 500, True,
                  "Nutrition, exercise, and wellness tips.", 0,
                  labeling_rationale="Unrelated generic health content"),
    ProfileRecord("Zenith Health", "zenithhealth", "dr_zenith_talks", "Dr. Zenith | Health Talks", 3200, 220, True,
                  "Medical professional sharing health insights.", 0,
                  labeling_rationale="Personal medical professional"),
    ProfileRecord("Zenith Health", "zenithhealth", "zenith_health_community", "Zenith Health Users", 650, 190, True,
                  "Patient community discussions.", 0,
                  labeling_rationale="Benign patient community forum"),
]

TEST_SET: list[ProfileRecord] = [
    # =========================================================================
    # Brand: Metro Bank (Official handle: metrobank) — Zero overlap with train
    # =========================================================================
    ProfileRecord("Metro Bank", "metrobank", "metrobank", "Metro Bank Official", 120000, 95, True,
                  "Official profile of Metro Bank.", 0,
                  labeling_rationale="Official brand account"),
    ProfileRecord("Metro Bank", "metrobank", "metrobamk", "Metro Bank Support", 34, 820, True,
                  "Customer assistance portal.", 1,
                  labeling_rationale="Adjacent swap: bamk→bank"),
    ProfileRecord("Metro Bank", "metrobank", "metro_bank_care", "Metro Care Team", 55, 1400, True,
                  "Account verification and KYC updates.", 1,
                  labeling_rationale="Added term: care"),
    ProfileRecord("Metro Bank", "metrobank", "metro-bank", "Metro Banking App", 92, 1100, True,
                  "Download our new mobile banking app.", 1,
                  labeling_rationale="Hyphen spacing variation"),
    ProfileRecord("Metro Bank", "metrobank", "metrro_bank", "Metro Bank Verification", 45, 900, True,
                  "Security verification desk.", 1,
                  labeling_rationale="Insertion: metrro→metro"),
    ProfileRecord("Metro Bank", "metrobank", "metr0bank", "Metro Bank Login", 20, 640, True,
                  "Login to your account. Verify now to avoid suspension.", 1,
                  labeling_rationale="Homoglyph: o→0 + urgency"),
    ProfileRecord("Metro Bank", "metrobank", "metrobank_official", "Metro Official Page", 38, 510, True,
                  "Exclusive cashback reward. Claim before it expires.", 1,
                  labeling_rationale="Added term: official + reward scam"),
    ProfileRecord("Metro Bank", "metrobank", "metrobank_team", "Metro Bank Team", 66, 730, True,
                  "Customer service desk. Password reset here.", 1,
                  labeling_rationale="Added term: team"),
    ProfileRecord("Metro Bank", "metrobank", "metro_diner", "Metro City Diner", 2100, 450, True,
                  "Best burgers in town.", 0,
                  labeling_rationale="Unrelated diner business"),
    ProfileRecord("Metro Bank", "metrobank", "metro_transit_updates", "City Metro Transit", 15000, 200, True,
                  "Public transit schedule.", 0,
                  labeling_rationale="Unrelated public service"),
    ProfileRecord("Metro Bank", "metrobank", "alex_tech", "Alex Rivera", 780, 520, True,
                  "Software engineer.", 0,
                  labeling_rationale="Unrelated personal account"),
    ProfileRecord("Metro Bank", "metrobank", "metro_bank_feedbacks", "Metro Bank User Reviews", 310, 150, True,
                  "Unofficial community feedback.", 0,
                  labeling_rationale="Benign feedback community"),
    ProfileRecord("Metro Bank", "metrobank", "metro_style_boutique", "Metro Style Boutique", 4300, 350, True,
                  "Fashion and accessories store.", 0,
                  labeling_rationale="Unrelated fashion store"),

    # =========================================================================
    # Brand: Omega Finance (Official handle: omegafinance) — Zero overlap
    # =========================================================================
    ProfileRecord("Omega Finance", "omegafinance", "omegafinance", "Omega Finance Official", 78000, 130, True,
                  "Trusted financial solutions. Official Omega Finance.", 0,
                  labeling_rationale="Official brand account"),
    ProfileRecord("Omega Finance", "omegafinance", "0megafinance", "Omega Finance Portal", 25, 590, True,
                  "Reset your password. Contact support.", 1,
                  labeling_rationale="Homoglyph: O→0"),
    ProfileRecord("Omega Finance", "omegafinance", "omega_finance_help", "Omega Help Center", 41, 870, True,
                  "Locked out? DM for immediate account recovery.", 1,
                  labeling_rationale="Added term: help + recovery lure"),
    ProfileRecord("Omega Finance", "omegafinance", "omegafinanec", "Omega Financial Services", 18, 710, True,
                  "Your loan is approved. Verify to receive funds.", 1,
                  labeling_rationale="Adjacent swap: anec→ance"),
    ProfileRecord("Omega Finance", "omegafinance", "omegafinance_verify", "Omega Verification Team", 30, 640, True,
                  "Action required: verify your account within 24 hours.", 1,
                  labeling_rationale="Added term: verify + urgency"),
    ProfileRecord("Omega Finance", "omegafinance", "omegafinace", "Omega Finance Login", 15, 520, True,
                  "Login portal for existing customers.", 1,
                  labeling_rationale="Deletion: omegafinace→omegafinance"),
    ProfileRecord("Omega Finance", "omegafinance", "omega_watches_co", "Omega Watch Collectors", 18000, 450, True,
                  "Luxury timepieces and accessories.", 0,
                  labeling_rationale="Unrelated watch brand sharing 'Omega'"),
    ProfileRecord("Omega Finance", "omegafinance", "finance_daily_tips", "Finance Daily", 25000, 300, True,
                  "Stock market updates and financial literacy.", 0,
                  labeling_rationale="Unrelated general finance content"),
    ProfileRecord("Omega Finance", "omegafinance", "omega_gym_fit", "Omega Gym & Fitness", 5600, 280, True,
                  "Gym memberships and fitness classes.", 0,
                  labeling_rationale="Unrelated gym business"),
    ProfileRecord("Omega Finance", "omegafinance", "omega_finance_community", "Omega Users Forum", 430, 170, True,
                  "Unofficial customer discussion board.", 0,
                  labeling_rationale="Benign community forum"),

    # =========================================================================
    # Brand: Bright Energy (Official handle: brightenergy) — Zero overlap
    # =========================================================================
    ProfileRecord("Bright Energy", "brightenergy", "brightenergy", "Bright Energy Official", 55000, 100, True,
                  "Clean energy for a brighter future. Official account.", 0,
                  labeling_rationale="Official brand account"),
    ProfileRecord("Bright Energy", "brightenergy", "bright_energy_support", "Bright Support Team", 27, 680, True,
                  "Bill payment issues? DM us immediately.", 1,
                  labeling_rationale="Added term: support + urgency"),
    ProfileRecord("Bright Energy", "brightenergy", "brightenregy", "Bright Energy Portal", 14, 520, True,
                  "Pay your bill online. Login now.", 1,
                  labeling_rationale="Adjacent swap: regy→ergy"),
    ProfileRecord("Bright Energy", "brightenergy", "br1ghtenergy", "Bright Energy Verify", 21, 610, True,
                  "Verify meter reading to avoid disconnection.", 1,
                  labeling_rationale="Homoglyph: i→1"),
    ProfileRecord("Bright Energy", "brightenergy", "brightenergy_official", "Bright Official Page", 44, 490, True,
                  "Exclusive solar panel rebate. Claim now.", 1,
                  labeling_rationale="Added term: official + claim scam"),
    ProfileRecord("Bright Energy", "brightenergy", "brightenerg", "Bright Energy Service", 17, 560, True,
                  "Service outage? Report here urgently.", 1,
                  labeling_rationale="Deletion: brightenerg→brightenergy"),
    ProfileRecord("Bright Energy", "brightenergy", "bright_ideas_blog", "Bright Ideas Blog", 9200, 380, True,
                  "Creative DIY projects and home improvement.", 0,
                  labeling_rationale="Unrelated DIY blog sharing 'Bright'"),
    ProfileRecord("Bright Energy", "brightenergy", "energy_saver_tips", "Energy Saver Tips", 14000, 260, True,
                  "Tips for reducing electricity bills.", 0,
                  labeling_rationale="Unrelated generic energy content"),
    ProfileRecord("Bright Energy", "brightenergy", "bright_solar_solutions", "Bright Solar Co.", 6800, 320, True,
                  "Commercial and residential solar installations.", 0,
                  labeling_rationale="Unrelated solar company sharing 'Bright'"),
    ProfileRecord("Bright Energy", "brightenergy", "bright_energy_reviews", "Bright Energy Community", 380, 140, True,
                  "Unofficial customer review discussions.", 0,
                  labeling_rationale="Benign community review forum"),
]


# ---------------------------------------------------------------------------
# Deterministic heuristic baseline (comparison reference, NOT ML)
# ---------------------------------------------------------------------------


def predict_impersonation_heuristic(features: dict[str, float]) -> tuple[int, float]:
    """Deterministic rule-based heuristic baseline (comparison baseline, NOT ML)."""
    if features.get("is_exact_official", 0.0) > 0:
        return 0, 0.0

    score = 0.0
    score += features.get("is_swap", 0.0) * 30.0
    score += features.get("is_spacing", 0.0) * 25.0
    score += features.get("is_added_term", 0.0) * 30.0
    score += features.get("is_homoglyph", 0.0) * 25.0
    score += features.get("is_name_similar", 0.0) * 20.0
    score += features.get("bio_phishing", 0.0) * 20.0
    score += features.get("low_followers", 0.0) * 10.0
    score += features.get("is_deletion", 0.0) * 25.0
    score += features.get("is_substitution", 0.0) * 25.0
    score += features.get("bio_urgency", 0.0) * 15.0
    score += min(10.0, features.get("digit_ratio", 0.0) * 20.0)
    if features.get("log_followers", 0.0) > 4.0:
        score -= 30.0

    risk_score = max(0.0, min(100.0, score))
    return (1 if risk_score >= 40.0 else 0), risk_score


def predict_impersonation(features: dict[str, float]) -> tuple[int, float]:
    """Backward compatibility alias pointing to deterministic heuristic."""
    return predict_impersonation_heuristic(features)


# ---------------------------------------------------------------------------
# Multi-model training pipeline
# ---------------------------------------------------------------------------


def _features_to_matrix(records: list[ProfileRecord]) -> list[list[float]]:
    """Convert ProfileRecords to a feature matrix using FEATURE_NAMES ordering."""
    return [[extract_features(r)[k] for k in FEATURE_NAMES] for r in records]


def _labels(records: list[ProfileRecord]) -> list[int]:
    return [r.ground_truth_label for r in records]


def _brand_groups(records: list[ProfileRecord]) -> list[str]:
    """Return brand name per record for GroupKFold splitting."""
    return [r.brand_name for r in records]


def train_classifier_pipeline(train_data: list[ProfileRecord]) -> Any | None:
    """Train a scikit-learn Pipeline (StandardScaler + LogisticRegression).

    Backward-compatible entry point. For multi-model training, use train_all_models().
    """
    if not SKLEARN_AVAILABLE:
        return None

    X = _features_to_matrix(train_data)
    y = _labels(train_data)

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(random_state=42, max_iter=1000)),
    ])
    pipeline.fit(X, y)
    return pipeline


def train_all_models(
    train_data: list[ProfileRecord],
) -> dict[str, Any]:
    """Train and cross-validate all candidate models on train_data.

    Returns a dict mapping model name → fitted model / pipeline.
    Cross-validation uses GroupKFold by brand to prevent brand leakage.
    """
    if not SKLEARN_AVAILABLE:
        return {}

    X = np.array(_features_to_matrix(train_data))
    y = np.array(_labels(train_data))
    groups = np.array(_brand_groups(train_data))

    n_unique = len(set(groups))
    n_splits = min(n_unique, 5)
    gkf = GroupKFold(n_splits=n_splits)

    models: dict[str, Pipeline] = {
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                random_state=42, max_iter=2000, C=1.0, class_weight="balanced",
            )),
        ]),
        "RandomForest": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(
                n_estimators=200, max_depth=8, min_samples_leaf=2,
                random_state=42, class_weight="balanced", n_jobs=-1,
            )),
        ]),
        "GradientBoosting": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", GradientBoostingClassifier(
                n_estimators=200, max_depth=4, learning_rate=0.1,
                min_samples_leaf=3, random_state=42, subsample=0.8,
            )),
        ]),
        "SVM": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", CalibratedClassifierCV(
                SVC(kernel="rbf", C=1.0, random_state=42, class_weight="balanced"),
            )),
        ]),
        "KNN": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", KNeighborsClassifier(
                n_neighbors=min(5, len(train_data) - 1),
                weights="distance", metric="euclidean",
            )),
        ]),
    }

    # Cross-validate each model with GroupKFold (no brand leakage)
    print("\n" + "=" * 72)
    print(f"GROUPED CROSS-VALIDATION (GroupKFold, {n_splits} splits by brand)")
    print("=" * 72)

    cv_scores: dict[str, float] = {}
    for name, pipe in models.items():
        scores = cross_val_score(pipe, X, y, cv=gkf, groups=groups, scoring="f1")
        mean_f1 = float(scores.mean())
        cv_scores[name] = mean_f1
        print(f"  {name:25s} CV F1: {mean_f1:.3f} ± {scores.std():.3f}  "
              f"(folds: {', '.join(f'{s:.2f}' for s in scores)})")

    # Fit all individual models on full training data
    fitted: dict[str, Any] = {}
    for name, pipe in models.items():
        pipe.fit(X, y)
        fitted[name] = pipe

    # Build soft voting ensemble from top-3 individual models
    top3_names = sorted(cv_scores, key=lambda k: cv_scores[k], reverse=True)[:3]
    print(f"\n  Ensemble members (top-3 CV F1): {top3_names}")

    ensemble = VotingClassifier(
        estimators=[(n, models[n]) for n in top3_names],
        voting="soft",
    )
    ensemble.fit(X, y)
    fitted["Ensemble"] = ensemble

    return fitted


def predict_trained_model(
    pipeline: Any | None, features: dict[str, float]
) -> tuple[int, float]:
    """Predict risk using trained model with non-negotiable official-asset gate."""
    # Deterministic exclusion gate: Official assets NEVER flagged (0% risk)
    if features.get("is_exact_official", 0.0) > 0:
        return 0, 0.0

    if pipeline is None:
        return predict_impersonation_heuristic(features)

    x_vec = [[features.get(k, 0.0) for k in FEATURE_NAMES]]
    if hasattr(pipeline, "predict_proba"):
        pred = int(pipeline.predict(x_vec)[0])
        prob = float(pipeline.predict_proba(x_vec)[0][1]) * 100.0
    else:
        pred = int(pipeline.predict(x_vec)[0])
        prob = 100.0 if pred == 1 else 0.0
    return pred, round(prob, 2)


# ---------------------------------------------------------------------------
# Evaluation utilities
# ---------------------------------------------------------------------------


def evaluate_predictions(
    y_true: list[int], y_pred: list[int], name: str
) -> dict[str, float]:
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    total = len(y_true)
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    acc = (tp + tn) / total if total > 0 else 0.0
    fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0

    print(f"\n--- {name} ---")
    print(f"Total: {total} | Positives: {tp + fn} | Negatives: {tn + fp}")
    print(f"Confusion Matrix: TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"Precision: {prec:.1%} | Recall: {rec:.1%} | F1: {f1:.1%} | Accuracy: {acc:.1%} | FPR: {fpr:.1%}")
    return {"precision": prec, "recall": rec, "f1": f1, "accuracy": acc, "fpr": fpr}


def evaluate_dataset(dataset: list[ProfileRecord], name: str) -> dict[str, float]:
    """Evaluate using heuristic baseline for backward compatibility."""
    y_true = [r.ground_truth_label for r in dataset]
    y_pred = [predict_impersonation_heuristic(extract_features(r))[0] for r in dataset]
    return evaluate_predictions(y_true, y_pred, f"Heuristic Baseline: {name}")


def _per_sample_diagnostics(
    records: list[ProfileRecord],
    model_name: str,
    model: Any,
) -> None:
    """Print per-sample prediction diagnostics for a model on given records."""
    print(f"\n  Per-Sample Diagnostics ({model_name}):")
    print(f"  {'Handle':<30s} {'Name':<30s} {'Truth':>5s} {'Pred':>5s} {'Prob':>7s} {'Correct':>8s}")
    print("  " + "-" * 115)
    for rec in records:
        feats = extract_features(rec)
        pred, prob = predict_trained_model(model, feats)
        correct = "✓" if pred == rec.ground_truth_label else "✗ MISS"
        print(f"  {rec.candidate_handle:<30s} {rec.candidate_name:<30s} {rec.ground_truth_label:>5d} "
              f"{pred:>5d} {prob:>6.1f}% {correct:>8s}")


def compare_all_models(
    train_data: list[ProfileRecord],
    test_data: list[ProfileRecord],
) -> dict[str, dict[str, float]]:
    """Full model comparison: majority baseline, heuristic, and all learned models."""
    print("=" * 72)
    print("BRAND-DISJOINT MULTI-MODEL COMPARISON")
    print(f"Train: {len(train_data)} samples ({len(set(r.brand_name for r in train_data))} brands)")
    print(f"Test:  {len(test_data)} samples ({len(set(r.brand_name for r in test_data))} brands)")
    print("=" * 72)

    y_test = _labels(test_data)
    results: dict[str, dict[str, float]] = {}

    # --- Baseline 1: Majority class ---
    y_train = _labels(train_data)
    majority_class = 1 if sum(y_train) > (len(y_train) / 2) else 0
    results["Majority"] = evaluate_predictions(
        y_test, [majority_class] * len(y_test), "1. Majority-Class Baseline (Test)"
    )

    # --- Baseline 2: Deterministic heuristic ---
    heur_preds = [predict_impersonation_heuristic(extract_features(r))[0] for r in test_data]
    results["Heuristic"] = evaluate_predictions(
        y_test, heur_preds, "2. Deterministic Heuristic Baseline (Test)"
    )

    # --- Learned models ---
    fitted_models = train_all_models(train_data)
    if not fitted_models:
        print("\n  sklearn not available; skipping learned models.")
        return results

    print("\n" + "=" * 72)
    print("HELD-OUT TEST SET EVALUATION")
    print("=" * 72)

    best_name, best_f1 = "", 0.0
    for idx, (name, model) in enumerate(fitted_models.items(), start=3):
        preds = [predict_trained_model(model, extract_features(r))[0] for r in test_data]
        metrics = evaluate_predictions(y_test, preds, f"{idx}. {name} (Test)")
        results[name] = metrics
        if metrics["f1"] >= best_f1:
            best_f1 = metrics["f1"]
            best_name = name

    # Per-sample diagnostics for the best model
    if best_name:
        print(f"\n{'=' * 72}")
        print(f"BEST MODEL: {best_name} (Test F1: {best_f1:.1%})")
        print(f"{'=' * 72}")
        _per_sample_diagnostics(test_data, best_name, fitted_models[best_name])

        # Feature importances / coefficients
        best_model = fitted_models[best_name]
        if hasattr(best_model, "named_steps"):
            clf = best_model.named_steps.get("clf")
            if hasattr(clf, "feature_importances_"):
                print(f"\n  Feature Importances ({best_name}):")
                importances = sorted(
                    zip(FEATURE_NAMES, clf.feature_importances_),
                    key=lambda x: x[1], reverse=True,
                )
                for feat, imp in importances:
                    bar = "█" * int(imp * 50)
                    print(f"    {feat:30s}: {imp:.4f} {bar}")
            elif hasattr(clf, "coef_"):
                print(f"\n  Learned Coefficients ({best_name}):")
                for feat, coef in sorted(
                    zip(FEATURE_NAMES, clf.coef_[0]),
                    key=lambda x: abs(x[1]), reverse=True,
                ):
                    sign = "+" if coef >= 0 else ""
                    print(f"    {feat:30s}: {sign}{coef:.4f}")
                print(f"    {'intercept':30s}: {clf.intercept_[0]:+.4f}")

    return results


def save_best_model(
    model: Any, model_name: str, output_dir: str | Path = "models",
) -> Path:
    """Serialize the best model to disk for reproducible inference."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"threatdesk_best_{model_name.lower().replace(' ', '_')}.pkl"
    with open(path, "wb") as f:
        pickle.dump({"model": model, "features": FEATURE_NAMES, "name": model_name}, f)
    print(f"\n  Model saved: {path}")
    return path


def load_model(path: str | Path) -> tuple[Any, tuple[str, ...]]:
    """Load a serialized model. Returns (model, feature_names)."""
    with open(path, "rb") as f:
        data = pickle.load(f)
    return data["model"], tuple(data["features"])


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    print("\nDataset Summary:")
    print(f"  TRAIN_SET: {len(TRAIN_SET)} samples across {len(set(r.brand_name for r in TRAIN_SET))} brands")
    print(f"  TEST_SET:  {len(TEST_SET)} samples across {len(set(r.brand_name for r in TEST_SET))} brands")

    train_brands = {r.brand_name for r in TRAIN_SET}
    test_brands = {r.brand_name for r in TEST_SET}
    print(f"  Train brands: {sorted(train_brands)}")
    print(f"  Test brands:  {sorted(test_brands)}")
    assert train_brands.isdisjoint(test_brands), "Brand leakage detected!"

    results = compare_all_models(TRAIN_SET, TEST_SET)

    # Summary table
    print(f"\n{'=' * 72}")
    print("FINAL SUMMARY")
    print(f"{'=' * 72}")
    print(f"  {'Model':<30s} {'Precision':>10s} {'Recall':>10s} {'F1':>10s} {'Accuracy':>10s} {'FPR':>10s}")
    print("  " + "-" * 80)
    for name, m in results.items():
        print(f"  {name:<30s} {m['precision']:>9.1%} {m['recall']:>9.1%} "
              f"{m['f1']:>9.1%} {m['accuracy']:>9.1%} {m['fpr']:>9.1%}")
