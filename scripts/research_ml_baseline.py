"""Reproducible Brand-Impersonation Feature Extraction & Learned Classifier Pipeline.

Demonstrates feature extraction and classification across brand impersonation candidates,
comparing:
  1. Majority-class baseline
  2. Deterministic heuristic baseline (rule-based scorer)
  3. Trained scikit-learn Pipeline (StandardScaler + LogisticRegression)
using brand-separated evaluation splits to prevent train/test data leakage.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from threatdesk.lookalike import (
    CATEGORY_ADDED_TERMS,
    CATEGORY_HOMOGLYPH,
    CATEGORY_INSERTION,
    CATEGORY_SPACING,
    CATEGORY_SUBSTITUTION,
    CATEGORY_SWAP,
    find_lookalike,
)

try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


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


FEATURE_NAMES = (
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
)

# Brand-separated synthetic evaluation dataset
# All examples are explicitly labeled SYNTHETIC_RESEARCH_BENCHMARK for research auditing.
TRAIN_SET: list[ProfileRecord] = [
    # Brand: Acme Bank (Official handle: acmebank)
    ProfileRecord("Acme Bank", "acmebank", "acmebank", "Acme Bank Official", 85000, 120, True, "Official profile of Acme Bank.", 0, labeling_rationale="Official brand account"),
    ProfileRecord("Acme Bank", "acmebank", "amcebank", "Acme Bank Helpline", 42, 650, True, "24/7 customer support. DM for urgent assistance.", 1, labeling_rationale="Swap impersonator"),
    ProfileRecord("Acme Bank", "acmebank", "acme_support", "Acme Support Desk", 15, 340, True, "Official customer care team.", 1, labeling_rationale="Added term impersonator"),
    ProfileRecord("Acme Bank", "acmebank", "ac-mebank", "Acme Bank Updates", 88, 1200, True, "Exclusive rewards and cashback.", 1, labeling_rationale="Hyphen lookalike"),
    ProfileRecord("Acme Bank", "acmebank", "acmebnk", "Acme Bank Portal", 60, 400, True, "Login to your account.", 1, labeling_rationale="Deletion lookalike"),
    ProfileRecord("Acme Bank", "acmebank", "john_doe_99", "John Doe", 320, 410, True, "Photographer and coffee lover.", 0, labeling_rationale="Unrelated personal user"),
    ProfileRecord("Acme Bank", "acmebank", "acme_cafe", "Acme Cafe & Bakery", 1200, 800, True, "Artisan bakery downtown.", 0, labeling_rationale="Unrelated local business"),
    ProfileRecord("Acme Bank", "acmebank", "acme_bank_fanclub", "Acme Bank Community", 450, 200, True, "Community discussions.", 0, labeling_rationale="Benign community fan page"),

    # Brand: Apex Crypto (Official handle: apexcrypto)
    ProfileRecord("Apex Crypto", "apexcrypto", "apexcrypto", "Apex Crypto Exchange", 250000, 45, True, "Leading crypto asset exchange.", 0, labeling_rationale="Official brand account"),
    ProfileRecord("Apex Crypto", "apexcrypto", "apex_crypto_help", "Apex Support Team", 110, 2400, True, "Recover locked wallets and reset 2FA.", 1, labeling_rationale="Added term impersonator"),
    ProfileRecord("Apex Crypto", "apexcrypto", "apexcrypt0", "Apex Rewards", 65, 890, True, "Claim your 100 USDT airdrop bonus.", 1, labeling_rationale="Homoglyph impersonator"),
    ProfileRecord("Apex Crypto", "apexcrypto", "apexx_crypto", "Apex Crypto Verify", 90, 750, True, "Verify account credentials.", 1, labeling_rationale="Insertion lookalike"),
    ProfileRecord("Apex Crypto", "apexcrypto", "apex_mechanics", "Apex Auto Repairs", 950, 400, True, "Car repair and maintenance.", 0, labeling_rationale="Unrelated auto repair business"),
    ProfileRecord("Apex Crypto", "apexcrypto", "crypto_dan_apex", "Dan | Crypto Enthusiast", 180, 310, True, "Just a crypto hobbyist.", 0, labeling_rationale="Small personal enthusiast"),
    ProfileRecord("Apex Crypto", "apexcrypto", "apex_daily_news", "Daily Fintech News", 35000, 150, True, "Curating crypto market news.", 0, labeling_rationale="Established news curator"),
]

TEST_SET: list[ProfileRecord] = [
    # Brand: Metro Bank (Official handle: metrobank) - Zero overlap with Acme Bank or Apex Crypto
    ProfileRecord("Metro Bank", "metrobank", "metrobank", "Metro Bank Official", 120000, 95, True, "Official profile of Metro Bank.", 0, labeling_rationale="Official brand account"),
    ProfileRecord("Metro Bank", "metrobank", "metrobamk", "Metro Bank Support", 34, 820, True, "Customer assistance portal.", 1, labeling_rationale="Swap impersonator"),
    ProfileRecord("Metro Bank", "metrobank", "metro_bank_care", "Metro Care Team", 55, 1400, True, "Account verification and KYC updates.", 1, labeling_rationale="Added term impersonator"),
    ProfileRecord("Metro Bank", "metrobank", "metro-bank", "Metro Banking App", 92, 1100, True, "Download our new mobile banking app.", 1, labeling_rationale="Hyphen lookalike"),
    ProfileRecord("Metro Bank", "metrobank", "metrro_bank", "Metro Bank Verification", 45, 900, True, "Security verification desk.", 1, labeling_rationale="Insertion lookalike"),
    ProfileRecord("Metro Bank", "metrobank", "metro_diner", "Metro City Diner", 2100, 450, True, "Best burgers in town.", 0, labeling_rationale="Unrelated diner business"),
    ProfileRecord("Metro Bank", "metrobank", "metro_transit_updates", "City Metro Transit", 15000, 200, True, "Public transit schedule.", 0, labeling_rationale="Unrelated public service"),
    ProfileRecord("Metro Bank", "metrobank", "alex_tech", "Alex Rivera", 780, 520, True, "Software engineer.", 0, labeling_rationale="Unrelated personal account"),
    ProfileRecord("Metro Bank", "metrobank", "metro_bank_feedbacks", "Metro Bank User Reviews", 310, 150, True, "Unofficial community feedback.", 0, labeling_rationale="Benign feedback community"),
]


def extract_features(rec: ProfileRecord) -> dict[str, float]:
    """Extract target-relative brand impersonation features."""
    if not (rec.candidate_handle or "").strip():
        return {k: 0.0 for k in ("is_exact_official",) + FEATURE_NAMES}

    is_exact_official = 1.0 if rec.candidate_handle.lower() == rec.official_handle.lower() else 0.0
    brand_keywords = [rec.brand_name, rec.brand_name.split()[0].lower(), rec.brand_name.replace(" ", "").lower()]
    m = find_lookalike(rec.candidate_handle, targets=brand_keywords, official_targets=[rec.official_handle])
    is_swap = 1.0 if m and m.category in (CATEGORY_SWAP, CATEGORY_INSERTION) else 0.0
    is_spacing = 1.0 if m and m.category == CATEGORY_SPACING else 0.0
    is_added_term = 1.0 if m and m.category == CATEGORY_ADDED_TERMS else 0.0
    is_homoglyph = 1.0 if m and m.category in (CATEGORY_HOMOGLYPH, CATEGORY_SUBSTITUTION) else 0.0

    m_name = find_lookalike(rec.candidate_name, targets=brand_keywords, official_targets=[rec.brand_name])
    is_name_similar = 1.0 if (m_name is not None or rec.brand_name.lower() in rec.candidate_name.lower()) else 0.0

    digits = sum(c.isdigit() for c in rec.candidate_handle)
    digit_ratio = digits / max(1, len(rec.candidate_handle))
    log_followers = math.log10(rec.followers + 1)
    following_ratio = rec.following / max(1, rec.followers)
    low_followers = 1.0 if rec.followers < 200 else 0.0

    phish_terms = ("support", "help", "care", "assistance", "kyc", "airdrop", "bonus", "wallet", "recover", "claim", "2fa")
    bio_phishing = 1.0 if any(w in rec.bio_text.lower() for w in phish_terms) else 0.0

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
    }


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
    score += min(10.0, features.get("digit_ratio", 0.0) * 20.0)
    if features.get("log_followers", 0.0) > 4.0:
        score -= 30.0

    risk_score = max(0.0, min(100.0, score))
    return (1 if risk_score >= 40.0 else 0), risk_score


def predict_impersonation(features: dict[str, float]) -> tuple[int, float]:
    """Backward compatibility alias pointing to deterministic heuristic."""
    return predict_impersonation_heuristic(features)


def train_classifier_pipeline(train_data: list[ProfileRecord]) -> Any | None:
    """Train a scikit-learn Pipeline (StandardScaler + LogisticRegression)."""
    if not SKLEARN_AVAILABLE:
        return None

    X = [[extract_features(r)[k] for k in FEATURE_NAMES] for r in train_data]
    y = [r.ground_truth_label for r in train_data]

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(random_state=42, max_iter=1000)),
    ])
    pipeline.fit(X, y)
    return pipeline


def predict_trained_model(pipeline: Any | None, features: dict[str, float]) -> tuple[int, float]:
    """Predict risk using trained Pipeline with non-negotiable official-asset gate."""
    # Deterministic exclusion gate: Official assets NEVER flagged (0% risk)
    if features.get("is_exact_official", 0.0) > 0:
        return 0, 0.0

    if pipeline is None:
        return predict_impersonation_heuristic(features)

    x_vec = [[features.get(k, 0.0) for k in FEATURE_NAMES]]
    pred = int(pipeline.predict(x_vec)[0])
    prob = float(pipeline.predict_proba(x_vec)[0][1]) * 100.0
    return pred, round(prob, 2)


def evaluate_predictions(y_true: list[int], y_pred: list[int], name: str) -> dict[str, float]:
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


def compare_all_models(train_data: list[ProfileRecord], test_data: list[ProfileRecord]) -> None:
    print("=================== BRAND-DISJOINT MODEL COMPARISON ===================")
    print(f"Train partition: {len(train_data)} samples | Test partition: {len(test_data)} samples")
    y_train = [r.ground_truth_label for r in train_data]
    y_test = [r.ground_truth_label for r in test_data]

    # Model 1: Majority-Class Baseline
    majority_class = 1 if sum(y_train) > (len(y_train) / 2) else 0
    evaluate_predictions(y_test, [majority_class] * len(y_test), "1. Majority-Class Baseline (Test)")

    # Model 2: Deterministic Heuristic Baseline
    heur_preds = [predict_impersonation_heuristic(extract_features(r))[0] for r in test_data]
    evaluate_predictions(y_test, heur_preds, "2. Deterministic Heuristic Baseline (Test)")

    # Model 3: Learned Pipeline (StandardScaler + LogisticRegression)
    pipeline = train_classifier_pipeline(train_data)
    if pipeline is not None:
        learned_preds = [predict_trained_model(pipeline, extract_features(r))[0] for r in test_data]
        evaluate_predictions(y_test, learned_preds, "3. Learned Pipeline (LogisticRegression) (Test)")
        clf = pipeline.named_steps["clf"]
        print("\nLearned Model Coefficients:")
        for feat, coef in zip(FEATURE_NAMES, clf.coef_[0]):
            print(f"  {feat:20s}: {coef:+.4f}")
        print(f"  {'intercept':20s}: {clf.intercept_[0]:+.4f}")


if __name__ == "__main__":
    compare_all_models(TRAIN_SET, TEST_SET)
