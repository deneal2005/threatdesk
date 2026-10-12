"""Unit tests for ML feature extraction, learned pipeline, and baseline evaluation."""
import pytest

from scripts.research_ml_baseline import (
    FEATURE_NAMES,
    ProfileRecord,
    TEST_SET,
    TRAIN_SET,
    evaluate_dataset,
    extract_features,
    predict_impersonation,
    predict_impersonation_heuristic,
    predict_trained_model,
    train_classifier_pipeline,
)


def test_feature_extraction_official_asset():
    rec = ProfileRecord(
        brand_name="Acme Bank",
        official_handle="acmebank",
        candidate_handle="acmebank",
        candidate_name="Acme Bank Official",
        followers=50000,
        following=100,
        has_bio=True,
        bio_text="Official verified profile",
        ground_truth_label=0,
    )
    feats = extract_features(rec)
    pred, score = predict_impersonation(feats)
    assert feats["is_exact_official"] == 1.0
    assert pred == 0
    assert score == 0.0


def test_feature_extraction_lookalike_variations():
    # Adjacent character swap
    rec_swap = ProfileRecord(
        brand_name="Acme Bank",
        official_handle="acmebank",
        candidate_handle="amcebank",
        candidate_name="Acme Bank Help",
        followers=30,
        following=500,
        has_bio=True,
        bio_text="Support assistance",
        ground_truth_label=1,
    )
    feats_swap = extract_features(rec_swap)
    pred_swap, score_swap = predict_impersonation(feats_swap)
    assert feats_swap["is_swap"] == 1.0
    assert pred_swap == 1
    assert score_swap >= 50.0

    # Spacing / hyphen variation
    rec_space = ProfileRecord(
        brand_name="Acme Bank",
        official_handle="acmebank",
        candidate_handle="ac-mebank",
        candidate_name="Acme Bank Online",
        followers=50,
        following=300,
        has_bio=True,
        bio_text="Updates portal",
        ground_truth_label=1,
    )
    feats_space = extract_features(rec_space)
    pred_space, score_space = predict_impersonation(feats_space)
    assert feats_space["is_spacing"] == 1.0
    assert pred_space == 1
    assert score_space >= 40.0


def test_zero_leakage_brand_separated_splits():
    train_brands = {r.brand_name.lower() for r in TRAIN_SET}
    test_brands = {r.brand_name.lower() for r in TEST_SET}
    # Mathematical proof: Train and Test brands are completely disjoint
    assert train_brands.isdisjoint(test_brands), "Train and Test sets must not share any brands!"

    train_officials = {r.official_handle.lower() for r in TRAIN_SET}
    test_officials = {r.official_handle.lower() for r in TEST_SET}
    assert train_officials.isdisjoint(test_officials), "Official handles must have zero overlap across splits!"


def test_official_asset_zero_false_positive_rate():
    all_profiles = TRAIN_SET + TEST_SET
    official_profiles = [p for p in all_profiles if p.candidate_handle.lower() == p.official_handle.lower()]
    assert len(official_profiles) >= 3

    for p in official_profiles:
        feats = extract_features(p)
        pred, score = predict_impersonation(feats)
        assert pred == 0, f"Official asset {p.candidate_handle} was falsely flagged!"
        assert score == 0.0, f"Official asset {p.candidate_handle} received non-zero score {score}!"


def test_learned_pipeline_fit_and_coefficients():
    pipe = train_classifier_pipeline(TRAIN_SET)
    assert pipe is not None
    assert "scaler" in pipe.named_steps
    assert "clf" in pipe.named_steps

    clf = pipe.named_steps["clf"]
    assert hasattr(clf, "coef_")
    assert clf.coef_.shape == (1, len(FEATURE_NAMES))
    assert hasattr(clf, "intercept_")
    # Learned positive weights on risk indicators
    coef_map = dict(zip(FEATURE_NAMES, clf.coef_[0]))
    assert coef_map["low_followers"] > 0
    assert coef_map["is_name_similar"] > 0
    assert coef_map["is_swap"] > 0


def test_learned_pipeline_prediction_and_exclusion_gate():
    pipe = train_classifier_pipeline(TRAIN_SET)
    # Impersonator test
    phish_feats = {
        "is_exact_official": 0.0,
        "is_swap": 1.0,
        "is_name_similar": 1.0,
        "low_followers": 1.0,
        "log_followers": 1.5,
        "following_ratio": 20.0,
        "bio_phishing": 1.0,
    }
    pred, prob = predict_trained_model(pipe, phish_feats)
    assert pred == 1
    assert prob >= 80.0

    # Official exclusion gate cannot be overridden even with adverse features
    official_feats = dict(phish_feats)
    official_feats["is_exact_official"] = 1.0
    off_pred, off_prob = predict_trained_model(pipe, official_feats)
    assert off_pred == 0
    assert off_prob == 0.0


def test_model_fallback_when_pipeline_unavailable():
    sample_feats = {
        "is_exact_official": 0.0,
        "is_swap": 1.0,
        "is_name_similar": 1.0,
        "low_followers": 1.0,
        "log_followers": 1.5,
        "bio_phishing": 1.0,
    }
    # When pipe is None, falls back to deterministic heuristic scorer
    pred_fallback, score_fallback = predict_trained_model(None, sample_feats)
    pred_heur, score_heur = predict_impersonation_heuristic(sample_feats)
    assert pred_fallback == pred_heur
    assert score_fallback == score_heur


def test_difficult_benign_accounts_not_flagged():
    pipe = train_classifier_pipeline(TRAIN_SET)
    # Fan club page
    fan_rec = ProfileRecord(
        brand_name="Metro Bank",
        official_handle="metrobank",
        candidate_handle="metro_bank_feedbacks",
        candidate_name="Metro Bank User Reviews",
        followers=310,
        following=150,
        has_bio=True,
        bio_text="Unofficial community feedback.",
        ground_truth_label=0,
    )
    feats = extract_features(fan_rec)
    pred_heur, _ = predict_impersonation_heuristic(feats)
    pred_pipe, prob_pipe = predict_trained_model(pipe, feats)
    assert pred_heur == 0
    assert pred_pipe == 0
    assert prob_pipe < 30.0


def test_empty_and_extreme_fallbacks():
    empty_rec = ProfileRecord(
        brand_name="Acme Bank",
        official_handle="acmebank",
        candidate_handle="",
        candidate_name="",
        followers=0,
        following=0,
        has_bio=False,
        bio_text="",
        ground_truth_label=0,
    )
    feats = extract_features(empty_rec)
    pred, score = predict_impersonation(feats)
    assert pred == 0
    assert score == 0.0

    large_rec = ProfileRecord(
        brand_name="Acme Bank",
        official_handle="acmebank",
        candidate_handle="celebrity_fan_club",
        candidate_name="Fan Club",
        followers=10_000_000,
        following=10,
        has_bio=True,
        bio_text="Official fan community",
        ground_truth_label=0,
    )
    feats_large = extract_features(large_rec)
    pred_large, score_large = predict_impersonation(feats_large)
    assert pred_large == 0
