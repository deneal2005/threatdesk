"""Unit tests for ML feature extraction, multi-model pipeline, and baseline evaluation."""
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
    train_all_models,
    train_classifier_pipeline,
)


# ---------------------------------------------------------------------------
# Feature extraction tests
# ---------------------------------------------------------------------------


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


def test_new_feature_dimensions():
    """Verify that 18 features are extracted (8 new features added)."""
    assert len(FEATURE_NAMES) == 18
    rec = ProfileRecord(
        brand_name="Acme Bank",
        official_handle="acmebank",
        candidate_handle="amcebank",
        candidate_name="Acme Help",
        followers=30,
        following=500,
        has_bio=True,
        bio_text="Verify now immediately",
        ground_truth_label=1,
    )
    feats = extract_features(rec)
    for name in FEATURE_NAMES:
        assert name in feats, f"Feature '{name}' missing from extracted features"
    assert "is_exact_official" in feats


def test_bio_urgency_feature():
    """Bio urgency feature fires on urgent action words."""
    urgent_rec = ProfileRecord(
        brand_name="Acme Bank",
        official_handle="acmebank",
        candidate_handle="acme_help",
        candidate_name="Acme Help",
        followers=20,
        following=300,
        has_bio=True,
        bio_text="Your account will be suspended immediately. Verify now.",
        ground_truth_label=1,
    )
    feats = extract_features(urgent_rec)
    assert feats["bio_urgency"] == 1.0

    calm_rec = ProfileRecord(
        brand_name="Acme Bank",
        official_handle="acmebank",
        candidate_handle="acme_cafe",
        candidate_name="Acme Cafe",
        followers=2000,
        following=300,
        has_bio=True,
        bio_text="Best coffee in town.",
        ground_truth_label=0,
    )
    feats_calm = extract_features(calm_rec)
    assert feats_calm["bio_urgency"] == 0.0


def test_handle_length_ratio_feature():
    """Handle length ratio is computed correctly."""
    rec = ProfileRecord(
        brand_name="Acme Bank",
        official_handle="acmebank",  # len=8
        candidate_handle="acmebank_official",  # len=17
        candidate_name="Acme Official",
        followers=30,
        following=500,
        has_bio=True,
        bio_text="Official page",
        ground_truth_label=1,
    )
    feats = extract_features(rec)
    assert feats["handle_length_ratio"] == pytest.approx(17 / 8, rel=0.01)


def test_fuzzy_similarity_feature():
    """Fuzzy similarity is a float between 0 and 1."""
    rec = ProfileRecord(
        brand_name="Acme Bank",
        official_handle="acmebank",
        candidate_handle="amcebank",
        candidate_name="Acme Help",
        followers=30,
        following=500,
        has_bio=True,
        bio_text="Help",
        ground_truth_label=1,
    )
    feats = extract_features(rec)
    assert 0.0 <= feats["fuzzy_similarity"] <= 1.0
    assert feats["fuzzy_similarity"] > 0.7


# ---------------------------------------------------------------------------
# Dataset integrity tests
# ---------------------------------------------------------------------------


def test_zero_leakage_brand_separated_splits():
    train_brands = {r.brand_name.lower() for r in TRAIN_SET}
    test_brands = {r.brand_name.lower() for r in TEST_SET}
    # Mathematical proof: Train and Test brands are completely disjoint
    assert train_brands.isdisjoint(test_brands), "Train and Test sets must not share any brands!"

    train_officials = {r.official_handle.lower() for r in TRAIN_SET}
    test_officials = {r.official_handle.lower() for r in TEST_SET}
    assert train_officials.isdisjoint(test_officials), "Official handles must have zero overlap across splits!"


def test_dataset_minimum_size():
    """Verify expanded dataset has at least 80 records total."""
    assert len(TRAIN_SET) >= 50, f"Train set too small: {len(TRAIN_SET)}"
    assert len(TEST_SET) >= 30, f"Test set too small: {len(TEST_SET)}"
    assert len(TRAIN_SET) + len(TEST_SET) >= 80


def test_dataset_brand_count():
    """Verify at least 5 train brands and 3 test brands."""
    train_brands = {r.brand_name for r in TRAIN_SET}
    test_brands = {r.brand_name for r in TEST_SET}
    assert len(train_brands) >= 5, f"Need >= 5 train brands, got {len(train_brands)}"
    assert len(test_brands) >= 3, f"Need >= 3 test brands, got {len(test_brands)}"


def test_dataset_class_balance():
    """Neither split should be extremely imbalanced (>80% one class)."""
    for name, dataset in [("TRAIN", TRAIN_SET), ("TEST", TEST_SET)]:
        pos = sum(r.ground_truth_label for r in dataset)
        ratio = pos / len(dataset)
        assert 0.2 <= ratio <= 0.8, f"{name} set severely imbalanced: {ratio:.1%} positive"


def test_official_asset_zero_false_positive_rate():
    all_profiles = TRAIN_SET + TEST_SET
    official_profiles = [p for p in all_profiles if p.candidate_handle.lower() == p.official_handle.lower()]
    assert len(official_profiles) >= 3

    for p in official_profiles:
        feats = extract_features(p)
        pred, score = predict_impersonation(feats)
        assert pred == 0, f"Official asset {p.candidate_handle} was falsely flagged!"
        assert score == 0.0, f"Official asset {p.candidate_handle} received non-zero score {score}!"


# ---------------------------------------------------------------------------
# Single-model pipeline tests (backward compatibility)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Multi-model pipeline tests
# ---------------------------------------------------------------------------


def test_train_all_models_returns_multiple():
    """train_all_models() returns at least 5 individual models + 1 ensemble."""
    fitted = train_all_models(TRAIN_SET)
    assert len(fitted) >= 6
    expected = {"LogisticRegression", "RandomForest", "GradientBoosting", "SVM", "KNN", "Ensemble"}
    assert expected.issubset(set(fitted.keys())), f"Missing models: {expected - set(fitted.keys())}"


def test_all_models_predict_correctly_on_obvious_cases():
    """Every model must correctly classify clearly malicious and clearly benign profiles."""
    fitted = train_all_models(TRAIN_SET)

    # Obviously malicious: swap + phishing bio + low followers
    malicious_rec = ProfileRecord(
        brand_name="Acme Bank",
        official_handle="acmebank",
        candidate_handle="amcebank",
        candidate_name="Acme Bank Support",
        followers=20,
        following=800,
        has_bio=True,
        bio_text="Verify your KYC immediately to avoid suspension.",
        ground_truth_label=1,
    )
    mal_feats = extract_features(malicious_rec)
    for name, model in fitted.items():
        pred, _ = predict_trained_model(model, mal_feats)
        assert pred == 1, f"{name} failed to detect obvious impersonator"

    # Obviously benign: unrelated handle, high followers
    benign_rec = ProfileRecord(
        brand_name="Acme Bank",
        official_handle="acmebank",
        candidate_handle="john_doe_99",
        candidate_name="John Doe",
        followers=5000,
        following=400,
        has_bio=True,
        bio_text="Photographer and coffee lover.",
        ground_truth_label=0,
    )
    ben_feats = extract_features(benign_rec)
    for name, model in fitted.items():
        pred, _ = predict_trained_model(model, ben_feats)
        assert pred == 0, f"{name} falsely flagged obvious benign profile"


def test_all_models_official_exclusion_gate():
    """The official-asset exclusion gate cannot be overridden by any model."""
    fitted = train_all_models(TRAIN_SET)
    adversarial_feats = {
        "is_exact_official": 1.0,
        "is_swap": 1.0,
        "is_name_similar": 1.0,
        "low_followers": 1.0,
        "bio_phishing": 1.0,
        "bio_urgency": 1.0,
    }
    for name, model in fitted.items():
        pred, prob = predict_trained_model(model, adversarial_feats)
        assert pred == 0, f"{name} overrode official exclusion gate!"
        assert prob == 0.0, f"{name} assigned non-zero probability to official asset!"


def test_ensemble_accuracy_on_test_set():
    """Ensemble achieves at least 95% accuracy on the held-out test set."""
    fitted = train_all_models(TRAIN_SET)
    ensemble = fitted["Ensemble"]
    correct = 0
    for rec in TEST_SET:
        feats = extract_features(rec)
        pred, _ = predict_trained_model(ensemble, feats)
        if pred == rec.ground_truth_label:
            correct += 1
    accuracy = correct / len(TEST_SET)
    assert accuracy >= 0.95, f"Ensemble accuracy too low: {accuracy:.1%}"


def test_no_false_positives_on_official_assets_all_models():
    """No model flags any official asset in train or test as impersonation."""
    fitted = train_all_models(TRAIN_SET)
    all_data = TRAIN_SET + TEST_SET
    officials = [r for r in all_data if r.candidate_handle.lower() == r.official_handle.lower()]
    assert len(officials) >= 8, f"Expected at least 8 official profiles, got {len(officials)}"

    for rec in officials:
        feats = extract_features(rec)
        for model_name, model in fitted.items():
            pred, prob = predict_trained_model(model, feats)
            assert pred == 0, f"{model_name} flagged official {rec.candidate_handle}!"
            assert prob == 0.0


# ---------------------------------------------------------------------------
# Difficult benign / edge case tests
# ---------------------------------------------------------------------------


def test_difficult_benign_accounts_not_flagged():
    pipe = train_classifier_pipeline(TRAIN_SET)
    # Fan club / review page
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
    pred_pipe, prob_pipe = predict_trained_model(pipe, feats)
    # The learned ML model correctly identifies this as benign (low prob)
    assert pred_pipe == 0
    assert prob_pipe < 40.0


def test_unrelated_business_with_shared_word_not_flagged():
    """Businesses sharing a common dictionary word with the brand should not be flagged."""
    pipe = train_classifier_pipeline(TRAIN_SET)
    rec = ProfileRecord(
        brand_name="Nova Insurance",
        official_handle="novainsurance",
        candidate_handle="nova_stargazers",
        candidate_name="Nova Astronomy Club",
        followers=4200,
        following=300,
        has_bio=True,
        bio_text="Amateur astronomy nights and telescope reviews.",
        ground_truth_label=0,
    )
    feats = extract_features(rec)
    pred, prob = predict_trained_model(pipe, feats)
    assert pred == 0, "Unrelated astronomy club was falsely flagged"


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
