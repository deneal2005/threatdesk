"""Unit tests for ML lookalike algorithm and baseline evaluation."""
import pytest

from threatdesk.lookalike_ml import (
    CATEGORY_ADDED_TERMS,
    CATEGORY_DELETION,
    CATEGORY_HOMOGLYPH,
    CATEGORY_INSERTION,
    CATEGORY_SPACING,
    CATEGORY_SUBSTITUTION,
    CATEGORY_SWAP,
    compare_lookalike,
    find_lookalike,
)


def test_character_swaps():
    m1 = compare_lookalike("amcebank", "acmebank")
    assert m1 is not None and m1.category == CATEGORY_SWAP
    assert "Swapped" in m1.explanation and "mc" in m1.explanation

    m2 = compare_lookalike("acmebnak", "acmebank")
    assert m2 is not None and m2.category == CATEGORY_SWAP
    assert "na" in m2.explanation

    m3 = compare_lookalike("Acme Bnak", "Acme Bank")
    assert m3 is not None and m3.category == CATEGORY_SWAP
    assert "bnak" in m3.candidate.lower()


def test_character_insertion():
    m = compare_lookalike("accmebank", "acmebank")
    assert m is not None and m.category == CATEGORY_INSERTION
    assert "Extra letter" in m.explanation and "c" in m.explanation


def test_character_deletion():
    m = compare_lookalike("acmbank", "acmebank")
    assert m is not None and m.category == CATEGORY_DELETION
    assert "Missing letter" in m.explanation and "e" in m.explanation


def test_character_substitution():
    m = compare_lookalike("acnebank", "acmebank")
    assert m is not None and m.category == CATEGORY_SUBSTITUTION
    assert "Replaced" in m.explanation and "m" in m.explanation and "n" in m.explanation


def test_spacing_and_hyphen_variations():
    m1 = compare_lookalike("ac-me bank", "acme bank")
    assert m1 is not None and m1.category == CATEGORY_SPACING

    m2 = compare_lookalike("ac_mebank", "acmebank")
    assert m2 is not None and m2.category == CATEGORY_SPACING

    m3 = compare_lookalike("Ac-me Bank", "Acme Bank")
    assert m3 is not None and m3.category == CATEGORY_SPACING


def test_added_suspicious_terms():
    m1 = compare_lookalike("Acme Bank Support", "Acme Bank")
    assert m1 is not None and m1.category == CATEGORY_ADDED_TERMS
    assert "support" in m1.explanation

    m2 = compare_lookalike("Acme Bank Official Help", "Acme Bank")
    assert m2 is not None and m2.category == CATEGORY_ADDED_TERMS
    assert "official" in m2.explanation or "help" in m2.explanation

    m3 = compare_lookalike("acme_support", "acme")
    assert m3 is not None and m3.category == CATEGORY_ADDED_TERMS

    m4 = compare_lookalike("acmesupport", "acme")
    assert m4 is not None and m4.category == CATEGORY_ADDED_TERMS
    assert "support" in m4.explanation

    m5 = compare_lookalike("officialacme", "acme")
    assert m5 is not None and m5.category == CATEGORY_ADDED_TERMS
    assert "official" in m5.explanation


def test_lookalike_symbols():
    m = compare_lookalike("acm0bank", "acmebank")
    assert m is not None and (m.category == CATEGORY_HOMOGLYPH or m.category == CATEGORY_SUBSTITUTION)


def test_exact_matches_not_flagged():
    assert compare_lookalike("acmebank", "acmebank") is None
    assert compare_lookalike("Acme Bank", "Acme Bank") is None
    assert find_lookalike("acmebank", ["acme"], ["acmebank"]) is None
    assert find_lookalike("@acmebank", ["acme"], ["acmebank"]) is None


def test_unrelated_assets_not_flagged():
    assert compare_lookalike("River Bank", "Acme Bank") is None
    assert find_lookalike("River Bank", ["Acme Bank", "acme"]) is None
    assert compare_lookalike("mac", "acme") is None
    assert compare_lookalike("action", "acme") is None


def test_empty_and_none_lookalike_fallbacks():
    assert compare_lookalike("", "acme") is None
    assert compare_lookalike("acme", "") is None
    assert compare_lookalike(None, "acme") is None  # type: ignore[arg-type]
    assert find_lookalike("", ["acme"]) is None
    assert find_lookalike("!!!", ["acme"]) is None


def test_research_ml_baseline_evaluation():
    from scripts.research_ml_baseline import (
        TEST_SET,
        TRAIN_SET,
        evaluate_dataset,
        evaluate_predictions,
        extract_features,
        predict_trained_model,
        train_classifier_pipeline,
    )
    res_train = evaluate_dataset(TRAIN_SET, "Train Set")
    res_test = evaluate_dataset(TEST_SET, "Test Set")
    assert res_train["precision"] >= 0.90
    assert res_test["precision"] >= 0.85
    assert res_test["f1"] >= 0.75

    pipe = train_classifier_pipeline(TRAIN_SET)
    assert pipe is not None
    y_test = [r.ground_truth_label for r in TEST_SET]
    y_pred = [predict_trained_model(pipe, extract_features(r))[0] for r in TEST_SET]
    ml_res = evaluate_predictions(y_test, y_pred, "ML Pipeline Test")
    assert ml_res["precision"] == 1.0
    assert ml_res["f1"] == 1.0
