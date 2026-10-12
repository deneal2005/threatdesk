"""Unit tests for explainable look-alike detection."""
import pytest

from threatdesk.brands import BrandContext
from threatdesk.checks.app_common import impersonation
from threatdesk.checks.social import social_signals
from threatdesk.lookalike import (
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
from threatdesk.scoring import Scorecard


BRAND = BrandContext(
    name="Acme Bank",
    keywords=["acme", "acmebank"],
    official_domains=["acmebank.com"],
    official_handles={"instagram": ["acmebank"], "telegram": ["acmebank"]},
    official_apps={"android": ["com.acme.bank"], "ios": ["1234567890"], "publishers": ["Acme Financial Group"]},
)


def test_character_swaps():
    # Handle adjacent swap
    m1 = compare_lookalike("amcebank", "acmebank")
    assert m1 is not None and m1.category == CATEGORY_SWAP
    assert "Swapped" in m1.explanation and "mc" in m1.explanation

    m2 = compare_lookalike("acmebnak", "acmebank")
    assert m2 is not None and m2.category == CATEGORY_SWAP
    assert "na" in m2.explanation

    # Multi-word app title adjacent swap
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
    # Multi-token with suspicious term
    m1 = compare_lookalike("Acme Bank Support", "Acme Bank")
    assert m1 is not None and m1.category == CATEGORY_ADDED_TERMS
    assert "support" in m1.explanation

    m2 = compare_lookalike("Acme Bank Official Help", "Acme Bank")
    assert m2 is not None and m2.category == CATEGORY_ADDED_TERMS
    assert "official" in m2.explanation or "help" in m2.explanation

    # Delimited handle
    m3 = compare_lookalike("acme_support", "acme")
    assert m3 is not None and m3.category == CATEGORY_ADDED_TERMS

    # Affix handle without delimiter
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
    # Unrelated name sharing generic word "bank"
    assert compare_lookalike("River Bank", "Acme Bank") is None
    assert find_lookalike("River Bank", ["Acme Bank", "acme"]) is None

    # Unrelated short words
    assert compare_lookalike("mac", "acme") is None
    assert compare_lookalike("action", "acme") is None


def test_social_signals_lookalike_integration():
    card = Scorecard()
    out = social_signals(
        card=card,
        brand=BRAND,
        platform="instagram",
        handle="amcebank",
        name="Acme Bank Official Support",
        bio="Customer care helpline",
    )
    codes = {s.code for s in card.signals}
    assert "handle_similar" in codes
    assert "name_similar" in codes

    # Verify explainable evidence format
    handle_ev = [s.evidence for s in card.signals if s.code == "handle_similar"][0]
    assert "Adjacent letter swap" in handle_ev or "Swapped" in handle_ev

    name_ev = [s.evidence for s in card.signals if s.code == "name_similar"][0]
    assert "Added suspicious word" in name_ev or "official" in name_ev.lower()

    # Verify check outcome detail contains structured metadata
    assert "lookalike" in out or "handle_lookalike" in out
    assert out.get("name_similar") is True


def test_social_signals_official_account_excluded():
    card = Scorecard()
    out = social_signals(
        card=card,
        brand=BRAND,
        platform="instagram",
        handle="acmebank",
        name="Acme Bank",
        bio="Official Instagram account of Acme Bank",
    )
    assert out == {"official": True}
    assert card.score == 0
    assert len(card.signals) == 0


def test_app_impersonation_lookalike_integration():
    card = Scorecard()
    out = impersonation(
        card=card,
        ctx_brand=BRAND,
        title="Acme Bnak Mobile",
        app_id="com.amcebnak.fakeapp",
        kind="android",
        developer="Rogue Dev LLC",
    )
    assert "similar_to" in out
    assert "lookalike" in out
    assert out["lookalike"]["category"] == CATEGORY_SWAP

    codes = {s.code for s in card.signals}
    assert "app_impersonation" in codes
    ev = [s.evidence for s in card.signals if s.code == "app_impersonation"][0]
    assert "Adjacent letter swap" in ev


def test_app_official_and_publisher_excluded():
    # Official app bundle ID
    card1 = Scorecard()
    out1 = impersonation(
        card=card1,
        ctx_brand=BRAND,
        title="Acme Bank Mobile",
        app_id="com.acme.bank",
        kind="android",
        developer="Acme Bank",
    )
    assert out1 == {"official": True}
    assert card1.score == 0

    # Official publisher
    card2 = Scorecard()
    out2 = impersonation(
        card=card2,
        ctx_brand=BRAND,
        title="Acme Bank Insurance",
        app_id="com.acme.group.insurance",
        kind="android",
        developer="Acme Financial Group",
        official_publisher="listed publisher Acme Financial Group",
    )
    assert out2 == {"official": True}
    assert card2.score == 0


def test_no_score_double_counting_on_lookalike():
    card = Scorecard()
    # Add handle similar
    assert card.add("handle_similar", "First reason")
    # Repeated add with different reason must NOT double count
    assert not card.add("handle_similar", "Duplicate attempt")
    assert card.score == 25
    assert len(card.signals) == 1


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

    # Verify that the trained ML pipeline achieves perfect precision on held-out test
    pipe = train_classifier_pipeline(TRAIN_SET)
    assert pipe is not None
    y_test = [r.ground_truth_label for r in TEST_SET]
    y_pred = [predict_trained_model(pipe, extract_features(r))[0] for r in TEST_SET]
    ml_res = evaluate_predictions(y_test, y_pred, "ML Pipeline Test")
    assert ml_res["precision"] == 1.0
    assert ml_res["f1"] == 1.0

