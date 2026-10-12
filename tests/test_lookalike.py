"""Look-alike engine: substitutions, spacing, added words, typos, and names that must NOT match."""
import pytest

from threatdesk.lookalike import best_title_match, compare, is_platform_id, skeleton


@pytest.mark.parametrize("candidate, reference, technique", [
    ("acmeb4nk", "acmebank", "character substitution: 4→a"),
    ("acrnebank", "acmebank", "rn→m"),
    ("аcmebank", "acmebank", "(non-Latin)"),                        # Cyrillic а
    ("acme_bank", "Acme Bank", "different spacing or punctuation"),
    ("acme.bank.help", "acmebank", "added words: help"),
    ("acmebankofficial", "acmebank", "added words: official"),
    ("theacmebank", "acmebank", "added words: the"),
    ("acmebank2024", "acmebank", "added words: 2024"),
    ("Acme Bank Customer Care", "Acme Bank", "added words: customercare"),
    ("acmebnak", "acmebank", "typo: 1 character"),
    ("acmebnak_support", "acmebank", "typo: 1 character"),
])
def test_impersonation_patterns_are_detected_and_explained(candidate, reference, technique):
    m = compare(candidate, reference)
    assert m is not None and m.strong(80), (candidate, m)
    assert technique in m.explain()


@pytest.mark.parametrize("candidate, reference", [
    ("johnsmith", "acmebank"), ("Acme Plumbing Co", "Acme Bank"), ("acmepay", "Acme Bank"),
    ("belle", "zelle"),                                  # short names: only exact (normalised) matches count
    ("Bank Statement Reader", "Acme Bank"), ("instagram", "acmebank"),
])
def test_unrelated_names_are_not_lookalikes(candidate, reference):
    m = compare(candidate, reference)
    assert m is None or not m.strong(70), (candidate, m)


def test_containment_is_weak_and_never_strong():
    m = compare("ACME Anvil Game", "acme")
    assert m.score == 60 and not m.strong(70) and "among other words" in m.explain()


def test_sensitivity_changes_what_counts():
    m = compare("acmebnak_support", "acmebank")
    assert m.strong(80) and not m.strong(90)


def test_title_parts_and_identity():
    m, label = best_title_match("Acme Bank - Mobile Banking", {"acme bank": "the brand"})
    assert m.score == 100 and label == "the brand" and m.candidate == "Acme Bank - Mobile Banking"
    assert skeleton("ACME-B4NK") == skeleton("acmebank")
    assert compare("Acme", "Acme").explain() == "identical name"


def test_platform_ids_are_not_names():
    assert is_platform_id("UCabcdefghijklmnopqrstuv") and is_platform_id("did:plc:abc") and is_platform_id("1234567")
    assert not is_platform_id("ucbank") and not is_platform_id("acmebank")
