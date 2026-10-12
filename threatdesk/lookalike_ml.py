"""Explainable look-alike detection for usernames, handles, and app titles.

Classifies variations into explicit categories (swaps, insertions, deletions,
substitutions, spacing/hyphen variations, added terms, and homoglyphs)
with plain-English evidence explanations suitable for non-technical users.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from rapidfuzz import fuzz
from rapidfuzz.distance import DamerauLevenshtein, Levenshtein

CATEGORY_SWAP = "character_swap"
CATEGORY_INSERTION = "character_insertion"
CATEGORY_DELETION = "character_deletion"
CATEGORY_SUBSTITUTION = "character_substitution"
CATEGORY_SPACING = "spacing_variation"
CATEGORY_ADDED_TERMS = "added_terms"
CATEGORY_HOMOGLYPH = "homoglyph"
CATEGORY_SIMILARITY = "close_similarity"

LABELS: dict[str, str] = {
    CATEGORY_SWAP: "Adjacent letter swap", CATEGORY_INSERTION: "Extra letter",
    CATEGORY_DELETION: "Missing letter", CATEGORY_SUBSTITUTION: "Letter replacement",
    CATEGORY_SPACING: "Hyphen or spacing variation", CATEGORY_ADDED_TERMS: "Added suspicious word",
    CATEGORY_HOMOGLYPH: "Look-alike symbol", CATEGORY_SIMILARITY: "Similar spelling",
}

SUSPICIOUS_TERMS: set[str] = {
    "official", "support", "verify", "verification", "verified", "help", "helpdesk", "care",
    "customercare", "customer-care", "customer_care", "service", "services", "security",
    "secure", "login", "signin", "kyc", "account", "accounts", "billing", "desk", "online",
    "portal", "team", "app", "mobile", "wallet", "rewards", "claims", "update", "pay",
    "payment", "assist", "assistance", "agent", "bot", "auth",
}

HOMOGLYPH_PAIRS: set[tuple[str, str]] = {
    ("o", "0"), ("0", "o"), ("l", "1"), ("1", "l"), ("i", "1"), ("1", "i"),
    ("e", "3"), ("3", "e"), ("a", "4"), ("4", "a"), ("s", "5"), ("5", "s"),
    ("b", "8"), ("8", "b"), ("g", "9"), ("9", "g"), ("t", "7"), ("7", "t"),
    ("e", "0"), ("0", "e"),
}


@dataclass(frozen=True)
class LookalikeMatch:
    category: str
    label: str
    explanation: str
    candidate: str
    target: str
    confidence: int

    def as_dict(self) -> dict:
        return asdict(self)


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _clean_tokens(s: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if t]


def _find_swap(tgt: str, cand: str) -> tuple[str, str] | None:
    return next(((cand[i:i + 2], tgt[i:i + 2]) for i in range(len(tgt) - 1)
                 if tgt[i] == cand[i + 1] and tgt[i + 1] == cand[i]), None)


def _find_substitution(tgt: str, cand: str) -> tuple[str, str] | None:
    return next(((tgt[i], cand[i]) for i in range(len(tgt)) if tgt[i] != cand[i]), None)


def _find_insertion(tgt: str, cand: str) -> str | None:
    return next((cand[i] for i in range(len(cand)) if tgt[:i] + tgt[i:] == cand[:i] + cand[i + 1:]), None)


def _find_deletion(tgt: str, cand: str) -> str | None:
    return next((tgt[i] for i in range(len(tgt)) if tgt[:i] + tgt[i + 1:] == cand), None)


def compare_lookalike(candidate: str, target: str) -> LookalikeMatch | None:
    """Compare a candidate name or handle against a single target string."""
    c_orig = (candidate or "").strip().lstrip("@")
    t_orig = (target or "").strip().lstrip("@")
    c_low = c_orig.lower()
    t_low = t_orig.lower()
    if not c_low or not t_low:
        return None

    cn = _norm(c_low)
    tn = _norm(t_low)
    if not cn or not tn or min(len(cn), len(tn)) < 3:
        return None

    # Exact match is legitimate/identical, not a look-alike
    if c_low == t_low or (cn == tn and len(c_orig) == len(t_orig) and c_orig == t_orig):
        return None

    # 1. Spacing and hyphen variations (same characters, different separation)
    if cn == tn:
        return LookalikeMatch(
            category=CATEGORY_SPACING,
            label=LABELS[CATEGORY_SPACING],
            explanation=f'Punctuation or spacing difference ("{c_orig}" vs "{t_orig}")',
            candidate=c_orig, target=t_orig, confidence=95,
        )

    # 2. Added / suspicious terms (multi-token or phrase)
    c_toks = _clean_tokens(c_low)
    t_toks = _clean_tokens(t_low)
    if t_toks and set(t_toks).issubset(set(c_toks)):
        added = [w for w in c_toks if w not in set(t_toks)]
        suspicious = [w for w in added if w in SUSPICIOUS_TERMS]
        if suspicious:
            terms_desc = ", ".join(f'"{w}"' for w in sorted(set(suspicious)))
            return LookalikeMatch(
                category=CATEGORY_ADDED_TERMS,
                label=LABELS[CATEGORY_ADDED_TERMS],
                explanation=f"Includes {terms_desc} alongside brand name",
                candidate=c_orig, target=t_orig, confidence=90,
            )

    # 2b. Attached affix terms in single-token handles (e.g. acmesupport, officialacme)
    if len(tn) >= 3:
        if cn.startswith(tn):
            suffix = cn[len(tn):]
            if suffix in SUSPICIOUS_TERMS:
                return LookalikeMatch(
                    category=CATEGORY_ADDED_TERMS,
                    label=LABELS[CATEGORY_ADDED_TERMS],
                    explanation=f'Appends word "{suffix}" to brand name',
                    candidate=c_orig, target=t_orig, confidence=90,
                )
        elif cn.endswith(tn):
            prefix = cn[:-len(tn)]
            if prefix in SUSPICIOUS_TERMS:
                return LookalikeMatch(
                    category=CATEGORY_ADDED_TERMS,
                    label=LABELS[CATEGORY_ADDED_TERMS],
                    explanation=f'Prepends word "{prefix}" before brand name',
                    candidate=c_orig, target=t_orig, confidence=90,
                )

    # 3. Single-edit operations via Damerau-Levenshtein
    d_dam = DamerauLevenshtein.distance(tn, cn)
    d_lev = Levenshtein.distance(tn, cn)

    if d_dam == 1:
        if len(cn) == len(tn):
            if d_lev == 2:
                # Adjacent swap (transposition)
                swap_info = _find_swap(tn, cn)
                detail = f'Swapped "{swap_info[0]}" instead of "{swap_info[1]}"' if swap_info else "Swapped adjacent letters"
                return LookalikeMatch(
                    category=CATEGORY_SWAP,
                    label=LABELS[CATEGORY_SWAP],
                    explanation=detail,
                    candidate=c_orig, target=t_orig, confidence=95,
                )
            # Single substitution
            sub_info = _find_substitution(tn, cn)
            if sub_info and (sub_info[0], sub_info[1]) in HOMOGLYPH_PAIRS:
                return LookalikeMatch(
                    category=CATEGORY_HOMOGLYPH,
                    label=LABELS[CATEGORY_HOMOGLYPH],
                    explanation=f'Uses look-alike symbol "{sub_info[1]}" instead of "{sub_info[0]}"',
                    candidate=c_orig, target=t_orig, confidence=92,
                )
            detail = f'Replaced "{sub_info[0]}" with "{sub_info[1]}"' if sub_info else "Letter replacement"
            return LookalikeMatch(
                category=CATEGORY_SUBSTITUTION,
                label=LABELS[CATEGORY_SUBSTITUTION],
                explanation=detail,
                candidate=c_orig, target=t_orig, confidence=90,
            )
        if len(cn) == len(tn) + 1:
            # Single insertion
            ins = _find_insertion(tn, cn)
            detail = f'Extra letter "{ins}" added' if ins else "Extra letter added"
            return LookalikeMatch(
                category=CATEGORY_INSERTION,
                label=LABELS[CATEGORY_INSERTION],
                explanation=detail,
                candidate=c_orig, target=t_orig, confidence=90,
            )
        if len(cn) == len(tn) - 1:
            # Single deletion
            del_char = _find_deletion(tn, cn)
            detail = f'Missing letter "{del_char}"' if del_char else "Missing letter"
            return LookalikeMatch(
                category=CATEGORY_DELETION,
                label=LABELS[CATEGORY_DELETION],
                explanation=detail,
                candidate=c_orig, target=t_orig, confidence=90,
            )

    # 4. Token-by-token alignment for multi-word titles (e.g. "Acme Bnak" vs "Acme Bank")
    if len(c_toks) == len(t_toks) and len(t_toks) > 1:
        diffs = []
        for ct, tt in zip(c_toks, t_toks):
            if ct != tt:
                m = compare_lookalike(ct, tt)
                if m:
                    diffs.append(m)
        if len(diffs) == 1:
            single = diffs[0]
            return LookalikeMatch(
                category=single.category,
                label=single.label,
                explanation=f'{single.explanation} in "{c_orig}"',
                candidate=c_orig, target=t_orig, confidence=single.confidence,
            )

    # 4b. Multi-word title where extra tokens are suspicious words:
    # e.g. "Acme Bnak Mobile" vs "Acme Bank" -> core is "Acme Bnak" (letter swap)
    if len(c_toks) > len(t_toks) and len(t_toks) >= 1:
        core_toks = [w for w in c_toks if w not in SUSPICIOUS_TERMS]
        if len(core_toks) == len(t_toks):
            m_core = compare_lookalike(" ".join(core_toks), " ".join(t_toks))
            if m_core and m_core.category in (CATEGORY_SWAP, CATEGORY_INSERTION, CATEGORY_DELETION,
                                              CATEGORY_SUBSTITUTION, CATEGORY_SPACING, CATEGORY_HOMOGLYPH):
                return LookalikeMatch(
                    category=m_core.category,
                    label=m_core.label,
                    explanation=f'{m_core.explanation} in "{c_orig}"',
                    candidate=c_orig, target=t_orig, confidence=m_core.confidence,
                )

    # 5. Fuzzy similarity fallback (high overall character match)
    ratio = fuzz.ratio(cn, tn)
    if ratio >= 82 and min(len(cn), len(tn)) >= 4:
        return LookalikeMatch(
            category=CATEGORY_SIMILARITY,
            label=LABELS[CATEGORY_SIMILARITY],
            explanation=f'{int(ratio)}% visual similarity to "{t_orig}"',
            candidate=c_orig, target=t_orig, confidence=int(ratio),
        )

    return None


def find_lookalike(candidate: str, targets: list[str],
                   official_targets: list[str] = ()) -> LookalikeMatch | None:
    """Find the best lookalike match for candidate among official assets and brand terms.

    If candidate matches an official asset exactly, returns None to prevent false positives.
    """
    c_clean = (candidate or "").strip().lstrip("@").lower()
    c_norm = _norm(c_clean)
    if not c_norm:
        return None

    # Exact official check: never flag an official asset
    for off in official_targets:
        off_clean = (off or "").strip().lstrip("@").lower()
        if c_clean == off_clean:
            return None

    best_match: LookalikeMatch | None = None
    # Sort targets by length descending so longer/more specific phrases take precedence
    all_targets = sorted(
        list(official_targets) + [t for t in targets if t not in official_targets],
        key=lambda x: len(x),
        reverse=True,
    )

    for tgt in all_targets:
        m = compare_lookalike(candidate, tgt)
        if m is not None:
            if best_match is None or m.confidence > best_match.confidence:
                best_match = m
                if m.confidence >= 95:
                    break

    return best_match
