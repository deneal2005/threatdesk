"""Look-alike name matching shared by the social, app, discovery and intake checks (pure functions).

compare("acme_b4nk_support", "Acme Bank") -> Match(score=85, techniques=["character substitution: 4→a",
"added words: support"]). Every match says *how* the name imitates the reference, so a finding can explain itself.

Name similarity is identity evidence only: scoring (scoring.assess) never lets it reach Medium risk on its own.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from rapidfuzz import fuzz
from rapidfuzz.distance import DamerauLevenshtein

from threatdesk.linkdetect import CONFUSABLES

DEFAULT_THRESHOLD = 80          # a match at or above this score is a look-alike (brand settings can change it)
WEAK_SCORE = 60                 # "contains the brand name among other words": recorded, never scored
FULL_NAME_LEN = 7               # "acmebank" inside "Acme Bank Wallet Tools" counts; "acme" inside "ACME Anvil" doesn't
FULL_NAME_SCORE = 80
MIN_TYPO_LEN = 6                # shorter references must match exactly (after normalisation): "zelle" vs "belle"
LEET = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s",
        "!": "i", "|": "l", "€": "e"}
# Letters that look the same in most fonts collapse to one class on both sides (i/l/1 -> l, rn -> m, vv -> w).
COLLAPSE = (("i", "l"), ("rn", "m"), ("vv", "w"))
# Words impersonators add to a real name. Matched as whole prefixes/suffixes of the squashed name.
AFFIXES = sorted({
    "official", "offical", "officiel", "real", "the", "team", "support", "suport", "help", "helpdesk", "helpline",
    "care", "customercare", "customer", "customers", "service", "services", "desk", "hq", "global", "india", "ind",
    "in", "usa", "us", "uk", "app", "apps", "online", "verified", "info", "contact", "center", "centre", "hub",
    "page", "account", "accounts", "ltd", "inc", "my", "get", "login", "secure", "kyc", "update", "updates",
    "reward", "rewards", "refund", "refunds", "bonus", "giveaway", "airdrop", "claim", "news", "mobile", "lite",
    "pro", "plus", "new", "apk", "hindi", "tv", "live",
}, key=len, reverse=True)
SPLIT_RE = re.compile(r"\s+[-–—|:·•]\s+|\s*[|:•]\s*")
PLATFORM_ID_RE = re.compile(r"^(uc[\w-]{22}|did:.+|\d{5,})$")


@dataclass
class Match:
    candidate: str
    reference: str
    score: int
    techniques: list[str] = field(default_factory=list)

    def strong(self, threshold: int = DEFAULT_THRESHOLD) -> bool:
        return self.score >= threshold

    def explain(self) -> str:
        return "; ".join(self.techniques)

    def as_dict(self) -> dict:
        return {"candidate": self.candidate[:120], "reference": self.reference, "score": self.score,
                "techniques": self.techniques}


def basic(s: str) -> str:
    """NFKC, case-folded, letters and digits only (any script): 'Acme_Bank.Help' -> 'acmebankhelp'."""
    return "".join(ch for ch in unicodedata.normalize("NFKC", s or "").casefold() if ch.isalnum())


def _mapped(ch: str) -> str:
    return CONFUSABLES.get(ch) or LEET.get(ch) or ch


def skeleton(s: str) -> str:
    """What the name looks like: confusable and leet characters mapped, separators dropped, i/l/rn/vv collapsed."""
    t = unicodedata.normalize("NFKC", s or "").casefold()
    out = "".join(_mapped(ch) for ch in t)
    out = "".join(ch for ch in out if ch.isascii() and ch.isalnum())
    for a, b in COLLAPSE:
        out = out.replace(a, b)
    return out


def substitutions(candidate: str, reference: str) -> list[str]:
    """Characters in the candidate that imitate other letters ('4→a', 'а→a (non-Latin)', 'rn→m')."""
    ref = basic(reference)
    out: list[str] = []
    for ch in unicodedata.normalize("NFKC", candidate or "").casefold():
        m = _mapped(ch)
        if m != ch and ch not in ref:
            out.append(f"{ch}→{m}" + (" (non-Latin)" if ch.isalpha() and not ch.isascii() else ""))
    cb = basic(candidate)
    for a, b in (("rn", "m"), ("vv", "w")):
        if a in cb and a not in ref and b in ref:
            out.append(f"{a}→{b}")
    return list(dict.fromkeys(out))


def _strip_variants(cb: str, depth: int = 4):
    """(form, words removed) for the name with impersonation affixes or trailing digits taken off, nearest first."""
    frontier, seen = [(cb, [])], {cb}
    for _ in range(depth):
        nxt = []
        for form, added in frontier:
            opts = []
            if (m := re.search(r"\d+$", form)) and m.start() >= 3:
                opts.append((form[:m.start()], m.group()))
            for w in AFFIXES:
                if len(form) - len(w) >= 3:
                    if form.endswith(w):
                        opts.append((form[:-len(w)], w))
                    if form.startswith(w):
                        opts.append((form[len(w):], w))
            for f, w in opts:
                if f not in seen:
                    seen.add(f)
                    nxt.append((f, added + [w]))
                    yield f, added + [w]
        frontier = nxt


def compare(candidate: str, reference: str) -> Match | None:
    """How closely `candidate` imitates `reference` (0-100) and which techniques it uses; None if unrelated."""
    cb, rb = basic(candidate), basic(reference)
    if len(rb) < 2 or not cb:
        return None
    rs = skeleton(reference)
    best: Match | None = None
    same_text = (candidate or "").strip().lstrip("@").casefold() == (reference or "").strip().lstrip("@").casefold()
    sep = "" if same_text else "different spacing or punctuation"

    def offer(score: int, how: list[str]) -> None:
        nonlocal best
        if best is None or score > best.score:
            best = Match(candidate, reference, score, [h for h in how if h])

    for form, added in [(cb, []), *_strip_variants(cb)]:
        penalty = 5 * min(len(added), 2)
        extra = [f"added words: {', '.join(added)}"] if added else []
        fs = skeleton(form)
        if form == rb:
            offer(100 - penalty, extra or [sep or "identical name"])
        elif fs == rs:
            subs = substitutions(candidate, reference)
            offer(95 - penalty, [f"character substitution: {', '.join(subs) or 'look-alike letters'}", *extra])
        elif len(rs) >= MIN_TYPO_LEN and abs(len(fs) - len(rs)) <= 2:
            d = DamerauLevenshtein.distance(fs, rs)
            if 0 < d <= (1 if len(rs) < 9 else 2):
                score = max(80, int(fuzz.ratio(fs, rs))) - penalty
                offer(score, [f"typo: {d} character{'s' if d > 1 else ''} added, removed, swapped or changed", *extra])
        if best and best.score >= 95:
            break
    if best:
        return best
    full = skeleton(candidate)
    ratio = int(fuzz.ratio(full, rs))
    if len(rs) >= 8 and ratio >= 85:
        return Match(candidate, reference, ratio, [f"similar spelling ({ratio}%)"])
    if len(rs) >= FULL_NAME_LEN and rs in full:
        return Match(candidate, reference, FULL_NAME_SCORE, [f"contains the full name '{reference}' with other words"])
    if len(rs) >= 4 and rs in full:
        return Match(candidate, reference, WEAK_SCORE, ["contains the name among other words"])
    return None


def best_match(candidate: str, references: dict[str, str] | list[str]) -> tuple[Match, str] | None:
    """Best match over {reference: label}; returns (match, label of the reference) or None."""
    refs = references if isinstance(references, dict) else {r: r for r in references}
    found = [(m, label) for ref, label in refs.items() if ref and (m := compare(candidate, ref))]
    return max(found, key=lambda x: x[0].score) if found else None


def title_parts(title: str) -> list[str]:
    """'Acme Bank - Mobile Banking' -> ['Acme Bank - Mobile Banking', 'Acme Bank', 'Mobile Banking']."""
    parts = [p.strip() for p in SPLIT_RE.split(title or "") if p and p.strip()]
    return list(dict.fromkeys([(title or "").strip(), *parts]))


def best_title_match(title: str, references: dict[str, str]) -> tuple[Match, str] | None:
    hits = [h for part in title_parts(title) if (h := best_match(part, references))]
    if not hits:
        return None
    m, label = max(hits, key=lambda x: x[0].score)
    m.candidate = title
    return m, label


def is_platform_id(value: str) -> bool:
    """YouTube channel ids, Bluesky DIDs and numeric page ids are identifiers, not names to compare."""
    return bool(PLATFORM_ID_RE.match((value or "").lower()))
