"""Lookalike generators: domains (cap 400) and Telegram handles (cap 40 per handle)."""
from __future__ import annotations

import re

TLDS = ["com", "net", "org", "in", "co", "co.in", "info", "xyz", "online", "site", "app", "io", "me", "live", "shop",
        "store", "top", "club", "biz", "support"]
KEYWORDS = ["login", "secure", "verify", "support", "help", "kyc", "account", "online", "official", "care"]
HOMOGLYPHS = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "m": ["rn"], "w": ["vv"], "e": ["3"], "a": ["4"],
              "s": ["5"], "0": ["o"], "1": ["l", "i"]}
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DOMAIN_CAP = 400
TG_CAP = 40
TG_SUFFIXES = ["_official", "_support", "_care", "_help", "_customercare", "_helpdesk", "_india", "_in"]
TG_RE = re.compile(r"^[a-z][a-z0-9_]{4,31}$")


def split_domain(domain: str) -> tuple[str, str]:
    """acmebank.co.in -> ('acmebank', 'co.in')."""
    from threatdesk.checks.domain import registrable_domain
    reg = registrable_domain(domain.lower())
    label, _, suffix = reg.partition(".")
    return label, suffix


def label_variants(label: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {"omission": [], "swap": [], "repeat": [], "homoglyph": [], "hyphen": [],
                                 "keyword": []}
    for i in range(len(label)):
        out["omission"].append(label[:i] + label[i + 1:])
        out["repeat"].append(label[:i] + label[i] + label[i:])
        for g in HOMOGLYPHS.get(label[i], []):
            out["homoglyph"].append(label[:i] + g + label[i + 1:])
        if i < len(label) - 1:
            out["swap"].append(label[:i] + label[i + 1] + label[i] + label[i + 2:])
        if 0 < i:
            out["hyphen"].append(label[:i] + "-" + label[i:])
    for k in KEYWORDS:
        out["keyword"] += [f"{label}{k}", f"{label}-{k}", f"{k}{label}", f"{k}-{label}"]
    return {k: [v for v in dict.fromkeys(vs) if v != label and _valid(v)] for k, vs in out.items()}


def _valid(label: str) -> bool:
    return bool(LABEL_RE.match(label)) and len(label) >= 2 and label[2:4] != "--"


def round_robin(groups: list[list[str]], cap: int, exclude: set[str]) -> list[str]:
    out: list[str] = []
    seen = set(exclude)
    idx = 0
    while len(out) < cap and any(idx < len(g) for g in groups):
        for g in groups:
            if idx < len(g) and g[idx] not in seen:
                seen.add(g[idx])
                out.append(g[idx])
                if len(out) >= cap:
                    break
        idx += 1
    return out


def domain_candidates(domain: str, cap: int = DOMAIN_CAP) -> list[str]:
    label, suffix = split_domain(domain)
    if not label or not suffix:
        return []
    variants = label_variants(label)
    groups = [[f"{v}.{suffix}" for v in vs] for vs in variants.values()]
    groups.append([f"{label}.{t}" for t in TLDS if t != suffix])
    groups.append([f"{v}.{t}" for t in TLDS if t != suffix for v in variants["keyword"]])          # keyword + TLD
    typos = variants["omission"] + variants["swap"] + variants["homoglyph"]
    groups.append([f"{v}.{t}" for t in ("com", "in", "net", "co") if t != suffix for v in typos])
    return round_robin(groups, cap, {f"{label}.{suffix}"})


def all_domain_candidates(official: list[str], cap: int = DOMAIN_CAP) -> list[str]:
    regs = list(dict.fromkeys(".".join(split_domain(d)) for d in official if d))
    return round_robin([domain_candidates(d, cap) for d in regs], cap, set(regs))


def telegram_candidates(handle: str, cap: int = TG_CAP) -> list[str]:
    h = handle.lower().lstrip("@")
    groups = [[h + s for s in TG_SUFFIXES], [f"{h}{s.replace('_', '')}" for s in TG_SUFFIXES]]
    v = label_variants(re.sub(r"[^a-z0-9]", "", h))
    groups += [v["omission"], v["repeat"], v["swap"]]
    return [c for c in round_robin(groups, cap * 2, {h}) if TG_RE.match(c)][:cap]
