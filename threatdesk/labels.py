"""Analyst decisions as labelled data: measure the rules on real findings and feed the profile model.

A finding an analyst confirmed (or sent to takedown) is labelled "scam"; one marked false positive is "legit";
every other status is undecided and left out. Nothing here writes to the database.

Replay: the stored signals of each decided finding are re-scored with the *current* rule weights, so a weight
change can be measured against past decisions without re-running any network check.
"""
from __future__ import annotations

from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk import profile_model
from threatdesk.models import Evidence, Finding, Signal
from threatdesk.scoring import RULES, VERDICT_EXCLUDED, SignalHit, assess, verdict

SCAM_STATUSES = ("confirmed", "takedown_requested", "taken_down")
LEGIT_STATUSES = ("false_positive",)
FLAGGED = ("High risk", "Medium risk")
NOISY_MIN_FIRES = 5          # a rule needs this many decided findings before its precision is judged
NOISY_PRECISION = 0.5


def label_for(status: str | None) -> str | None:
    return "scam" if status in SCAM_STATUSES else "legit" if status in LEGIT_STATUSES else None


def _profile_features(db: Session, finding_id: int) -> dict | None:
    ev = db.scalars(select(Evidence).where(Evidence.finding_id == finding_id, Evidence.kind == "social_profile")
                    .order_by(Evidence.captured_at.desc(), Evidence.id.desc()).limit(1)).first()
    content = ev.content_json if ev else None
    if not isinstance(content, dict) or content.get("platform") != "instagram":
        return None
    return profile_model.instagram_features(content.get("raw") or {})


def export(db: Session, org_id: int | None) -> list[dict]:
    """One row per decided finding. org_id=None means every organisation (the caller must mean it).
    Rows carry signal codes and model features only: no URLs, handles or names leave the database."""
    q = select(Finding).where(Finding.status.in_(SCAM_STATUSES + LEGIT_STATUSES)).order_by(Finding.id)
    if org_id is not None:
        q = q.where(Finding.org_id == org_id)
    rows = []
    for f in db.scalars(q):
        codes = sorted({s.code for s in db.scalars(select(Signal).where(Signal.finding_id == f.id))})
        rows.append({"finding_id": f.id, "org_id": f.org_id, "brand_id": f.brand_id, "kind": f.kind,
                     "label": label_for(f.status), "status": f.status, "score": f.score, "verdict": f.verdict,
                     "checks_ran": f.checks_ran, "signals": codes,
                     "profile_features": _profile_features(db, f.id) if f.kind == "social_profile" else None})
    return rows


def replay(row: dict) -> str:
    """The verdict today's rules would give this finding's stored signals."""
    if row["verdict"] == VERDICT_EXCLUDED:
        return VERDICT_EXCLUDED
    hits = [SignalHit(c, RULES[c][0], "") for c in row["signals"] if c in RULES]
    return verdict(assess(hits, row["kind"]).score, row["checks_ran"], False, row["kind"])


def _confusion(pairs: list[tuple[str, bool]]) -> dict:
    tp = sum(lab == "scam" and hit for lab, hit in pairs)
    fp = sum(lab == "legit" and hit for lab, hit in pairs)
    fn = sum(lab == "scam" and not hit for lab, hit in pairs)
    tn = sum(lab == "legit" and not hit for lab, hit in pairs)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "n": len(pairs),
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None}


def report(rows: list[dict]) -> dict:
    """Accuracy of the stored verdicts and of today's rules, per kind, and the rules that fire on false positives."""
    stored = _confusion([(r["label"], r["verdict"] in FLAGGED) for r in rows])
    now = _confusion([(r["label"], replay(r) in FLAGGED) for r in rows])
    kinds = {k: _confusion([(r["label"], replay(r) in FLAGGED) for r in rows if r["kind"] == k])
             for k in sorted({r["kind"] for r in rows})}
    on_scam = Counter(c for r in rows if r["label"] == "scam" for c in r["signals"])
    on_legit = Counter(c for r in rows if r["label"] == "legit" for c in r["signals"])
    rules = {}
    for code in sorted(set(on_scam) | set(on_legit)):
        n = on_scam[code] + on_legit[code]
        rules[code] = {"on_scam": on_scam[code], "on_legit": on_legit[code],
                       "precision": round(on_scam[code] / n, 3), "points": RULES.get(code, (None,))[0]}
    noisy = sorted((c for c, v in rules.items() if v["points"] and v["points"] > 0
                    and v["on_scam"] + v["on_legit"] >= NOISY_MIN_FIRES and v["precision"] < NOISY_PRECISION),
                   key=lambda c: rules[c]["precision"])
    return {"labelled": len(rows), "scam": sum(r["label"] == "scam" for r in rows),
            "legit": sum(r["label"] == "legit" for r in rows),
            "with_profile_features": sum(bool(r.get("profile_features")) for r in rows),
            "stored_verdicts": stored, "current_rules": now, "by_kind": kinds, "rules": rules,
            "noisy_rules": noisy}
