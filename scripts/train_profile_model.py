"""Train the Instagram fake-profile model and write threatdesk/profile_model.json.

    python -m scripts.train_profile_model DATASET.csv [--extra labels.jsonl] [--out PATH] [--force]

DATASET.csv: the public fake/real Instagram profile table (columns "profile pic", "nums/length username", ...,
"fake"), e.g. dataset.csv from github.com/allu16kumoulica/Fake-Social-Media-Profile-Detection-and-Reporting.
It is not committed here (no licence is stated); the model file records its sha256 so the run is traceable.

--extra: labelled analyst decisions exported by scripts/label_report.py; rows with Instagram profile features are
added to the training data, so the model learns from your own confirmed / false-positive findings.

Safety: 20% of DATASET.csv (fixed seed) is held out and never trained on; analyst rows only ever join the training
side. The new and the current model are both scored on those same held-out rows; if the new one is worse (lower F1
or precision), nothing is written unless --force is given. Wrong or careless labels therefore cannot slip in.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from threatdesk import profile_model as pm

MIN_PRECISION = 0.95       # the decision threshold is the lowest one that keeps cross-validated precision here
SEED = 7


def load_csv(path: Path) -> tuple[list[dict], list[int]]:
    X, y = [], []
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            row = {k.strip(): (v or "").strip() for k, v in row.items() if k}
            if row.get("fake") not in ("0", "1"):
                continue
            X.append(pm.dataset_features(row))
            y.append(int(row["fake"]))
    return X, y


def load_extra(path: Path) -> tuple[list[dict], list[int]]:
    X, y = [], []
    for line in path.read_text(encoding="utf-8").splitlines():
        rec = json.loads(line) if line.strip() else {}
        feats = rec.get("profile_features")
        if feats and rec.get("label") in ("scam", "legit") and set(pm.FEATURES) <= set(feats):
            X.append({k: float(feats[k]) for k in pm.FEATURES})
            y.append(1 if rec["label"] == "scam" else 0)
    return X, y


def _matrix(X: list[dict]):
    import numpy as np
    return np.array([[x[k] for k in pm.FEATURES] for x in X], dtype=float)


def _threshold(y, prob) -> float:
    """Lowest threshold whose precision stays >= MIN_PRECISION (high precision: a false alarm costs analyst time)."""
    for t in [i / 100 for i in range(50, 100)]:
        pred = prob >= t
        tp = int(((pred == 1) & (y == 1)).sum())
        fp = int(((pred == 1) & (y == 0)).sum())
        if tp and tp / (tp + fp) >= MIN_PRECISION:
            return t
    return 0.99


def _scores(y, prob, t: float) -> dict:
    from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
    pred = (prob >= t).astype(int)
    return {"precision": round(float(precision_score(y, pred, zero_division=0)), 3),
            "recall": round(float(recall_score(y, pred, zero_division=0)), 3),
            "f1": round(float(f1_score(y, pred, zero_division=0)), 3),
            "roc_auc": round(float(roc_auc_score(y, prob)), 3), "n": int(len(y))}


def train(X: list[dict], y: list[int], extra: tuple[list[dict], list[int]] = ([], [])) -> tuple[dict, dict]:
    import warnings

    import numpy as np
    from sklearn.ensemble import AdaBoostClassifier, RandomForestClassifier
    from sklearn.linear_model import LogisticRegressionCV
    from sklearn.model_selection import StratifiedKFold, cross_val_predict, train_test_split
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    warnings.filterwarnings("ignore", category=FutureWarning)    # sklearn API-transition notices only
    a_tr, a_te, y_tr, y_te = train_test_split(_matrix(X), np.array(y), test_size=0.2, stratify=y, random_state=SEED)
    if extra[0]:
        a_tr, y_tr = np.vstack([a_tr, _matrix(extra[0])]), np.concatenate([y_tr, extra[1]])
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    lr = lambda: make_pipeline(StandardScaler(), LogisticRegressionCV(Cs=10, cv=cv, max_iter=5000))  # noqa: E731
    cv_prob = cross_val_predict(lr(), a_tr, y_tr, cv=cv, method="predict_proba")[:, 1]
    t = _threshold(y_tr, cv_prob)
    model = lr().fit(a_tr, y_tr)
    held = _scores(y_te, model.predict_proba(a_te)[:, 1], t)
    # Reference models (not shipped): the InstaGuard AdaBoost and a random forest, on the same split, at 0.5.
    refs = {name: _scores(y_te, est.fit(a_tr, y_tr).predict_proba(a_te)[:, 1], 0.5)
            for name, est in (("adaboost_reference", AdaBoostClassifier(random_state=SEED)),
                              ("random_forest_reference", RandomForestClassifier(300, random_state=SEED)))}
    final = lr().fit(np.vstack([a_tr, a_te]), np.concatenate([y_tr, y_te]))     # ship: fitted on everything
    scaler, clf = final[0], final[-1]
    out = {"features": list(pm.FEATURES), "mean": [round(float(v), 6) for v in scaler.mean_],
           "scale": [round(float(v), 6) for v in scaler.scale_], "coef": [round(float(v), 6) for v in clf.coef_[0]],
           "intercept": round(float(clf.intercept_[0]), 6), "threshold": t}
    report = {"cv_train": _scores(y_tr, cv_prob, t), "held_out": held, **refs}
    return out, {"report": report}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("dataset", type=Path)
    ap.add_argument("--extra", type=Path)
    ap.add_argument("--out", type=Path, default=pm.MODEL_PATH)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    X, y = load_csv(a.dataset)
    extra = load_extra(a.extra) if a.extra else ([], [])
    extra_n = len(extra[1])
    if len(set(y)) < 2 or len(y) < 50:
        print(f"not enough labelled rows in {a.dataset} ({len(y)})", file=sys.stderr)
        return 2
    weights, info = train(X, y, extra)
    y = y + extra[1]
    new = info["report"]["held_out"]
    sha = hashlib.sha256(a.dataset.read_bytes()).hexdigest()
    current = pm.load.__wrapped__(str(a.out)) if a.out.exists() else None
    if current and not a.force:
        # Each model's held-out score came from a fit that never saw those rows. Same base file + same seed means
        # the same held-out rows, so the two numbers are directly comparable.
        if (current.get("training") or {}).get("dataset_sha256") != sha:
            print(f"{a.out} was trained on a different base dataset; held-out scores are not comparable. "
                  "Nothing written (use --force).", file=sys.stderr)
            return 1
        old = (current.get("metrics") or {}).get("held_out") or {}
        info["report"]["previous_model_held_out"] = old
        if new["f1"] < old.get("f1", 0) - 0.005 or new["precision"] < old.get("precision", 0) - 0.005:
            print(json.dumps(info["report"], indent=2))
            print(f"new model is worse than {a.out} on the same held-out rows; nothing written (use --force)",
                  file=sys.stderr)
            return 1
    model = {"version": datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"), **weights,
             "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "training": {"dataset_sha256": sha, "dataset_rows": len(y) - extra_n, "analyst_rows": extra_n,
                          "positive_rate": round(sum(y) / len(y), 3), "min_precision_target": MIN_PRECISION,
                          "held_out_fraction": 0.2, "seed": SEED},
             "metrics": info["report"]}
    a.out.write_text(json.dumps(model, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(info["report"], indent=2))
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
