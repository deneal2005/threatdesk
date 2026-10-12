"""Measure detection accuracy on your analysts' decisions and export them as training labels.

    python -m scripts.label_report --org ORG_ID [--out labels/labels.jsonl]
    python -m scripts.label_report --all-orgs   [--out labels/labels.jsonl]

Read-only: it never changes a finding. Prints precision/recall of the stored verdicts and of today's rules (replayed
on the stored signals), per asset kind, and the rules that mostly fire on false positives. Writes one JSON line per
decided finding (signal codes and model features only, no URLs or names) for:

    python -m scripts.train_profile_model DATASET.csv --extra labels/labels.jsonl

Pooling every organisation's decisions into one shared model needs --all-orgs on purpose.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from threatdesk import labels
from threatdesk.db import session_scope


def _pct(v) -> str:
    return "-" if v is None else f"{100 * v:.0f}%"


def format_report(rep: dict) -> str:
    out = [f"decided findings: {rep['labelled']} ({rep['scam']} scam, {rep['legit']} legit); "
           f"{rep['with_profile_features']} with Instagram model features", ""]
    for name, key in (("verdicts when investigated", "stored_verdicts"), ("today's rules (replayed)", "current_rules")):
        m = rep[key]
        out.append(f"{name:28} precision {_pct(m['precision']):>4}  recall {_pct(m['recall']):>4}  "
                   f"(tp {m['tp']} fp {m['fp']} fn {m['fn']} tn {m['tn']})")
    out += ["", "by kind (today's rules):"]
    out += [f"  {k:16} n {m['n']:4}  precision {_pct(m['precision']):>4}  recall {_pct(m['recall']):>4}"
            for k, m in rep["by_kind"].items()]
    if rep["noisy_rules"]:
        out += ["", "rules that fire mostly on false positives (review their weight):"]
        out += [f"  {c:28} +{rep['rules'][c]['points']:<3} on scam {rep['rules'][c]['on_scam']:4}  "
                f"on legit {rep['rules'][c]['on_legit']:4}" for c in rep["noisy_rules"]]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    who = ap.add_mutually_exclusive_group(required=True)
    who.add_argument("--org", type=int)
    who.add_argument("--all-orgs", action="store_true")
    ap.add_argument("--out", type=Path, default=Path("labels/labels.jsonl"))
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    a = ap.parse_args(argv)
    with session_scope() as db:
        rows = labels.export(db, None if a.all_orgs else a.org)
    if not rows:
        print("no decided findings yet: confirm or mark false positive in the app first", file=sys.stderr)
        return 1
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    rep = labels.report(rows)
    print(json.dumps(rep, indent=2) if a.json else format_report(rep))
    print(f"\nwrote {len(rows)} rows to {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
