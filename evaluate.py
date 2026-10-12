"""Measure detection quality on a labelled list of URLs.

    python evaluate.py [testset.csv] [--brand-db]

testset.csv columns: url,label,brand_optional   (label = scam | legit; brand = a brand name, optional)
A row counts as predicted scam when the verdict is High or Medium risk. Prints every row, a confusion matrix,
precision, recall and every miss with its signals, and writes testset.results.csv next to the input.
--brand-db loads the named brand (official assets, keywords, logo) from the database instead of using the name only.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import sys
from dataclasses import dataclass, field
from pathlib import Path

SCAM_VERDICTS = ("High risk", "Medium risk")


@dataclass
class Row:
    line: int
    url: str
    label: str
    brand: str = ""
    verdict: str = ""
    score: int = 0
    signals: list[str] = field(default_factory=list)
    error: str = ""


def load(path: Path) -> list[Row]:
    if not path.exists():
        raise FileNotFoundError(f"{path} not found")
    rows: list[Row] = []
    with path.open(newline="", encoding="utf-8") as f:
        for i, rec in enumerate(csv.DictReader(f), start=2):
            url, label = (rec.get("url") or "").strip(), (rec.get("label") or "").strip().lower()
            if not url:
                continue
            if label not in ("scam", "legit"):
                raise ValueError(f"line {i}: label must be 'scam' or 'legit', got {label!r}")
            rows.append(Row(i, url, label, (rec.get("brand_optional") or "").strip()))
    return rows


def metrics(rows: list[Row]) -> dict:
    done = [r for r in rows if not r.error]
    tp = sum(r.label == "scam" and r.verdict in SCAM_VERDICTS for r in done)
    fp = sum(r.label == "legit" and r.verdict in SCAM_VERDICTS for r in done)
    fn = sum(r.label == "scam" and r.verdict not in SCAM_VERDICTS for r in done)
    tn = sum(r.label == "legit" and r.verdict not in SCAM_VERDICTS for r in done)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "errors": len(rows) - len(done),
            "insufficient": sum(r.verdict == "Insufficient data" for r in done),
            "precision": tp / (tp + fp) if tp + fp else None, "recall": tp / (tp + fn) if tp + fn else None}


def format_report(rows: list[Row], m: dict) -> str:
    pct = lambda v: "-" if v is None else f"{100 * v:.0f}%"  # noqa: E731
    out = [f"{r.label:5} {r.verdict or 'ERROR':18} {r.score:3}  {r.url}" + (f"  ({r.error})" if r.error else "")
           for r in rows]
    out += ["", "                 predicted scam   predicted not",
            f"actually scam    {m['tp']:14}   {m['fn']:13}", f"actually legit   {m['fp']:14}   {m['tn']:13}", "",
            f"precision {pct(m['precision'])}  recall {pct(m['recall'])}  insufficient {m['insufficient']}  "
            f"errors {m['errors']}"]
    misses = [r for r in rows if not r.error and (r.label == "scam") != (r.verdict in SCAM_VERDICTS)]
    if misses:
        out += ["", "Misses:"] + [f"  {r.label} {r.url}: {r.verdict} {r.score} {', '.join(r.signals) or 'no signals'}"
                                  for r in misses]
    return "\n".join(out)


def _brand(name: str, from_db: bool):
    from threatdesk.brands import BrandContext
    if not name:
        return BrandContext()
    if from_db:
        from sqlalchemy import select

        from threatdesk.db import session_scope
        from threatdesk.models import AssetWhitelist, Brand
        with session_scope() as s:
            b = s.scalar(select(Brand).where(Brand.name == name))
            if b is not None:
                wl = s.scalars(select(AssetWhitelist).where(AssetWhitelist.brand_id == b.id)).all()
                return BrandContext.from_models(b, wl)
    return BrandContext(name=name)


async def run(rows: list[Row], brand_db: bool) -> None:
    import httpx

    from threatdesk import scamlists
    from threatdesk.config import get_settings
    from threatdesk.investigator import investigate
    settings = get_settings()
    if settings.scam_lists:
        scamlists.load_cache(settings)
        if not scamlists.STATE.ready():
            print("downloading scam lists (first run, a few minutes)...", file=sys.stderr)
            await scamlists.refresh(settings)
    sem = asyncio.Semaphore(3)
    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=30)) as client:
        async def one(r: Row) -> None:
            async with sem:
                try:
                    rep = await investigate(r.url, brand=_brand(r.brand, brand_db), client=client)
                    r.verdict, r.score, r.signals = rep.verdict, rep.score, [s["code"] for s in rep.signals]
                except Exception as e:  # noqa: BLE001 - one bad row never stops the evaluation
                    r.error = f"{type(e).__name__}: {e}"[:120]
        await asyncio.gather(*(one(r) for r in rows))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("testset", nargs="?", default="testset.csv")
    ap.add_argument("--brand-db", action="store_true")
    a = ap.parse_args(argv)
    path = Path(a.testset)
    try:
        rows = load(path)
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"{path}: {e}", file=sys.stderr)
        return 2
    if not rows:
        print(f"{path} has no rows (columns: url,label,brand_optional)", file=sys.stderr)
        return 2
    asyncio.run(run(rows, a.brand_db))
    print(format_report(rows, metrics(rows)))
    out = path.with_name(path.stem + ".results.csv")
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label", "brand", "verdict", "score", "signals", "error"])
        for r in rows:
            w.writerow([r.url, r.label, r.brand, r.verdict, r.score, " ".join(r.signals), r.error])
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
