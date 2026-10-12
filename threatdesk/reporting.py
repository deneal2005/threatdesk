"""Per-brand summary numbers and CSV export (computed from stored data only)."""
from __future__ import annotations

import csv
import io
from collections import Counter
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatdesk.metrics import OPEN
from threatdesk.models import Campaign, CampaignFinding, CaseEvent, Finding
from threatdesk.safety import defang, defang_text

CSV_FIELDS = ["id", "brand_id", "kind", "display_name", "url_defanged", "score", "severity", "verdict", "status",
              "source", "user_submitted", "first_seen", "last_seen"]


def _first_event_times(db: Session, org_id: int, fids: list[int], to: str) -> dict[int, object]:
    rows = db.execute(select(CaseEvent.finding_id, func.min(CaseEvent.at))
                      .where(CaseEvent.org_id == org_id, CaseEvent.type == "status", CaseEvent.to_status == to,
                             CaseEvent.finding_id.in_(fids or [-1])).group_by(CaseEvent.finding_id)).all()
    return dict(rows)


def _avg_hours(deltas: list[timedelta]) -> str:
    deltas = [d for d in deltas if d.total_seconds() >= 0]
    if not deltas:
        return "-"
    return f"{sum(d.total_seconds() for d in deltas) / len(deltas) / 3600:.1f} h"


def brand_summary(db: Session, org_id: int, brand_id: int) -> dict:
    rows = list(db.scalars(select(Finding).where(Finding.org_id == org_id, Finding.brand_id == brand_id,
                                                 Finding.in_triage.is_(True))))
    fids = [f.id for f in rows]
    seen = {f.id: f.first_seen for f in rows}
    taken = _first_event_times(db, org_id, fids, "taken_down")
    confirmed = _first_event_times(db, org_id, fids, "confirmed")
    found_taken = [at - seen[fid] for fid, at in taken.items() if fid in seen]
    conf_taken = [at - confirmed[fid] for fid, at in taken.items() if fid in confirmed]
    camp_ids = {cid for (cid,) in db.execute(select(CampaignFinding.campaign_id).where(
        CampaignFinding.org_id == org_id, CampaignFinding.finding_id.in_(fids or [-1])))}
    camps = list(db.scalars(select(Campaign).where(Campaign.id.in_(camp_ids or {-1}))))
    camps.sort(key=lambda c: -len({f for s in c.shared for f in s.get("findings", [])}))
    return {
        "total": len(rows), "customer": sum(f.is_user_submitted for f in rows),
        "found_taken": _avg_hours(found_taken), "found_taken_n": len(found_taken),
        "confirmed_taken": _avg_hours(conf_taken), "confirmed_taken_n": len(conf_taken),
        "by_status": Counter(f.status for f in rows).most_common(),
        "by_severity": Counter(f.severity for f in rows).most_common(),
        "by_kind": Counter(f.kind for f in rows).most_common(),
        "open_high": sorted((f for f in rows if f.status in OPEN and f.severity == "High"),
                            key=lambda f: -f.score)[:15],
        "campaigns": camps[:5],
    }


def _cell(v) -> str:
    """Spreadsheet formula guard: a cell starting with = + - @ tab or CR is prefixed with a quote."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def findings_csv(rows: list[Finding]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_FIELDS)
    for f in rows:
        w.writerow([_cell(v) for v in (
            f.id, f.brand_id or "", f.kind, defang_text(f.display_name), defang(f.url), f.score, f.severity,
            f.verdict, f.status, f.source, "yes" if f.is_user_submitted else "no",
            f.first_seen.isoformat(timespec="seconds"), f.last_seen.isoformat(timespec="seconds"))])
    return buf.getvalue()
