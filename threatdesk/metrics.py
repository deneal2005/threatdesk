"""Dashboard numbers, computed from findings and case_events (never estimated)."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatdesk.models import CaseEvent, Finding

OPEN = ("new", "investigating", "confirmed", "takedown_requested", "monitoring")


def _first_events(db: Session, org_id: int, to_status: str) -> dict[int, object]:
    """finding_id -> time of the first status event that moved it to to_status."""
    rows = db.execute(select(CaseEvent.finding_id, func.min(CaseEvent.at))
                      .where(CaseEvent.org_id == org_id, CaseEvent.type == "status", CaseEvent.to_status == to_status)
                      .group_by(CaseEvent.finding_id)).all()
    return {fid: at for fid, at in rows}


def _fmt(td: timedelta | None) -> str:
    if td is None:
        return "-"
    hours = td.total_seconds() / 3600
    return f"{hours:.1f} h" if hours < 48 else f"{hours / 24:.1f} d"


def _avg(deltas: list[timedelta]) -> timedelta | None:
    deltas = [d for d in deltas if d.total_seconds() >= 0]
    return sum(deltas, timedelta()) / len(deltas) if deltas else None


def dashboard_metrics(db: Session, org_id: int) -> dict:
    triage = (Finding.org_id == org_id, Finding.in_triage.is_(True))
    new = db.scalar(select(func.count(Finding.id)).where(*triage, Finding.status == "new")) or 0
    by_sev = dict(db.execute(select(Finding.severity, func.count(Finding.id))
                             .where(*triage, Finding.status.in_(OPEN)).group_by(Finding.severity)).all())
    confirmed = _first_events(db, org_id, "confirmed")
    taken = _first_events(db, org_id, "taken_down")
    fps = _first_events(db, org_id, "false_positive")
    seen = dict(db.execute(select(Finding.id, Finding.first_seen).where(Finding.id.in_(list(confirmed) or [-1]))).all())
    detect = [at - seen[fid] for fid, at in confirmed.items() if fid in seen]
    takedown = [at - confirmed[fid] for fid, at in taken.items() if fid in confirmed]
    decided = len(confirmed) + len(fps)
    return {
        "new": new,
        "open": {s: by_sev.get(s, 0) for s in ("High", "Medium", "Low")},
        "detect_confirm": _fmt(_avg(detect)), "detect_confirm_n": len(detect),
        "confirm_takedown": _fmt(_avg(takedown)), "confirm_takedown_n": len(takedown),
        "precision": f"{100 * len(confirmed) / decided:.0f}%" if decided else "-", "precision_n": decided,
    }
