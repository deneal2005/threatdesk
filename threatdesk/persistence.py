"""Persist an investigation Report as a finding with check_results, signals, evidence and indicators."""
from __future__ import annotations

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from threatdesk.checks.base import EvidenceItem
from threatdesk.db import utcnow
from threatdesk.investigator import Report
from threatdesk.jsonutil import jsonable
from threatdesk.models import (
    CampaignFinding, CaseEvent, CheckResult, Evidence, Finding, Indicator, Job, Notification, ReportIntake, Signal,
)
from threatdesk.scoring import VERDICT_EXCLUDED, severity, verdict


def scope_key(brand_id: int | None, dedupe_key: str) -> str:
    return f"{brand_id or 0}:{dedupe_key}"[:320]


def find_existing(db: Session, org_id: int, brand_id: int | None, dedupe_key: str) -> Finding | None:
    return db.scalar(select(Finding).where(Finding.org_id == org_id,
                                           Finding.scope_key == scope_key(brand_id, dedupe_key)))


def _apply(db: Session, f: Finding, r: Report) -> None:
    f.display_name, f.url, f.kind = r.display_name[:300], r.url, r.kind
    f.score, f.severity, f.verdict, f.checks_ran = r.score, r.severity, r.verdict, r.checks_ran
    f.last_seen = utcnow()
    if r.ai.get("status") == "ok":
        f.ai_json = r.ai
        f.summary_ai = r.ai.get("summary")
    db.execute(delete(CheckResult).where(CheckResult.finding_id == f.id))
    db.execute(delete(Signal).where(Signal.finding_id == f.id))
    for c in r.checks:
        db.add(CheckResult(org_id=f.org_id, finding_id=f.id, check=c["check"], status=c["status"],
                           detail=jsonable(c["detail"])))
    for s in r.signals:
        db.add(Signal(org_id=f.org_id, finding_id=f.id, code=s["code"], points=s["points"], evidence=s["evidence"]))
    for e in r.evidence:
        db.add(Evidence(org_id=f.org_id, finding_id=f.id, kind=e.kind, sha256=e.sha256, content_json=jsonable(e.content)))
    if r.facts:
        ev = EvidenceItem("investigation_facts", jsonable(r.facts))
        db.add(Evidence(org_id=f.org_id, finding_id=f.id, kind=ev.kind, sha256=ev.sha256, content_json=ev.content))
    have = set(db.execute(select(Indicator.type, Indicator.value).where(Indicator.finding_id == f.id)).all())
    for t, v in r.indicators:
        if (t, v) not in have:
            db.add(Indicator(org_id=f.org_id, finding_id=f.id, type=t, value=v))
            have.add((t, v))


def save_report(db: Session, org_id: int, brand_id: int | None, r: Report, source: str, *,
                in_triage: bool = True, user_submitted: bool = False) -> tuple[Finding, bool]:
    """Returns (finding, created). Commits."""
    for attempt in range(2):
        existing = find_existing(db, org_id, brand_id, r.dedupe_key)
        try:
            if existing:
                _apply(db, existing, r)
                existing.in_triage = existing.in_triage or in_triage
                existing.is_user_submitted = existing.is_user_submitted or user_submitted
                db.commit()
                return existing, False
            f = Finding(org_id=org_id, brand_id=brand_id, source=source, kind=r.kind, dedupe_key=r.dedupe_key[:300],
                        scope_key=scope_key(brand_id, r.dedupe_key), display_name=r.display_name[:300], url=r.url,
                        in_triage=in_triage, is_user_submitted=user_submitted, status="new")
            db.add(f)
            db.flush()
            _apply(db, f, r)
            db.commit()
            return f, True
        except IntegrityError:
            db.rollback()                      # another worker inserted the same asset: retry as an update
            if attempt:
                raise
    raise RuntimeError("unreachable")


def rescore(db: Session, f: Finding) -> None:
    """Recompute score/verdict from the stored signals and ran checks (after user-supplied details)."""
    signals = db.scalars(select(Signal).where(Signal.finding_id == f.id)).all()
    ran = len(db.scalars(select(CheckResult.id).where(CheckResult.finding_id == f.id,
                                                      CheckResult.status == "ran")).all())
    excluded = f.verdict == VERDICT_EXCLUDED
    f.score = 0 if excluded else max(0, min(100, sum(s.points for s in signals)))
    f.severity = severity(f.score)
    f.checks_ran = ran
    f.verdict = verdict(f.score, ran, excluded, f.kind)
    db.flush()


def add_evidence(db: Session, f: Finding, kind: str, content: dict) -> Evidence:
    item = EvidenceItem(kind, content)
    ev = Evidence(org_id=f.org_id, finding_id=f.id, kind=kind, sha256=item.sha256, content_json=item.content)
    db.add(ev)
    db.flush()
    return ev


def delete_investigation(db: Session, job: Job) -> bool:
    """Delete an ad-hoc investigation job. Its finding goes too only when it was never saved to triage and no
    other job produced it. Saved findings and their evidence are never deleted. Returns True if the finding went."""
    fid = (job.result or {}).get("finding_id")
    org_id, job_id = job.org_id, job.id
    db.delete(job)
    db.flush()
    f = db.get(Finding, fid) if fid else None
    if f is None or f.in_triage or f.org_id != org_id:
        db.commit()
        return False
    others = db.scalars(select(Job).where(Job.org_id == org_id, Job.type == "investigate", Job.id != job_id)).all()
    if any((j.result or {}).get("finding_id") == fid for j in others):
        db.commit()
        return False
    for model in (CheckResult, Signal, Indicator, Evidence, CampaignFinding, CaseEvent, Notification):
        db.execute(delete(model).where(model.finding_id == fid))     # bulk: scratch results only
    db.execute(update(ReportIntake).where(ReportIntake.finding_id == fid).values(finding_id=None))
    db.delete(f)
    db.commit()
    return True
