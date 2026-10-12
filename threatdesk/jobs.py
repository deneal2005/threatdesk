"""Job queue on the jobs table: enqueue, atomic claim, finish, retry with backoff, stale reset.

State machine: queued -> running -> done
                                 -> queued (retry, attempts < max_attempts, run_after = now + backoff)
                                 -> failed (attempts exhausted)
Startup: running -> queued (the previous process died mid-job).
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from threatdesk.db import utcnow
from threatdesk.models import Job

BACKOFF_SECONDS = [10, 60, 300]


def enqueue(db: Session, type_: str, payload: dict, org_id: int | None, created_by: int | None = None,
            max_attempts: int = 3, delay_seconds: int = 0) -> Job:
    job = Job(type=type_, payload=payload, org_id=org_id, created_by=created_by, max_attempts=max_attempts,
              run_after=utcnow() + timedelta(seconds=delay_seconds))
    db.add(job)
    db.flush()
    return job


def claim_next(db: Session, types: list[str] | None = None) -> Job | None:
    """Atomically move one due job from queued to running. Safe with several workers:
    the conditional UPDATE succeeds for exactly one claimer."""
    due = select(Job.id).where(Job.status == "queued", Job.run_after <= utcnow())
    if types:
        due = due.where(Job.type.in_(types))
    # Jobs a person is waiting on (created_by set: Investigate, scan button) go before background scan work.
    candidates = list(db.scalars(due.where(Job.created_by.is_not(None)).order_by(Job.id).limit(5)))
    candidates += [j for j in db.scalars(due.order_by(Job.id).limit(5)) if j not in candidates]
    for job_id in candidates:
        res = db.execute(update(Job).where(Job.id == job_id, Job.status == "queued")
                         .values(status="running", started=utcnow(), attempts=Job.attempts + 1))
        db.commit()
        if res.rowcount == 1:
            return db.get(Job, job_id)
    return None


def finish(db: Session, job_id: int, result: dict | None = None) -> None:
    db.execute(update(Job).where(Job.id == job_id).values(status="done", finished=utcnow(), result=result, error=None))
    db.commit()


def fail(db: Session, job_id: int, error: str) -> str:
    """Record a failure; requeue with backoff or mark failed. Returns the new status."""
    job = db.get(Job, job_id)
    if job is None:
        return "missing"
    job.error = error[:1000]
    if job.attempts < job.max_attempts:
        delay = BACKOFF_SECONDS[min(job.attempts - 1, len(BACKOFF_SECONDS) - 1)]
        job.status, job.run_after = "queued", utcnow() + timedelta(seconds=delay)
    else:
        job.status, job.finished = "failed", utcnow()
    db.commit()
    return job.status


def reset_stale(db: Session) -> int:
    """At startup every 'running' job belongs to a dead process: put it back in the queue."""
    res = db.execute(update(Job).where(Job.status == "running").values(status="queued", run_after=utcnow()))
    db.commit()
    return res.rowcount or 0


def has_pending(db: Session, type_: str, org_id: int, key: str, value) -> bool:
    rows = db.scalars(select(Job).where(Job.type == type_, Job.org_id == org_id,
                                        Job.status.in_(["queued", "running"]))).all()
    return any((j.payload or {}).get(key) == value for j in rows)
