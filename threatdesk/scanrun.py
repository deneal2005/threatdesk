"""A brand scan as one unit of work: discovery, the investigation of every lead it finds, and a check of every
official asset that is not verified yet. Progress is read from the jobs table, so what the page shows is what ran.

Every job a scan queues carries "scan_id" (the scan job's id) in its payload.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk import jobs
from threatdesk.assets import checking, store
from threatdesk.db import utcnow
from threatdesk.models import Brand, Job

LIVE = ("queued", "running")
CHILD_TYPES = ("investigate", checking.JOB)
MAX_CHILDREN = 3000


@dataclass
class Counts:
    total: int = 0
    queued: int = 0
    running: int = 0
    done: int = 0
    failed: int = 0
    cancelled: int = 0

    def add(self, status: str) -> None:
        key = status if status in ("queued", "running", "done", "cancelled") else "failed"
        self.total += 1
        setattr(self, key, getattr(self, key) + 1)

    @property
    def finished(self) -> int:
        return self.done + self.failed + self.cancelled

    @property
    def live(self) -> int:
        return self.queued + self.running

    @property
    def percent(self) -> int:
        return round(100 * self.finished / self.total) if self.total else 100


@dataclass
class Progress:
    scan: Job
    leads: Counts = field(default_factory=Counts)
    checks: Counts = field(default_factory=Counts)
    new_findings: int = 0
    updated_findings: int = 0
    official_skipped: int = 0
    verified: int = 0
    finding_ids: list[int] = field(default_factory=list)

    @property
    def discovery(self) -> str:
        return self.scan.status

    @property
    def active(self) -> bool:
        return self.scan.status in LIVE or self.leads.live > 0 or self.checks.live > 0

    @property
    def stopped(self) -> bool:
        return bool((self.scan.payload or {}).get("stopped_at"))

    @property
    def state(self) -> str:
        """queued | running | done | partial (finished with some failures) | failed (discovery itself failed)
        | stopped (a person stopped it)."""
        if self.active:
            return "queued" if self.scan.status == "queued" and not self.checks.finished else "running"
        if self.stopped:
            return "stopped"
        if self.scan.status == "failed":
            return "failed"
        return "partial" if self.leads.failed or self.checks.failed else "done"

    @property
    def sources(self) -> list[dict]:
        return list((self.scan.result or {}).get("sources", []))

    @property
    def finished_at(self):
        return self.scan.finished


def _pending_scan(db: Session, brand: Brand) -> Job | None:
    rows = db.scalars(select(Job).where(Job.org_id == brand.org_id, Job.type == "scan", Job.status.in_(LIVE))
                      .order_by(Job.id.desc())).all()
    return next((j for j in rows if (j.payload or {}).get("brand_id") == brand.id), None)


def latest_scan(db: Session, brand: Brand) -> Job | None:
    rows = db.scalars(select(Job).where(Job.org_id == brand.org_id, Job.type == "scan")
                      .order_by(Job.id.desc()).limit(60)).all()
    return next((j for j in rows if (j.payload or {}).get("brand_id") == brand.id), None)


def start(db: Session, brand: Brand, user_id: int | None) -> tuple[Job, bool]:
    """Queue a full scan for the brand. Returns (scan job, started). A scan already queued or running is
    returned as is (started False), so double clicks and two people pressing the button never run two scans."""
    running = _pending_scan(db, brand)
    if running is not None:
        return running, False
    scan = jobs.enqueue(db, "scan", {"brand_id": brand.id}, brand.org_id, created_by=user_id, max_attempts=3)
    queued = sum(checking.enqueue_all(db, brand, kind, user_id, scan_id=scan.id) for kind in store.MODELS)
    scan.payload = {**scan.payload, "asset_checks": queued}
    db.flush()
    return scan, True


def _children(db: Session, brand: Brand, scan: Job) -> list[Job]:
    rows = db.scalars(select(Job).where(Job.org_id == brand.org_id, Job.type.in_(CHILD_TYPES), Job.id > scan.id)
                      .order_by(Job.id).limit(MAX_CHILDREN)).all()
    return [j for j in rows if (j.payload or {}).get("scan_id") == scan.id]


def stop(db: Session, brand: Brand, user_id: int | None) -> Job | None:
    """Stop the brand's queued or running scan: discovery and every lead investigation and asset check it queued
    that has not finished. Work already in flight completes on its own but is not recorded against the scan and
    queues nothing new. Returns the stopped scan, or None when nothing was running."""
    p = progress(db, brand)
    if p is None or not p.active:
        return None
    scan = p.scan
    live = [j for j in _children(db, brand, scan) if j.status in LIVE]
    jobs.cancel(db, [scan.id, *(j.id for j in live)], reason="Stopped by a teammate")
    for j in live:                          # asset rows marked "pending" for these checks go back to what they were
        payload = j.payload or {}
        if j.type != checking.JOB or payload.get("kind") not in store.MODELS:
            continue
        row = store.get_row(db, brand, payload["kind"], int(payload.get("asset_id") or 0))
        if row is not None and row.verification_status == "pending":
            row.verification_status = payload.get("prev") or "unverified"
            row.verification_method = payload.get("prev_method")
    scan.payload = {**(scan.payload or {}), "stopped_at": utcnow().isoformat(), "stopped_by": user_id}
    db.flush()
    return scan


def progress(db: Session, brand: Brand, scan: Job | None = None) -> Progress | None:
    scan = scan or latest_scan(db, brand)
    if scan is None:
        return None
    p = Progress(scan)
    for j in _children(db, brand, scan):
        res = j.result or {}
        if j.type == "investigate":
            p.leads.add(j.status)
            if j.status == "done":
                if res.get("finding_id"):
                    p.finding_ids.append(res["finding_id"])
                    if res.get("created"):
                        p.new_findings += 1
                    else:
                        p.updated_findings += 1
                elif res.get("skipped"):
                    p.official_skipped += 1
        else:
            p.checks.add(j.status)
            if j.status == "done" and res.get("status") == "verified":
                p.verified += 1
    p.new_findings += int((scan.result or {}).get("search_findings_new") or 0)
    return p
