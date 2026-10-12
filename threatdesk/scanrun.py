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

    def add(self, status: str) -> None:
        key = status if status in ("queued", "running", "done") else "failed"
        self.total += 1
        setattr(self, key, getattr(self, key) + 1)

    @property
    def finished(self) -> int:
        return self.done + self.failed

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
    def state(self) -> str:
        """queued | running | done | partial (finished with some failures) | failed (discovery itself failed)."""
        if self.active:
            return "queued" if self.scan.status == "queued" and not self.checks.finished else "running"
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


def progress(db: Session, brand: Brand, scan: Job | None = None) -> Progress | None:
    scan = scan or latest_scan(db, brand)
    if scan is None:
        return None
    p = Progress(scan)
    children = db.scalars(select(Job).where(Job.org_id == brand.org_id, Job.type.in_(CHILD_TYPES), Job.id > scan.id)
                          .order_by(Job.id).limit(MAX_CHILDREN)).all()
    for j in children:
        payload = j.payload or {}
        if payload.get("scan_id") != scan.id:
            continue
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
