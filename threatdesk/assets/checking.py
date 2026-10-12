"""The verify_asset background job: snapshot the asset, run verification, store the outcome."""
from __future__ import annotations

import asyncio
import logging

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk import jobs
from threatdesk.assets import store
from threatdesk.db import session_scope, utcnow
from threatdesk.logs import kv
from threatdesk.models import Brand, Job

log = logging.getLogger("threatdesk.verify")
JOB = "verify_asset"
CHECK_TIMEOUT = 60
BULK_LIMIT = 50
SNAP_FIELDS = {
    "website": ("url", "domain", "url_key", "verify_token"),
    "social": ("platform", "handle", "handle_key", "platform_id", "profile_url", "verify_token"),
    "app": ("platform", "store_id", "bundle_id", "market", "store_url", "verify_token"),
}


def _live_jobs(db: Session, brand: Brand) -> set[tuple[str, int]]:
    rows = db.scalars(select(Job).where(Job.org_id == brand.org_id, Job.type == JOB,
                                        Job.status.in_(["queued", "running"]))).all()
    return {((j.payload or {}).get("kind"), (j.payload or {}).get("asset_id")) for j in rows}


def enqueue_check(db: Session, brand: Brand, kind: str, row, user_id: int | None, paid: bool) -> bool:
    """Queue one verification (skipped when one is already queued or running for this asset)."""
    if (kind, row.id) in _live_jobs(db, brand):
        return False
    prev, prev_method = row.verification_status, row.verification_method
    if prev == "pending":
        prev, prev_method = "unverified", None
    row.verification_status = "pending"
    jobs.enqueue(db, JOB, {"kind": kind, "asset_id": row.id, "brand_id": brand.id, "paid": paid, "prev": prev,
                           "prev_method": prev_method}, brand.org_id, created_by=user_id, max_attempts=1)
    db.flush()
    return True


def enqueue_all(db: Session, brand: Brand, kind: str, user_id: int | None) -> int:
    """Check every active unverified entry (never the paid profile readers)."""
    todo = [r for r in store.rows(db, brand, kind) if r.active and r.verification_status == "unverified"]
    return sum(enqueue_check(db, brand, kind, r, user_id, paid=False) for r in todo[:BULK_LIMIT])


def heal_stuck(db: Session, brand: Brand, data: dict[str, list]) -> bool:
    """A row left 'pending' with no live job (crash, restart, old process) goes back to unverified."""
    pending = [(k, r) for k, rs in data.items() for r in rs if r.verification_status == "pending"]
    if not pending:
        return False
    live = _live_jobs(db, brand)
    changed = False
    for kind, r in pending:
        if (kind, r.id) not in live:
            r.verification_status = "unverified"
            r.verification_note = "The last check didn't finish. Try again."
            changed = True
    if changed:
        db.flush()
    return changed


def _snapshot(row, kind: str) -> dict:
    return {f: getattr(row, f) for f in SNAP_FIELDS[kind]} | {"id": row.id, "name": getattr(row, "name", "")}


def _load(org_id: int, payload: dict) -> dict | None:
    with session_scope() as db:
        brand = db.scalar(select(Brand).where(Brand.id == payload.get("brand_id"), Brand.org_id == org_id))
        if brand is None:
            return None
        row = store.get_row(db, brand, payload["kind"], int(payload["asset_id"]))
        if row is None:
            return None
        sites = [s for s in store.rows(db, brand, "website") if s.verified and s.active and s.id != row.id]
        return {"snap": _snapshot(row, payload["kind"]),
                "verified_domains": [s.domain for s in sites],
                "verified_urls": [s.url for s in sites][:3]}


async def _run(client: httpx.AsyncClient, kind: str, snap: dict, paid: bool, verified_domains: list[str] = (),
               verified_urls: list[str] = ()):
    from threatdesk.assets import verify
    from threatdesk.config import get_settings
    if kind == "website":
        return await verify.verify_website(client, snap, list(verified_domains))
    pages = verify.Pages(client, list(verified_urls))
    if kind == "social":
        return await verify.verify_social(client, get_settings(), snap, list(verified_domains), pages, paid)
    return await verify.verify_app(client, snap, list(verified_urls), pages)


def _save(org_id: int, payload: dict, snap: dict, out) -> dict:
    kind = payload["kind"]
    with session_scope() as db:
        brand = db.scalar(select(Brand).where(Brand.id == payload.get("brand_id"), Brand.org_id == org_id))
        row = store.get_row(db, brand, kind, int(payload["asset_id"])) if brand else None
        if row is None:
            return {"skipped": "asset removed during the check"}
        if any(getattr(row, f) != snap.get(f) for f in store.IDENTITY[kind]):
            return {"skipped": "asset changed during the check"}
        if out.status is None:                       # inconclusive: never downgrade
            row.verification_status = payload.get("prev") or "unverified"
            row.verification_method = payload.get("prev_method")
        else:
            row.verification_status = out.status
            if out.status == "verified":
                row.verification_method, row.verified_at = out.method, utcnow()
            else:
                row.verification_method, row.verified_at = None, None
        row.verification_note = out.note[:1000] if out.note else None
        for k, v in (out.fill or {}).items():
            if v and hasattr(row, k) and not getattr(row, k):
                setattr(row, k, str(v)[:120])
        store.sync_index(db, brand)
        return {"kind": kind, "asset_id": row.id, "status": row.verification_status, "method": row.verification_method}


async def handle_verify(jid: int, payload: dict, org_id: int | None) -> dict:
    from threatdesk.assets.verify import Outcome
    loaded = await asyncio.to_thread(_load, org_id, payload)
    if loaded is None:
        return {"skipped": "asset or brand not found"}
    snap = loaded["snap"]
    try:
        async with httpx.AsyncClient(limits=httpx.Limits(max_connections=10)) as client:
            out = await asyncio.wait_for(_run(client, payload["kind"], snap, bool(payload.get("paid")),
                                              loaded["verified_domains"], loaded["verified_urls"]), CHECK_TIMEOUT)
    except Exception as e:  # noqa: BLE001 - the row must never stay "pending"
        log.warning("verification failed", extra=kv(kind=payload.get("kind"), error=type(e).__name__))
        out = Outcome(None, None, "The check could not finish (network or timeout). Try again later.")
    return await asyncio.to_thread(_save, org_id, payload, snap, out)
