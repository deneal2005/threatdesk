"""Keep findings consistent with the brand profile: an asset that becomes official or allow-listed leaves the queue.

Without this, a finding opened before the brand listed (or allow-listed) the asset stays open forever, because later
scans skip official assets instead of re-scoring them.
"""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk.brands import BrandContext
from threatdesk.investigator import exclusion
from threatdesk.linkdetect import detect
from threatdesk.models import AssetWhitelist, Brand, CaseEvent, Finding
from threatdesk.safety import InvalidInput
from threatdesk.scoring import VERDICT_EXCLUDED

log = logging.getLogger("threatdesk.reconcile")
AUTO_CLOSE_FROM = ("new", "investigating", "monitoring")      # never overrides an analyst's confirmation


def close_as_official(db: Session, f: Finding, reason: str, excluded: bool = True) -> bool:
    """Mark a finding as an official/allowed asset (excluded=False: keep its re-scored verdict, e.g. likely
    brand-owned); close it if it is still open. Returns True if closed."""
    if excluded:
        f.verdict, f.score, f.severity = VERDICT_EXCLUDED, 0, "Low"
    if f.status not in AUTO_CLOSE_FROM or not f.in_triage:
        return False
    db.add(CaseEvent(org_id=f.org_id, finding_id=f.id, user_id=None, type="status", to_status="false_positive",
                     body=f"{f.status} -> false_positive: closed automatically, {reason}"))
    f.status = "false_positive"
    db.flush()
    return True


def reconcile_brand(db: Session, brand: Brand) -> int:
    """Close open findings of this brand that its current official assets or allow list now cover."""
    wl = db.scalars(select(AssetWhitelist).where(AssetWhitelist.org_id == brand.org_id,
                                                 AssetWhitelist.brand_id == brand.id)).all()
    ctx = BrandContext.from_models(brand, wl)
    closed = 0
    for f in db.scalars(select(Finding).where(Finding.org_id == brand.org_id, Finding.brand_id == brand.id,
                                              Finding.verdict != VERDICT_EXCLUDED)):
        if not f.url:
            continue
        try:
            reason = exclusion(detect(f.url), ctx)
        except InvalidInput:
            continue
        if reason:
            closed += close_as_official(db, f, reason)
    if closed:
        log.info("closed findings now covered by the brand profile", extra={"fields": {"count": closed}})
    return closed
