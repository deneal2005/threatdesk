"""Delete a brand and everything that only exists because of it.

Removed: the brand, its official assets and allow list, its findings with their check results, signals, evidence,
indicators, case history and alerts, its customer reports, its campaigns, and its scan / investigation / verification
jobs. Every statement is scoped to the brand's org AND brand, so other brands' data is never touched.

Evidence is append-only for edits made through the ORM; deleting the finding it belongs to is the one sanctioned way
it goes away, so it is removed with a bulk statement (which bypasses the per-row guard on purpose).
"""
from __future__ import annotations

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from threatdesk.models import (
    AssetWhitelist, Brand, BrandApp, BrandSocialAccount, BrandWebsite, Campaign, CampaignFinding, CaseEvent,
    CheckResult, Evidence, Finding, Indicator, Job, Notification, ReportIntake, Signal,
)

CHUNK = 500
FINDING_CHILDREN = (CheckResult, Signal, Evidence, Indicator, CaseEvent, CampaignFinding, Notification)


def _chunks(ids: list[int]):
    for i in range(0, len(ids), CHUNK):
        yield ids[i:i + CHUNK]


def impact(db: Session, brand: Brand) -> dict:
    """What deleting the brand removes (shown in the confirmation)."""
    def count(model) -> int:
        return db.scalar(select(func.count()).select_from(model)
                         .where(model.org_id == brand.org_id, model.brand_id == brand.id)) or 0

    return {"findings": count(Finding), "assets": sum(count(m) for m in (BrandWebsite, BrandSocialAccount, BrandApp)),
            "reports": count(ReportIntake), "scans": len(brand_jobs(db, brand, types=("scan",)))}


def brand_jobs(db: Session, brand: Brand, types: tuple[str, ...] | None = None) -> list[int]:
    """Jobs whose payload names this brand (the jobs table stores the brand inside its JSON payload)."""
    q = select(Job).where(Job.org_id == brand.org_id)
    if types:
        q = q.where(Job.type.in_(types))
    return [j.id for j in db.scalars(q) if (j.payload or {}).get("brand_id") == brand.id]


def delete_brand(db: Session, brand: Brand) -> dict:
    org, bid = brand.org_id, brand.id
    finding_ids = list(db.scalars(select(Finding.id).where(Finding.org_id == org, Finding.brand_id == bid)))
    removed = {"findings": len(finding_ids)}

    # Campaigns: the brand's own, and any cross-brand campaign that would be left with fewer than two findings.
    own_campaigns = set(db.scalars(select(Campaign.id).where(Campaign.org_id == org, Campaign.brand_id == bid)))
    touched = set()
    for ids in _chunks(finding_ids):
        touched |= set(db.scalars(select(CampaignFinding.campaign_id).where(
            CampaignFinding.org_id == org, CampaignFinding.finding_id.in_(ids))))

    for ids in _chunks(finding_ids):
        for model in FINDING_CHILDREN:
            db.execute(delete(model).where(model.org_id == org, model.finding_id.in_(ids))
                       .execution_options(synchronize_session=False))

    gone = set(finding_ids)
    for cid in touched - own_campaigns:
        left = list(db.scalars(select(CampaignFinding.finding_id).where(CampaignFinding.org_id == org,
                                                                        CampaignFinding.campaign_id == cid)))
        camp = db.get(Campaign, cid)
        if len(left) < 2:
            own_campaigns.add(cid)
        elif camp is not None:                 # keep it, minus the deleted findings in its shared-value list
            camp.shared = [{**s, "findings": [f for f in s.get("findings", []) if f not in gone]}
                           for s in camp.shared or []]
    if own_campaigns:
        db.execute(delete(CampaignFinding).where(CampaignFinding.org_id == org,
                                                 CampaignFinding.campaign_id.in_(own_campaigns)))
        db.execute(delete(Campaign).where(Campaign.org_id == org, Campaign.id.in_(own_campaigns)))
    removed["campaigns"] = len(own_campaigns)

    # Customer reports point at findings and jobs: remove them before either.
    res = db.execute(delete(ReportIntake).where(ReportIntake.org_id == org, ReportIntake.brand_id == bid))
    removed["reports"] = res.rowcount or 0
    for ids in _chunks(finding_ids):
        db.execute(delete(Finding).where(Finding.org_id == org, Finding.id.in_(ids))
                   .execution_options(synchronize_session=False))

    # Jobs: a running one may still finish; its handler finds the brand gone and saves nothing.
    job_ids = brand_jobs(db, brand)
    for ids in _chunks(job_ids):
        db.execute(delete(Job).where(Job.org_id == org, Job.id.in_(ids)))
    removed["jobs"] = len(job_ids)

    assets = 0
    for model in (BrandWebsite, BrandSocialAccount, BrandApp, AssetWhitelist):
        assets += db.execute(delete(model).where(model.org_id == org, model.brand_id == bid)).rowcount or 0
    removed["assets"] = assets
    db.execute(delete(Brand).where(Brand.org_id == org, Brand.id == bid))
    db.expunge_all()
    return removed
