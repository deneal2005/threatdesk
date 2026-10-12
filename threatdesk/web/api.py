"""Read-only JSON API (plus investigate) authenticated by a per-org API key: Authorization: Bearer td_..."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk import jobs
from threatdesk.assets import store
from threatdesk.db import get_db
from threatdesk.linkdetect import detect
from threatdesk.models import ApiKey, Brand, Finding, Job
from threatdesk.riskview import TIERS, tiers_for
from threatdesk.safety import InvalidInput, defang, defang_text
from threatdesk.security import allow, hash_api_key
from threatdesk.serverless import pump_if_serverless
from threatdesk.tenancy import get_owned, scoped

router = APIRouter(prefix="/api/v1")


def api_org(request: Request, db: Session = Depends(get_db)) -> int:
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    key = db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_api_key(token), ApiKey.revoked.is_(False))) \
        if token.startswith("td_") else None
    if key is None:
        raise HTTPException(401, "invalid or missing API key")
    if not allow("api", str(key.id)):
        raise HTTPException(429, "rate limit: 60 requests per minute per key")
    return key.org_id


def finding_json(f: Finding, tier: str | None = None) -> dict:
    return {"id": f.id, "brand_id": f.brand_id, "kind": f.kind, "display_name": defang_text(f.display_name),
            "url_defanged": defang(f.url), "score": f.score, "severity": f.severity, "verdict": f.verdict,
            "status": f.status, "source": f.source, "user_submitted": f.is_user_submitted,
            "first_seen": f.first_seen.isoformat(), "last_seen": f.last_seen.isoformat(),
            "classification": tier, "classification_label": TIERS[tier][0] if tier in TIERS else None}


@router.get("/findings")
def list_findings(request: Request, org_id: int = Depends(api_org), db: Session = Depends(get_db)):
    p = request.query_params
    q = scoped(Finding, org_id).where(Finding.in_triage.is_(True))
    if p.get("brand_id", "").isdigit():
        q = q.where(Finding.brand_id == int(p["brand_id"]))
    if p.get("status"):
        q = q.where(Finding.status == p["status"])
    if p.get("severity"):
        q = q.where(Finding.severity == p["severity"])
    limit = min(500, max(1, int(p["limit"]))) if p.get("limit", "").isdigit() else 100
    found = list(db.scalars(q.order_by(Finding.score.desc(), Finding.id.desc()).limit(limit)))
    tiers = tiers_for(db, found)
    rows = [finding_json(f, tiers[f.id]) for f in found]
    return {"findings": rows, "count": len(rows)}


@router.get("/findings/{fid:int}")
def get_finding(fid: int, org_id: int = Depends(api_org), db: Session = Depends(get_db)):
    f = get_owned(db, Finding, fid, org_id)
    return finding_json(f, tiers_for(db, [f])[f.id])


ASSET_FIELDS = {"website": ("url", "domain", "url_key", "kind", "purpose"),
                "social": ("platform", "handle", "platform_id", "profile_url", "display_name", "purpose", "region"),
                "app": ("platform", "store_id", "bundle_id", "name", "product", "store_url", "market", "category")}


def asset_json(kind: str, r) -> dict:
    return {"id": r.id, **{k: getattr(r, k) for k in ASSET_FIELDS[kind]}, "primary": r.is_primary, "active": r.active,
            "verification": r.verification_status, "verification_method": r.verification_method,
            "verified_at": r.verified_at.isoformat() if r.verified_at else None, "notes": r.notes}


@router.get("/brands")
def list_brands(org_id: int = Depends(api_org), db: Session = Depends(get_db)):
    counts, _ = store.org_summary(db, org_id)
    out = []
    for b in db.scalars(scoped(Brand, org_id).order_by(Brand.id)):
        c = counts.get(b.id, {})
        out.append({"id": b.id, "name": b.name, "assets": {k: c.get(k, 0) for k in ("website", "social", "app")}})
    return {"brands": out}


@router.get("/brands/{brand_id:int}/assets")
def brand_assets(brand_id: int, org_id: int = Depends(api_org), db: Session = Depends(get_db)):
    b = get_owned(db, Brand, brand_id, org_id)
    return {"brand_id": b.id, "name": b.name,
            "websites": [asset_json("website", r) for r in store.rows(db, b, "website")],
            "social_accounts": [asset_json("social", r) for r in store.rows(db, b, "social")],
            "apps": [asset_json("app", r) for r in store.rows(db, b, "app")]}


class InvestigateIn(BaseModel):
    url: str
    brand_id: int | None = None


@router.post("/investigate")
def api_investigate(body: InvestigateIn, org_id: int = Depends(api_org), db: Session = Depends(get_db)):
    try:
        link = detect(body.url)
    except InvalidInput as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    if body.brand_id is not None:
        get_owned(db, Brand, body.brand_id, org_id)
    job = jobs.enqueue(db, "investigate", {"url": link.url, "brand_id": body.brand_id, "source": "api",
                                           "in_triage": True}, org_id, max_attempts=2)
    db.commit()
    return JSONResponse({"job_id": job.id, "status": job.status, "poll": f"/api/v1/jobs/{job.id}"}, status_code=202)


@router.get("/jobs/{job_id:int}")
def get_job(job_id: int, org_id: int = Depends(api_org), _run: None = Depends(pump_if_serverless),
            db: Session = Depends(get_db)):
    j = get_owned(db, Job, job_id, org_id)
    return {"job_id": j.id, "type": j.type, "status": j.status, "attempts": j.attempts, "error": j.error,
            "result": j.result}
