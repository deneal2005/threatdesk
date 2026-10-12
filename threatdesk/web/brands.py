"""Brand list, create, settings, logo, allow list, scan trigger. Official assets live in web/assets.py."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk import brands as svc
from threatdesk import jobs
from threatdesk.assets import store
from threatdesk.assets.forms import parse_initial_assets
from threatdesk.db import get_db
from threatdesk.images import MAX_UPLOAD, process_logo_upload
from threatdesk.models import AssetWhitelist, Brand, User
from threatdesk.reconcile import reconcile_brand
from threatdesk.safety import InvalidInput, clean_domain, clean_text
from threatdesk.tenancy import get_owned, scoped
from threatdesk.web.brandpage import brand_page
from threatdesk.web.deps import csrf_protect, current_user
from threatdesk.web.templating import render

router = APIRouter()
CSRF = Depends(csrf_protect)


def _form_values(brand: Brand) -> dict:
    return {"name": brand.name, "keywords": ", ".join(brand.keywords or []),
            "scan_interval_hours": brand.scan_interval_hours,
            "publishers": "\n".join((brand.official_apps or {}).get("publishers", [])),
            "sensitivity": svc.sensitivity_of(brand)}


async def _logo(form) -> tuple[bytes, str] | None:
    up = form.get("logo")
    if up is None or isinstance(up, str) or not getattr(up, "filename", ""):
        return None
    data = await up.read(MAX_UPLOAD + 1)
    if not data:
        return None
    return process_logo_upload(data)


@router.get("/brands")
def list_brands(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = list(db.scalars(scoped(Brand, user.org_id).order_by(Brand.name)))
    counts, primaries = store.org_summary(db, user.org_id)
    return render(request, "brands.html", {"brands": rows, "counts": counts, "primaries": primaries})


@router.get("/brands/new")
def new_brand(request: Request, user: User = Depends(current_user)):
    return render(request, "brand_form.html", {"brand": None, "v": {"scan_interval_hours": 24,
                                                                    "sensitivity": svc.DEFAULT_SENSITIVITY}})


def _apply_settings(brand: Brand, data: svc.BrandSettings) -> None:
    brand.name, brand.keywords, brand.scan_interval_hours = data.name, data.keywords, data.scan_interval_hours
    brand.official_apps = {**(brand.official_apps or {}), "publishers": data.publishers}
    brand.detection = {**(brand.detection or {}), "sensitivity": data.sensitivity}


@router.post("/brands", dependencies=[CSRF])
async def create_brand(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    form = await request.form()
    v = {k: form.get(k) for k in ("name", "websites", "profiles", "apps", "keywords", "scan_interval_hours",
                                  "publishers", "sensitivity") if isinstance(form.get(k), str)}
    try:
        data = svc.parse_brand_settings(v)
        assets = parse_initial_assets(v)
        logo = await _logo(form)
    except InvalidInput as e:
        return render(request, "brand_form.html", {"brand": None, "v": v, "error": str(e)}, 400)
    brand = Brand(org_id=user.org_id, name=data.name, report_token=svc.new_report_token(), official_domains=[],
                  official_handles={}, official_apps={}, keywords=[])
    _apply_settings(brand, data)
    if logo:
        brand.logo_blob, brand.logo_phash = logo
    db.add(brand)
    db.flush()
    for kind in ("website", "social", "app"):
        for item in assets[kind]:
            store.add(db, brand, kind, item)
    store.sync_index(db, brand)
    db.commit()
    return RedirectResponse(f"/brands/{brand.id}?m=brand_created", status_code=303)


@router.get("/brands/{brand_id:int}")
def show_brand(brand_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    if store.migrate_legacy(db, brand):
        db.commit()
    return brand_page(request, user, db, brand)


@router.get("/brands/{brand_id:int}/edit")
def edit_brand(brand_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    return render(request, "brand_form.html", {"brand": brand, "v": _form_values(brand)})


@router.post("/brands/{brand_id:int}", dependencies=[CSRF])
async def update_brand(brand_id: int, request: Request, user: User = Depends(current_user),
                       db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    form = await request.form()
    v = {k: form.get(k) for k in ("name", "keywords", "scan_interval_hours", "publishers", "sensitivity")
         if isinstance(form.get(k), str)}
    try:
        data = svc.parse_brand_settings(v)
        logo = await _logo(form)
    except InvalidInput as e:
        return render(request, "brand_form.html", {"brand": brand, "v": v, "error": str(e)}, 400)
    _apply_settings(brand, data)
    if logo:
        brand.logo_blob, brand.logo_phash = logo
    db.commit()
    return RedirectResponse(f"/brands/{brand.id}?m=saved", status_code=303)


@router.get("/brands/{brand_id:int}/logo")
def brand_logo(brand_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    if not brand.logo_blob:
        return Response(status_code=404)
    return Response(brand.logo_blob, media_type="image/png", headers={"Cache-Control": "private, max-age=300"})


@router.post("/brands/{brand_id:int}/whitelist", dependencies=[CSRF])
async def add_whitelist(brand_id: int, request: Request, user: User = Depends(current_user),
                        db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    form = await request.form()
    type_ = str(form.get("type") or "")
    if type_ not in svc.WHITELIST_TYPES:
        raise InvalidInput("Choose what kind of entry this is.")
    value = clean_text(str(form.get("value") or ""), 300, required=True, label="Value").lower()
    if type_ == "domain":
        value = clean_domain(value)
    elif type_ == "handle":
        value = value.lstrip("@")
    reason = clean_text(str(form.get("reason") or ""), 500, label="Reason")
    db.add(AssetWhitelist(org_id=user.org_id, brand_id=brand.id, type=type_, value=value, reason=reason))
    db.flush()
    reconcile_brand(db, brand)
    db.commit()
    return RedirectResponse(f"/brands/{brand.id}?tab=allow&m=whitelisted", status_code=303)


@router.post("/brands/{brand_id:int}/whitelist/{wid:int}/delete", dependencies=[CSRF])
def delete_whitelist(brand_id: int, wid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    row = db.scalar(select(AssetWhitelist).where(AssetWhitelist.id == wid, AssetWhitelist.org_id == user.org_id,
                                                 AssetWhitelist.brand_id == brand.id))
    if row is not None:
        db.delete(row)
        db.commit()
    return RedirectResponse(f"/brands/{brand.id}?tab=allow&m=deleted", status_code=303)


@router.post("/brands/{brand_id:int}/scan", dependencies=[CSRF])
def scan_now(brand_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    if not jobs.has_pending(db, "scan", user.org_id, "brand_id", brand.id):
        jobs.enqueue(db, "scan", {"brand_id": brand.id}, user.org_id, created_by=user.id, max_attempts=3)
        db.commit()
    return RedirectResponse(f"/brands/{brand.id}?m=queued", status_code=303)
