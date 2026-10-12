"""Brand list, create, settings, logo, allow list, scan trigger. Official assets live in web/assets.py."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk import brands as svc
from threatdesk import branddelete, scanrun
from threatdesk.assets import store
from threatdesk.assets.forms import parse_initial_assets
from threatdesk.db import get_db
from threatdesk.images import MAX_UPLOAD, process_logo_upload
from threatdesk.models import AssetWhitelist, Brand, User
from threatdesk.reconcile import reconcile_brand
from threatdesk.safety import InvalidInput, clean_domain, clean_text
from threatdesk.tenancy import get_owned, scoped
from threatdesk.web.brandpage import brand_page
from threatdesk.web.deps import csrf_protect, current_user, require_admin
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


@router.get("/brands/{brand_id:int}/delete")
def confirm_delete_brand(brand_id: int, request: Request, user: User = Depends(require_admin),
                         db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    return render(request, "brand_delete.html", {"brand": brand, "impact": branddelete.impact(db, brand)})


@router.post("/brands/{brand_id:int}/delete", dependencies=[CSRF])
async def delete_brand(brand_id: int, request: Request, user: User = Depends(require_admin),
                       db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    typed = str((await request.form()).get("confirm_name") or "").strip()
    if typed.casefold() != brand.name.strip().casefold():
        return render(request, "brand_delete.html", {
            "brand": brand, "impact": branddelete.impact(db, brand),
            "error": "The name you typed doesn't match, so nothing was deleted."}, 400)
    branddelete.delete_brand(db, brand)
    db.commit()
    return RedirectResponse("/brands?m=brand_deleted", status_code=303)


@router.get("/brands/{brand_id:int}/logo")
def brand_logo(brand_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    if not brand.logo_blob:
        return Response(status_code=404)
    return Response(brand.logo_blob, media_type="image/png", headers={"Cache-Control": "private, max-age=300"})


@router.post("/brands/{brand_id:int}/setup/{step}/{action}", dependencies=[CSRF])
def setup_skip(brand_id: int, step: str, action: str, user: User = Depends(current_user),
               db: Session = Depends(get_db)):
    """Mark an optional setup step as not applicable (no apps, no social accounts), or undo that."""
    from threatdesk.web.brandpage import SKIPPABLE
    brand = get_owned(db, Brand, brand_id, user.org_id)
    if step not in SKIPPABLE or action not in ("skip", "unskip"):
        raise HTTPException(404, "Not found.")
    det = dict(brand.detection or {})
    skipped = [s for s in det.get("setup_skipped") or [] if s != step]
    det["setup_skipped"] = skipped + ([step] if action == "skip" else [])
    brand.detection = det
    db.commit()
    return RedirectResponse(f"/brands/{brand.id}?m=saved", status_code=303)


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


def _after_scan(back: str, brand: Brand, started: bool) -> RedirectResponse:
    m = "queued" if started else "scan_already_running"
    if back == "dashboard":
        return RedirectResponse(f"/?m={m}", status_code=303)
    return RedirectResponse(f"/brands/{brand.id}?m={m}", status_code=303)


@router.post("/brands/{brand_id:int}/scan", dependencies=[CSRF])
async def scan_now(brand_id: int, request: Request, user: User = Depends(current_user),
                   db: Session = Depends(get_db)):
    """Discovery, investigation of every lead, and a check of every unverified official asset, in the background."""
    brand = get_owned(db, Brand, brand_id, user.org_id)
    _scan, started = scanrun.start(db, brand, user.id)
    db.commit()
    back = str((await request.form()).get("back") or "")
    if request.headers.get("hx-request"):
        return brand_scan_panel(request, db, brand, compact=back == "dashboard")
    return _after_scan(back, brand, started)


@router.post("/brands/{brand_id:int}/scan/stop", dependencies=[CSRF])
async def scan_stop(brand_id: int, request: Request, user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    """Stop the brand's running scan and everything it queued that hasn't finished."""
    brand = get_owned(db, Brand, brand_id, user.org_id)
    stopped = scanrun.stop(db, brand, user.id)
    db.commit()
    back = str((await request.form()).get("back") or "")
    if request.headers.get("hx-request"):
        return brand_scan_panel(request, db, brand, compact=back == "dashboard")
    m = "scan_stopped" if stopped else "scan_not_running"
    return RedirectResponse(f"/?m={m}" if back == "dashboard" else f"/brands/{brand.id}?m={m}", status_code=303)


@router.get("/brands/{brand_id:int}/scan/button")
def scan_button(brand_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """The header scan button alone, for tabs without the progress panel: it polls itself while a scan runs."""
    brand = get_owned(db, Brand, brand_id, user.org_id)
    p = scanrun.progress(db, brand)
    return render(request, "_scan_button.html", {"brand": brand, "scan_running": bool(p and p.active),
                                                 "self_poll": True})


@router.post("/scan-all", dependencies=[CSRF])
def scan_all(user: User = Depends(current_user), db: Session = Depends(get_db)):
    started = [scanrun.start(db, b, user.id)[1] for b in db.scalars(scoped(Brand, user.org_id))]
    db.commit()
    m = "queued_all" if any(started) else "scan_already_running" if started else "no_brands"
    return RedirectResponse(f"/?m={m}", status_code=303)


def brand_scan_panel(request: Request, db: Session, brand: Brand, compact: bool = False, button: bool = False):
    """The progress panel; on a poll it also refreshes the page's scan button (the brand header, or the dashboard's
    when it scans a single brand) so the button re-enables when the scan ends."""
    p = scanrun.progress(db, brand)
    polled = bool(request.headers.get("hx-request"))
    return render(request, "_scan_progress.html", {
        "brand": brand, "p": p, "compact": compact, "with_button": button, "scan_running": bool(p and p.active),
        "oob_button": polled and (button or not compact)})


@router.get("/brands/{brand_id:int}/scan/progress")
def scan_progress(brand_id: int, request: Request, compact: int = 0, button: int = 0,
                  user: User = Depends(current_user), db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    return brand_scan_panel(request, db, brand, compact=bool(compact), button=bool(button))


@router.get("/discovery")
def discovery_redirect(request: Request):
    return RedirectResponse("/brands", status_code=303)
