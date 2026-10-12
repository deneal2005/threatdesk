"""Official websites, social accounts and app listings: add, edit, remove, make primary, check (verify)."""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from threatdesk.assets import checking, forms, store
from threatdesk.assets.platforms import PLATFORMS
from threatdesk.db import get_db
from threatdesk.models import Brand, User
from threatdesk.reconcile import reconcile_brand
from threatdesk.safety import InvalidInput
from threatdesk.tenancy import get_owned
from threatdesk.web.brandpage import METHODS, brand_page
from threatdesk.web.deps import csrf_protect, current_user
from threatdesk.web.templating import render

router = APIRouter()
SEGMENTS = {"websites": "website", "social": "social", "apps": "app"}
TAB = {v: k for k, v in SEGMENTS.items()}
CSRF = Depends(csrf_protect)


@router.get("/assets")
def assets_index_redirect():
    return RedirectResponse("/brands", status_code=303)



def _kind(segment: str) -> str:
    if segment not in SEGMENTS:
        raise HTTPException(404, "Not found.")
    return SEGMENTS[segment]


def _asset(db: Session, brand: Brand, kind: str, asset_id: int):
    row = store.get_row(db, brand, kind, asset_id)
    if row is None:
        raise HTTPException(404, "Not found.")
    return row


def _back(brand: Brand, kind: str, m: str, **params) -> RedirectResponse:
    q = urlencode({"tab": TAB[kind], "m": m, **{k: v for k, v in params.items() if v not in (None, "")}})
    return RedirectResponse(f"/brands/{brand.id}?{q}", status_code=303)


async def _form(request: Request) -> dict:
    return {k: v for k, v in (await request.form()).items() if isinstance(v, str)}


def _parse(kind: str, form: dict) -> list[dict]:
    if kind == "website":
        return [forms.parse_website(form)]
    if kind == "social":
        return [forms.parse_social(form)]
    return forms.parse_new_app(form)


def checking_useful(db: Session, brand: Brand, kind: str, row) -> bool:
    """Check a new entry automatically only when it can succeed without the owner doing anything first."""
    self_id = row.id if kind == "website" else None                  # ids are per table
    sites = [s for s in store.rows(db, brand, "website") if s.verified and s.active and s.id != self_id]
    if kind == "website":
        return any(row.domain == s.domain or row.domain.endswith("." + s.domain) for s in sites)
    return bool(sites)


@router.post("/brands/{brand_id:int}/{segment}", dependencies=[CSRF])
async def add_asset(brand_id: int, segment: str, request: Request, user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    kind = _kind(segment)
    form = await _form(request)
    try:
        items = _parse(kind, form)
        results = [store.add(db, brand, kind, item) for item in items]
    except InvalidInput as e:
        db.rollback()
        return brand_page(request, user, db, brand, TAB[kind],
                          {"v": form, "form_error": str(e), "add_open": True}, 400)
    created = [r for r, new in results if new]
    for row in created:
        if checking_useful(db, brand, kind, row):
            checking.enqueue_check(db, brand, kind, row, user.id, paid=False)
    if created:
        reconcile_brand(db, brand)
    db.commit()
    first = results[0][0]
    return _back(brand, kind, "asset_added" if created else "asset_exists", added=first.id, add=1,
                 platform=form.get("platform") if kind == "social" and form.get("platform") in PLATFORMS else None)


@router.post("/brands/{brand_id:int}/{segment}/check-all", dependencies=[CSRF])
def check_all(brand_id: int, segment: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    kind = _kind(segment)
    n = checking.enqueue_all(db, brand, kind, user.id)
    db.commit()
    return _back(brand, kind, "checking_all" if n else "nothing_to_check")


@router.get("/brands/{brand_id:int}/{segment}/{asset_id:int}/edit")
def edit_asset(brand_id: int, segment: str, asset_id: int, request: Request, user: User = Depends(current_user),
               db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    kind = _kind(segment)
    return _edit_page(request, brand, kind, _asset(db, brand, kind, asset_id))


def _edit_page(request: Request, brand: Brand, kind: str, row, error: str = "", v: dict | None = None,
               status_code: int = 200):
    return render(request, "asset_edit.html", {"brand": brand, "kind": kind, "segment": TAB[kind], "r": row,
                                               "v": v or {}, "error": error, "website_kinds": forms.WEBSITE_KINDS,
                                               "methods": METHODS, "label": store.describe(kind, row)}, status_code)


def _edit_data(kind: str, row, form: dict) -> dict:
    if kind == "website":
        return forms.parse_website(form)
    if kind == "social":
        return forms.parse_social({**form, "platform": form.get("platform") or row.platform})
    ref = form.get("store_ref") or row.store_id
    return forms.parse_app_listing(row.platform, ref, form, form.get("bundle_id", ""))


@router.post("/brands/{brand_id:int}/{segment}/{asset_id:int}", dependencies=[CSRF])
async def update_asset(brand_id: int, segment: str, asset_id: int, request: Request,
                       user: User = Depends(current_user), db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    kind = _kind(segment)
    row = store.get_row(db, brand, kind, asset_id)
    if row is None:
        return _back(brand, kind, "asset_gone")
    form = await _form(request)
    try:
        version = int(form.get("version") or 0) or None
    except ValueError:
        version = None
    conflict = "Someone else changed this while you were editing. Here is the latest version; make your change again."
    try:
        store.update(db, brand, kind, row, _edit_data(kind, row, form), version)
        reconcile_brand(db, brand)
        db.commit()
    except InvalidInput as e:
        db.rollback()
        return _edit_page(request, brand, kind, store.get_row(db, brand, kind, asset_id), str(e), form, 400)
    except (store.Conflict, StaleDataError):
        db.rollback()
        fresh = store.get_row(db, brand, kind, asset_id)
        if fresh is None:
            return _back(brand, kind, "asset_gone")
        return _edit_page(request, brand, kind, fresh, conflict, None, 409)
    return _back(brand, kind, "asset_saved")


@router.post("/brands/{brand_id:int}/{segment}/{asset_id:int}/delete", dependencies=[CSRF])
def delete_asset(brand_id: int, segment: str, asset_id: int, user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    kind = _kind(segment)
    row = store.get_row(db, brand, kind, asset_id)
    if row is not None:                         # idempotent: already gone is fine
        store.delete(db, brand, kind, row)
        db.commit()
    return _back(brand, kind, "asset_removed")


@router.post("/brands/{brand_id:int}/{segment}/{asset_id:int}/primary", dependencies=[CSRF])
def make_primary(brand_id: int, segment: str, asset_id: int, user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    kind = _kind(segment)
    row = store.get_row(db, brand, kind, asset_id)
    if row is None:
        return _back(brand, kind, "asset_gone")
    store.set_primary(db, brand, kind, row)
    db.commit()
    return _back(brand, kind, "asset_primary")


@router.post("/brands/{brand_id:int}/{segment}/{asset_id:int}/check", dependencies=[CSRF])
def check_asset(brand_id: int, segment: str, asset_id: int, user: User = Depends(current_user),
                db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    kind = _kind(segment)
    row = store.get_row(db, brand, kind, asset_id)
    if row is None:
        return _back(brand, kind, "asset_gone")
    checking.enqueue_check(db, brand, kind, row, user.id, paid=True)
    db.commit()
    return _back(brand, kind, "checking")
