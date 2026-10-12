"""Create, update and delete official assets; keep the brand's matching index in step; migrate legacy brands."""
from __future__ import annotations

import secrets

from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from threatdesk.assets.forms import LIMITS, store_url
from threatdesk.assets.platforms import canonical_url, handle_key, label
from threatdesk.models import Brand, BrandApp, BrandSocialAccount, BrandWebsite
from threatdesk.safety import InvalidInput

MODELS = {"website": BrandWebsite, "social": BrandSocialAccount, "app": BrandApp}
FIELDS = {
    "website": ["url", "domain", "url_key", "kind", "purpose"],
    "social": ["platform", "handle", "handle_key", "platform_id", "profile_url", "display_name", "purpose", "region"],
    "app": ["platform", "store_id", "bundle_id", "name", "product", "store_url", "market", "category"],
}
# Changing any of these means it is a different asset: verification no longer applies.
IDENTITY = {"website": ["url_key"], "social": ["platform", "handle_key", "platform_id"],
            "app": ["platform", "store_id", "bundle_id"]}
COMMON = ["notes", "is_primary", "active"]
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class Conflict(Exception):
    """Someone else saved this asset after the form was opened (optimistic lock)."""


def new_token(kind: str) -> str:
    if kind == "social":           # short enough to paste into a bio
        return "TD-" + "".join(secrets.choice(CODE_ALPHABET) for _ in range(6))
    return secrets.token_urlsafe(18)


def rows(db: Session, brand: Brand, kind: str) -> list:
    m = MODELS[kind]
    return list(db.scalars(select(m).where(m.org_id == brand.org_id, m.brand_id == brand.id).order_by(m.id)))


def get_row(db: Session, brand: Brand, kind: str, asset_id: int):
    m = MODELS[kind]
    return db.scalar(select(m).where(m.id == asset_id, m.org_id == brand.org_id, m.brand_id == brand.id))


def describe(kind: str, row) -> str:
    if kind == "website":
        return row.url_key
    if kind == "social":
        h = row.handle if row.platform in ("linkedin", "reddit", "whatsapp", "other") else f"@{row.handle}"
        return f"{h} on {label(row.platform)}"
    return f"{row.name or row.store_id} ({'Android' if row.platform == 'android' else 'iOS'})"


def find_duplicate(db: Session, brand: Brand, kind: str, data: dict, exclude_id: int | None = None):
    m = MODELS[kind]
    q = select(m).where(m.org_id == brand.org_id, m.brand_id == brand.id)
    if exclude_id is not None:
        q = q.where(m.id != exclude_id)
    if kind == "website":
        return db.scalar(q.where(m.url_key == data.get("url_key")))
    if kind == "social":
        dup = db.scalar(q.where(m.platform == data.get("platform"), m.handle_key == data.get("handle_key")))
        if dup is None and data.get("platform_id"):
            dup = db.scalar(q.where(m.platform == data.get("platform"), m.platform_id == data.get("platform_id")))
        return dup
    return db.scalar(q.where(m.platform == data.get("platform"), m.store_id == data.get("store_id")))


def _clear_other_primaries(db: Session, brand: Brand, kind: str, row) -> None:
    """One primary website per brand; one primary account / app per platform."""
    for other in rows(db, brand, kind):
        if other.id != row.id and other.is_primary and (kind == "website" or other.platform == row.platform):
            other.is_primary = False
    db.flush()


def _ensure_primary_website(db: Session, brand: Brand) -> None:
    sites = rows(db, brand, "website")
    if sites and not any(s.is_primary for s in sites):
        pick = next((s for s in sites if s.active), sites[0])
        pick.is_primary = True
        db.flush()


def add(db: Session, brand: Brand, kind: str, data: dict) -> tuple[object, bool]:
    """(row, created). An identical record already on the brand is returned with created=False, so a double
    submit or a repeated paste is harmless instead of an error."""
    if dup := find_duplicate(db, brand, kind, data):
        return dup, False
    m = MODELS[kind]
    if len(rows(db, brand, kind)) >= LIMITS[kind]:
        raise InvalidInput(f"This brand already has {LIMITS[kind]} of these; remove old ones first.")
    row = m(org_id=brand.org_id, brand_id=brand.id, verify_token=new_token(kind),
            **{k: data.get(k) for k in FIELDS[kind] + COMMON if k in data})
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:                # a concurrent request saved the same asset first
        if dup := find_duplicate(db, brand, kind, data):
            return dup, False
        raise
    if row.is_primary:
        _clear_other_primaries(db, brand, kind, row)
    if kind == "website":
        _ensure_primary_website(db, brand)
    sync_index(db, brand)
    return row, True


def update(db: Session, brand: Brand, kind: str, row, data: dict, version: int | None) -> None:
    if version is not None and version != row.version:
        raise Conflict()
    if dup := find_duplicate(db, brand, kind, data, exclude_id=row.id):
        raise InvalidInput(f"{describe(kind, dup)} is already on this brand.")
    if any(data.get(k) != getattr(row, k) for k in IDENTITY[kind] if k in data):
        row.verification_status, row.verification_method, row.verified_at = "unverified", None, None
        row.verification_note = "Details changed; check again to verify."
    for k in FIELDS[kind] + COMMON:
        if k in data:
            setattr(row, k, data[k])
    if row.is_primary:
        _clear_other_primaries(db, brand, kind, row)
    db.flush()
    if kind == "website":
        _ensure_primary_website(db, brand)
    sync_index(db, brand)


def set_primary(db: Session, brand: Brand, kind: str, row) -> None:
    row.is_primary = True
    _clear_other_primaries(db, brand, kind, row)
    db.flush()
    sync_index(db, brand)


def delete(db: Session, brand: Brand, kind: str, row) -> None:
    db.delete(row)
    db.flush()
    if kind == "website":
        _ensure_primary_website(db, brand)
    sync_index(db, brand)


def _uniq(values) -> list[str]:
    out: list[str] = []
    for v in values:
        if v and v not in out:
            out.append(v)
    return out


def sync_index(db: Session, brand: Brand) -> None:
    """Rebuild brands.official_* from the active rows (inactive assets are records only, not official)."""
    sites = [s for s in rows(db, brand, "website") if s.active]
    sites.sort(key=lambda s: not s.is_primary)             # primary domain first
    accounts = [a for a in rows(db, brand, "social") if a.active]
    apps = [a for a in rows(db, brand, "app") if a.active]
    handles: dict[str, list[str]] = {}
    for a in accounts:
        handles.setdefault(a.platform, [])
        handles[a.platform] = _uniq([*handles[a.platform], a.handle_key, (a.platform_id or "").lower()])
    publishers = list((brand.official_apps or {}).get("publishers", []))
    brand.official_domains = _uniq(s.domain for s in sites)
    brand.official_handles = handles
    brand.official_apps = {"android": _uniq(a.store_id for a in apps if a.platform == "android"),
                           "ios": _uniq(a.store_id for a in apps if a.platform == "ios"),
                           "ios_bundles": _uniq(a.bundle_id for a in apps if a.platform == "ios"),
                           "publishers": publishers}
    db.flush()


def org_summary(db: Session, org_id: int) -> tuple[dict, dict]:
    """({brand_id: {"website": n, "social": n, "app": n, "verified": n}}, {brand_id: primary url_key})."""
    counts: dict[int, dict] = {}
    for kind, m in MODELS.items():
        q = (select(m.brand_id, func.count(m.id), func.sum(case((m.verification_status == "verified", 1), else_=0)))
             .where(m.org_id == org_id).group_by(m.brand_id))
        for bid, n, verified in db.execute(q).all():
            c = counts.setdefault(bid, {"website": 0, "social": 0, "app": 0, "verified": 0})
            c[kind] = n
            c["verified"] += int(verified or 0)
    primaries = dict(db.execute(select(BrandWebsite.brand_id, BrandWebsite.url_key)
                                .where(BrandWebsite.org_id == org_id, BrandWebsite.is_primary.is_(True))).all())
    return counts, primaries


LEGACY_NOTE = "Added from the brand's earlier official lists."


def migrate_legacy(db: Session, brand: Brand) -> int:
    """A brand saved before asset records existed: one row per domain, handle and app (idempotent)."""
    if any(rows(db, brand, k) for k in MODELS):
        return 0
    # Snapshot first: every add() rebuilds the index from rows and would wipe the lists still to migrate.
    domains = list(brand.official_domains or [])
    handles_by_platform = {p: list(hs) for p, hs in (brand.official_handles or {}).items()}
    apps = {k: list(v) for k, v in (brand.official_apps or {}).items()}
    made = 0
    for i, d in enumerate(domains):
        _, ok = add(db, brand, "website", {"url": f"https://{d}/", "domain": d, "url_key": d, "kind": "main",
                                           "is_primary": i == 0, "notes": LEGACY_NOTE})
        made += ok
    for plat, hs in handles_by_platform.items():
        plat = plat if plat in ("instagram", "x", "facebook", "youtube", "tiktok", "linkedin", "telegram", "whatsapp",
                                "threads", "bluesky", "pinterest", "snapchat", "reddit", "github") else "other"
        for h in hs:
            if not h:
                continue
            _, ok = add(db, brand, "social", {"platform": plat, "handle": h, "handle_key": handle_key(plat, h),
                                              "profile_url": canonical_url(plat, h), "notes": LEGACY_NOTE})
            made += ok
    for plat in ("android", "ios"):
        for sid in apps.get(plat, []):
            _, ok = add(db, brand, "app", {"platform": plat, "store_id": sid, "store_url": store_url(plat, sid),
                                           "notes": LEGACY_NOTE})
            made += ok
    brand.official_apps = {**(brand.official_apps or {}), "publishers": apps.get("publishers", [])}
    sync_index(db, brand)
    return made


def migrate_all(db: Session) -> int:
    return sum(migrate_legacy(db, b) for b in db.scalars(select(Brand)).all())

