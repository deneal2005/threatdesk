"""Builds the brand detail page: tabs, per-tab search/filter/pagination, grouping and verification help."""
from __future__ import annotations

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk.assets import store
from threatdesk.assets.forms import APP_PLATFORMS, WEBSITE_KINDS
from threatdesk.assets.platforms import PLATFORMS
from threatdesk.brands import WHITELIST_TYPES
from threatdesk.config import get_settings
from threatdesk.models import AssetWhitelist, Brand, Job, User
from threatdesk.web.templating import render

TABS = [("overview", "Overview"), ("websites", "Websites"), ("social", "Social accounts"), ("apps", "Mobile apps"),
        ("allow", "Allow list")]
TAB_KIND = {"websites": "website", "social": "social", "apps": "app"}
PAGE_SIZE = 50
STATUS_FILTERS = {"": "Any status", "verified": "Verified", "unverified": "Not verified", "primary": "Primary",
                  "inactive": "Inactive"}
SEARCH_FIELDS = {
    "website": ("url", "domain", "purpose", "notes", "kind"),
    "social": ("handle", "display_name", "purpose", "region", "platform", "notes", "platform_id"),
    "app": ("name", "store_id", "bundle_id", "product", "market", "category", "notes", "platform"),
}
METHODS = {"dns_txt": "DNS TXT record", "meta_tag": "meta tag on the site", "parent_domain": "verified parent domain",
           "linked_from_website": "linked from a verified website", "bio_code": "code in the bio",
           "bluesky_domain": "Bluesky domain handle", "assetlinks": "assetlinks.json", "aasa": "apple-app-site-association"}


def report_url(request: Request, brand: Brand) -> str:
    base = get_settings().public_base_url or str(request.base_url).rstrip("/")
    return f"{base}/report/{brand.report_token}"


def _matches(row, q: str, status: str, platform: str) -> bool:
    if platform and getattr(row, "platform", None) != platform:
        return False
    if status == "verified" and row.verification_status != "verified":
        return False
    if status == "unverified" and row.verification_status == "verified":
        return False
    if status == "primary" and not row.is_primary:
        return False
    if status == "inactive" and row.active:
        return False
    if q:
        kind = "website" if hasattr(row, "url_key") else "social" if hasattr(row, "handle_key") else "app"
        hay = " ".join(str(getattr(row, f, "") or "") for f in SEARCH_FIELDS[kind]).lower()
        return all(w in hay for w in q.lower().split())
    return True


def _group(kind: str, items: list) -> list[tuple[str, list]]:
    if kind == "website":
        return [("", items)] if items else []
    if kind == "social":
        order = list(PLATFORMS)
        groups: dict[str, list] = {}
        for r in items:
            groups.setdefault(r.platform, []).append(r)
        return sorted(groups.items(), key=lambda g: order.index(g[0]) if g[0] in order else 99)
    named: dict[str, list] = {}
    unnamed = []
    for r in items:
        key = r.product or r.name
        (named.setdefault(key, []) if key else unnamed).append(r)
    ordered = sorted(named.items(), key=lambda g: (not any(r.is_primary for r in g[1]), g[0].lower()))
    return ordered + ([("", unnamed)] if unnamed else [])


def tab_view(rows: list, kind: str, params) -> dict:
    q = (params.get("q") or "").strip()[:100]
    status = params.get("status") if params.get("status") in STATUS_FILTERS else ""
    platform = (params.get("platform") or "").strip()
    present = sorted({r.platform for r in rows}, key=lambda p: list(PLATFORMS).index(p) if p in PLATFORMS else 99) \
        if kind == "social" else []
    shown = [r for r in rows if _matches(r, q, status, platform)]
    shown.sort(key=lambda r: (not r.is_primary, not r.active, r.id))
    try:
        page = max(1, int(params.get("page") or 1))
    except ValueError:
        page = 1
    pages = max(1, -(-len(shown) // PAGE_SIZE))
    page = min(page, pages)
    window = shown[(page - 1) * PAGE_SIZE: page * PAGE_SIZE]
    return {"total": len(rows), "shown": len(shown), "groups": _group(kind, window), "page": page, "pages": pages,
            "q": q, "status": status, "platform": platform, "platforms_present": present,
            "filters_on": len(rows) > 6, "filtered": bool(q or status or platform),
            "pending": any(r.verification_status == "pending" for r in rows),
            "unverified": sum(1 for r in rows if r.active and r.verification_status == "unverified")}


def _scans(db: Session, brand: Brand) -> list[Job]:
    jobs = db.scalars(select(Job).where(Job.org_id == brand.org_id, Job.type == "scan")
                      .order_by(Job.id.desc()).limit(40)).all()
    return [j for j in jobs if (j.payload or {}).get("brand_id") == brand.id][:5]


def brand_page(request: Request, user: User, db: Session, brand: Brand, tab: str | None = None,
               extra: dict | None = None, status_code: int = 200):
    tab = tab or request.query_params.get("tab") or "overview"
    if tab not in dict(TABS):
        tab = "overview"
    data = {k: store.rows(db, brand, k) for k in store.MODELS}
    from threatdesk.assets.checking import heal_stuck
    if heal_stuck(db, brand, data):
        db.commit()
    whitelist = list(db.scalars(select(AssetWhitelist).where(AssetWhitelist.org_id == user.org_id,
                                                             AssetWhitelist.brand_id == brand.id)
                                .order_by(AssetWhitelist.id.desc())))
    counts = {"websites": len(data["website"]), "social": len(data["social"]), "apps": len(data["app"]),
              "allow": len(whitelist)}
    sites, accounts, apps = data["website"], data["social"], data["app"]
    primary = next((s for s in sites if s.is_primary), sites[0] if sites else None)
    setup = []
    if not (primary and primary.verified):
        setup.append(("Verify your main website", "Proves you control it, and lets ThreatDesk confirm your accounts "
                      "and apps through it.", f"/brands/{brand.id}?tab=websites"))
    if not accounts:
        setup.append(("Add your social accounts", "Every official profile, so look-alikes of them stand out.",
                      f"/brands/{brand.id}?tab=social&add=1"))
    if not apps:
        setup.append(("Add your mobile apps", "So copycat apps in the stores stand out.",
                      f"/brands/{brand.id}?tab=apps&add=1"))
    if not brand.logo_phash:
        setup.append(("Upload your logo", "Used to spot apps and profiles that copy your icon.",
                      f"/brands/{brand.id}/edit"))
    scans = _scans(db, brand)
    params = request.query_params
    ctx = {
        "brand": brand, "tab": tab, "tabs": TABS, "counts": counts, "primary": primary, "data": data,
        "whitelist": whitelist, "whitelist_types": WHITELIST_TYPES, "setup": setup, "scans": scans,
        "scan_running": bool(scans and scans[0].status in ("queued", "running")),
        "report_link": report_url(request, brand), "website_kinds": WEBSITE_KINDS, "app_platforms": APP_PLATFORMS,
        "status_filters": STATUS_FILTERS, "methods": METHODS, "added": params.get("added"),
        "add_open": bool(params.get("add")), "last_platform": params.get("platform", ""),
        "verified_sites": [s for s in sites if s.verified and s.active], "v": {}, "form_error": "",
    }
    if tab in TAB_KIND:
        ctx["view"] = tab_view(data[TAB_KIND[tab]], TAB_KIND[tab], params)
        ctx["segment"] = tab
        ctx["kind"] = TAB_KIND[tab]
    ctx.update(extra or {})
    return render(request, "brand.html", ctx, status_code)
