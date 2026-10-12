"""Builds the brand detail page: tabs, per-tab search/filter/pagination, grouping and verification help."""
from __future__ import annotations

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk import scanrun
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


SKIPPABLE = {"social": "We have no social accounts", "apps": "We have no mobile apps",
             "logo": "We'd rather not upload a logo"}


def setup_steps(brand: Brand, primary, accounts: list, apps: list, progress) -> dict:
    """What is left to set up, each step with its state and the one action that moves it forward.
    None of it gates scanning; each step only makes detection more precise."""
    bid = brand.id
    skipped = set((brand.detection or {}).get("setup_skipped") or [])
    steps = []
    if primary is None:
        steps.append({"key": "website", "state": "todo", "title": "Add your main website",
                      "why": "Scans never flag what you list, and your accounts and apps are verified through it.",
                      "detail": "No website listed yet.",
                      "href": f"/brands/{bid}?tab=websites&add=1", "label": "Add website"})
    elif primary.verification_status == "pending":
        steps.append({"key": "website", "state": "pending", "title": "Verify your main website",
                      "why": "Proves the site is yours, so accounts and apps can be verified through it.",
                      "detail": f"Checking {primary.url_key} now…", "href": f"/brands/{bid}?tab=websites"})
    elif not primary.verified:
        steps.append({"key": "website", "state": "todo", "title": "Verify your main website",
                      "why": "Proves the site is yours, so accounts and apps can be verified through it.",
                      "detail": f"{primary.url_key} is listed but not verified. Add the DNS TXT record or meta tag "
                                f"shown on the Websites tab, then check.",
                      "post": f"/brands/{bid}/websites/{primary.id}/check", "label": "Check now",
                      "href": f"/brands/{bid}?tab=websites#website-{primary.id}", "href_label": "How to verify"})
    else:
        steps.append({"key": "website", "state": "done", "title": "Main website verified",
                      "detail": f"{primary.url_key} · {METHODS.get(primary.verification_method or '', 'verified')}",
                      "href": f"/brands/{bid}?tab=websites"})
    for key, rows, noun, tab in (("social", accounts, "social account", "social"), ("apps", apps, "app", "apps")):
        title = "List your official social accounts" if key == "social" else "List your mobile apps"
        why = ("Look-alikes of your real accounts stand out, and your own regional accounts are never flagged."
               if key == "social" else "Copycat apps in the stores stand out against your real listings.")
        if rows:
            verified = sum(1 for r in rows if r.verified)
            steps.append({"key": key, "state": "done", "title": title,
                          "detail": f"{len(rows)} {noun}{'s' if len(rows) != 1 else ''} listed · {verified} verified. "
                                    "Unverified ones are checked on every Scan now.",
                          "href": f"/brands/{bid}?tab={tab}"})
        elif key in skipped:
            steps.append({"key": key, "state": "skipped", "title": title, "detail": SKIPPABLE[key] + ".",
                          "href": f"/brands/{bid}?tab={tab}&add=1", "href_label": "Add one after all"})
        else:
            steps.append({"key": key, "state": "todo", "title": title, "why": why, "detail": f"No {noun}s listed.",
                          "href": f"/brands/{bid}?tab={tab}&add=1", "label": f"Add {noun}",
                          "skip": SKIPPABLE[key]})
    if brand.logo_phash:
        steps.append({"key": "logo", "state": "done", "title": "Logo uploaded",
                      "detail": "Used to spot apps and profiles that copy your icon.", "href": f"/brands/{bid}/edit"})
    elif "logo" in skipped:
        steps.append({"key": "logo", "state": "skipped", "title": "Upload your logo", "detail": "Skipped.",
                      "href": f"/brands/{bid}/edit", "href_label": "Upload one after all"})
    else:
        steps.append({"key": "logo", "state": "todo", "title": "Upload your logo",
                      "why": "Spots apps and profiles that copy your icon.", "detail": "No logo yet.",
                      "href": f"/brands/{bid}/edit", "label": "Upload logo", "skip": SKIPPABLE["logo"]})
    if progress is None:
        steps.append({"key": "scan", "state": "todo", "title": "Run your first scan",
                      "why": "Finds look-alikes, investigates each one and checks your unverified assets.",
                      "detail": "Not scanned yet. You can scan before finishing the steps above.",
                      "post": f"/brands/{bid}/scan", "label": "Scan now"})
    elif progress.active:
        steps.append({"key": "scan", "state": "pending", "title": "First scan", "detail": "Running now: progress below.",
                      "href": f"#scan-progress-{bid}"})
    else:
        steps.append({"key": "scan", "state": "done", "title": "Scanned",
                      "detail": f"Scans repeat every {brand.scan_interval_hours} h." if brand.scan_interval_hours
                      else "Automatic scans are off; use Scan now.", "href": f"#scan-progress-{bid}"})
    finished = sum(1 for s in steps if s["state"] in ("done", "skipped"))
    return {"steps": steps, "done": finished, "total": len(steps), "complete": finished == len(steps)}


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
    scans = _scans(db, brand)
    progress = scanrun.progress(db, brand, scans[0]) if scans else None
    setup = setup_steps(brand, primary, accounts, apps, progress)
    params = request.query_params
    ctx = {
        "brand": brand, "tab": tab, "tabs": TABS, "counts": counts, "primary": primary, "data": data,
        "whitelist": whitelist, "whitelist_types": WHITELIST_TYPES, "setup": setup, "scans": scans,
        "p": progress, "scan_running": bool(progress and progress.active),
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
