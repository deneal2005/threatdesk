"""Findings list (filters), detail, save, case workflow, bulk false positive, user-supplied profile details."""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatdesk import cases
from threatdesk.db import get_db, utcnow
from threatdesk.images import MAX_UPLOAD
from threatdesk.metrics import OPEN
from threatdesk.models import Brand, Finding, User
from threatdesk.riskview import TIERS, tiers_for
from threatdesk.safety import InvalidInput
from threatdesk.tenancy import get_owned, scoped
from threatdesk.web.deps import csrf_protect, current_user
from threatdesk.web.reportview import report_context
from threatdesk.web.templating import render

router = APIRouter()
CSRF = Depends(csrf_protect)
VIEWS = (("open", "Open"), ("new", "New"), ("all", "All"))


def _int(v: str | None) -> int | None:
    return int(v) if v and str(v).strip().isdigit() else None


def _epoch(d: datetime) -> int:
    return int(d.replace(tzinfo=UTC).timestamp())


def _since_cutoff(raw: str, last_visit: datetime | None) -> datetime | None:
    """"since=<unix seconds>" is the cut-off the filter form was rendered with; "since=1" means the stored last visit.

    Every visit to the list moves the stored last visit to "now", so the form has to carry the earlier value:
    otherwise applying the filter would compare against the page load it was submitted from and show nothing."""
    if raw == "1":
        return last_visit
    if raw.isdigit() and len(raw) <= 12:
        return datetime.fromtimestamp(int(raw), UTC).replace(tzinfo=None)
    return None


@router.get("/findings")
def list_findings(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = request.query_params
    view = p.get("view") if p.get("view") in dict(VIEWS) else "open"
    status = p.get("status") if p.get("status") in cases.TRANSITIONS else ""
    if status:
        view = "all"
    brand_id, severity, source = _int(p.get("brand_id")), p.get("severity", ""), p.get("source", "")
    reported = p.get("reported") == "1"
    last_visit = user.last_findings_visit
    cutoff = _since_cutoff(p.get("since", ""), last_visit)
    since = cutoff is not None
    since_at = cutoff or last_visit         # shown next to the checkbox and carried in links
    query_str = p.get("q", "").strip()
    base = scoped(Finding, user.org_id).where(Finding.in_triage.is_(True))
    if brand_id:
        base = base.where(Finding.brand_id == brand_id)
    sev_raw = severity.strip().capitalize() if severity else ""
    sev_norm = "High" if severity.lower() == "critical" else sev_raw
    # Keep the canonical value so the panel preselects it and Apply/paging carry it; an unknown one is no filter
    severity = sev_norm if sev_norm in ("High", "Medium", "Low") else ""
    if severity:
        base = base.where(Finding.severity == severity)
    if source == "discovery":                  # every automated scan source ("discovery:web_search", ...)
        base = base.where(Finding.source.like("discovery:%"))
    elif source:
        base = base.where(Finding.source == source)
    if reported:
        base = base.where(Finding.is_user_submitted.is_(True))
    if query_str:
        base = base.where(
            Finding.display_name.ilike(f"%{query_str}%") | Finding.url.ilike(f"%{query_str}%")
        )
    if cutoff:
        base = base.where(Finding.first_seen > cutoff)
    views = {"open": base.where(Finding.status.in_(OPEN)), "new": base.where(Finding.status == "new"), "all": base}
    counts = {k: db.scalar(select(func.count()).select_from(q.subquery())) or 0 for k, q in views.items()}
    page = max(1, _int(p.get("page")) or 1)
    page_size = min(100, max(1, _int(p.get("page_size")) or 50))
    sort_by = p.get("sort", "score")
    if sort_by not in ("score", "newest", "oldest"):
        sort_by = "score"

    q = views[view].where(Finding.status == status) if status else views[view]
    if sort_by == "newest":
        ordered = q.order_by(Finding.last_seen.desc(), Finding.score.desc())
    elif sort_by == "oldest":
        ordered = q.order_by(Finding.first_seen.asc(), Finding.score.desc())
    else:
        ordered = q.order_by(Finding.score.desc(), Finding.last_seen.desc())

    tier_f = p.get("tier") if p.get("tier") in TIERS else ""
    if tier_f:
        # The classification is derived from signals, not stored, so filter before paging: filtering one page
        # afterwards left short or empty pages and a "matching" total that ignored the filter
        candidates = list(db.scalars(ordered))
        all_tiers = tiers_for(db, candidates)
        matched = [f for f in candidates if all_tiers[f.id] == tier_f]
        total_matching = len(matched)
    else:
        total_matching = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    total_pages = max(1, (total_matching + page_size - 1) // page_size)
    page = min(page, total_pages)            # a stale link past the last page shows the last page, not "nothing found"

    offset = (page - 1) * page_size
    if tier_f:
        rows = matched[offset:offset + page_size]
        tiers = {f.id: all_tiers[f.id] for f in rows}
    else:
        rows = list(db.scalars(ordered.offset(offset).limit(page_size)))
        tiers = tiers_for(db, rows)
    brands = list(db.scalars(scoped(Brand, user.org_id).order_by(Brand.name)))
    sources = sorted(s for (s,) in db.execute(select(Finding.source).where(Finding.org_id == user.org_id,
                                                                            Finding.in_triage.is_(True)).distinct()))
    if not since:
        user.last_findings_visit = utcnow()
        db.commit()
    filtered = bool(brand_id or severity or source or since or reported or status or tier_f or query_str)
    return render(request, "findings.html", {
        "rows": rows, "view": view, "views": VIEWS, "counts": counts, "brands": brands,
        "names": {b.id: b.name for b in brands}, "sources": sources, "brand_id": brand_id, "severity": severity,
        "status_f": status, "source": source, "since": since, "reported": reported,
        "since_at": since_at, "since_value": _epoch(since_at) if since_at else 1,
        "filtered": filtered, "statuses": list(cases.TRANSITIONS), "tiers": tiers, "tier_f": tier_f,
        "tier_info": TIERS, "query_str": query_str, "page": page, "total_pages": total_pages,
        "page_size": page_size, "total_matching": total_matching, "sort_by": sort_by})


@router.get("/findings/{fid:int}")
def finding_detail(fid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = get_owned(db, Finding, fid, user.org_id)
    ctx = report_context(db, f)
    ctx["moves"] = sorted(cases.TRANSITIONS.get(f.status, set()))
    return render(request, "finding.html", ctx)


@router.post("/findings/{fid:int}/save", dependencies=[CSRF])
def save_finding(fid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = get_owned(db, Finding, fid, user.org_id)
    if not f.in_triage:
        f.in_triage = True
        cases._event(db, f, user, "comment", "saved from an ad-hoc investigation")
        db.commit()
    return RedirectResponse(f"/findings/{f.id}?m=saved", status_code=303)


@router.post("/findings/{fid:int}/status", dependencies=[CSRF])
def set_status(fid: int, to: str = Form(""), reason: str = Form(""), whitelist: str = Form(""),
               user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = get_owned(db, Finding, fid, user.org_id)
    cases.change_status(db, f, user, to, reason)
    if to == "false_positive" and whitelist:
        cases.add_to_whitelist(db, f, reason)
    db.commit()
    return RedirectResponse(f"/findings/{f.id}?m=status", status_code=303)


@router.post("/findings/{fid:int}/assign", dependencies=[CSRF])
def set_assignee(fid: int, assignee_id: str = Form(""), user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    f = get_owned(db, Finding, fid, user.org_id)
    uid = _int(assignee_id)
    assignee = db.get(User, uid) if uid else None
    if uid and assignee is None:
        raise InvalidInput("That person is not in your organisation.")
    cases.assign(db, f, user, assignee)
    db.commit()
    return RedirectResponse(f"/findings/{f.id}?m=assigned", status_code=303)


@router.post("/findings/{fid:int}/comment", dependencies=[CSRF])
def add_comment(fid: int, body: str = Form(""), user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = get_owned(db, Finding, fid, user.org_id)
    cases.comment(db, f, user, body)
    db.commit()
    return RedirectResponse(f"/findings/{f.id}?m=commented", status_code=303)


@router.post("/findings/bulk", dependencies=[CSRF])
async def bulk(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    form = await request.form()
    ids = [i for i in (_int(str(v)) for v in form.getlist("ids")) if i][:500]
    reason = str(form.get("reason") or "")
    whitelist = bool(form.get("whitelist"))
    if not reason.strip():
        raise InvalidInput("Reason is required.")
    rows = db.scalars(scoped(Finding, user.org_id).where(Finding.id.in_(ids or [-1]))).all()   # own org only
    for f in rows:
        if "false_positive" in cases.TRANSITIONS.get(f.status, set()):
            cases.change_status(db, f, user, "false_positive", reason)
            if whitelist:
                cases.add_to_whitelist(db, f, reason)
    db.commit()
    return RedirectResponse("/findings?m=bulk", status_code=303)


@router.post("/findings/{fid:int}/profile-details", dependencies=[CSRF])
async def profile_details(fid: int, request: Request, user: User = Depends(current_user),
                          db: Session = Depends(get_db)):
    from threatdesk.userprofile import apply_profile_details
    f = get_owned(db, Finding, fid, user.org_id)
    form = await request.form()
    up = form.get("photo")
    photo = None
    if up is not None and not isinstance(up, str) and getattr(up, "filename", ""):
        photo = await up.read(MAX_UPLOAD + 1) or None
    apply_profile_details(db, f, user, {k: v for k, v in form.items() if isinstance(v, str)}, photo)
    db.commit()
    return RedirectResponse(f"/findings/{f.id}?m=details", status_code=303)
