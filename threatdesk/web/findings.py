"""Findings list (filters), detail, save, case workflow, bulk false positive, user-supplied profile details."""
from __future__ import annotations

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


@router.get("/findings")
def list_findings(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = request.query_params
    view = p.get("view") if p.get("view") in dict(VIEWS) else "open"
    status = p.get("status") if p.get("status") in cases.TRANSITIONS else ""
    if status:
        view = "all"
    brand_id, severity, source = _int(p.get("brand_id")), p.get("severity", ""), p.get("source", "")
    since, reported = p.get("since") == "1", p.get("reported") == "1"
    query_str = p.get("q", "").strip()
    base = scoped(Finding, user.org_id).where(Finding.in_triage.is_(True))
    if brand_id:
        base = base.where(Finding.brand_id == brand_id)
    sev_raw = severity.strip().capitalize() if severity else ""
    sev_norm = "High" if severity.lower() == "critical" else sev_raw
    if sev_norm in ("High", "Medium", "Low"):
        base = base.where(Finding.severity == sev_norm)
    if source:
        base = base.where(Finding.source == source)
    if reported:
        base = base.where(Finding.is_user_submitted.is_(True))
    if query_str:
        base = base.where(
            Finding.display_name.ilike(f"%{query_str}%") | Finding.url.ilike(f"%{query_str}%")
        )
    last_visit = user.last_findings_visit
    if since and last_visit:
        base = base.where(Finding.first_seen > last_visit)
    views = {"open": base.where(Finding.status.in_(OPEN)), "new": base.where(Finding.status == "new"), "all": base}
    counts = {k: db.scalar(select(func.count()).select_from(q.subquery())) or 0 for k, q in views.items()}
    q = views[view].where(Finding.status == status) if status else views[view]
    rows = list(db.scalars(q.order_by(Finding.score.desc(), Finding.last_seen.desc()).limit(500)))
    tiers = tiers_for(db, rows)
    tier_f = p.get("tier") if p.get("tier") in TIERS else ""
    if tier_f:
        rows = [f for f in rows if tiers[f.id] == tier_f]
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
        "status_f": status, "source": source, "since": since, "reported": reported, "last_visit": last_visit,
        "filtered": filtered, "statuses": list(cases.TRANSITIONS), "tiers": tiers, "tier_f": tier_f,
        "tier_info": TIERS, "query_str": query_str})


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
