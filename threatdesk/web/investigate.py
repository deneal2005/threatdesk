"""Investigate: paste a link -> job -> HTMX polling -> report -> save as finding / profile details."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk import jobs
from threatdesk.db import get_db
from threatdesk.linkdetect import detect
from threatdesk.models import Brand, Finding, Job, User
from threatdesk.persistence import delete_investigation
from threatdesk.safety import InvalidInput
from threatdesk.security import allow
from threatdesk.tenancy import get_owned, scoped
from threatdesk.web.deps import csrf_protect, current_user
from threatdesk.web.reportview import report_context
from threatdesk.web.templating import render

router = APIRouter()
CSRF = Depends(csrf_protect)


def _recent(db: Session, user: User) -> list[tuple[Job, Finding | None]]:
    rows = list(db.scalars(scoped(Job, user.org_id).where(Job.type == "investigate", Job.created_by == user.id)
                           .order_by(Job.id.desc()).limit(15)))
    ids = [(j.result or {}).get("finding_id") for j in rows]
    found = {f.id: f for f in db.scalars(select(Finding).where(Finding.id.in_([i for i in ids if i] or [-1]),
                                                              Finding.org_id == user.org_id))}
    return [(j, found.get((j.result or {}).get("finding_id"))) for j in rows]


def _form_page(request: Request, db: Session, user: User, status_code: int = 200, **extra):
    """The investigate form; an input error keeps the recent investigations visible."""
    brands = list(db.scalars(scoped(Brand, user.org_id).order_by(Brand.name)))
    return render(request, "investigate.html", {"brands": brands, "recent": _recent(db, user), "value": "",
                                                "brand_id": None, **extra}, status_code)


@router.get("/investigate")
def investigate_form(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _form_page(request, db, user)


@router.post("/investigate", dependencies=[CSRF])
def investigate_submit(request: Request, url: str = Form(""), brand_id: str = Form(""),
                       user: User = Depends(current_user), db: Session = Depends(get_db)):
    bid = int(brand_id) if brand_id.strip().isdigit() else None
    if not allow("investigate", str(user.id)):
        return _form_page(request, db, user, value=url[:2000], brand_id=bid, status_code=429,
                          error="Limit is 10 investigations per minute.")
    try:
        link = detect(url)
    except InvalidInput as e:
        return _form_page(request, db, user, value=url[:2000], brand_id=bid if bid else 0, status_code=400,
                          error=str(e))
    if bid is not None:
        get_owned(db, Brand, bid, user.org_id)
    job = jobs.enqueue(db, "investigate", {"url": link.url, "brand_id": bid, "source": "investigate"}, user.org_id,
                       created_by=user.id, max_attempts=2)
    db.commit()
    return RedirectResponse(f"/investigate/jobs/{job.id}", status_code=303)


def _job_ctx(db: Session, job: Job, org_id: int) -> dict:
    ctx: dict = {"job": job, "f": None}
    fid = (job.result or {}).get("finding_id")
    if job.status == "done" and fid:
        f = db.scalar(select(Finding).where(Finding.id == fid, Finding.org_id == org_id))
        if f is not None:
            ctx.update(report_context(db, f))
    return ctx


@router.get("/investigate/jobs/{job_id:int}")
def job_page(job_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    job = get_owned(db, Job, job_id, user.org_id)
    return render(request, "job.html", _job_ctx(db, job, user.org_id))


@router.post("/investigate/jobs/{job_id:int}/delete", dependencies=[CSRF])
def job_delete(job_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    job = get_owned(db, Job, job_id, user.org_id)
    if job.type != "investigate" or job.created_by != user.id:
        return RedirectResponse("/investigate", status_code=303)
    if job.status in ("queued", "running"):
        return RedirectResponse("/investigate?m=still_running", status_code=303)
    delete_investigation(db, job)
    return RedirectResponse("/investigate?m=deleted", status_code=303)


@router.get("/investigate/jobs/{job_id:int}/status")
def job_status(job_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    job = get_owned(db, Job, job_id, user.org_id)
    return render(request, "_job_status.html", _job_ctx(db, job, user.org_id))
