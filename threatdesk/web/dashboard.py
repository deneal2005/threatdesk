"""Dashboard and notifications."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import update
from sqlalchemy.orm import Session

from threatdesk.db import get_db
from threatdesk.metrics import dashboard_metrics
from threatdesk.models import Brand, Finding, Notification, User
from threatdesk.tenancy import scoped
from threatdesk.web.deps import csrf_protect, current_user
from threatdesk.web.templating import render

router = APIRouter()


@router.get("/")
def dashboard(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    brands = list(db.scalars(scoped(Brand, user.org_id).order_by(Brand.name)))
    queue = list(db.scalars(scoped(Finding, user.org_id).where(Finding.in_triage.is_(True), Finding.status == "new")
                            .order_by(Finding.score.desc(), Finding.last_seen.desc()).limit(8)))
    names = {b.id: b.name for b in brands}
    return render(request, "dashboard.html", {"brands": brands, "queue": queue, "names": names,
                                              "metrics": dashboard_metrics(db, user.org_id)})


@router.get("/notifications")
def notifications(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = list(db.scalars(scoped(Notification, user.org_id).order_by(Notification.id.desc()).limit(200)))
    return render(request, "notifications.html", {"rows": rows})


@router.post("/notifications/read", dependencies=[Depends(csrf_protect)])
def mark_read(user: User = Depends(current_user), db: Session = Depends(get_db)):
    db.execute(update(Notification).where(Notification.org_id == user.org_id, Notification.read.is_(False))
               .values(read=True))
    db.commit()
    return RedirectResponse("/notifications", status_code=303)

