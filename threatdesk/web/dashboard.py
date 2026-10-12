"""Dashboard and notifications."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from threatdesk.assets import store
from threatdesk.db import get_db
from threatdesk.metrics import dashboard_metrics
from threatdesk.models import Brand, CaseEvent, Finding, Notification, User
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
    metrics = dashboard_metrics(db, user.org_id)

    # Real recent activity from case events and newly discovered findings
    events = list(db.scalars(
        select(CaseEvent).where(CaseEvent.org_id == user.org_id).order_by(CaseEvent.at.desc()).limit(8)
    ))
    event_finding_ids = [e.finding_id for e in events]
    findings_map = {f.id: f for f in db.scalars(
        select(Finding).where(Finding.id.in_(event_finding_ids or [-1]), Finding.org_id == user.org_id)
    )}
    users_map = {u.id: u.email for u in db.scalars(select(User).where(User.org_id == user.org_id))}

    activity = []
    for e in events:
        activity.append({
            "event": e,
            "finding": findings_map.get(e.finding_id),
            "user_email": users_map.get(e.user_id, "ThreatDesk Engine"),
        })

    recent_findings = list(db.scalars(
        scoped(Finding, user.org_id).order_by(Finding.first_seen.desc()).limit(6)
    ))

    asset_counts, _ = store.org_summary(db, user.org_id)
    monitored_assets_count = sum(sum(b.values()) for b in asset_counts.values())

    return render(request, "dashboard.html", {
        "brands": brands, "queue": queue, "names": names, "metrics": metrics,
        "activity": activity, "recent_findings": recent_findings,
        "monitored_assets_count": monitored_assets_count,
    })


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

