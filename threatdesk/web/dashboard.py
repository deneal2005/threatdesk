"""Dashboard and notifications."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from threatdesk import scanrun
from threatdesk.assets import store
from threatdesk.db import get_db, utcnow
from threatdesk.metrics import dashboard_metrics
from threatdesk.models import Brand, CaseEvent, Finding, Notification, User
from threatdesk.tenancy import scoped
from threatdesk.web.deps import csrf_protect, current_user
from threatdesk.web.templating import render

router = APIRouter()


@router.get("/")
@router.get("/dashboard")
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

    # Scans in progress, or finished in the last half hour, so the result of "Scan now" is visible right here.
    scan_cards = []
    recent = utcnow() - timedelta(minutes=30)
    for b in brands[:12]:
        p = scanrun.progress(db, b)
        if p and (p.active or (p.finished_at and p.finished_at > recent) or p.scan.created > recent):
            scan_cards.append((b, p))

    return render(request, "dashboard.html", {
        "brands": brands, "queue": queue, "names": names, "metrics": metrics,
        "activity": activity, "recent_findings": recent_findings,
        "monitored_assets_count": monitored_assets_count, "scan_cards": scan_cards,
    })


MENU_SIZE = 8


def _unread(db: Session, org_id: int) -> int:
    return db.scalar(select(func.count(Notification.id)).where(Notification.org_id == org_id,
                                                               Notification.read.is_(False))) or 0


@router.get("/notifications")
def notifications(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = list(db.scalars(scoped(Notification, user.org_id).order_by(Notification.id.desc()).limit(200)))
    return render(request, "notifications.html", {"rows": rows})


def _menu(request: Request, db: Session, user: User):
    rows = list(db.scalars(scoped(Notification, user.org_id).order_by(Notification.id.desc()).limit(MENU_SIZE)))
    return render(request, "_notif_menu.html", {"rows": rows, "unread": _unread(db, user.org_id), "oob": True})


@router.get("/notifications/menu")
def notifications_menu(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """The bell's dropdown: latest alerts, read state, mark-as-read actions."""
    return _menu(request, db, user)


@router.get("/notifications/badge")
def notifications_badge(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return render(request, "_notif_badge.html", {"unread": _unread(db, user.org_id)})


@router.get("/notifications/{nid:int}/open")
def open_notification(nid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Mark one alert read and go to what it is about."""
    n = db.scalar(scoped(Notification, user.org_id).where(Notification.id == nid))
    if n is None:
        return RedirectResponse("/notifications?m=alert_gone", status_code=303)
    n.read = True
    db.commit()
    if n.finding_id and db.scalar(scoped(Finding, user.org_id).where(Finding.id == n.finding_id)) is not None:
        return RedirectResponse(f"/findings/{n.finding_id}", status_code=303)
    return RedirectResponse("/notifications?m=finding_gone" if n.finding_id else "/notifications", status_code=303)


@router.post("/notifications/{nid:int}/read", dependencies=[Depends(csrf_protect)])
def mark_one_read(nid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    db.execute(update(Notification).where(Notification.org_id == user.org_id, Notification.id == nid)
               .values(read=True))
    db.commit()
    if request.headers.get("hx-request"):
        return _menu(request, db, user)
    return RedirectResponse("/notifications", status_code=303)


@router.post("/notifications/read", dependencies=[Depends(csrf_protect)])
def mark_read(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    db.execute(update(Notification).where(Notification.org_id == user.org_id, Notification.read.is_(False))
               .values(read=True))
    db.commit()
    if request.headers.get("hx-request"):
        return _menu(request, db, user)
    return RedirectResponse("/notifications?m=all_read", status_code=303)
