"""Request dependencies: current user (tenant scope), admin check, CSRF, client IP."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatdesk.db import get_db
from threatdesk.models import Finding, Notification, User
from threatdesk.security import CSRF_COOKIE, SESSION_COOKIE, csrf_valid, read_session


class LoginRequired(Exception):
    pass


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    data = read_session(request.cookies.get(SESSION_COOKIE))
    if not data:
        raise LoginRequired()
    user = db.get(User, int(data["uid"]))
    if user is None or user.org_id != int(data["oid"]):
        raise LoginRequired()
    request.state.user = user
    request.state.unread = db.scalar(select(func.count(Notification.id)).where(
        Notification.org_id == user.org_id, Notification.read.is_(False))) or 0
    request.state.new_count = db.scalar(select(func.count(Finding.id)).where(
        Finding.org_id == user.org_id, Finding.in_triage.is_(True), Finding.status == "new")) or 0
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Admins only.")
    return user


async def csrf_protect(request: Request) -> None:
    token = request.headers.get("x-csrf-token")
    if not token:
        form = await request.form()
        token = form.get("csrf_token")
    if not csrf_valid(request.cookies.get(CSRF_COOKIE), token if isinstance(token, str) else None):
        raise HTTPException(403, "Invalid or missing CSRF token. Reload the page and try again.")
