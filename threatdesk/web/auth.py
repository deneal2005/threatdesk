"""Signup (creates org + admin), login, logout, user management."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatdesk.db import get_db
from threatdesk.models import Org, User
from threatdesk.safety import InvalidInput, clean_email, clean_text
from threatdesk.security import (
    DUMMY_HASH, SESSION_COOKIE, SESSION_MAX_AGE, allow, cookie_kwargs, hash_password, make_session, verify_password,
)
from threatdesk.web.deps import client_ip, csrf_protect, require_admin
from threatdesk.web.templating import render

router = APIRouter()
CSRF = Depends(csrf_protect)
MIN_PW = 10


def _login_response(user: User, message: str = "welcome") -> RedirectResponse:
    resp = RedirectResponse(f"/?m={message}", status_code=303)
    resp.set_cookie(SESSION_COOKIE, make_session(user.id, user.org_id), max_age=SESSION_MAX_AGE, **cookie_kwargs())
    return resp


def _check_password(pw: str) -> str:
    if not (MIN_PW <= len(pw or "") <= 200):
        raise InvalidInput(f"Password must be {MIN_PW}-200 characters.")
    return pw


def _email_taken(db: Session, email: str) -> bool:
    return bool(db.scalar(select(func.count(User.id)).where(User.email == email)))


@router.get("/signup")
def signup_form(request: Request):
    return render(request, "signup.html", {"v": {}})


@router.post("/signup", dependencies=[CSRF])
def signup(request: Request, org_name: str = Form(""), email: str = Form(""), password: str = Form(""),
           db: Session = Depends(get_db)):
    v = {"org_name": org_name[:120], "email": email[:254]}
    if not allow("signup", client_ip(request)):
        return render(request, "signup.html", {"v": v, "error": "Too many signups from this address. Try later."}, 429)
    try:
        name = clean_text(org_name, 120, required=True, label="Organisation name")
        mail = clean_email(email)
        _check_password(password)
        if _email_taken(db, mail):
            raise InvalidInput("That email is already registered.")
    except InvalidInput as e:
        return render(request, "signup.html", {"v": v, "error": str(e)}, 400)
    org = Org(name=name)
    db.add(org)
    db.flush()
    user = User(org_id=org.id, email=mail, password_hash=hash_password(password), role="admin")
    db.add(user)
    db.commit()
    return _login_response(user, "welcome_new")


@router.get("/login")
def login_form(request: Request):
    return render(request, "login.html", {"email": ""})


@router.post("/login", dependencies=[CSRF])
def login(request: Request, email: str = Form(""), password: str = Form(""), db: Session = Depends(get_db)):
    shown = email.strip()[:254]
    if not allow("login", client_ip(request)):
        return render(request, "login.html", {"email": shown, "error": "Too many login attempts. Wait a minute."}, 429)
    user = db.scalar(select(User).where(User.email == email.strip().lower()))
    ok = verify_password(user.password_hash if user else DUMMY_HASH, password or "")
    if not user or not ok:
        return render(request, "login.html", {"email": shown, "error": "Wrong email or password."}, 400)
    return _login_response(user)


@router.post("/logout", dependencies=[CSRF])
def logout():
    resp = RedirectResponse("/login?m=loggedout", status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.post("/settings/users", dependencies=[CSRF])
def add_user(request: Request, email: str = Form(""), password: str = Form(""), role: str = Form("analyst"),
             admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    mail = clean_email(email)
    _check_password(password)
    if role not in ("analyst", "admin"):
        raise InvalidInput("Role must be analyst or admin.")
    if _email_taken(db, mail):
        raise InvalidInput("That email is already registered.")
    db.add(User(org_id=admin.org_id, email=mail, password_hash=hash_password(password), role=role))
    db.commit()
    return RedirectResponse("/settings?m=user", status_code=303)


@router.post("/settings/users/{user_id:int}/delete", dependencies=[CSRF])
def remove_user(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    from threatdesk.tenancy import get_owned
    target = get_owned(db, User, user_id, admin.org_id)
    if target.id == admin.id:
        raise InvalidInput("Cannot remove your own user account.")
    if target.role == "admin":
        admin_count = db.scalar(
            select(func.count(User.id)).where(User.org_id == admin.org_id, User.role == "admin")
        ) or 0
        if admin_count <= 1:
            raise InvalidInput("Cannot remove the only administrator of the organisation.")
    db.delete(target)
    db.commit()
    return RedirectResponse("/settings?m=user_removed", status_code=303)


@router.get("/team")
def team_redirect(request: Request):
    return RedirectResponse("/settings#team", status_code=303)
