"""Direct DB helpers: a legacy JSON-only brand ("Acme Bank") and extra users."""
from __future__ import annotations

from sqlalchemy import select

from threatdesk import db
from threatdesk.brands import new_report_token
from threatdesk.models import Brand, Org, User
from threatdesk.security import hash_password


def make_brand(org_id: int, name: str = "Acme Bank", **kw) -> int:
    with db.session_scope() as s:
        b = Brand(org_id=org_id, name=name, report_token=new_report_token(),
                  official_domains=kw.get("domains", ["acmebank.com"]),
                  official_handles=kw.get("handles", {"instagram": ["acmebank"], "telegram": ["acmebank"]}),
                  official_apps=kw.get("apps", {"android": ["com.acme.bank"], "ios": []}),
                  keywords=kw.get("keywords", ["acme"]), scan_interval_hours=kw.get("interval", 24))
        s.add(b)
        s.flush()
        return b.id


def make_user(email: str, org_name: str = "Other Org", role: str = "admin", pw: str = "correct horse 1") -> int:
    with db.session_scope() as s:
        org = Org(name=org_name)
        s.add(org)
        s.flush()
        u = User(org_id=org.id, email=email, password_hash=hash_password(pw), role=role)
        s.add(u)
        s.flush()
        return u.id


def org_of(email: str) -> int:
    with db.session_scope() as s:
        return s.scalar(select(User.org_id).where(User.email == email))
