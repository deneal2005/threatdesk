"""Settings: org users, API keys, integration status (configured or not; values are never shown)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from threatdesk.config import get_settings
from threatdesk.db import get_db
from threatdesk.models import ApiKey, Org, User
from threatdesk.monitoring import clean_webhook, mask_webhook, send_external
from threatdesk.safety import InvalidInput, clean_email, clean_text
from threatdesk.security import new_api_key
from threatdesk.tenancy import get_owned, scoped
from threatdesk.web.deps import csrf_protect, current_user, require_admin
from threatdesk.web.templating import render

router = APIRouter()
CSRF = Depends(csrf_protect)


def integrations() -> list[tuple[str, str, bool]]:
    s = get_settings()
    return [
        ("Gemini AI", "GEMINI_API_KEY", bool(s.gemini_api_key)),
        ("YouTube Data API", "YOUTUBE_API_KEY", bool(s.youtube_api_key)),
        ("Google Safe Browsing", "SAFE_BROWSING_API_KEY", bool(s.safe_browsing_api_key)),
        ("VirusTotal", "VT_API_KEY", bool(s.vt_api_key)),
        ("URLhaus", "URLHAUS_AUTH_KEY", bool(s.urlhaus_auth_key)),
        ("Google Custom Search", "GOOGLE_CSE_KEY + GOOGLE_CSE_CX", bool(s.google_cse_key and s.google_cse_cx)),
        ("Brave Search", "BRAVE_API_KEY", bool(s.brave_api_key)),
        ("Apify profile reader", "APIFY_TOKEN", bool(s.apify_token)),
        ("Public scam lists", "SCAM_LISTS", s.scam_lists),
        ("PhishTank", "PHISHTANK_APP_KEY (optional)", True),
        ("Email relay", "SMTP_HOST", bool(s.smtp_host and s.smtp_from)),
        ("Cron endpoint", "CRON_SECRET", bool(s.cron_secret)),
        ("Screenshots", "ENABLE_SCREENSHOTS", s.enable_screenshots),
    ]


def _ctx(db: Session, org_id: int, **extra) -> dict:
    org = db.get(Org, org_id)
    hooks = [u for u in (org.alert_webhooks or "").split(",") if u.strip()]
    return {"org": org, "users": list(db.scalars(scoped(User, org_id).order_by(User.created))),
            "keys": list(db.scalars(scoped(ApiKey, org_id).order_by(ApiKey.id.desc()))),
            "webhooks": [mask_webhook(u) for u in hooks], "integrations": integrations(), **extra}


@router.get("/settings")
def settings(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return render(request, "settings.html", _ctx(db, user.org_id))


@router.post("/settings/alerts", dependencies=[CSRF])
def save_alerts(request: Request, webhooks: str = Form(""), email: str = Form(""), clear_webhooks: str = Form(""),
                admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    org = db.get(Org, admin.org_id)
    urls = [u.strip() for u in webhooks.split(",") if u.strip()]
    if len(urls) > 5:
        raise InvalidInput("At most 5 webhooks.")
    cleaned = [clean_webhook(u) for u in urls]
    if clear_webhooks:
        org.alert_webhooks = None
    if cleaned:                                   # saved URLs are never shown again; blank keeps them
        org.alert_webhooks = ",".join(cleaned)
    org.alert_email = clean_email(email) if email.strip() else None
    db.commit()
    return RedirectResponse("/settings?m=alerts", status_code=303)


@router.post("/settings/alerts/test", dependencies=[CSRF])
def test_alert(request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    org = db.get(Org, admin.org_id)
    if not (org.alert_webhooks or org.alert_email):
        raise InvalidInput("Add a webhook or an email address first.")
    out = send_external(f"ThreatDesk test alert for {org.name}. Alerts for new Medium and High findings arrive here.",
                        org.alert_webhooks, org.alert_email)
    hooks = ", ".join(out["webhooks"]) or "none"
    return render(request, "settings.html", _ctx(db, admin.org_id, test_result=f"Test alert: webhooks {hooks} · "
                                                                               f"email {out['email']}."))


@router.post("/settings/api-keys", dependencies=[CSRF])
def create_key(request: Request, label: str = Form(""), admin: User = Depends(require_admin),
               db: Session = Depends(get_db)):
    name = clean_text(label, 80, required=True, label="Label")
    key, digest, prefix = new_api_key()
    db.add(ApiKey(org_id=admin.org_id, key_hash=digest, prefix=prefix, label=name, created_by=admin.id))
    db.commit()
    return render(request, "settings.html", _ctx(db, admin.org_id, new_key=key, msg_override="key"))


@router.post("/settings/api-keys/{key_id:int}/revoke", dependencies=[CSRF])
def revoke_key(key_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    k = get_owned(db, ApiKey, key_id, admin.org_id)
    k.revoked = True
    db.commit()
    return RedirectResponse("/settings?m=revoked", status_code=303)

