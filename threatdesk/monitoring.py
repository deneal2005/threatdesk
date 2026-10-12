"""Monitoring: scheduler tick (enqueue due scans) and new-finding notifications (in-app, webhook, email)."""
from __future__ import annotations

import logging
import smtplib
from datetime import timedelta
from email.message import EmailMessage
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk import jobs
from threatdesk.config import get_settings
from threatdesk.db import session_scope, utcnow
from threatdesk.logs import kv
from threatdesk.models import Brand, Finding, Notification, Org
from threatdesk.safety import InvalidInput, defang_text

log = logging.getLogger("threatdesk.monitoring")
EXTERNAL_MIN_SEVERITY = ("High", "Medium")
WEBHOOK_HOSTS = ("hooks.slack.com", "discord.com", "discordapp.com", "chat.googleapis.com", "webhook.office.com")


def due_brands(db: Session) -> list[Brand]:
    now = utcnow()
    out = []
    for b in db.scalars(select(Brand).where(Brand.scan_interval_hours > 0)).all():
        if b.last_scan_at and b.last_scan_at > now - timedelta(hours=b.scan_interval_hours):
            continue
        if jobs.has_pending(db, "scan", b.org_id, "brand_id", b.id):
            continue
        out.append(b)
    return out


def tick() -> dict:
    """Enqueue a scan for every brand whose interval has passed (in-process every 5 min, or POST /cron/tick)."""
    with session_scope() as db:
        ids = []
        for b in due_brands(db):
            jobs.enqueue(db, "scan", {"brand_id": b.id, "scheduled": True}, b.org_id, max_attempts=3)
            b.last_scan_at = utcnow()
            ids.append(b.id)
        purged = jobs.purge_background(db, get_settings().job_retention_days)
    if ids:
        log.info("scheduled scans", extra=kv(count=len(ids)))
    if purged:
        log.info("purged old background jobs", extra=kv(count=purged))
    return {"enqueued_scans": len(ids), "brand_ids": ids, "purged_jobs": purged}


def _link(f: Finding) -> str:
    return f"{get_settings().public_base_url}/findings/{f.id}"


def clean_webhook(raw: str) -> str:
    url = (raw or "").strip()
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    ok = p.scheme == "https" and len(url) <= 600 and any(host == h or host.endswith("." + h) for h in WEBHOOK_HOSTS)
    if not ok:
        raise InvalidInput("Webhooks must be https URLs from Slack, Discord, Google Chat or Microsoft Teams.")
    return url


def mask_webhook(url: str) -> str:
    return f"{urlsplit(url).hostname}/…{url[-4:]}"


def notify_new_finding(db: Session, f: Finding) -> None:
    """In-app alert for every new finding; Medium/High also go to the finding's own org webhooks/email."""
    from threatdesk.web.present import source_label
    text = (f"New {f.severity} finding ({source_label(f.source)}): {defang_text(f.display_name)} - {f.verdict}, "
            f"score {f.score}")
    db.add(Notification(org_id=f.org_id, finding_id=f.id, text=text))
    db.flush()
    if f.severity not in EXTERNAL_MIN_SEVERITY:
        return
    org = db.get(Org, f.org_id)
    if org and (org.alert_webhooks or org.alert_email):
        try:
            send_external(f"{text}\n{_link(f)}", org.alert_webhooks, org.alert_email)
        except Exception:  # noqa: BLE001 - an alert channel must never break saving a finding
            log.exception("alert delivery failed")


def send_external(text: str, webhooks: str | None = None, email_to: str | None = None) -> dict:
    out: dict = {"webhooks": [], "email": "not configured"}
    for url in [u.strip() for u in (webhooks or "").split(",") if u.strip()]:
        try:
            r = httpx.post(url, json={"text": text, "content": text}, timeout=5)
            out["webhooks"].append(f"HTTP {r.status_code}")
        except httpx.HTTPError as e:
            out["webhooks"].append(f"failed ({type(e).__name__})")
    s = get_settings()
    if email_to and s.smtp_host and s.smtp_from:
        try:
            msg = EmailMessage()
            msg["Subject"], msg["From"], msg["To"] = "ThreatDesk alert", s.smtp_from, email_to
            msg.set_content(text)
            with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=10) as smtp:
                smtp.starttls()
                if s.smtp_user:
                    smtp.login(s.smtp_user, s.smtp_password or "")
                smtp.send_message(msg)
            out["email"] = "sent"
        except (OSError, smtplib.SMTPException) as e:
            out["email"] = f"failed ({type(e).__name__})"
    elif email_to:
        out["email"] = "no SMTP relay on this server"
    return out
