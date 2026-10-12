from datetime import timedelta

import httpx
from sqlalchemy import select

from threatdesk import config, db, monitoring
from threatdesk.db import utcnow
from threatdesk.models import Brand, Finding, Job, Notification, Org
from tests.brandhelp import make_brand
from tests.helpers import csrf, make_client, post, signup


def _org(name="O", hooks=None) -> int:
    with db.session_scope() as s:
        o = Org(name=name, alert_webhooks=hooks)
        s.add(o)
        s.flush()
        return o.id


def test_tick_enqueues_due_brands_once():
    oid = _org()
    due = make_brand(oid, "Due", interval=24)
    make_brand(oid, "Off", interval=0)
    fresh = make_brand(oid, "Fresh", interval=24)
    with db.session_scope() as s:
        s.get(Brand, fresh).last_scan_at = utcnow() - timedelta(hours=1)
    assert monitoring.tick() == {"enqueued_scans": 1, "brand_ids": [due], "purged_jobs": 0}
    assert monitoring.tick()["enqueued_scans"] == 0                  # already scanned / pending
    with db.session_scope() as s:
        assert len(s.scalars(select(Job).where(Job.type == "scan")).all()) == 1


def test_cron_endpoint_secret():
    c = make_client()
    assert c.post("/cron/tick").status_code == 503
    config.override(cron_secret="s3cret")
    assert c.post("/cron/tick", headers={"X-Cron-Secret": "wrong"}).status_code == 401
    r = c.post("/cron/tick", headers={"X-Cron-Secret": "s3cret"})
    assert r.status_code == 200 and r.json() == {"enqueued_scans": 0, "brand_ids": [], "purged_jobs": 0}


def _finding(oid: int, severity: str, source: str = "discovery:domains") -> Finding:
    with db.session_scope() as s:
        f = Finding(org_id=oid, source=source, kind="website", dedupe_key=f"host:{severity}.example",
                    scope_key=f"0:host:{severity}.example", display_name=f"{severity}.example",
                    url=f"https://{severity}.example/", score=75 if severity == "High" else 10, severity=severity,
                    verdict="High risk")
        s.add(f)
        s.flush()
        return f


def test_notifications_in_app_and_webhook_only_for_own_org(monkeypatch):
    sent = []
    monkeypatch.setattr(httpx, "post", lambda url, json, timeout: sent.append((url, json)) or httpx.Response(200))
    a = _org("A", "https://hooks.slack.com/services/A,https://discord.com/api/webhooks/A")
    b = _org("B", "https://hooks.slack.com/services/B")
    hi, lo = _finding(a, "High"), _finding(a, "Low")
    with db.session_scope() as s:
        monitoring.notify_new_finding(s, s.get(Finding, hi.id))
        monitoring.notify_new_finding(s, s.get(Finding, lo.id))
    with db.session_scope() as s:
        texts = [n.text for n in s.scalars(select(Notification).where(Notification.org_id == a))]
        assert len(texts) == 2 and texts[0].startswith("New High finding (Scan · Look-alike domains): High[.]example")
        assert not s.scalars(select(Notification).where(Notification.org_id == b)).all()
    assert [u for u, _ in sent] == ["https://hooks.slack.com/services/A", "https://discord.com/api/webhooks/A"]
    assert sent[0][1]["text"] == sent[0][1]["content"] and "/findings/" in sent[0][1]["text"]


def test_alert_settings_validated_masked_and_admin_only():
    c = make_client()
    signup(c)
    r = post(c, "/settings/alerts", {"webhooks": "https://evil.example/hook"})
    assert r.status_code == 400 and "Slack, Discord" in r.text
    r = post(c, "/settings/alerts", {"webhooks": "https://hooks.slack.com/services/T000/B000/abcd1234",
                                     "email": "alerts@example.com"})
    assert r.status_code == 303
    page = c.get("/settings").text
    assert "hooks.slack.com/…1234" in page and "T000/B000" not in page and "alerts@example.com" in page
    post(c, "/settings/users", {"email": "ana@example.com", "password": "teammate pass 1", "role": "analyst"})
    c.cookies.clear()
    tok = csrf(c, "/login")
    c.post("/login", data={"email": "ana@example.com", "password": "teammate pass 1", "csrf_token": tok})
    assert post(c, "/settings/alerts", {"email": "x@example.com"}).status_code == 403


def test_old_background_jobs_are_purged_but_history_is_kept():
    from threatdesk import jobs
    old = utcnow() - timedelta(days=45)
    with db.session_scope() as s:
        rows = [Job(type="investigate", payload={"source": "discovery:domains"}, status="done", finished=old),
                Job(type="investigate", payload={"source": "discovery:ios"}, status="done", finished=utcnow()),
                Job(type="investigate", payload={"source": "investigate"}, status="done", finished=old),
                Job(type="scan", payload={"brand_id": 1}, status="done", finished=old)]
        s.add_all(rows)
        s.flush()
        assert jobs.purge_background(s, 30) == 1
        assert jobs.purge_background(s, 0) == 0                       # 0 keeps everything
        left = {(j.type, j.payload["source"] if "source" in j.payload else "") for j in s.scalars(select(Job))}
    assert left == {("investigate", "discovery:ios"), ("investigate", "investigate"), ("scan", "")}
