import asyncio
from datetime import timedelta

from threatdesk import config, db, jobs, serverless
from threatdesk.config import load_settings, normalize_db_url
from threatdesk.db import utcnow
from threatdesk.handlers import HANDLERS
from threatdesk.main import _scrub_breadcrumb
from threatdesk.models import Job, Org
from tests.helpers import make_client, signup


def _org() -> int:
    with db.session_scope() as s:
        o = Org(name="O")
        s.add(o)
        s.flush()
        return o.id


def _enqueue(oid: int, type_: str = "investigate") -> int:
    with db.session_scope() as s:
        return jobs.enqueue(s, type_, {"url": "https://x.com"}, oid).id


def _status(jid: int) -> str:
    with db.session_scope() as s:
        return s.get(Job, jid).status


def _fake_handler(monkeypatch, calls: list):
    async def fake(jid, payload, org_id):
        calls.append(jid)
        return {"ok": True}
    monkeypatch.setitem(HANDLERS, "investigate", fake)


def test_vercel_env_defaults_and_supabase_url(monkeypatch):
    monkeypatch.delenv("THREATDESK_TESTING")
    for k in ("DATABASE_URL", "ENV", "START_WORKER", "SCAM_LISTS", "CACHE_DIR", "SERVERLESS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("SECRET_KEY", "k" * 40)
    monkeypatch.setenv("POSTGRES_URL", "postgres://u:p@aws-0.pooler.supabase.com:6543/postgres"
                                       "?sslmode=require&supa=base-pooler.x")
    s = load_settings()
    assert s.serverless and s.is_prod and not s.start_worker and not s.scam_lists
    assert s.cache_dir.startswith("/tmp/")
    assert s.database_url == ("postgresql+psycopg://u:p@aws-0.pooler.supabase.com:6543/postgres?sslmode=require")
    monkeypatch.setenv("SERVERLESS", "false")
    assert not load_settings().serverless


def test_normalize_db_url_keeps_libpq_params():
    assert normalize_db_url("postgresql://u@h/db?sslmode=require&pgbouncer=true&connect_timeout=5") == \
        "postgresql+psycopg://u@h/db?sslmode=require&connect_timeout=5"
    assert normalize_db_url("postgresql://u@h/db") == "postgresql+psycopg://u@h/db"


def test_reset_stale_only_old_running_jobs():
    oid = _org()
    old, fresh = _enqueue(oid), _enqueue(oid)
    with db.session_scope() as s:
        for jid, age in ((old, 900), (fresh, 5)):
            j = s.get(Job, jid)
            j.status, j.started = "running", utcnow() - timedelta(seconds=age)
    with db.session_scope() as s:
        assert jobs.reset_stale(s, older_than_seconds=300) == 1
    assert _status(old) == "queued" and _status(fresh) == "running"


def test_run_due_respects_max_jobs_and_window(monkeypatch):
    calls: list = []
    _fake_handler(monkeypatch, calls)
    oid = _org()
    ids = [_enqueue(oid) for _ in range(3)]
    assert asyncio.run(serverless.run_due(max_jobs=1)) == {"jobs_run": 1, "stale_reset": 0}
    assert asyncio.run(serverless.run_due(max_jobs=10, window=1)) == {"jobs_run": 0, "stale_reset": 0}
    assert asyncio.run(serverless.drain())["jobs_run"] == 2
    assert calls == ids and all(_status(j) == "done" for j in ids)


def test_signed_in_htmx_poll_runs_a_job_anonymous_does_not(monkeypatch):
    calls: list = []
    _fake_handler(monkeypatch, calls)
    config.override(serverless=True)
    c = make_client()
    poll = {"HX-Request": "true", "HX-Trigger": "asset-list"}
    jid = _enqueue(_org())
    c.get("/login", headers=poll)
    assert calls == []                                            # anonymous: no pump
    signup(c)
    c.get("/", headers={"HX-Request": "true", "HX-Trigger": "some-button"})
    assert calls == []                                            # not a status poll
    c.get("/", headers=poll)
    assert calls == [jid] and _status(jid) == "done"


def test_cron_get_with_bearer_drains_queue_on_serverless(monkeypatch):
    calls: list = []
    _fake_handler(monkeypatch, calls)
    config.override(serverless=True, cron_secret="s3cret")
    jid = _enqueue(_org())
    c = make_client()
    assert c.get("/cron/tick", headers={"Authorization": "Bearer wrong"}).status_code == 401
    r = c.get("/cron/tick", headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200
    assert r.json() == {"enqueued_scans": 0, "brand_ids": [], "purged_jobs": 0, "jobs_run": 1, "stale_reset": 0}
    assert calls == [jid]


def test_sentry_breadcrumbs_drop_query_strings():
    crumb = {"type": "http", "data": {"url": "https://api.example/v1?key=SECRET", "http.query": "key=SECRET"}}
    out = _scrub_breadcrumb(crumb, {})
    assert out["data"] == {"url": "https://api.example/v1"}
