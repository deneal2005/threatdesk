import asyncio
from datetime import timedelta

import pytest
from sqlalchemy import select

from threatdesk import config, db, jobs
from threatdesk.db import utcnow
from threatdesk.handlers import HANDLERS
from threatdesk.models import CheckResult, Evidence, Finding, Job, Org
from threatdesk.persistence import save_report
from threatdesk.worker import Worker
from tests.brandhelp import make_brand, org_of
from tests.helpers import csrf, make_client, signup
from tests.netfixtures import offline  # noqa: F401


@pytest.fixture(autouse=True)
def _no_lists():
    config.override(scam_lists=False)


def _org() -> int:
    with db.session_scope() as s:
        o = Org(name="O")
        s.add(o)
        s.flush()
        return o.id


def test_queue_state_machine_backoff_and_failure():
    oid = _org()
    with db.session_scope() as s:
        j = jobs.enqueue(s, "investigate", {"url": "https://x.com"}, oid, max_attempts=2)
        jid = j.id
    with db.session_scope() as s:
        got = jobs.claim_next(s)
        assert got.id == jid and got.status == "running" and got.attempts == 1
        assert jobs.claim_next(s) is None                     # nothing else due
        assert jobs.fail(s, jid, "boom") == "queued"
        assert s.get(Job, jid).run_after > utcnow() + timedelta(seconds=5)
        s.get(Job, jid).run_after = utcnow()
        s.commit()
        assert jobs.claim_next(s).attempts == 2
        assert jobs.fail(s, jid, "boom again") == "failed"
        assert s.get(Job, jid).finished is not None


def test_user_jobs_first_and_types_and_stale_reset():
    oid = _org()
    with db.session_scope() as s:
        bg = jobs.enqueue(s, "scan", {"brand_id": 1}, oid).id
        mine = jobs.enqueue(s, "investigate", {"url": "https://x.com"}, oid, created_by=None).id
        s.get(Job, mine).created_by = None
    with db.session_scope() as s:
        from threatdesk.models import User
        u = User(org_id=oid, email="u@example.com", password_hash="x")
        s.add(u)
        s.flush()
        s.get(Job, mine).created_by = u.id
    with db.session_scope() as s:
        assert jobs.claim_next(s).id == mine                  # a person is waiting on this one
        assert jobs.claim_next(s, types=["verify_asset"]) is None
        assert jobs.claim_next(s).id == bg
        assert jobs.reset_stale(s) == 2
        assert {j.status for j in s.scalars(select(Job))} == {"queued"}


def _fake_report(score=60, dedupe="host:acmebank-kyc.xyz"):
    from threatdesk.checks.base import EvidenceItem
    from threatdesk.investigator import Report
    return Report(url="https://acmebank-kyc.xyz/", kind="website", link={}, display_name="acmebank-kyc.xyz",
                  dedupe_key=dedupe, checks=[{"check": "dns", "status": "ran", "detail": {"state": "resolved"}}],
                  signals=[{"code": "domain_has_brand", "points": 20, "evidence": "x"}], score=score,
                  severity="Medium", verdict="Medium risk", checks_ran=5, indicators=[("ip", "1.2.3.4")],
                  evidence=[EvidenceItem("page_capture", {"t": 1})], ai={"status": "x"},
                  facts={"dns": {"state": "resolved"}})


def test_dedupe_updates_last_seen_and_appends_evidence():
    oid = _org()
    with db.session_scope() as s:
        f1, created1 = save_report(s, oid, None, _fake_report(), "discovery:domains")
        first_seen, fid = f1.first_seen, f1.id
    with db.session_scope() as s:
        f2, created2 = save_report(s, oid, None, _fake_report(score=80), "discovery:domains")
        assert (created1, created2) == (True, False) and f2.id == fid and f2.score == 80
        assert f2.first_seen == first_seen and f2.last_seen >= first_seen
        assert len(s.scalars(select(Evidence).where(Evidence.finding_id == fid)).all()) == 4   # appended
        assert len(s.scalars(select(CheckResult).where(CheckResult.finding_id == fid)).all()) == 1   # replaced


def test_investigate_ui_job_report_and_save(offline, monkeypatch):
    c = make_client()
    signup(c)
    bid = make_brand(org_of("a@example.com"))
    r = c.post("/investigate", data={"url": "hxxps://acmebank-kyc[.]xyz/login", "brand_id": str(bid),
                                     "csrf_token": csrf(c, "/investigate")})
    assert r.status_code == 303
    jid = int(r.headers["location"].rsplit("/", 1)[1])
    page = c.get(f"/investigate/jobs/{jid}").text
    assert "hx-get" in page and "Waiting for a free worker" in page

    from threatdesk import handlers
    real = handlers.investigate

    async def offline_investigate(url, brand=None, **kw):
        async with offline() as client:
            return await real(url, brand=brand, client=client, use_ai=False)
    monkeypatch.setattr(handlers, "investigate", offline_investigate)
    with db.session_scope() as s:
        j = jobs.claim_next(s)
        args = (j.id, j.type, dict(j.payload), j.org_id, j.attempts)
    asyncio.run(Worker(concurrency=1).run_one(*args))
    status = c.get(f"/investigate/jobs/{jid}/status").text
    assert "hx-get" not in status and "High risk" in status and "Why it was flagged" in status
    assert "Save as finding" in status and "acmebank-kyc[.]xyz" in status
    with db.session_scope() as s:
        f = s.scalar(select(Finding))
        assert not f.in_triage and f.source == "investigate"
        fid = f.id
    assert "acmebank-kyc" not in c.get("/findings").text          # ad-hoc results stay out of triage
    r = c.post(f"/findings/{fid}/save", data={"csrf_token": csrf(c, f"/findings/{fid}")})
    assert r.status_code == 303
    assert "acmebank-kyc[.]xyz" in c.get("/findings").text
    assert "saved from an ad-hoc investigation" in c.get(f"/findings/{fid}").text


def test_investigate_rate_limit_and_validation():
    c = make_client()
    signup(c)
    tok = csrf(c, "/investigate")
    r = c.post("/investigate", data={"url": "not a url", "csrf_token": tok})
    assert r.status_code == 400 and "single URL" in r.text and "Your recent investigations" in r.text
    codes = [c.post("/investigate", data={"url": f"https://x{i}.com", "csrf_token": tok}).status_code
             for i in range(11)]
    assert codes[:9].count(303) == 9 and codes[-1] == 429


def test_delete_investigation_variants():
    c = make_client()
    signup(c)
    oid = org_of("a@example.com")
    tok = csrf(c, "/investigate")
    c.post("/investigate", data={"url": "https://a.example.com", "csrf_token": tok})
    with db.session_scope() as s:
        j = s.scalar(select(Job))
        r = c.post(f"/investigate/jobs/{j.id}/delete", data={"csrf_token": tok})
        assert "still_running" in r.headers["location"]
        f, _ = save_report(s, oid, None, _fake_report(), "investigate", in_triage=False)
        j.status, j.result = "done", {"finding_id": f.id}
        jid, fid = j.id, f.id
    c.post(f"/investigate/jobs/{jid}/delete", data={"csrf_token": tok})
    with db.session_scope() as s:
        assert s.get(Job, jid) is None and s.get(Finding, fid) is None          # never saved: gone
        f, _ = save_report(s, oid, None, _fake_report(dedupe="host:kept.example"), "investigate", in_triage=True)
        j2 = jobs.enqueue(s, "investigate", {"url": "https://kept.example"}, oid,
                          created_by=s.scalar(select(Job.created_by)) or 1)
        j2.status, j2.result = "done", {"finding_id": f.id}
        from threatdesk.models import User
        j2.created_by = s.scalar(select(User.id))
        jid2, fid2 = j2.id, f.id
    c.post(f"/investigate/jobs/{jid2}/delete", data={"csrf_token": tok})
    with db.session_scope() as s:
        assert s.get(Job, jid2) is None and s.get(Finding, fid2) is not None    # saved findings are kept


def test_outage_retries_instead_of_saving(monkeypatch):
    from threatdesk import handlers
    from threatdesk.investigator import Report

    async def outage(url, brand=None, **kw):
        return Report(url=url, kind="website", link={}, display_name="x", dedupe_key="host:x",
                      checks=[{"check": "dns", "status": "not_possible", "detail": {"reason": "DNS lookup timed out"}},
                              {"check": "page_fetch", "status": "not_possible",
                               "detail": {"reason": "network error (ConnectError)"}}],
                      verdict="Insufficient data")
    monkeypatch.setattr(handlers, "investigate", outage)
    oid = _org()
    with db.session_scope() as s:
        jid = jobs.enqueue(s, "investigate", {"url": "https://x.com", "source": "discovery:domains"}, oid).id
    with db.session_scope() as s:
        j = jobs.claim_next(s)
        args = (j.id, j.type, dict(j.payload), j.org_id, j.attempts)
    asyncio.run(Worker(concurrency=1).run_one(*args))
    with db.session_scope() as s:
        j = s.get(Job, jid)
        assert j.status == "queued" and "NetworkUnavailable" in j.error
        assert s.scalar(select(Finding)) is None


def test_worker_timeout_and_unknown_type(monkeypatch):
    oid = _org()

    async def slow(jid, payload, org_id):
        await asyncio.sleep(5)
    monkeypatch.setitem(HANDLERS, "investigate", slow)
    with db.session_scope() as s:
        a = jobs.enqueue(s, "investigate", {}, oid, max_attempts=1).id
        b = jobs.enqueue(s, "mystery", {}, oid, max_attempts=1).id
    with db.session_scope() as s:
        assert {jobs.claim_next(s).id, jobs.claim_next(s).id} == {a, b}      # attempts -> 1 (of 1)
    w = Worker(concurrency=1)
    w.timeout = 0.1
    asyncio.run(w.run_one(a, "investigate", {}, oid, 1))
    asyncio.run(w.run_one(b, "mystery", {}, oid, 1))
    with db.session_scope() as s:
        assert s.get(Job, a).status == "failed" and s.get(Job, a).error == "timed out"
        assert "unknown job type" in s.get(Job, b).error


def test_jobs_isolated_between_orgs():
    a, b = make_client(), make_client()
    signup(a, "a@example.com", "A")
    signup(b, "b@example.com", "B")
    a.post("/investigate", data={"url": "https://x.example.com", "csrf_token": csrf(a, "/investigate")})
    with db.session_scope() as s:
        jid = s.scalar(select(Job.id))
    assert b.get(f"/investigate/jobs/{jid}").status_code == 404
    assert b.get(f"/investigate/jobs/{jid}/status").status_code == 404
    assert b.post(f"/investigate/jobs/{jid}/delete", data={"csrf_token": csrf(b, "/investigate")}).status_code == 404
