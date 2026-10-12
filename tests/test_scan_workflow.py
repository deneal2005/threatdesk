"""Scan now runs everything (discovery, lead investigations, asset checks), progress reflects real jobs,
the setup checklist is actionable, and deleting a brand removes only that brand's data."""
import asyncio

import pytest
from sqlalchemy import func, select

from threatdesk import config, db, jobs
from threatdesk.discovery import scan as scan_mod
from threatdesk.models import (
    Brand, BrandSocialAccount, BrandWebsite, CaseEvent, Evidence, Finding, Job, Notification, Signal,
)
from threatdesk.persistence import save_report
from threatdesk.worker import Worker
from tests.brandhelp import make_user, org_of
from tests.helpers import csrf, make_client, signup


@pytest.fixture(autouse=True)
def _no_lists():
    config.override(scam_lists=False)


def _brand(c, name="Acme Bank", websites="https://acmebank.com", profiles="https://instagram.com/acmebank") -> int:
    r = c.post("/brands", data={"name": name, "websites": websites, "profiles": profiles, "keywords": "acme",
                                "csrf_token": csrf(c, "/brands/new")})
    assert r.status_code == 303, r.text[:400]
    return int(r.headers["location"].split("/")[2].split("?")[0])


def _scan(c, bid, **extra):
    return c.post(f"/brands/{bid}/scan", data={"csrf_token": csrf(c, f"/brands/{bid}"), **extra})


def _jobs(type_=None):
    with db.session_scope() as s:
        q = select(Job)
        if type_:
            q = q.where(Job.type == type_)
        return [(j.id, j.type, dict(j.payload), j.org_id, j.attempts, j.status) for j in s.scalars(q.order_by(Job.id))]


def _run(job):
    with db.session_scope() as s:
        s.get(Job, job[0]).status = "running"
    asyncio.run(Worker(concurrency=1).run_one(*job[:5]))


def _fake_sources(monkeypatch, urls):
    async def found(*a, **k):
        return "ok", list(urls)

    async def nothing(*a, **k):
        return "ok: 0", []

    async def no_search(*a, **k):
        return "not configured (GOOGLE_CSE_KEY+GOOGLE_CSE_CX or BRAVE_API_KEY)", []
    monkeypatch.setattr(scan_mod.sources, "src_domains", found)
    for name in ("src_crtsh", "src_ios", "src_android", "src_youtube", "src_bluesky", "src_telegram"):
        monkeypatch.setattr(scan_mod.sources, name, nothing)
    monkeypatch.setattr(scan_mod, "src_websearch", no_search)


def test_scan_now_queues_discovery_and_asset_checks_once():
    c = make_client()
    signup(c)
    bid = _brand(c)
    r = _scan(c, bid)
    assert r.status_code == 303 and "m=queued" in r.headers["location"]
    scans, checks = _jobs("scan"), _jobs("verify_asset")
    assert len(scans) == 1 and scans[0][2]["brand_id"] == bid
    assert len(checks) == 2 and all(j[2]["scan_id"] == scans[0][0] for j in checks)   # the website and the account
    assert scans[0][2]["asset_checks"] == 2
    # a second press (double click, or a teammate) never starts a second scan or re-queues the checks
    r = _scan(c, bid)
    assert "scan_already_running" in r.headers["location"]
    assert len(_jobs("scan")) == 1 and len(_jobs("verify_asset")) == 2
    page = c.get(f"/brands/{bid}").text
    assert f'id="scan-progress-{bid}"' in page and "every 2s" in page and "Scan running" in page
    assert "Waiting for a free worker" in page and "0/2" in page


def test_progress_follows_real_jobs_to_the_end(monkeypatch):
    c = make_client()
    signup(c)
    bid = _brand(c, profiles="")
    _fake_sources(monkeypatch, ["https://acmebank-kyc.xyz/", "https://acme-bank.top/"])
    _scan(c, bid)
    scan = _jobs("scan")[0]
    _run(scan)
    leads = _jobs("investigate")
    assert len(leads) == 2 and all(j[2]["scan_id"] == scan[0] for j in leads)
    part = c.get(f"/brands/{bid}/scan/progress", headers={"HX-Request": "true"}).text
    assert "Scanning now" in part and "0/2" in part and "every 2s" in part
    assert f'id="scan-btn-{bid}" ' in part and "hx-swap-oob" in part              # header button follows along

    from threatdesk import handlers
    from tests.test_jobs import _fake_report

    async def fake_investigate(url, brand=None, **kw):
        return _fake_report(dedupe=f"host:{url.split('/')[2]}")
    monkeypatch.setattr(handlers, "investigate", fake_investigate)
    for j in leads + _jobs("verify_asset"):
        if j[1] == "verify_asset":
            from threatdesk.assets import checking
            from threatdesk.assets.verify import Outcome

            async def no_network(*a, **k):
                return Outcome("unverified", None, "No verification code found yet.")
            monkeypatch.setattr(checking, "_run", no_network)
        _run(j)
    part = c.get(f"/brands/{bid}/scan/progress").text
    assert "Scan finished" in part and "every 2s" not in part
    assert "2/2" in part and ">2</span> new findings" in part and "1/1" in part
    assert "Review findings" in part
    dash = c.get("/").text                                                       # and on the dashboard
    assert f'id="scan-progress-{bid}-c"' in dash and "Scan finished" in dash


def test_failed_discovery_is_reported_not_hidden(monkeypatch):
    c = make_client()
    signup(c)
    bid = _brand(c, profiles="")

    async def boom(*a, **k):
        raise RuntimeError("upstream down")
    monkeypatch.setattr(scan_mod, "run_scan", boom)
    _scan(c, bid)
    with db.session_scope() as s:
        j = s.get(Job, _jobs("scan")[0][0])
        j.max_attempts, j.attempts = 1, 1                       # the last allowed attempt
    _run(_jobs("scan")[0])
    part = c.get(f"/brands/{bid}/scan/progress").text
    assert "Failed after 1 attempt(s): RuntimeError: upstream down" in part
    assert "Scanning now" in part                               # the asset check it queued still runs
    from threatdesk.assets import checking
    from threatdesk.assets.verify import Outcome

    async def no_network(*a, **k):
        return Outcome(None, None, "The check could not finish.")
    monkeypatch.setattr(checking, "_run", no_network)
    _run(_jobs("verify_asset")[0])
    part = c.get(f"/brands/{bid}/scan/progress").text
    assert "Scan stopped" in part and "upstream down" in part and "Try again" in part and "every 2s" not in part


def test_dashboard_scan_returns_to_dashboard_and_scan_all():
    c = make_client()
    signup(c)
    a = _brand(c, profiles="")
    r = c.post(f"/brands/{a}/scan", data={"back": "dashboard", "csrf_token": csrf(c, "/")})
    assert r.headers["location"] == "/?m=queued"
    b = _brand(c, name="Beta Pay", websites="https://betapay.com", profiles="")
    r = c.post("/scan-all", data={"csrf_token": csrf(c, "/")})
    assert r.headers["location"] == "/?m=queued_all"
    assert sorted(j[2]["brand_id"] for j in _jobs("scan")) == sorted([a, b])     # a was already running: not twice
    assert "Scan all 2 brands" in c.get("/").text


def test_setup_steps_are_actionable_and_skippable():
    c = make_client()
    signup(c)
    bid = _brand(c, profiles="")
    page = c.get(f"/brands/{bid}").text
    assert "Verify your main website" in page and "Check now" in page and "How to verify" in page
    assert "List your mobile apps" in page and "Run your first scan" in page and "of 5 done" in page
    assert "Scanning works at any point" in page
    r = c.post(f"/brands/{bid}/setup/apps/skip", data={"csrf_token": csrf(c, f"/brands/{bid}")})
    assert r.status_code == 303
    page = c.get(f"/brands/{bid}").text
    assert "We have no mobile apps." in page and "Undo" in page and "1 of 5 done" in page
    c.post(f"/brands/{bid}/setup/apps/unskip", data={"csrf_token": csrf(c, f"/brands/{bid}")})
    assert "0 of 5 done" in c.get(f"/brands/{bid}").text
    assert c.post(f"/brands/{bid}/setup/website/skip", data={"csrf_token": csrf(c, f"/brands/{bid}")}).status_code == 404


def _finding(org, bid, key):
    from tests.test_jobs import _fake_report
    r = _fake_report(dedupe=key)
    r.display_name = key.split(":", 1)[1]
    with db.session_scope() as s:
        f, _ = save_report(s, org, bid, r, "discovery:domains", in_triage=True)
        s.add(CaseEvent(org_id=org, finding_id=f.id, type="comment", body="seen"))
        s.add(Notification(org_id=org, finding_id=f.id, text="New finding"))
        return f.id


def test_delete_brand_removes_only_that_brand():
    c = make_client()
    signup(c)
    org = org_of("a@example.com")
    a = _brand(c)
    b = _brand(c, name="Beta Pay", websites="https://betapay.com", profiles="https://instagram.com/betapay")
    fa, fb = _finding(org, a, "host:acmebank-kyc.xyz"), _finding(org, b, "host:betapay-kyc.xyz")
    _scan(c, a)
    _scan(c, b)
    page = c.get(f"/brands/{a}/delete").text
    assert "Delete Acme Bank?" in page and ">1</span> finding" in page and "Type <strong>Acme Bank</strong>" in page
    r = c.post(f"/brands/{a}/delete", data={"confirm_name": "acme", "csrf_token": csrf(c, f"/brands/{a}/delete")})
    assert r.status_code == 400 and "so nothing was deleted" in r.text
    r = c.post(f"/brands/{a}/delete", data={"confirm_name": "acme bank", "csrf_token": csrf(c, f"/brands/{a}/delete")})
    assert r.status_code == 303 and r.headers["location"] == "/brands?m=brand_deleted"
    with db.session_scope() as s:
        assert s.get(Brand, a) is None and s.get(Brand, b) is not None
        assert s.get(Finding, fa) is None and s.get(Finding, fb) is not None
        for model in (Signal, Evidence, CaseEvent, Notification):
            assert s.scalar(select(func.count()).select_from(model).where(model.finding_id == fa)) == 0
            assert s.scalar(select(func.count()).select_from(model).where(model.finding_id == fb)) > 0
        assert s.scalar(select(func.count()).select_from(BrandWebsite).where(BrandWebsite.brand_id == a)) == 0
        assert s.scalar(select(func.count()).select_from(BrandSocialAccount).where(BrandSocialAccount.brand_id == b)) == 1
    assert all(j[2].get("brand_id") != a for j in _jobs()) and any(j[2].get("brand_id") == b for j in _jobs())
    assert c.get(f"/brands/{a}").status_code == 404
    assert "acmebank-kyc" not in c.get("/findings?view=all").text and "Acme Bank" not in c.get("/brands").text
    assert "betapay-kyc" in c.get("/findings?view=all").text


def test_delete_brand_is_admin_only_and_late_jobs_save_nothing(monkeypatch):
    c = make_client()
    signup(c)
    org = org_of("a@example.com")
    bid = _brand(c, profiles="")
    with db.session_scope() as s:
        j = jobs.enqueue(s, "investigate", {"url": "https://acmebank-kyc.xyz/", "brand_id": bid,
                                            "source": "discovery:domains"}, org)
        jid = j.id
    # an analyst can't delete
    from threatdesk.models import User
    from threatdesk.security import hash_password
    with db.session_scope() as s:
        s.add(User(org_id=org, email="an@example.com", password_hash=hash_password("correct horse 1"), role="analyst"))
    other = make_client()
    other.post("/login", data={"email": "an@example.com", "password": "correct horse 1",
                               "csrf_token": csrf(other, "/login")})
    assert other.get(f"/brands/{bid}/delete").status_code == 403
    # the job was claimed before the delete: it finds the brand gone and saves nothing
    with db.session_scope() as s:
        s.get(Job, jid).status = "running"
    args = (jid, "investigate", {"url": "https://acmebank-kyc.xyz/", "brand_id": bid, "source": "discovery:domains"},
            org, 1)
    c.post(f"/brands/{bid}/delete", data={"confirm_name": "Acme Bank", "csrf_token": csrf(c, f"/brands/{bid}/delete")})

    async def must_not_run(*a, **k):
        raise AssertionError("investigated a lead of a deleted brand")
    from threatdesk import handlers
    monkeypatch.setattr(handlers, "investigate", must_not_run)
    res = asyncio.run(handlers.handle_investigate(*args[:1], args[2], org))
    assert res == {"skipped": "brand deleted"}
    with db.session_scope() as s:
        assert s.scalar(select(func.count()).select_from(Finding)) == 0
    make_user("x@example.com")                                                   # other orgs unaffected


def test_dashboard_button_follows_the_scan_when_one_brand():
    c = make_client()
    signup(c)
    bid = _brand(c, profiles="")
    c.post(f"/brands/{bid}/scan", data={"back": "dashboard", "csrf_token": csrf(c, "/")})
    dash = c.get("/").text
    assert "Scan running…" in dash and "compact=1&amp;button=1" in dash
    part = c.get(f"/brands/{bid}/scan/progress?compact=1&button=1", headers={"HX-Request": "true"}).text
    assert f'id="scan-btn-{bid}"' in part and 'name="back" value="dashboard"' in part and "hx-swap-oob" in part
