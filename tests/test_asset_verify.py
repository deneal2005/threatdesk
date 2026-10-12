import asyncio

import pytest
from sqlalchemy import select

from threatdesk import config, db
from threatdesk.assets import checking, sources, store, verify
from threatdesk.models import Brand, BrandApp, BrandSocialAccount, BrandWebsite, Job
from tests.brandhelp import org_of
from tests.helpers import csrf, make_client, signup


@pytest.fixture
def fake_net(monkeypatch):
    """Replace the network reads used by verification with a small fake world."""
    world = {"txt": {}, "pages": {}, "json": {}, "profiles": {}}

    async def txt_records(name):
        return world["txt"].get(name, [])

    async def fetch_page(client, url):
        if url not in world["pages"]:
            raise sources.Unavailable(f"{url} answered HTTP 404")
        return url, world["pages"][url]

    async def fetch_json_file(client, url):
        return world["json"].get(url)

    async def read_profile(client, settings, platform, handle, pid, url, paid):
        if (platform, handle) not in world["profiles"]:
            raise sources.Unavailable("profile not readable")
        return world["profiles"][(platform, handle)]

    async def read_store(client, platform, store_id, market=""):
        return {"name": "Acme Mobile", "bundle_id": "com.acme.ios" if platform == "ios" else None}

    for name, fn in (("txt_records", txt_records), ("fetch_page", fetch_page), ("fetch_json_file", fetch_json_file),
                     ("read_profile", read_profile), ("read_store", read_store)):
        monkeypatch.setattr(sources, name, fn)
    return world


def _brand(c) -> int:
    data = {"name": "Acme Bank", "websites": "acmebank.com\nshop.acmebank.com", "profiles":
            "https://www.youtube.com/@AcmeBank\nhttps://www.instagram.com/acmebank",
            "apps": "com.acme.bank\nid1234567890", "csrf_token": csrf(c, "/brands/new")}
    r = c.post("/brands", data=data)
    return int(r.headers["location"].split("/")[2].split("?")[0])


def _run_all_jobs():
    from threatdesk import jobs
    from threatdesk.worker import Worker
    while True:
        with db.session_scope() as s:
            j = jobs.claim_next(s)
            if j is None:
                return
            args = (j.id, j.type, dict(j.payload), j.org_id, j.attempts)
        asyncio.run(Worker(concurrency=1).run_one(*args))


def test_website_dns_meta_and_parent(fake_net):
    c = make_client()
    signup(c)
    bid = _brand(c)
    with db.session_scope() as s:
        main = s.scalar(select(BrandWebsite).where(BrandWebsite.url_key == "acmebank.com"))
        fake_net["txt"]["acmebank.com"] = [f"threatdesk-verification={main.verify_token}"]
        main_id = main.id
    tok = csrf(c, f"/brands/{bid}?tab=websites")
    r = c.post(f"/brands/{bid}/websites/{main_id}/check", data={"csrf_token": tok})
    assert "m=checking" in r.headers["location"]
    with db.session_scope() as s:
        assert s.get(BrandWebsite, main_id).verification_status == "pending"
    assert "Checking…" in c.get(f"/brands/{bid}?tab=websites").text
    _run_all_jobs()
    with db.session_scope() as s:
        row = s.get(BrandWebsite, main_id)
        assert row.verification_status == "verified" and row.verification_method == "dns_txt"
    c.post(f"/brands/{bid}/websites/check-all", data={"csrf_token": tok})
    _run_all_jobs()
    with db.session_scope() as s:
        shop = s.scalar(select(BrandWebsite).where(BrandWebsite.url_key == "shop.acmebank.com"))
        assert shop.verification_method == "parent_domain"


def test_inconclusive_keeps_status():
    out = asyncio.run(verify.verify_website(None, {"domain": "x.example", "verify_token": "t",
                                                   "url": "https://x.example/"}, []))
    assert out.status in (None, "unverified")


def test_social_via_website_link_or_bio_code_and_bio_link_is_not_proof(fake_net):
    c = make_client()
    signup(c)
    bid = _brand(c)
    with db.session_scope() as s:
        site = s.scalar(select(BrandWebsite).where(BrandWebsite.url_key == "acmebank.com"))
        site.verification_status = "verified"
        yt = s.scalar(select(BrandSocialAccount).where(BrandSocialAccount.platform == "youtube"))
        ig = s.scalar(select(BrandSocialAccount).where(BrandSocialAccount.platform == "instagram"))
        ids, token = (yt.id, ig.id), yt.verify_token
    fake_net["pages"]["https://acmebank.com/"] = "<a href='https://twitter.com/acme'>x</a>"
    fake_net["profiles"][("youtube", "AcmeBank")] = {"name": "Acme Bank", "bio": "Visit https://acmebank.com",
                                                     "links": [], "id": "UCacme"}
    fake_net["profiles"][("instagram", "acmebank")] = {"name": "Acme", "bio": f"Official. {token.lower()}",
                                                       "links": [], "id": None}
    tok = csrf(c, f"/brands/{bid}?tab=social")
    for rid in ids:
        c.post(f"/brands/{bid}/social/{rid}/check", data={"csrf_token": tok})
    _run_all_jobs()
    with db.session_scope() as s:
        y, i = s.get(BrandSocialAccount, ids[0]), s.get(BrandSocialAccount, ids[1])
        assert y.verification_status == "unverified" and "not proof" in y.verification_note   # bio link only
        assert y.display_name == "Acme Bank"                                                   # blanks filled
        assert i.verification_status == "unverified"            # Instagram code is the YouTube account's, not its own
    fake_net["pages"]["https://acmebank.com/"] = "<a href='https://www.youtube.com/@acmebank'>YouTube</a>"
    c.post(f"/brands/{bid}/social/{ids[0]}/check", data={"csrf_token": tok})
    _run_all_jobs()
    with db.session_scope() as s:
        assert s.get(BrandSocialAccount, ids[0]).verification_method == "linked_from_website"


def test_apps_via_website_link_assetlinks_and_aasa(fake_net):
    c = make_client()
    signup(c)
    bid = _brand(c)
    with db.session_scope() as s:
        s.scalar(select(BrandWebsite).where(BrandWebsite.url_key == "acmebank.com")).verification_status = "verified"
        android = s.scalar(select(BrandApp).where(BrandApp.platform == "android")).id
        ios = s.scalar(select(BrandApp).where(BrandApp.platform == "ios")).id
    fake_net["pages"]["https://acmebank.com/"] = "<p>no links</p>"
    fake_net["json"]["https://acmebank.com/.well-known/assetlinks.json"] = [
        {"relation": ["delegate_permission/common.handle_all_urls"],
         "target": {"namespace": "android_app", "package_name": "com.acme.bank"}}]
    fake_net["json"]["https://acmebank.com/.well-known/apple-app-site-association"] = {
        "applinks": {"details": [{"appIDs": ["ABCDE12345.com.acme.ios"]}]}}
    tok = csrf(c, f"/brands/{bid}?tab=apps")
    for rid in (android, ios):
        c.post(f"/brands/{bid}/apps/{rid}/check", data={"csrf_token": tok})
    _run_all_jobs()
    with db.session_scope() as s:
        assert s.get(BrandApp, android).verification_method == "assetlinks"
        a = s.get(BrandApp, ios)
        assert a.verification_method == "aasa" and a.bundle_id == "com.acme.ios" and a.name == "Acme Mobile"


def test_result_dropped_when_asset_changed_and_stuck_rows_healed(fake_net, monkeypatch):
    c = make_client()
    signup(c)
    bid = _brand(c)
    with db.session_scope() as s:
        site = s.scalar(select(BrandWebsite).where(BrandWebsite.url_key == "shop.acmebank.com"))
        checking.enqueue_check(s, s.get(Brand, bid), "website", site, None, False)
        sid = site.id
    real = checking._run

    async def edited_mid_check(*args, **kw):
        out = await real(*args, **kw)
        with db.session_scope() as s:                       # the owner edits the address while the check runs
            row = s.get(BrandWebsite, sid)
            row.url_key, row.domain = "changed.example", "changed.example"
        return out
    monkeypatch.setattr(checking, "_run", edited_mid_check)
    _run_all_jobs()
    with db.session_scope() as s:
        job = s.scalar(select(Job).where(Job.type == "verify_asset"))
        assert job.result == {"skipped": "asset changed during the check"}
        row = s.get(BrandWebsite, sid)
        assert row.verification_status == "pending"          # left behind: no live job any more
    page = c.get(f"/brands/{bid}?tab=websites").text
    assert "The last check didn&#39;t finish" in page or "The last check didn't finish" in page
    with db.session_scope() as s:
        assert s.get(BrandWebsite, sid).verification_status == "unverified"
        assert store.describe("website", s.get(BrandWebsite, sid)) == "changed.example"
    assert config.get_settings()
