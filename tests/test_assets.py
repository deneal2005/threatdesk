import pytest
from sqlalchemy import select

from threatdesk import db
from threatdesk.assets import forms, store
from threatdesk.assets.platforms import parse_profile
from threatdesk.models import Brand, BrandApp, BrandSocialAccount, BrandWebsite
from threatdesk.safety import InvalidInput
from tests.brandhelp import make_brand, org_of
from tests.helpers import csrf, make_client, signup


@pytest.mark.parametrize("raw,hint,platform,handle,key,pid", [
    ("https://www.instagram.com/AcmeBank/", "", "instagram", "AcmeBank", "acmebank", None),
    ("@acmebank.help", "instagram", "instagram", "acmebank.help", "acmebank.help", None),
    ("https://www.youtube.com/@AcmeBank", "", "youtube", "AcmeBank", "acmebank", None),
    ("https://www.youtube.com/channel/UCabcdefghijklmnopqrstuv", "", "youtube", "UCabcdefghijklmnopqrstuv",
     "ucabcdefghijklmnopqrstuv", "UCabcdefghijklmnopqrstuv"),
    ("https://www.facebook.com/profile.php?id=1000123", "", "facebook", "1000123", "1000123", "1000123"),
    ("https://www.linkedin.com/company/acme-bank/", "", "linkedin", "company/acme-bank", "company/acme-bank", None),
    ("https://bsky.app/profile/acmebank.bsky.social", "", "bluesky", "acmebank.bsky.social", "acmebank", None),
    ("https://wa.me/919876543210", "", "whatsapp", "919876543210", "919876543210", None),
    ("https://www.reddit.com/user/AcmeBank", "", "reddit", "u/AcmeBank", "u/acmebank", None),
    ("t.me/s/acmebank", "", "telegram", "acmebank", "acmebank", None),
])
def test_profile_parsing(raw, hint, platform, handle, key, pid):
    p = parse_profile(raw, hint)
    assert (p.platform, p.handle, p.handle_key, p.platform_id) == (platform, handle, key, pid)
    assert p.profile_url.startswith("https://")


def test_profile_parsing_errors():
    with pytest.raises(InvalidInput, match="post, video or page"):
        parse_profile("https://www.instagram.com/p/Cabc123/")
    with pytest.raises(InvalidInput, match="but Instagram is selected"):
        parse_profile("https://x.com/acmebank", "instagram")
    with pytest.raises(InvalidInput, match="Choose the platform"):
        parse_profile("acmebank")
    assert parse_profile("u/acme_bank", "reddit").handle_key == "u/acme_bank"


def test_website_and_app_parsers():
    assert forms.parse_website_url("WWW.AcmeBank.com/in/") == ("https://www.acmebank.com/in/", "acmebank.com",
                                                                "acmebank.com/in")
    assert forms.parse_website_url("http://acmebank.com")[2] == "acmebank.com"
    for bad in ("ftp://acmebank.com", "https://user:pw@acmebank.com", "https://10.0.0.1/", ""):
        with pytest.raises(InvalidInput):
            forms.parse_website_url(bad)
    assert forms.parse_android_ref("https://play.google.com/store/apps/details?id=com.acme.bank&hl=en") == \
        "com.acme.bank"
    assert forms.parse_ios_ref("https://apps.apple.com/in/app/acme/id1234567890") == ("1234567890", "IN")
    assert forms.parse_ios_ref("id1234567890") == ("1234567890", "")
    with pytest.raises(InvalidInput, match="name"):
        forms.parse_new_app({"android": "com.acme.bank", "ios": "1234567890"})
    pair = forms.parse_new_app({"android": "com.acme.bank", "ios": "1234567890", "name": "Acme"})
    assert [a["platform"] for a in pair] == ["android", "ios"] and {a["product"] for a in pair} == {"Acme"}


def _brand_page(c, bid, tab):
    return c.get(f"/brands/{bid}?tab={tab}")


def _create(c, **extra):
    data = {"name": "Acme Bank", "websites": "acmebank.com\nacmebank.in\ncareers.acmebank.com",
            "profiles": "https://www.instagram.com/acmebank\nhttps://www.instagram.com/acmebank.help\n"
                        "https://www.instagram.com/acmebank_in\nhttps://www.youtube.com/@AcmeBank",
            "apps": "https://play.google.com/store/apps/details?id=com.acme.bank\nhttps://apps.apple.com/app/id1234567890",
            "keywords": "acme", "scan_interval_hours": "0", "csrf_token": csrf(c, "/brands/new"), **extra}
    r = c.post("/brands", data=data)
    assert r.status_code == 303, r.text[:400]
    return int(r.headers["location"].split("/")[2].split("?")[0])


def test_quick_start_creates_records_and_index():
    c = make_client()
    signup(c)
    bid = _create(c)
    with db.session_scope() as s:
        b = s.get(Brand, bid)
        sites = s.scalars(select(BrandWebsite).where(BrandWebsite.brand_id == bid).order_by(BrandWebsite.id)).all()
        assert [w.url_key for w in sites] == ["acmebank.com", "acmebank.in", "careers.acmebank.com"]
        assert [w.is_primary for w in sites] == [True, False, False]
        assert len(s.scalars(select(BrandSocialAccount).where(BrandSocialAccount.brand_id == bid)).all()) == 4
        assert len(s.scalars(select(BrandApp).where(BrandApp.brand_id == bid)).all()) == 2
        assert b.official_domains[0] == "acmebank.com"
        assert b.official_handles["instagram"] == ["acmebank", "acmebank.help", "acmebank_in"]
        assert b.official_apps["android"] == ["com.acme.bank"] and b.official_apps["ios"] == ["1234567890"]
    page = c.get(f"/brands/{bid}").text
    assert "Set up Acme" in page and "of 5 done" in page and "Customer report link" in page


def test_invalid_quick_start_names_the_line_and_keeps_input():
    c = make_client()
    signup(c)
    r = c.post("/brands", data={"name": "Acme", "websites": "acmebank.com", "profiles": "acmebank",
                                "csrf_token": csrf(c, "/brands/new")})
    assert r.status_code == 400
    assert "Social accounts, &#34;acmebank&#34;: Choose the platform" in r.text or \
        'Social accounts, "acmebank": Choose the platform' in r.text
    assert "acmebank.com" in r.text


def test_many_accounts_per_platform_add_edit_remove_and_duplicates():
    c = make_client()
    signup(c)
    bid = _create(c)
    tok = csrf(c, f"/brands/{bid}?tab=social")
    r = c.post(f"/brands/{bid}/social", data={"platform": "auto", "handle": "https://www.instagram.com/acmebank.careers",
                                              "csrf_token": tok})
    assert r.status_code == 303 and "m=asset_added" in r.headers["location"]
    r = c.post(f"/brands/{bid}/social", data={"platform": "instagram", "handle": "@AcmeBank", "csrf_token": tok})
    assert "m=asset_exists" in r.headers["location"]
    r = c.post(f"/brands/{bid}/social", data={"platform": "x", "handle": "acmebank", "csrf_token": tok})
    assert "m=asset_added" in r.headers["location"]
    page = _brand_page(c, bid, "social").text
    assert "@acmebank.careers" in page and "X (Twitter)" in page
    r = c.post(f"/brands/{bid}/social", data={"platform": "instagram", "handle": "https://x.com/acme",
                                              "csrf_token": tok})
    assert r.status_code == 400 and "but Instagram is selected" in r.text and 'value="https://x.com/acme"' in r.text
    with db.session_scope() as s:
        row = s.scalar(select(BrandSocialAccount).where(BrandSocialAccount.handle_key == "acmebank.help"))
        rid, version = row.id, row.version
    r = c.post(f"/brands/{bid}/social/{rid}", data={"platform": "instagram", "handle": "acmebank.help",
                                                    "display_name": "Acme Help", "status": "inactive",
                                                    "version": str(version), "csrf_token": tok})
    assert r.status_code == 303, r.text[:300]
    r = c.post(f"/brands/{bid}/social/{rid}", data={"platform": "instagram", "handle": "acmebank.help",
                                                    "version": str(version), "csrf_token": tok})
    assert r.status_code == 409 and "Someone else changed this" in r.text
    with db.session_scope() as s:
        assert "acmebank.help" not in s.get(Brand, bid).official_handles["instagram"]       # inactive: not official
    c.post(f"/brands/{bid}/social/{rid}/delete", data={"csrf_token": tok})
    r = c.post(f"/brands/{bid}/social/{rid}/delete", data={"csrf_token": tok})               # idempotent
    assert r.status_code == 303
    with db.session_scope() as s:
        assert s.get(BrandSocialAccount, rid) is None
        assert s.get(Brand, bid).official_handles["instagram"] == ["acmebank", "acmebank_in", "acmebank.careers"]


def test_websites_primary_and_identity_change_clears_verification():
    c = make_client()
    signup(c)
    bid = _create(c)
    tok = csrf(c, f"/brands/{bid}?tab=websites")
    with db.session_scope() as s:
        sites = s.scalars(select(BrandWebsite).where(BrandWebsite.brand_id == bid).order_by(BrandWebsite.id)).all()
        first, second = sites[0].id, sites[1].id
        sites[1].verification_status, sites[1].verification_method = "verified", "dns_txt"
    c.post(f"/brands/{bid}/websites/{second}/primary", data={"csrf_token": tok})
    c.post(f"/brands/{bid}/websites/{first}/delete", data={"csrf_token": tok})
    with db.session_scope() as s:
        row = s.get(BrandWebsite, second)
        assert row.is_primary and s.get(Brand, bid).official_domains[0] == "acmebank.in"
        version = row.version
    c.post(f"/brands/{bid}/websites/{second}", data={"url": "acmebank.in", "kind": "regional", "purpose": "India",
                                                     "version": str(version), "csrf_token": tok})
    with db.session_scope() as s:
        assert s.get(BrandWebsite, second).verification_status == "verified"     # metadata only
        version = s.get(BrandWebsite, second).version
    c.post(f"/brands/{bid}/websites/{second}", data={"url": "acmebank.in/en", "kind": "regional",
                                                     "version": str(version), "csrf_token": tok})
    with db.session_scope() as s:
        row = s.get(BrandWebsite, second)
        assert row.verification_status == "unverified" and "Details changed" in row.verification_note


def test_brand_and_assets_isolated_between_orgs():
    a, b = make_client(), make_client()
    signup(a, "a@example.com", "Org A")
    bid = _create(a)
    signup(b, "b@example.com", "Org B")
    with db.session_scope() as s:
        site = s.scalar(select(BrandWebsite.id).where(BrandWebsite.brand_id == bid))
    tok = csrf(b, "/brands")
    assert b.get(f"/brands/{bid}").status_code == 404
    assert b.get(f"/brands/{bid}/websites/{site}/edit").status_code == 404
    assert b.post(f"/brands/{bid}/websites/{site}/delete", data={"csrf_token": tok}).status_code == 404
    assert b.post(f"/brands/{bid}/websites", data={"url": "evil.com", "csrf_token": tok}).status_code == 404
    other = make_brand(org_of("b@example.com"), "B brand")
    assert a.get(f"/brands/{other}/websites/{site}/edit").status_code == 404      # asset of another brand


def test_legacy_brand_migrated_on_view():
    c = make_client()
    signup(c)
    bid = make_brand(org_of("a@example.com"))
    assert c.get(f"/brands/{bid}?tab=social").status_code == 200
    with db.session_scope() as s:
        b = s.get(Brand, bid)
        assert {w.url_key for w in store.rows(s, b, "website")} == {"acmebank.com"}
        assert {(a.platform, a.handle_key) for a in store.rows(s, b, "social")} == {("instagram", "acmebank"),
                                                                                  ("telegram", "acmebank")}
        assert b.official_apps["android"] == ["com.acme.bank"]
