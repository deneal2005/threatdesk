"""App store detection with synthetic listings (no network): Google Play via a patched scraper, App Store via
httpx.MockTransport. Covers official exclusion, look-alikes, publisher evidence, failures and score gating."""
import httpx
import pytest

from threatdesk import config
from threatdesk.brands import BrandContext
from threatdesk.checks import apps
from threatdesk.investigator import investigate

ACME = BrandContext(id=1, name="Acme Bank", official_domains=["acmebank.com"], keywords=["acme"],
                    official_apps={"android": ["com.acmebank.mobile"], "ios": ["1111111111"],
                                   "ios_bundles": ["com.acmebank.ios"], "publishers": ["Acme Bank Ltd"]})
OFFICIAL_DEV_ID = "5700313618786177705"
RECENT = "Sep 1, 2026"


def listing(**kw) -> dict:
    base = {"title": "Acme Bank", "developer": "Acme Bank Ltd", "developerId": OFFICIAL_DEV_ID,
            "developerEmail": "apps@acmebank.com", "developerWebsite": None, "privacyPolicy": "https://x.example/p",
            "installs": "1,000,000+", "released": "Jan 5, 2015", "ratings": 250000, "score": 4.4, "genre": "Finance",
            "icon": None, "url": "https://play.google.com/store/apps/details?id=x", "description": "Banking app."}
    return base | kw


@pytest.fixture
def play(monkeypatch):
    """Install a fake Play catalogue: {package: listing or Exception}."""
    catalogue: dict = {"com.acmebank.mobile": listing()}
    apps._official_devs.clear()

    def fake_app(pkg):
        item = catalogue.get(pkg)
        if isinstance(item, Exception):
            raise item
        if item is None:
            from google_play_scraper.exceptions import NotFoundError
            raise NotFoundError("App not found(404).")
        return item
    monkeypatch.setattr(apps, "_play_app", fake_app)
    monkeypatch.setattr(apps, "_play_perms", lambda pkg: {"SMS": ["read your text messages"]}
                        if "kyc" in pkg else {})

    async def no_site(ctx, website):
        return ctx.not_possible("developer_website", "not fetched in tests")
    monkeypatch.setattr(apps, "check_dev_website", no_site)
    config.override(scam_lists=False)
    return catalogue


async def run(url: str, brand=ACME, handler=None):
    transport = httpx.MockTransport(handler or (lambda r: httpx.Response(404)))
    async with httpx.AsyncClient(transport=transport) as c:
        return await investigate(url, brand=brand, client=c, use_ai=False)


def codes(r) -> set[str]:
    return {s["code"] for s in r.signals}


async def test_official_play_app_is_excluded(play):
    r = await run("https://play.google.com/store/apps/details?id=com.acmebank.mobile")
    assert r.verdict == "Official/whitelisted asset" and r.score == 0 and r.signals == []


async def test_same_developer_account_is_official_even_if_unlisted(play):
    play["com.acmebank.cards"] = listing(title="Acme Bank Cards", developer="ACME BANK LIMITED", developerEmail="")
    r = await run("https://play.google.com/store/apps/details?id=com.acmebank.cards")
    assert r.verdict == "Official/whitelisted asset"
    assert "same Google Play developer account as official app com.acmebank.mobile" in r.excluded_reason


async def test_copied_publisher_name_on_another_account_is_not_official(play):
    play["com.acmebank.kyc"] = listing(title="AcmeBank KYC Update", developerId="999", developerEmail="kyc@gmail.com",
                                       released=RECENT, ratings=3, privacyPolicy=None)
    r = await run("https://play.google.com/store/apps/details?id=com.acmebank.kyc")
    assert r.excluded_reason is None
    assert {"app_impersonation", "app_publisher_lookalike", "app_package_lookalike", "app_new", "app_low_ratings",
            "app_dev_free_email", "app_no_privacy_policy", "app_dangerous_permissions"} <= codes(r)
    pub = next(s for s in r.signals if s["code"] == "app_publisher_lookalike")
    assert "different Google Play developer account" in pub["evidence"]
    assert r.verdict == "High risk"


async def test_lookalike_title_alone_stays_low(play):
    """A different publisher plus a similar title is identity evidence only: capped below Medium."""
    play["com.studio.acmeb4nk"] = listing(title="Acme B4nk Wallet Tools", developer="Indie Studio",
                                          developerId="42", developerEmail="")
    r = await run("https://play.google.com/store/apps/details?id=com.studio.acmeb4nk")
    assert "app_impersonation" in codes(r) and "app_package_lookalike" in codes(r)
    raw = sum(s["points"] for s in r.signals)
    assert raw > 35 and r.score == 35 and r.verdict == "No strong signals"


async def test_unrelated_app_with_other_publisher_gets_no_identity_signal(play):
    play["com.games.anvil"] = listing(title="ACME Anvil Game", developer="RoadRunner Games", developerId="7",
                                      developerEmail="")
    r = await run("https://play.google.com/store/apps/details?id=com.games.anvil")
    assert not codes(r) & {"app_impersonation", "app_publisher_lookalike", "app_package_lookalike"}
    detail = next(c["detail"] for c in r.checks if c["check"] == "play_details")
    assert detail["title_mentions"]["score"] == 60          # recorded as a weak mention, not scored


async def test_scraper_failures_do_not_crash(play):
    play["com.broken.app"] = ValueError("unexpected page layout")
    r = await run("https://play.google.com/store/apps/details?id=com.broken.app")
    c = next(c for c in r.checks if c["check"] == "play_details")
    assert c["status"] == "not_possible" and "ValueError" in c["detail"]["reason"]
    r = await run("https://play.google.com/store/apps/details?id=com.missing.app")
    assert "not found" in r.checks[0]["detail"]["reason"] and r.verdict == "Insufficient data"
    play["com.empty.app"] = {"title": None}
    r = await run("https://play.google.com/store/apps/details?id=com.empty.app")
    assert "malformed" in r.checks[0]["detail"]["reason"]


async def test_official_lookup_failure_falls_back_to_name_rule(play):
    play["com.acmebank.mobile"] = TimeoutError("play down")
    play["com.acmebank.cards"] = listing(title="Acme Cards", developerId="123", developerEmail="")
    r = await run("https://play.google.com/store/apps/details?id=com.acmebank.cards")
    assert r.excluded_reason == "official publisher: listed publisher Acme Bank Ltd"


def itunes(results_by_id: dict):
    def handler(req: httpx.Request):
        if req.url.host == "itunes.apple.com":
            app_id = req.url.params.get("id")
            if app_id == "50000":
                return httpx.Response(500)
            if app_id == "50001":
                return httpx.Response(200, content=b"<html>not json</html>")
            return httpx.Response(200, json={"results": [results_by_id[app_id]] if app_id in results_by_id else []})
        return httpx.Response(404)
    return handler


IOS_FAKE = {"trackName": "Acme Bank Support", "sellerName": "Fast Apps LLC", "artistName": "Fast Apps LLC",
            "bundleId": "com.acmebank.support", "releaseDate": "2026-09-20T00:00:00Z", "userRatingCount": 2,
            "description": "Acme Bank customer care. Share OTP to unblock your account urgently."}


async def test_ios_lookalike_and_official_seller():
    r = await run("https://apps.apple.com/app/id2222222222", handler=itunes({"2222222222": IOS_FAKE}))
    assert {"app_impersonation", "app_package_lookalike", "app_new", "app_low_ratings", "scam_phrases"} <= codes(r)
    assert r.verdict in ("High risk", "Medium risk")
    own = IOS_FAKE | {"trackName": "Acme Bank Business", "sellerName": "Acme Bank Ltd", "bundleId": "com.acmebank.biz"}
    r = await run("https://apps.apple.com/app/id3333333333", handler=itunes({"3333333333": own}))
    assert r.verdict == "Official/whitelisted asset"


async def test_ios_store_errors_are_explicit():
    r = await run("https://apps.apple.com/app/id50000", handler=itunes({}))
    assert r.checks[0]["status"] == "not_possible" and "HTTP 500" in r.checks[0]["detail"]["reason"]
    r = await run("https://apps.apple.com/app/id50001", handler=itunes({}))
    assert r.checks[0]["status"] == "not_possible"
    r = await run("https://apps.apple.com/app/id12345", handler=itunes({}))
    assert "not found" in r.checks[0]["detail"]["reason"]


def _png(pattern: str) -> bytes:
    import io

    from PIL import Image, ImageDraw
    img = Image.new("RGB", (128, 128), "white")
    d = ImageDraw.Draw(img)
    if pattern == "logo":
        d.rectangle((20, 20, 108, 60), fill="navy")
        d.ellipse((40, 70, 88, 118), fill="red")
    else:
        for x in range(0, 128, 16):
            d.line((x, 0, 127 - x, 127), fill="black", width=3)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


async def test_icon_matching_the_logo_is_flagged_only_when_not_official(play, monkeypatch):
    import dataclasses

    from threatdesk import images
    from threatdesk.checks import app_common

    logo_hash = images.phash_hex(images.decode(_png("logo")))
    brand = dataclasses.replace(ACME, logo_phash=logo_hash)
    icons = {"https://icons.example/copy.png": _png("logo"), "https://icons.example/other.png": _png("other")}

    class Fetched:
        def __init__(self, body):
            self.status_code, self.truncated, self.body = 200, False, body

    async def fake_fetch(client, url, **kw):
        return Fetched(icons[url])
    monkeypatch.setattr(app_common, "safe_fetch", fake_fetch)
    play["com.fake.acmeb4nk"] = listing(title="Acme B4nk", developer="X", developerId="1", developerEmail="",
                                        icon="https://icons.example/copy.png")
    r = await run("https://play.google.com/store/apps/details?id=com.fake.acmeb4nk", brand=brand)
    icon = next(c for c in r.checks if c["check"] == "icon_vs_logo")
    assert icon["status"] == "ran" and icon["detail"]["match"] is True and "icon_matches_logo" in codes(r)
    assert r.score > 35 and r.verdict in ("Medium risk", "High risk")   # copied logo corroborates the name
    play["com.other.app"] = listing(title="Acme B4nk", developer="X", developerId="1", developerEmail="",
                                    icon="https://icons.example/other.png")
    r = await run("https://play.google.com/store/apps/details?id=com.other.app", brand=brand)
    assert "icon_matches_logo" not in codes(r)
    play["com.acmebank.mobile"] = listing(icon="https://icons.example/copy.png")
    r = await run("https://play.google.com/store/apps/details?id=com.acmebank.mobile", brand=brand)
    assert r.verdict == "Official/whitelisted asset" and r.signals == []
