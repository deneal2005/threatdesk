import io

import pytest
from PIL import Image

from threatdesk import db
from threatdesk.brands import BrandContext, parse_brand_settings, publisher_key
from threatdesk.images import distance, process_logo_upload
from threatdesk.models import Brand
from threatdesk.safety import InvalidInput
from tests.helpers import csrf, make_client, signup


def _png(color=(200, 30, 30), size=(64, 64)) -> bytes:
    img = Image.new("RGB", size, "white")
    for x in range(16, 48):
        for y in range(16, 48):
            img.putpixel((x, y), color)
    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


def test_parse_brand_settings():
    s = parse_brand_settings({"name": " Acme Bank ", "keywords": "Acme, acmepay acme", "scan_interval_hours": "0",
                              "publishers": "Acme Insurance Ltd; Acme Tech Pvt. Ltd."})
    assert (s.name, s.keywords, s.scan_interval_hours) == ("Acme Bank", ["acme", "acmepay"], 0)
    assert s.publishers == ["Acme Insurance Ltd", "Acme Tech Pvt. Ltd."]
    for bad in ({"name": ""}, {"name": "x", "scan_interval_hours": "999"}, {"name": "x", "keywords": "a!"}):
        with pytest.raises(InvalidInput):
            parse_brand_settings(bad)
    assert publisher_key("Acme Insurance Pvt. Ltd.") == "acmeinsurance"


def test_brand_context_matching_and_publishers():
    b = BrandContext(name="Acme Bank", official_domains=["acmebank.com"], keywords=["acme"],
                     official_apps={"android": ["com.acme.bank"], "publishers": ["Acme Insurance Ltd"]},
                     whitelist=[("domain", "partner.com")])
    assert b.is_official_host("www.login.acmebank.com") and not b.is_official_host("acmebank.com.evil.xyz")
    assert b.is_whitelisted("domain", "shop.partner.com") and b.terms() == ["acme bank", "acme"]
    assert b.official_publisher("Acme Insurance Limited") == "listed publisher Acme Insurance Ltd"
    assert b.official_publisher("Someone", "https://help.acmebank.com/") == "developer website help.acmebank.com"
    assert b.official_publisher("Acme Bank Official Apps") is None


def test_logo_upload_reencoded_and_served():
    c = make_client()
    signup(c)
    tok = csrf(c, "/brands/new")
    r = c.post("/brands", data={"name": "Acme", "websites": "acme.example", "csrf_token": tok},
               files={"logo": ("logo.png", _png() + b"TRAILING PAYLOAD", "image/png")})
    assert r.status_code == 303, r.text[:300]
    bid = int(r.headers["location"].split("/")[2].split("?")[0])
    with db.session_scope() as s:
        b = s.get(Brand, bid)
        assert b.logo_phash and b"TRAILING PAYLOAD" not in b.logo_blob
    r = c.get(f"/brands/{bid}/logo")
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"


def test_logo_rejections():
    with pytest.raises(InvalidInput, match="readable image"):
        process_logo_upload(b"GIF89a not really")
    with pytest.raises(InvalidInput, match="1 MB"):
        process_logo_upload(b"x" * (1024 * 1024 + 1))
    gif = io.BytesIO()
    Image.new("RGB", (8, 8)).save(gif, format="GIF")
    with pytest.raises(InvalidInput, match="not allowed"):
        process_logo_upload(gif.getvalue())
    a, b = process_logo_upload(_png())[1], process_logo_upload(_png((180, 40, 40)))[1]
    assert distance(a, b) <= 10


def test_allow_list_add_remove_and_isolation():
    c = make_client()
    signup(c)
    tok = csrf(c, "/brands/new")
    r = c.post("/brands", data={"name": "Acme", "websites": "acme.example", "csrf_token": tok})
    bid = int(r.headers["location"].split("/")[2].split("?")[0])
    r = c.post(f"/brands/{bid}/whitelist", data={"type": "domain", "value": "https://Partner.example/shop",
                                                 "reason": "reseller", "csrf_token": tok})
    assert r.status_code == 303
    page = c.get(f"/brands/{bid}?tab=allow").text
    assert "partner.example" in page and "reseller" in page
    other = make_client()
    signup(other, "b@example.com", "B")
    assert other.get(f"/brands/{bid}?tab=allow").status_code == 404
