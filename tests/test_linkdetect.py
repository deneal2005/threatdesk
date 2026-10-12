import pytest

from threatdesk.indicators import extract
from threatdesk.linkdetect import detect, homograph, normalize_url, skeleton
from threatdesk.safety import InvalidInput


@pytest.mark.parametrize("raw,kind,ident,key", [
    ("https://play.google.com/store/apps/details?id=com.Acme.Bank&hl=en", "android_app", "com.Acme.Bank",
     "android:com.acme.bank"),
    ("https://apps.apple.com/in/app/acme/id1234567890", "ios_app", "1234567890", "ios:1234567890"),
    ("https://www.youtube.com/@AcmeBank", "youtube", "@AcmeBank", "youtube:@acmebank"),
    ("https://youtube.com/channel/UCabc123", "youtube", "UCabc123", "youtube:ucabc123"),
    ("https://youtu.be/dQw4w9WgXcQ", "youtube", "", "youtube:video:dQw4w9WgXcQ"),
    ("https://t.me/s/acmebank_help", "telegram", "acmebank_help", "telegram:acmebank_help"),
    ("https://t.me/joinchat/abcdef", "website", "", "host:t.me"),
    ("https://bsky.app/profile/acme.bsky.social", "bluesky", "acme.bsky.social", "bluesky:acme.bsky.social"),
    ("https://www.instagram.com/AcmeBank_Help/?igshid=1", "closed_social", "AcmeBank_Help", "instagram:acmebank_help"),
    ("https://www.facebook.com/profile.php?id=12345", "closed_social", "12345", "facebook:12345"),
    ("https://www.instagram.com/p/Cxyz/", "closed_social", "", "host:www.instagram.com"),
    ("acmebank-kyc.xyz/login", "website", "", "host:acmebank-kyc.xyz"),
])
def test_link_kinds_and_dedupe_keys(raw, kind, ident, key):
    link = detect(raw)
    assert (link.kind, link.ident, link.dedupe_key) == (kind, ident, key)


def test_normalisation():
    assert normalize_url("hxxps://evil[.]com/x?utm_source=a&id=7#frag") == "https://evil.com/x?id=7"
    assert normalize_url("EVIL.com") == "https://evil.com/"
    assert normalize_url("http://evil.com:80/a") == "http://evil.com/a"
    assert normalize_url("https://evil.com:8443/") == "https://evil.com:8443/"
    assert normalize_url("https://bücher.de/").startswith("https://xn--bcher-kva.de")
    for bad in ("", "two words.com", "ftp://x.com", "https://localhost/", "x" * 2001):
        with pytest.raises(InvalidInput):
            normalize_url(bad)


def test_homograph():
    assert skeleton("аcmebank") == "acmebank"            # Cyrillic a
    puny = "аcmebank.com".encode("idna").decode()
    hg = homograph(puny, ["acmebank.com"], ["acme bank"])
    assert hg["is_idn"] and hg["matches"] == ["acmebank.com"] and hg["suspicious"]
    assert not homograph("acmebank.co", ["acmebank.com"], [])["suspicious"]


def test_indicator_extraction():
    ind = extract("Call +91 98765 43210 or 09876543211, pay acme.kyc@ybl, mail help@acme-support.com, "
                  "chat wa.me/919876543210, follow @acme_help, see bit.ly/abc123 or https://evil.com/x.")
    assert ind["phone"][:2] == ["9876543210", "9876543211"]
    assert ind["upi"] == ["acme.kyc@ybl"] and ind["email"] == ["help@acme-support.com"]
    assert "wa.me/919876543210" in ind["messaging"][0] and "acme_help" in ind["handle"]
    assert "https://evil.com/x" in ind["url"] and "bit.ly/abc123" in ind["url"]
