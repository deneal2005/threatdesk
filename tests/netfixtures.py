"""Offline network for tests: a MockTransport for RDAP/archive/CT/PhishTank plus a phishing page, and DNS patches.

Nothing here touches the real network. The phishing page is served for acmebank-kyc.xyz (pinned to a fake public
IP, exactly like safe_fetch connects in production).
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import timedelta

import httpx
import pytest

from threatdesk.db import utcnow

PHISH_IP = "93.184.216.34"
HOSTS = {"acmebank-kyc.xyz": PHISH_IP, "acmebank.com": "93.184.216.35", "old-bakery.com": "93.184.216.36",
         "rdap.org": "93.184.216.40", "t.me": "93.184.216.41", "telegram.me": "93.184.216.42",
         "acme-support-help.online": "93.184.216.37", "acmebank-rewards.xyz": "93.184.216.38"}

PHISH_HTML = """<!doctype html><html><head><title>Acme Bank KYC Update</title>
<meta name="description" content="Official Acme Bank customer care"></head><body>
<h1>Acme Bank - KYC pending</h1>
<p>Dear customer, your account will be blocked within 24 hours. Update your KYC immediately.</p>
<p>Enter your net banking password and the OTP we sent you to verify your account.</p>
<form action="/submit" method="post"><label>User ID</label><input name="userid">
<label>Password</label><input type="password" name="pwd"><label>OTP</label><input name="otp_code">
<button>Verify now</button></form>
<p>Need help? Chat with us on <a href="https://wa.me/919876543210">WhatsApp</a> or pay the fee to acmekyc@ybl</p>
</body></html>"""

BAKERY_HTML = """<!doctype html><html><head><title>Old Bakery - fresh bread since 1998</title></head><body>
<p>Sourdough, rye and pastries baked every morning. Visit our shop on the corner.</p>
<a href="/contact">Contact</a> <a href="/privacy">Privacy</a></body></html>"""


SUPPORT_HTML = """<!doctype html><html><head><title>Acme Bank Customer Care Helpline</title></head><body>
<h1>Acme Bank official customer care</h1><p>Toll free helpline 24x7. Call or WhatsApp +91 98765 43210 for refunds,
KYC update and blocked cards. Our support team will ask you to share the OTP to verify you.</p>
<a href="https://wa.me/919876543210">Chat now</a></body></html>"""

REWARDS_HTML = """<!doctype html><html><head><title>Claim your reward | Acme Bank</title></head><body>
<h2>Congratulations! You have won Acme reward points in our lucky draw.</h2>
<p>Claim your reward today only. Pay the processing fee of Rs 99 via UPI only to acmekyc@ybl and get flat 90% off.</p>
</body></html>"""


def _rdap_domain(name: str, days_old: int) -> dict:
    reg = (utcnow() - timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"objectClassName": "domain", "ldhName": name.upper(),
            "events": [{"eventAction": "registration", "eventDate": reg},
                       {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}],
            "status": ["client transfer prohibited"],
            "entities": [{"roles": ["registrar"], "handle": "1068",
                          "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Cheap Names Inc"]]],
                          "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [
                              ["fn", {}, "text", "Abuse desk"], ["email", {}, "text", "abuse@cheapnames.example"],
                              ["tel", {}, "uri", "tel:+1.5555550100"]]]}]},
                         {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]]}],
            "nameservers": [{"ldhName": "NS1.CHEAPNAMES.EXAMPLE"}]}


def handler(request: httpx.Request) -> httpx.Response:
    host = (request.headers.get("host") or request.url.host).split(":")[0]    # pinned fetches carry the name here
    vhost = host
    path = request.url.path
    if host == "data.iana.org":
        return httpx.Response(404)
    if host == "rdap.org":
        if path == "/domain/acmebank-kyc.xyz":
            return httpx.Response(200, json=_rdap_domain("acmebank-kyc.xyz", 5))
        if path == "/domain/old-bakery.com":
            return httpx.Response(200, json=_rdap_domain("old-bakery.com", 3000))
        if path == "/domain/acmebank.com":
            return httpx.Response(200, json=_rdap_domain("acmebank.com", 5000))
        if path == "/domain/acme-support-help.online":
            return httpx.Response(200, json=_rdap_domain("acme-support-help.online", 12))
        if path == "/domain/acmebank-rewards.xyz":
            return httpx.Response(200, json=_rdap_domain("acmebank-rewards.xyz", 40))
        if path.startswith("/ip/"):
            return httpx.Response(200, json={"name": "TINYHOST-NET", "handle": "NET-1", "country": "NL",
                                             "startAddress": "93.184.216.0", "endAddress": "93.184.216.255",
                                             "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [
                                                 ["email", {}, "text", "abuse@tinyhost.example"]]]}]})
        return httpx.Response(404)
    if host == "archive.org":
        if "old-bakery" in str(request.url):
            return httpx.Response(200, json={"archived_snapshots": {"closest": {
                "available": True, "timestamp": "20020101000000"}}})
        return httpx.Response(200, json={"archived_snapshots": {}})
    if host == "web.archive.org":
        return httpx.Response(200, json=[])
    if host == "crt.sh":
        return httpx.Response(502)
    if host == "api.certspotter.com":
        dom = request.url.params.get("domain", "")
        return httpx.Response(200, json=[{"not_before": "2026-01-01T00:00:00Z",
                                          "dns_names": [dom, f"www.{dom}"]}] if dom in HOSTS else [])
    if host == "checkurl.phishtank.com":
        return httpx.Response(200, json={"results": {"in_database": False}})
    if host in HOSTS:
        if vhost == "acmebank-kyc.xyz":
            return httpx.Response(200, html=PHISH_HTML)
        if vhost == "old-bakery.com":
            return httpx.Response(200, html=BAKERY_HTML)
        if vhost == "acme-support-help.online":
            return httpx.Response(200, html=SUPPORT_HTML)
        if vhost == "acmebank-rewards.xyz":
            return httpx.Response(200, html=REWARDS_HTML)
        if vhost == "acmebank.com":
            return httpx.Response(200, html="<html><head><title>Acme Bank</title></head><body>Welcome</body></html>")
    return httpx.Response(404)


def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@contextmanager
def offline_patches():
    """Patch DNS, TLS and ASN so investigations run fully offline against `handler` (also used by the demo seed)."""
    from threatdesk import safety
    from threatdesk.checks import domain, rdap, tls

    async def resolve_host(h, port):
        if h in HOSTS:
            return [HOSTS[h]]
        raise OSError(f"{h}: NXDOMAIN")

    async def resolve_a(h, res=None, lifetime=4.0):
        return ("resolved", [HOSTS[h]]) if h in HOSTS else ("nxdomain", [])

    async def no_tls(ip, host, verify):
        raise ConnectionRefusedError()

    async def no_asn(ip):
        return {}

    patches = [(safety, "resolve_host", resolve_host), (domain, "resolve_a", resolve_a), (tls, "_handshake", no_tls),
               (rdap, "_asn", no_asn)]
    saved = [(mod, name, getattr(mod, name)) for mod, name, _ in patches]
    for mod, name, fn in patches:
        setattr(mod, name, fn)
    rdap._bootstrap.clear()
    try:
        yield client
    finally:
        for mod, name, fn in saved:
            setattr(mod, name, fn)


@pytest.fixture
def offline():
    with offline_patches() as make:
        yield make
