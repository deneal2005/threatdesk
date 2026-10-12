import httpx
import pytest

from threatdesk import safety
from threatdesk.safety import UnsafeURL, check_url, defang, defang_text, ip_is_blocked, safe_fetch


@pytest.mark.parametrize("ip", ["10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "::1", "fc00::1",
                                "0.0.0.0", "224.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "100.64.0.1"])
def test_private_addresses_blocked(ip):
    assert ip_is_blocked(ip)


def test_public_addresses_allowed():
    assert not ip_is_blocked("93.184.216.34") and not ip_is_blocked("2606:4700::6810:84e5")


async def test_url_policy(monkeypatch):
    async def resolve(host, port):
        return {"internal.example.com": ["10.1.2.3"], "ok.example.com": ["93.184.216.34"]}[host]
    monkeypatch.setattr(safety, "resolve_host", resolve)
    for bad in ("ftp://ok.example.com/", "https://ok.example.com:22/", "http://metadata.google.internal/",
                "https://internal.example.com/", "http://127.0.0.1/"):
        with pytest.raises(UnsafeURL):
            await check_url(bad)
    assert await check_url("https://ok.example.com/") == ("https://ok.example.com/", "93.184.216.34")


async def test_redirects_revalidated_and_pinned(monkeypatch):
    async def resolve(host, port):
        return {"a.example.com": ["93.184.216.34"], "b.example.com": ["10.0.0.5"]}[host]
    monkeypatch.setattr(safety, "resolve_host", resolve)
    seen = []

    def handler(req: httpx.Request):
        seen.append((req.url.host, req.headers["host"]))
        return httpx.Response(302, headers={"location": "https://b.example.com/x"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        with pytest.raises(UnsafeURL):
            await safe_fetch(c, "https://a.example.com/")
    assert seen == [("93.184.216.34", "a.example.com")]          # connected to the pinned IP with the real Host


async def test_size_cap_and_redirect_limit(monkeypatch):
    async def resolve(host, port):
        return ["93.184.216.34"]
    monkeypatch.setattr(safety, "resolve_host", resolve)

    def big(req):
        return httpx.Response(200, content=b"x" * 300_000)

    async with httpx.AsyncClient(transport=httpx.MockTransport(big)) as c:
        r = await safe_fetch(c, "https://a.example.com/", max_bytes=1000)
    assert r.truncated and len(r.body) == 1000 and r.chain[0]["ip"] == "93.184.216.34"

    def loop(req):
        return httpx.Response(301, headers={"location": "/again"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(loop)) as c:
        with pytest.raises(UnsafeURL, match="redirects"):
            await safe_fetch(c, "https://a.example.com/")


def test_defang():
    assert defang("https://evil.com/login.php") == "hxxps://evil[.]com/login.php"
    assert defang_text("visit evil.com or https://x.evil.org/a") == "visit evil[.]com or hxxps://x[.]evil[.]org/a"
