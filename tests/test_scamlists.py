import asyncio
import io
import zipfile

import httpx

from threatdesk import config, scamlists
from threatdesk.scamlists import ScamLists, build, hkey, keep, lookup_keys, parse_line, parse_tranco


def test_parse_line_formats():
    assert parse_line("||evil.example^") == "evil.example"
    assert parse_line("0.0.0.0 evil.example # comment") == "evil.example"
    assert parse_line("https://www.evil.example/login?x=1") == "evil.example"
    assert parse_line("*.evil.example") == "evil.example"
    assert parse_line("# heading") is None and parse_line("not a domain") is None


def test_list_mistakes_are_cleaned():
    top = {hkey("surveymonkey.com")}
    assert not keep("bit.ly", top) and not keep("surveymonkey.com", top) and not keep("paypal.com", top)
    assert not keep("login.surveymonkey.com", top)              # subdomain of a popular site
    assert keep("evil.example", top) and keep("phish-1.vercel.app", top)
    assert not keep("vercel.app", top)


def test_lookup_keys_never_a_platform():
    assert lookup_keys("a.b.evil.example") == ["a.b.evil.example", "b.evil.example", "evil.example"]
    assert lookup_keys("x.y.vercel.app") == ["x.y.vercel.app", "y.vercel.app"]
    assert lookup_keys("evil.co.in") == ["evil.co.in"]
    assert lookup_keys("vercel.app") == []


def test_lookup_and_tranco_parsing():
    state = ScamLists()
    state.sources["listA"] = build("evil.example\nphish-1.vercel.app\nbit.ly\n", set())
    state.sources["listB"] = build("||evil.example^\n", set())
    assert state.lookup("login.evil.example") == ("evil.example", ["listA", "listB"])
    assert state.lookup("phish-1.vercel.app")[0] == "phish-1.vercel.app"
    assert state.lookup("other-2.vercel.app") == (None, [])
    assert state.lookup("bit.ly") == (None, []) and state.total() == 3
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("top-1m.csv", "1,google.com\n2,bit.ly\n3,example.org\n")
    assert parse_tranco(buf.getvalue(), limit=2) == {hkey("google.com"), hkey("bit.ly")}


def test_refresh_keeps_failed_source_and_caches(tmp_path):
    s = config.override(cache_dir=str(tmp_path), scam_list_exclude=())
    state = ScamLists()
    state.sources["devspen"] = build("old.example\n", set())

    def handler(req: httpx.Request):
        if "tranco" in str(req.url):
            return httpx.Response(500)
        if "devspen" in str(req.url).lower():
            return httpx.Response(503)
        return httpx.Response(200, text="new-evil.example\n")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await scamlists.refresh(s, c, state)
    report = asyncio.run(go())
    assert report["devspen"].startswith("failed") and state.lookup("old.example")[0] == "old.example"
    assert state.lookup("new-evil.example")[1]
    fresh = ScamLists()
    scamlists.load_cache(s, fresh)
    assert fresh.lookup("new-evil.example")[0] == "new-evil.example"


def test_every_source_has_terms():
    from threatdesk.constants import SCAM_LIST_SOURCES
    assert all(name and url.startswith("https://") and terms for name, url, terms in SCAM_LIST_SOURCES)
