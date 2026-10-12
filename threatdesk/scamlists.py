"""Public scam/phishing lists (constants.SCAM_LIST_SOURCES): downloaded at runtime, cleaned, looked up in memory.

Each list is reduced to sorted 64-bit BLAKE2b hashes of host names (about 8 bytes per domain), cached on disk and
refreshed every 6 hours. Popular sites (Tranco top 100k), platforms, shorteners and public suffixes are removed
first: they appear on community lists by mistake and would otherwise flag half the internet.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import logging
import time
import zipfile
from array import array
from bisect import bisect_left
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from threatdesk import constants as C
from threatdesk.config import Settings
from threatdesk.logs import kv
from threatdesk.safety import DOMAIN_RE

log = logging.getLogger("threatdesk.scamlists")
REFRESH_HOURS = 6
TRANCO_REFRESH_HOURS = 24 * 7
DOWNLOAD_TIMEOUT = 120.0
_OFFICIAL = {d for _n, ds, _t, _l in C.KNOWN_BRANDS for d in ds}
_RESTRICTED = set(C.RESTRICTED_SUFFIXES)
_FREE = set(C.FREE_HOSTING_SUFFIXES)
_SHORT = set(C.SHORTENERS)
_GENERIC_SLD = {"com", "co", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "nic", "mil", "info", "biz"}


def hkey(domain: str) -> int:
    return int.from_bytes(hashlib.blake2b(domain.encode(), digest_size=8).digest(), "big", signed=True)


def _registrable(host: str) -> str:
    from threatdesk.checks.domain import registrable_domain
    return registrable_domain(host)


def _free_suffix(host: str) -> str | None:
    hits = [s for s in _FREE if host.endswith("." + s)]
    return max(hits, key=len) if hits else None


def _suffixes(host: str) -> list[str]:
    """host and its parents, down to the registrable domain or the free-hosting subdomain (never the platform)."""
    labels = host.split(".")
    free = _free_suffix(host)
    floor = (len(free.split(".")) + 1) if free else len(_registrable(host).split("."))
    return [".".join(labels[i:]) for i in range(0, len(labels) - floor + 1)]


def parse_line(line: str) -> str | None:
    s = line.strip().lower()
    if not s or s[0] in "#!;[":
        return None
    s = s.split("#", 1)[0].strip()
    if s.startswith("||"):
        s = s[2:].split("^", 1)[0]
    parts = s.split()
    if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::"):
        s = parts[1]
    elif parts:
        s = parts[0]
    if "://" in s:
        s = urlsplit(s).hostname or ""
    s = s.split("/", 1)[0].split(":", 1)[0].removeprefix("*.").removeprefix("www.").strip(".")
    return s if s and DOMAIN_RE.match(s) else None


def keep(host: str, top: set[int]) -> bool:
    """False for list mistakes: platforms, shorteners, public suffixes and popular sites."""
    if host in _SHORT or host in _FREE or host in _RESTRICTED or host.split(".")[0] in _GENERIC_SLD and \
            host.count(".") == 1:
        return False
    if any(host == d or host.endswith("." + d) for d in _OFFICIAL):
        return False
    if hkey(host) in top:
        return False
    if _free_suffix(host):                       # a user's site on a free platform: keep it
        return True
    return hkey(_registrable(host)) not in top


def lookup_keys(host: str) -> list[str]:
    host = (host or "").lower().rstrip(".").removeprefix("www.")
    if not host or host in _FREE or host in _OFFICIAL:
        return []
    return [h for h in _suffixes(host) if h.split(".")[0] not in _GENERIC_SLD or h.count(".") > 1]


def build(text: str, top: set[int]) -> array:
    keys = {hkey(h) for h in (parse_line(ln) for ln in text.splitlines()) if h and keep(h, top)}
    return array("q", sorted(keys))


def parse_tranco(zipped: bytes, limit: int = C.TRANCO_SANITISE_TOP) -> set[int]:
    with zipfile.ZipFile(io.BytesIO(zipped)) as z:
        name = next(n for n in z.namelist() if n.endswith(".csv"))
        out: set[int] = set()
        with z.open(name) as f:
            for i, raw in enumerate(io.TextIOWrapper(f, encoding="utf-8", errors="replace")):
                if i >= limit:
                    break
                dom = raw.strip().split(",")[-1].lower()
                if dom:
                    out.add(hkey(dom))
        return out


def _contains(arr: array, key: int) -> bool:
    i = bisect_left(arr, key)
    return i < len(arr) and arr[i] == key


class ScamLists:
    def __init__(self) -> None:
        self.sources: dict[str, array] = {}
        self.fetched: dict[str, float] = {}
        self.attempted: float = 0.0

    def ready(self) -> bool:
        return bool(self.sources)

    def total(self) -> int:
        return sum(len(a) for a in self.sources.values())

    def lookup(self, host: str) -> tuple[str | None, list[str]]:
        for h in lookup_keys(host):
            k = hkey(h)
            hits = [name for name, arr in self.sources.items() if _contains(arr, k)]
            if hits:
                return h, sorted(hits)
        return None, []

    def oldest_fetch(self) -> float:
        return min(self.fetched.values()) if self.fetched else 0.0


STATE = ScamLists()


def _dir(settings: Settings) -> Path:
    return Path(settings.cache_dir) / "scamlists"


def _active(settings: Settings) -> list[tuple[str, str, str]]:
    return [s for s in C.SCAM_LIST_SOURCES if s[0] not in settings.scam_list_exclude]


def load_cache(settings: Settings, state: ScamLists = STATE) -> None:
    d = _dir(settings)
    try:
        meta = json.loads((d / "meta.json").read_text())
    except (OSError, ValueError):
        return
    for name, _url, _terms in _active(settings):
        p = d / f"{name}.bin"
        if name in meta and p.exists():
            arr = array("q")
            arr.frombytes(p.read_bytes())
            state.sources[name], state.fetched[name] = arr, float(meta[name])


def _save(settings: Settings, state: ScamLists) -> None:
    d = _dir(settings)
    d.mkdir(parents=True, exist_ok=True)
    for name, arr in state.sources.items():
        (d / f"{name}.bin").write_bytes(arr.tobytes())
    (d / "meta.json").write_text(json.dumps(state.fetched))


async def _tranco(client: httpx.AsyncClient, settings: Settings) -> set[int]:
    p = _dir(settings) / "tranco_top.bin"
    if p.exists() and time.time() - p.stat().st_mtime < TRANCO_REFRESH_HOURS * 3600:
        arr = array("q")
        arr.frombytes(p.read_bytes())
        return set(arr)
    try:
        r = await client.get(C.TRANCO_URL, timeout=DOWNLOAD_TIMEOUT, follow_redirects=True)
        r.raise_for_status()
        top = await asyncio.to_thread(parse_tranco, r.content)
    except (httpx.HTTPError, zipfile.BadZipFile, StopIteration) as e:
        log.warning("tranco download failed", extra=kv(error=type(e).__name__))
        if p.exists():
            arr = array("q")
            arr.frombytes(p.read_bytes())
            return set(arr)
        return set()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(array("q", sorted(top)).tobytes())
    return top


async def refresh(settings: Settings, client: httpx.AsyncClient | None = None, state: ScamLists = STATE) -> dict:
    """Download every active list; a list that fails keeps its previous copy."""
    own = client is None
    client = client or httpx.AsyncClient()
    state.attempted = time.time()
    report: dict[str, str] = {}
    try:
        top = await _tranco(client, settings)
        for name, url, _terms in _active(settings):
            try:
                r = await client.get(url, timeout=DOWNLOAD_TIMEOUT, follow_redirects=True)
                r.raise_for_status()
                arr = await asyncio.to_thread(build, r.text, top)
                state.sources[name], state.fetched[name] = arr, time.time()
                report[name] = f"{len(arr)} domains"
            except httpx.HTTPError as e:
                report[name] = f"failed ({type(e).__name__}); kept {len(state.sources.get(name, []))}"
        if state.sources:
            await asyncio.to_thread(_save, settings, state)
    finally:
        if own:
            await client.aclose()
    log.info("scam lists refreshed", extra=kv(total=state.total(), sources=report))
    return report


async def run_refresher(settings: Settings, stop: asyncio.Event) -> None:
    await asyncio.to_thread(load_cache, settings, STATE)
    while not stop.is_set():
        if not STATE.ready() or time.time() - STATE.oldest_fetch() > REFRESH_HOURS * 3600:
            try:
                await refresh(settings)
            except Exception:  # noqa: BLE001 - try again next round
                log.exception("scam list refresh failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=1800)
        except asyncio.TimeoutError:
            pass
