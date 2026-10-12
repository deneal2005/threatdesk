"""URL normalisation, link-type detection and IDN homograph analysis."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit, urlunsplit

from rapidfuzz import fuzz

from threatdesk.constants import CLOSED_SOCIAL_HOSTS
from threatdesk.safety import InvalidInput

TRACKING = re.compile(r"^(utm_\w+|fbclid|gclid|igshid|si|mc_cid|mc_eid|ref_src)$", re.I)
MAX_URL = 2000
YOUTUBE_HOSTS = {"youtube.com", "m.youtube.com", "music.youtube.com", "youtu.be"}
TELEGRAM_HOSTS = {"t.me", "telegram.me"}
TG_NOT_HANDLE = {"joinchat", "share", "addstickers", "addemoji", "proxy", "socks", "iv", "c", "addlist"}
TG_HANDLE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$")
SOCIAL_NOT_ACCOUNT = {"p", "reel", "reels", "status", "share", "watch", "groups", "i", "home", "explore", "stories",
                      "tv", "search", "hashtag", "events", "sharer", "sharer.php", "permalink.php", "story.php",
                      "photo.php", "intent"}
# Look-alike characters (Cyrillic/Greek/Latin extensions/digits) -> the ASCII letter they imitate.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "ɡ": "g", "ӏ": "l", "һ": "h", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h", "ԛ": "q", "ԝ": "w", "ү": "y",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "τ": "t", "ε": "e", "υ": "u", "χ": "x", "β": "b",
    "ı": "i", "ł": "l", "ø": "o", "đ": "d", "ħ": "h", "0": "o", "1": "l",
}


@dataclass
class Link:
    raw: str
    url: str
    host: str
    kind: str                # website | android_app | ios_app | youtube | telegram | bluesky | closed_social
    ident: str = ""
    platform: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def dedupe_key(self) -> str:
        if self.kind == "android_app":
            return f"android:{self.ident.lower()}"
        if self.kind == "ios_app":
            return f"ios:{self.ident}"
        if self.kind == "youtube" and not self.ident and self.extra.get("video_id"):
            return f"youtube:video:{self.extra['video_id']}"
        if self.kind in ("youtube", "telegram", "bluesky", "closed_social") and self.ident:
            return f"{self.platform or self.kind}:{self.ident.lower()}"
        return f"host:{self.host}"


def normalize_url(raw: str) -> str:
    s = (raw or "").strip()
    if not s or len(s) > MAX_URL or re.search(r"[\s]", s):
        raise InvalidInput("Paste a single URL (no spaces, max 2000 characters).")
    s = re.sub(r"^hxxp", "http", s, flags=re.I).replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I):
        s = "https://" + s
    p = urlsplit(s)
    scheme = p.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidInput("Only http/https links can be investigated.")
    try:
        host = (p.hostname or "").rstrip(".")
        port = p.port
    except ValueError:
        raise InvalidInput("That does not look like a URL with a domain.")
    if not host or "." not in host:
        raise InvalidInput("That does not look like a URL with a domain.")
    try:
        host = host.encode("idna").decode("ascii").lower() if not host.isascii() else host.lower()
    except UnicodeError:
        raise InvalidInput("That does not look like a URL with a domain.")
    netloc = host if ":" not in host else f"[{host}]"
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        netloc += f":{port}"
    query = urlencode([(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not TRACKING.match(k)])
    return urlunsplit((scheme, netloc, p.path or "/", query, ""))


def detect(raw: str) -> Link:
    url = normalize_url(raw)
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    base = host[4:] if host.startswith("www.") else host
    parts = [x for x in p.path.split("/") if x]
    q = parse_qs(p.query)
    link = Link(raw=raw, url=url, host=host, kind="website")
    if base == "play.google.com" and p.path.startswith("/store/apps/details") and q.get("id"):
        link.kind, link.ident, link.platform = "android_app", q["id"][0], "play"
    elif base in ("apps.apple.com", "itunes.apple.com") and (m := re.search(r"/id(\d{5,12})", p.path)):
        link.kind, link.ident, link.platform = "ios_app", m.group(1), "appstore"
    elif base in YOUTUBE_HOSTS:
        link.platform = "youtube"
        if base == "youtu.be" and parts:
            link.kind, link.extra = "youtube", {"by": "video", "video_id": parts[0]}
        elif parts and parts[0].startswith("@"):
            link.kind, link.ident, link.extra = "youtube", parts[0], {"by": "handle"}
        elif len(parts) > 1 and parts[0] == "channel":
            link.kind, link.ident, link.extra = "youtube", parts[1], {"by": "id"}
        elif len(parts) > 1 and parts[0] in ("c", "user"):
            link.kind, link.ident, link.extra = "youtube", parts[1], {"by": "legacy"}
        elif parts and parts[0] == "watch" and q.get("v"):
            link.kind, link.extra = "youtube", {"by": "video", "video_id": q["v"][0]}
        elif len(parts) > 1 and parts[0] in ("shorts", "live", "embed"):
            link.kind, link.extra = "youtube", {"by": "video", "video_id": parts[1]}
        else:
            link.platform = ""
    elif base in TELEGRAM_HOSTS and parts:
        handle = parts[1] if parts[0] == "s" and len(parts) > 1 else parts[0]
        if handle.lower() not in TG_NOT_HANDLE and TG_HANDLE.match(handle):
            link.kind, link.ident, link.platform = "telegram", handle, "telegram"
    elif base == "bsky.app" and len(parts) > 1 and parts[0] == "profile":
        link.kind, link.ident, link.platform = "bluesky", parts[1], "bluesky"
    elif host in CLOSED_SOCIAL_HOSTS:
        link.kind, link.platform = "closed_social", CLOSED_SOCIAL_HOSTS[host]
        if parts and parts[0] == "profile.php":
            link.ident = (q.get("id") or [""])[0]
        elif parts and parts[0].lower() not in SOCIAL_NOT_ACCOUNT:
            link.ident = parts[0].lstrip("@")
    return link


def _scripts(label: str) -> set[str]:
    out = set()
    for ch in label:
        if ch.isdigit() or ch in "-_":
            continue
        try:
            out.add(unicodedata.name(ch).split()[0])
        except ValueError:
            out.add("UNKNOWN")
    return out


def skeleton(text: str) -> str:
    s = unicodedata.normalize("NFKC", text or "").lower()
    return "".join(CONFUSABLES.get(ch, ch) for ch in s)


def homograph(host: str, official_domains: list[str], brand_terms: list[str]) -> dict:
    labels = (host or "").lower().split(".")
    is_idn = any(lb.startswith("xn--") for lb in labels)
    try:
        uni = ".".join(lb.encode("ascii").decode("idna") if lb.startswith("xn--") else lb for lb in labels)
    except UnicodeError:
        uni = host
    mixed = any(len(_scripts(lb)) > 1 for lb in uni.split("."))
    sk = skeleton(uni)
    matches: list[str] = []
    for off in official_domains:
        if sk == off or sk.split(".")[0] == off.split(".")[0] or fuzz.ratio(sk, off) >= 90:
            matches.append(off)
    if not matches:
        for t in brand_terms:
            t = t.replace(" ", "")
            if len(t) >= 4 and t in sk.replace("-", "") and t not in (host or "").replace("-", ""):
                matches.append(t)
    return {"is_idn": is_idn, "unicode": uni, "mixed_script": mixed, "skeleton": sk, "matches": matches,
            "suspicious": bool(is_idn and (matches or mixed))}
