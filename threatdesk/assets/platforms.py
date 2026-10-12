"""Social platforms: labels, handle rules, profile-link parsing and canonical profile URLs (pure functions)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

from threatdesk.safety import InvalidInput

# key: (label, mark, handle regex, example). Order = display order on the brand page.
PLATFORMS: dict[str, tuple[str, str, str, str]] = {
    "instagram": ("Instagram", "IG", r"[A-Za-z0-9._]{1,30}", "acmebank"),
    "x": ("X (Twitter)", "X", r"[A-Za-z0-9_]{1,15}", "acmebank"),
    "facebook": ("Facebook", "FB", r"[A-Za-z0-9.\-]{2,80}", "acmebank"),
    "youtube": ("YouTube", "YT", r"[A-Za-z0-9._\-]{3,60}", "acmebank"),
    "tiktok": ("TikTok", "TT", r"[A-Za-z0-9._]{2,24}", "acmebank"),
    "linkedin": ("LinkedIn", "in", r"[A-Za-z0-9_\-%.]{2,100}", "company/acmebank"),
    "telegram": ("Telegram", "TG", r"[A-Za-z][A-Za-z0-9_]{3,31}", "acmebank"),
    "whatsapp": ("WhatsApp", "WA", r"\+?[0-9 ]{7,20}", "+91 98765 43210"),
    "threads": ("Threads", "Th", r"[A-Za-z0-9._]{1,30}", "acmebank"),
    "bluesky": ("Bluesky", "BS", r"[A-Za-z0-9.\-]{3,253}", "acmebank.com"),
    "pinterest": ("Pinterest", "Pi", r"[A-Za-z0-9_]{3,30}", "acmebank"),
    "snapchat": ("Snapchat", "SC", r"[A-Za-z0-9._\-]{3,15}", "acmebank"),
    "reddit": ("Reddit", "Re", r"(u/|r/)?[A-Za-z0-9_\-]{3,21}", "u/acmebank"),
    "github": ("GitHub", "GH", r"[A-Za-z0-9\-]{1,39}", "acmebank"),
    "other": ("Other platform", "··", r".{1,160}", "https://community.example.com/acmebank"),
}
HOSTS = {
    "instagram.com": "instagram", "x.com": "x", "twitter.com": "x", "facebook.com": "facebook", "fb.com": "facebook",
    "youtube.com": "youtube", "youtu.be": "youtube", "tiktok.com": "tiktok", "linkedin.com": "linkedin",
    "t.me": "telegram", "telegram.me": "telegram", "wa.me": "whatsapp", "whatsapp.com": "whatsapp",
    "threads.net": "threads", "threads.com": "threads", "bsky.app": "bluesky", "snapchat.com": "snapchat",
    "reddit.com": "reddit", "github.com": "github",
}
# First path segments that are pages, feeds or posts rather than an account.
NOT_PROFILE = {
    "instagram": {"p", "reel", "reels", "stories", "explore", "tv", "accounts", "direct", "about", "legal"},
    "x": {"i", "home", "explore", "search", "intent", "share", "hashtag", "settings", "notifications", "messages",
          "compose", "login", "signup", "tos", "privacy"},
    "facebook": {"watch", "groups", "events", "share", "sharer", "sharer.php", "photo", "photo.php", "story.php",
                 "permalink.php", "marketplace", "gaming", "reel", "videos", "login", "help", "hashtag"},
    "youtube": {"watch", "shorts", "playlist", "results", "feed", "embed", "live", "hashtag", "post"},
    "tiktok": {"tag", "discover", "music", "explore", "foryou", "following", "live", "search"},
    "threads": {"search", "login"},
    "telegram": {"joinchat", "share", "addstickers", "addemoji", "proxy", "socks", "iv", "c", "addlist"},
    "linkedin": {"posts", "feed", "pulse", "jobs", "learning", "events", "groups"},
    "github": {"settings", "marketplace", "topics", "explore", "features", "login", "sponsors", "search", "about"},
    "pinterest": {"pin", "search", "ideas", "today"},
    "snapchat": {"spotlight", "discover", "lens"},
    "reddit": {"comments", "search", "submit"},
}
POST_PARTS = re.compile(r"/(status|statuses|posts?|videos?|photos?|reel|reels|comments|video|post)/", re.I)
LINKEDIN_SECTIONS = ("company", "showcase", "school", "in")
PID_RE = re.compile(r"^[A-Za-z0-9_:.\-]{2,120}$")


def label(platform: str) -> str:
    return PLATFORMS.get(platform, (platform.capitalize(),))[0]


def mark(platform: str) -> str:
    return PLATFORMS[platform][1] if platform in PLATFORMS else "··"


@dataclass
class Profile:
    platform: str
    handle: str
    handle_key: str
    platform_id: str | None
    profile_url: str


def _platform_of_host(host: str) -> str | None:
    host = (host or "").lower().rstrip(".")
    for prefix in ("www.", "m.", "mobile.", "web.", "vm.", "in.", "music."):
        if host.startswith(prefix) and host[len(prefix):] in HOSTS:
            host = host[len(prefix):]
    if host in HOSTS:
        return HOSTS[host]
    if "pinterest" in host.split("."):
        return "pinterest"
    return None


def looks_like_link(raw: str) -> bool:
    s = (raw or "").strip().lower()
    if re.match(r"^[a-z][a-z0-9+.-]*://", s):
        return True
    first = s.split("/", 1)[0].split("?", 1)[0]
    if "/" in s and "." in first:                  # host/path ("t.me/acme"); "u/acme" and "company/acme" are handles
        return True
    return _platform_of_host(first) is not None


def _check(platform: str, handle: str) -> str:
    if platform == "other":
        return handle
    lab, _, rx, example = PLATFORMS[platform]
    part = handle.split("/", 1)[1] if platform == "linkedin" and "/" in handle else handle
    if platform == "whatsapp" and handle.startswith("channel/"):
        part = "+0000000"
    if not re.fullmatch(rx, part):
        raise InvalidInput(f"'{handle[:60]}' doesn't look like a {lab} handle (for example {example}).")
    return handle


def canonical_url(platform: str, handle: str, platform_id: str | None = None) -> str:
    h = handle
    if platform == "instagram":
        return f"https://www.instagram.com/{h}/"
    if platform == "x":
        return f"https://x.com/{h}"
    if platform == "facebook":
        if platform_id and h == platform_id and h.isdigit():
            return f"https://www.facebook.com/profile.php?id={platform_id}"
        return f"https://www.facebook.com/{h}"
    if platform == "youtube":
        if h.startswith("UC") and len(h) >= 20:
            return f"https://www.youtube.com/channel/{h}"
        return f"https://www.youtube.com/@{h}"
    if platform == "tiktok":
        return f"https://www.tiktok.com/@{h}"
    if platform == "linkedin":
        return f"https://www.linkedin.com/{h if '/' in h else 'company/' + h}/"
    if platform == "telegram":
        return f"https://t.me/{h}"
    if platform == "whatsapp":
        return f"https://whatsapp.com/{h}" if h.startswith("channel/") else f"https://wa.me/{re.sub(r'[^0-9]', '', h)}"
    if platform == "threads":
        return f"https://www.threads.net/@{h}"
    if platform == "bluesky":
        return f"https://bsky.app/profile/{h if '.' in h or h.startswith('did:') else h + '.bsky.social'}"
    if platform == "pinterest":
        return f"https://www.pinterest.com/{h}/"
    if platform == "snapchat":
        return f"https://www.snapchat.com/add/{h}"
    if platform == "reddit":
        return f"https://www.reddit.com/{h if '/' in h else 'u/' + h}/"
    if platform == "github":
        return f"https://github.com/{h}"
    return h if h.lower().startswith(("http://", "https://")) else ""


def handle_key(platform: str, handle: str) -> str:
    k = (handle or "").strip().lstrip("@").lower()
    if platform == "bluesky" and k.endswith(".bsky.social"):
        k = k[: -len(".bsky.social")]
    if platform == "whatsapp" and not k.startswith("channel/"):
        k = re.sub(r"[^0-9]", "", k)
    if platform == "reddit" and not k.startswith(("u/", "r/")):
        k = "u/" + k
    return k[:160]


def _from_link(raw: str) -> tuple[str, str, str | None]:
    """(platform, handle, platform_id) from a profile link. Raises InvalidInput for posts and unknown links."""
    s = raw.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I):
        s = "https://" + s
    p = urlparse(s)
    plat = _platform_of_host(p.hostname or "")
    if plat is None:
        return "other", s[:160], None
    lab = label(plat)
    parts = [x for x in p.path.split("/") if x]
    post = InvalidInput(f"That {lab} link points to a post, video or page, not an account.")
    tabbed = plat in ("youtube", "linkedin")            # /@x/videos and /company/x/posts are tabs of the account
    if not parts or (not tabbed and POST_PARTS.search(p.path + "/")) or parts[0].lower() in NOT_PROFILE.get(plat, set()):
        if not (plat == "facebook" and parts and parts[0] == "profile.php"):
            raise post
    first = parts[0]
    pid = None
    if plat == "youtube":
        if first.startswith("@"):
            handle = first[1:]
        elif first in ("channel", "c", "user") and len(parts) > 1:
            handle = parts[1]
            pid = parts[1] if first == "channel" else None
        else:
            raise post
    elif plat == "facebook":
        if first == "profile.php":
            ident = (parse_qs(p.query).get("id") or [""])[0]
            if not ident.isdigit():
                raise post
            handle, pid = ident, ident
        elif first == "people" and len(parts) >= 3:
            handle, pid = parts[1], parts[2]
        else:
            handle = first
    elif plat == "linkedin":
        if first not in LINKEDIN_SECTIONS or len(parts) < 2:
            raise post
        handle = f"{first}/{parts[1]}"
    elif plat == "whatsapp":
        handle = f"channel/{parts[1]}" if first == "channel" and len(parts) > 1 else first
    elif plat == "bluesky":
        if first != "profile" or len(parts) < 2:
            raise post
        handle = parts[1]
        pid = handle if handle.startswith("did:") else None
    elif plat == "snapchat":
        handle = parts[1] if first == "add" and len(parts) > 1 else first
    elif plat == "reddit":
        if first in ("user", "u") and len(parts) > 1:
            handle = f"u/{parts[1]}"
        elif first == "r" and len(parts) > 1:
            handle = f"r/{parts[1]}"
        else:
            raise post
    elif plat == "telegram":
        if first.startswith("+"):
            raise post
        handle = parts[1] if first == "s" and len(parts) > 1 else first
    elif plat in ("tiktok", "threads"):
        if not first.startswith("@"):
            raise post
        handle = first[1:]
    else:
        handle = first.lstrip("@")
    return plat, handle, pid


def parse_profile(raw: str, platform_hint: str = "", platform_id: str = "") -> Profile:
    raw = (raw or "").strip()
    hint = "" if platform_hint in ("", "auto") else platform_hint
    if hint and hint not in PLATFORMS:
        raise InvalidInput("Choose a platform from the list.")
    if not raw:
        raise InvalidInput("Paste a profile link or a handle.")
    if len(raw) > 500:
        raise InvalidInput("That is too long for a profile link (max 500 characters).")
    pid = None
    if looks_like_link(raw):
        plat, handle, pid = _from_link(raw)
        if hint and plat != hint:
            if plat == "other" and hint != "other":
                raise InvalidInput(f"That link is not a {label(hint)} profile.")
            if hint != "other":
                raise InvalidInput(f"That link is for {label(plat)}, but {label(hint)} is selected.")
            plat, handle, pid = "other", raw, None
    else:
        if not hint:
            raise InvalidInput("Choose the platform, or paste the full profile link.")
        plat, handle = hint, raw.lstrip("@")
        if plat == "linkedin" and "/" not in handle:
            handle = f"company/{handle}"
        if plat == "bluesky" and handle.startswith("did:"):
            pid = handle
    handle = _check(plat, handle.strip())
    explicit = (platform_id or "").strip()
    if explicit:
        if not PID_RE.match(explicit):
            raise InvalidInput("Platform ID can only contain letters, digits and _ : . - (2-120 characters).")
        pid = explicit
    return Profile(plat, handle[:160], handle_key(plat, handle), pid, canonical_url(plat, handle, pid)[:500])
