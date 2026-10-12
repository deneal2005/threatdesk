"""Brand settings parsing and official-asset / whitelist matching (pure functions, unit tested)."""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field

from threatdesk.safety import InvalidInput, clean_list, clean_text

LEGAL_SUFFIX_RE = re.compile(r"\b(private|pvt|limited|ltd|llc|llp|inc|incorporated|corporation|corp|company|co|plc|"
                             r"gmbh|ag|sa|bv|nv|pty|technologies|technology)\b\.?", re.I)
ANDROID_RE = re.compile(r"^[a-zA-Z][\w]*(\.[a-zA-Z][\w]*)+$")
IOS_RE = re.compile(r"^\d{5,12}$")
KEYWORD_RE = re.compile(r"^[\w.-]{2,40}$")
WHITELIST_TYPES = {"domain": "Domain", "handle": "Handle", "android": "Android app", "ios": "iOS app",
                   "dedupe_key": "Exact asset key"}


def clean_android(v: str) -> str:
    s = (v or "").strip()
    if len(s) > 150 or not ANDROID_RE.match(s):
        raise InvalidInput(f"'{s[:60]}' is not an Android package name (e.g. com.acme.bank).")
    return s


def clean_ios(v: str) -> str:
    s = (v or "").strip().lower().removeprefix("id")
    if not IOS_RE.match(s):
        raise InvalidInput(f"'{v[:60]}' is not an App Store app id (5-12 digits).")
    return s


def clean_keyword(v: str) -> str:
    s = (v or "").strip().lower()
    if not KEYWORD_RE.match(s):
        raise InvalidInput(f"Keyword '{s[:40]}' must be 2-40 letters, digits, dots, dashes or underscores.")
    return s


def publisher_key(name: str) -> str:
    """'Acme Insurance Pvt. Ltd.' -> 'acmeinsurance' (legal suffixes and punctuation removed)."""
    return re.sub(r"[^a-z0-9]", "", LEGAL_SUFFIX_RE.sub(" ", (name or "").lower()))


def clean_publisher(v: str) -> str:
    s = clean_text(v, 120, label="Publisher name")
    if len(publisher_key(s)) < 2:
        raise InvalidInput(f"'{s[:40]}' is not a usable publisher name.")
    return s


@dataclass
class BrandSettings:
    name: str
    keywords: list[str]
    scan_interval_hours: int
    publishers: list[str]


def parse_brand_settings(form: dict) -> BrandSettings:
    name = clean_text(form.get("name"), 80, required=True, label="Brand name")
    keywords = clean_list(form.get("keywords") or "", clean_keyword, max_items=15)
    raw = str(form.get("scan_interval_hours") or "").strip()
    try:
        interval = int(raw) if raw else 24
    except ValueError:
        raise InvalidInput("Scan interval must be a whole number of hours (0-720).")
    if not 0 <= interval <= 720:
        raise InvalidInput("Scan interval must be 0-720 hours (0 turns automatic scans off).")
    publishers = clean_list(form.get("publishers") or "", clean_publisher, max_items=20, names=True)
    return BrandSettings(name, keywords, interval, publishers)


def new_report_token() -> str:
    return secrets.token_urlsafe(18)


def domain_matches(host: str, official: str) -> bool:
    host, official = (host or "").lower().rstrip("."), (official or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return bool(official) and (host == official or host.endswith("." + official))


@dataclass
class BrandContext:
    """Plain data handed to checks (ORM objects never cross into async check code)."""
    id: int | None = None
    name: str = ""
    official_domains: list[str] = field(default_factory=list)
    official_handles: dict[str, list[str]] = field(default_factory=dict)
    official_apps: dict[str, list[str]] = field(default_factory=dict)
    keywords: list[str] = field(default_factory=list)
    logo_phash: str | None = None
    whitelist: list[tuple[str, str]] = field(default_factory=list)

    @classmethod
    def from_models(cls, brand, whitelist_rows=()) -> BrandContext:
        return cls(id=brand.id, name=brand.name, official_domains=list(brand.official_domains or []),
                   official_handles={k: list(v) for k, v in (brand.official_handles or {}).items()},
                   official_apps={k: list(v) for k, v in (brand.official_apps or {}).items()},
                   keywords=list(brand.keywords or []), logo_phash=brand.logo_phash,
                   whitelist=[(w.type, (w.value or "").lower()) for w in whitelist_rows])

    def all_handles(self) -> set[str]:
        return {h for hs in self.official_handles.values() for h in hs if h}

    def terms(self) -> list[str]:
        out: list[str] = []
        for t in [self.name, *self.keywords]:
            t = (t or "").strip().lower()
            if t and t not in out:
                out.append(t)
        return out

    def is_official_host(self, host: str) -> bool:
        return any(domain_matches(host, d) for d in self.official_domains)

    def is_whitelisted(self, type_: str, value: str) -> bool:
        v = (value or "").lower().lstrip("@")
        for t, w in self.whitelist:
            if t != type_:
                continue
            if v == w or (type_ == "domain" and domain_matches(v, w)):
                return True
        return False

    def official_publishers(self) -> list[str]:
        return list(self.official_apps.get("publishers", []))

    def official_publisher(self, developer: str = "", website: str = "", email: str = "") -> str | None:
        """Why an app's publisher counts as the brand: its website or email is on an official domain, or its name is
        on the brand's publisher list (Play developer names are not verified, so only an exact listed name counts)."""
        from urllib.parse import urlparse
        host = urlparse(website if "://" in (website or "") else f"https://{website}").hostname if website else ""
        if host and self.is_official_host(host):
            return f"developer website {host}"
        mail_domain = (email or "").rsplit("@", 1)[-1].lower() if "@" in (email or "") else ""
        if mail_domain and self.is_official_host(mail_domain):
            return f"developer email @{mail_domain}"
        key = publisher_key(developer)
        for p in self.official_publishers():
            if key and key == publisher_key(p):
                return f"listed publisher {p}"
        return None

    def is_official_asset(self, kind: str, ident: str) -> bool:
        ident = (ident or "").lower().lstrip("@")
        if kind in ("android", "android_app"):
            return ident in [a.lower() for a in self.official_apps.get("android", [])]
        if kind in ("ios", "ios_app"):
            return ident in [a.lower() for a in self.official_apps.get("ios", [])]
        return ident in [h.lower() for h in self.official_handles.get(kind, [])]
