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
# Look-alike sensitivity (lookalike.compare score needed to count as a look-alike). Lower catches more variants
# and produces more leads to review.
SENSITIVITY = {"strict": 90, "balanced": 80, "broad": 70}
DEFAULT_SENSITIVITY = "balanced"
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
    sensitivity: str = DEFAULT_SENSITIVITY


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
    sensitivity = str(form.get("sensitivity") or DEFAULT_SENSITIVITY).strip().lower()
    if sensitivity not in SENSITIVITY:
        raise InvalidInput("Look-alike sensitivity must be strict, balanced or broad.")
    return BrandSettings(name, keywords, interval, publishers, sensitivity)


def sensitivity_of(brand) -> str:
    value = ((getattr(brand, "detection", None) or {}).get("sensitivity") or DEFAULT_SENSITIVITY)
    return value if value in SENSITIVITY else DEFAULT_SENSITIVITY


def new_report_token() -> str:
    return secrets.token_urlsafe(18)


def known_brand_domains(name: str, official_domains: list[str]) -> tuple[str | None, list[str]]:
    """Well-known brands (constants.KNOWN_BRANDS) publish many official domains (amazon.in, amazon.co.uk...). When a
    brand is one of them - same name AND one of its listed domains on the built-in list - those count as official
    too. Both must match: a brand that only lists github.com is not Microsoft."""
    from threatdesk.constants import KNOWN_BRANDS
    key = re.sub(r"[^a-z0-9]", "", (name or "").lower())
    for known, domains, _tokens, _loose in KNOWN_BRANDS:
        if re.sub(r"[^a-z0-9]", "", known.lower()) == key and                 any(domain_matches(o, d) or domain_matches(d, o) for o in official_domains for d in domains):
            return known, list(domains)
    return None, []


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
    lookalike_threshold: int = SENSITIVITY[DEFAULT_SENSITIVITY]
    known_brand: str | None = None                       # set when the brand is one of constants.KNOWN_BRANDS
    known_domains: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.name and not self.known_domains:
            self.known_brand, self.known_domains = known_brand_domains(self.name, self.official_domains)

    @classmethod
    def from_models(cls, brand, whitelist_rows=()) -> BrandContext:
        return cls(id=brand.id, name=brand.name, official_domains=list(brand.official_domains or []),
                   official_handles={k: list(v) for k, v in (brand.official_handles or {}).items()},
                   official_apps={k: list(v) for k, v in (brand.official_apps or {}).items()},
                   keywords=list(brand.keywords or []), logo_phash=brand.logo_phash,
                   whitelist=[(w.type, (w.value or "").lower()) for w in whitelist_rows],
                   lookalike_threshold=SENSITIVITY[sensitivity_of(brand)])

    def all_handles(self) -> set[str]:
        return {h for hs in self.official_handles.values() for h in hs if h}

    def reference_handles(self) -> dict[str, str]:
        """{handle: label} of official handles to compare names with (platform ids such as UC... are skipped)."""
        from threatdesk.lookalike import is_platform_id
        out: dict[str, str] = {}
        for platform, hs in self.official_handles.items():
            for h in hs:
                if h and not is_platform_id(h) and h not in out:
                    out[h] = f"official {platform} account @{h}"
        return out

    def name_references(self) -> dict[str, str]:
        """{name: label} for the brand name, keywords and official app names."""
        out = {self.name.lower(): f"the brand name '{self.name}'"} if self.name else {}
        for k in self.keywords:
            out.setdefault(k.lower(), f"brand keyword '{k}'")
        for n in self.official_apps.get("names", []):
            out.setdefault(n.lower(), f"official app '{n}'")
        return out

    def terms(self) -> list[str]:
        out: list[str] = []
        for t in [self.name, *self.keywords]:
            t = (t or "").strip().lower()
            if t and t not in out:
                out.append(t)
        return out

    def is_official_host(self, host: str) -> bool:
        return any(domain_matches(host, d) for d in [*self.official_domains, *self.known_domains])

    def official_reason(self, host: str) -> str | None:
        """Why a host counts as official: listed by the brand, or on ThreatDesk's built-in list for this brand."""
        if any(domain_matches(host, d) for d in self.official_domains):
            return f"official domain of {self.name}"
        if any(domain_matches(host, d) for d in self.known_domains):
            return f"official {self.known_brand} domain (ThreatDesk's built-in list for well-known brands)"
        return None

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
