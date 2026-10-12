"""Validation and normalisation of website, social-account and app inputs (pure functions, unit tested)."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qs, urlparse

from threatdesk.assets.platforms import parse_profile
from threatdesk.safety import InvalidInput, clean_domain, clean_text

WEBSITE_KINDS = {
    "main": "Main website", "regional": "Regional or country site", "product": "Product or service site",
    "campaign": "Campaign or event site", "support": "Help or support site",
    "corporate": "Corporate or investor site", "other": "Other",
}
APP_PLATFORMS = {"android": "Android", "ios": "iOS"}
LIMITS = {"website": 500, "social": 1000, "app": 500}
PACKAGE_RE = re.compile(r"^[a-zA-Z][\w]*(\.[a-zA-Z][\w]*)+$")


def _flag(form: dict, name: str) -> bool:
    return str(form.get(name) or "").lower() in ("1", "on", "true", "yes")


def common_fields(form: dict) -> dict:
    out = {"notes": clean_text(form.get("notes"), 2000, label="Notes"), "is_primary": _flag(form, "is_primary")}
    if "status" in form:                                  # edit page: Active / Inactive
        out["active"] = form.get("status") != "inactive"
    return out


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def parse_website_url(raw: str) -> tuple[str, str, str]:
    """(url as given, domain without www, url_key = domain + path) for one official website."""
    s = (raw or "").strip()
    if not s:
        raise InvalidInput("Enter the website address.")
    if len(s) > 500:
        raise InvalidInput("That address is too long (max 500 characters).")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I):
        s = "https://" + s
    p = urlparse(s)
    if p.scheme.lower() not in ("http", "https"):
        raise InvalidInput("Only http and https websites can be added.")
    if p.username or p.password:
        raise InvalidInput("Remove the user name or password from the address.")
    host = (p.hostname or "").lower().rstrip(".")
    if not host:
        raise InvalidInput("That does not look like a website address.")
    if _is_ip(host):
        raise InvalidInput("Use the website's domain name, not an IP address.")
    domain = clean_domain(host)
    typed = host.encode("idna").decode("ascii") if not host.isascii() else host
    path = re.sub(r"/{2,}", "/", p.path or "/")
    if len(path) > 200:
        raise InvalidInput("That address path is too long (max 200 characters).")
    port = f":{p.port}" if p.port else ""
    url = f"{p.scheme.lower()}://{typed}{port}{path}"
    url_key = (domain + path.rstrip("/")).lower()
    return url, domain, url_key


def parse_website(form: dict) -> dict:
    url, domain, url_key = parse_website_url(form.get("url") or "")
    kind = form.get("kind") if form.get("kind") in WEBSITE_KINDS else "main"
    return {"url": url, "domain": domain, "url_key": url_key, "kind": kind,
            "purpose": clean_text(form.get("purpose"), 120, label="Purpose"), **common_fields(form)}


def parse_social(form: dict) -> dict:
    prof = parse_profile(form.get("handle") or "", form.get("platform") or "", form.get("platform_id") or "")
    return {"platform": prof.platform, "handle": prof.handle, "handle_key": prof.handle_key,
            "platform_id": prof.platform_id, "profile_url": prof.profile_url,
            "display_name": clean_text(form.get("display_name"), 120, label="Display name"),
            "purpose": clean_text(form.get("purpose"), 120, label="Purpose"),
            "region": clean_text(form.get("region"), 60, label="Region or language"), **common_fields(form)}


def parse_android_ref(raw: str) -> str:
    s = (raw or "").strip()
    if "play.google.com" in s.lower():
        s = (parse_qs(urlparse(s if "://" in s else "https://" + s).query).get("id") or [""])[0]
    if len(s) > 150 or not PACKAGE_RE.match(s):
        raise InvalidInput(f"'{(raw or '')[:60]}' is not a Google Play link or package name (e.g. com.acme.bank).")
    return s


def parse_ios_ref(raw: str) -> tuple[str, str]:
    """(numeric app id, market country code or '') from an App Store link, 'id123…' or the bare number."""
    s = (raw or "").strip()
    market = ""
    if "apple.com" in s.lower():
        p = urlparse(s if "://" in s else "https://" + s)
        m = re.search(r"/id(\d{5,12})", p.path)
        cc = re.match(r"^/([a-z]{2})/", p.path)
        market = cc.group(1).upper() if cc else ""
        s = m.group(1) if m else ""
    else:
        s = s.lower().removeprefix("id")
    if not re.fullmatch(r"\d{5,12}", s):
        raise InvalidInput(f"'{(raw or '')[:60]}' is not an App Store link or app id (e.g. id1234567890).")
    return s, market


def clean_bundle(raw: str) -> str | None:
    s = (raw or "").strip()
    if not s:
        return None
    if len(s) > 155 or not PACKAGE_RE.match(s):
        raise InvalidInput(f"'{s[:60]}' is not a bundle identifier (e.g. com.acme.bank).")
    return s


def store_url(platform: str, store_id: str, market: str = "") -> str:
    if platform == "android":
        return f"https://play.google.com/store/apps/details?id={store_id}"
    cc = (market or "").lower()
    return f"https://apps.apple.com/{cc}/app/id{store_id}" if re.fullmatch(r"[a-z]{2}", cc) else \
        f"https://apps.apple.com/app/id{store_id}"


def app_meta(form: dict) -> dict:
    return {"name": clean_text(form.get("name"), 120, label="App name"),
            "product": clean_text(form.get("product"), 120, label="Product or service"),
            "market": clean_text(form.get("market"), 60, label="Country or market"),
            "category": clean_text(form.get("category"), 60, label="Category"), **common_fields(form)}


def parse_app_listing(platform: str, ref: str, form: dict, bundle: str = "") -> dict:
    meta = app_meta(form)
    if platform == "android":
        store_id, market, bundle_id = parse_android_ref(ref), meta["market"], None
    else:
        store_id, found = parse_ios_ref(ref)
        market, bundle_id = meta["market"] or found, clean_bundle(bundle)
    meta["market"] = market
    return {"platform": platform, "store_id": store_id, "bundle_id": bundle_id,
            "store_url": store_url(platform, store_id, market), **meta}


def parse_new_app(form: dict) -> list[dict]:
    android, ios, bundle = (form.get(k, "").strip() for k in ("android", "ios", "bundle_id"))
    if not android and not ios:
        raise InvalidInput("Paste a Google Play or App Store link (or both).")
    if bundle and not ios:
        raise InvalidInput("A bundle identifier needs an App Store link or id as well.")
    if android and ios and not (form.get("name") or "").strip():
        raise InvalidInput("Give the app a name when you add both stores, so the two listings stay together.")
    form = dict(form)
    form["product"] = (form.get("product") or "").strip() or (form.get("name") or "").strip()
    out = []
    if android:
        out.append(parse_app_listing("android", android, form))
    if ios:
        out.append(parse_app_listing("ios", ios, form, bundle))
    return out


def _lines(raw: str, limit: int, what: str) -> list[str]:
    parts = [p.strip() for p in re.split(r"[\n,]+", raw or "") if p.strip()]
    if len(parts) > limit:
        raise InvalidInput(f"{what}: at most {limit} lines.")
    return parts


def parse_initial_assets(form: dict) -> dict[str, list[dict]]:
    """The quick-start fields of the new-brand form. Errors name the line that is wrong."""
    out: dict[str, list[dict]] = {"website": [], "social": [], "app": []}
    sites = _lines(form.get("websites") or "", 50, "Official websites")
    if not sites:
        raise InvalidInput("Add at least one official website.")
    for i, line in enumerate(sites):
        try:
            out["website"].append(parse_website({"url": line, "kind": "main" if i == 0 else "regional",
                                                 "is_primary": "1" if i == 0 else ""}))
        except InvalidInput as e:
            raise InvalidInput(f'Official websites, "{line[:60]}": {e}')
    for line in _lines(form.get("profiles") or "", 100, "Social accounts"):
        try:
            out["social"].append(parse_social({"handle": line}))
        except InvalidInput as e:
            raise InvalidInput(f'Social accounts, "{line[:60]}": {e}')
    for line in _lines(form.get("apps") or "", 50, "App store links"):
        ios = "apple.com" in line.lower() or re.fullmatch(r"(id)?\d{5,12}", line.lower()) is not None
        try:
            out["app"].append(parse_app_listing("ios" if ios else "android", line, {}))
        except InvalidInput as e:
            raise InvalidInput(f'App store links, "{line[:60]}": {e}')
    return out
