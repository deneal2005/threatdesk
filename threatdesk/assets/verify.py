"""Verification: evidence that the brand controls an asset, not just that someone typed it in.

Accepted proof: a DNS TXT record or meta tag on the website; a link to the account/listing from a verified
website's home page; the account's code in its bio; a Bluesky handle on a verified domain; assetlinks.json or
apple-app-site-association on a verified website. A bio or store listing that merely points at the brand's site
is NOT proof (impostors and copycats do exactly that). Inconclusive checks never downgrade.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

from threatdesk.assets import sources
from threatdesk.assets.platforms import parse_profile
from threatdesk.safety import InvalidInput

TXT_PREFIX = "threatdesk-verification="
META_NAME = "threatdesk-verification"
METHODS = ("dns_txt", "meta_tag", "parent_domain", "linked_from_website", "bio_code", "bluesky_domain", "assetlinks",
           "aasa")
MAX_PAGES = 3
_META_RE = [re.compile(r'<meta[^>]+name=["\']threatdesk-verification["\'][^>]*content=["\']([^"\']+)["\']', re.I),
            re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*name=["\']threatdesk-verification["\']', re.I)]


@dataclass
class Outcome:
    status: str | None          # verified | unverified | None (inconclusive: keep what was there)
    method: str | None
    note: str
    fill: dict = field(default_factory=dict)


def under(domain: str, parent: str) -> bool:
    return domain == parent or domain.endswith("." + parent)


def meta_codes(html: str) -> list[str]:
    return [m.group(1).strip() for rx in _META_RE for m in rx.finditer(html or "")]


class Pages:
    """Home pages of the brand's verified websites, fetched once per check."""

    def __init__(self, client, urls: list[str]):
        self.client, self.urls = client, list(urls)[:MAX_PAGES]
        self._links: list[tuple[str, list[str]]] | None = None
        self.errors: list[str] = []

    async def links(self) -> list[tuple[str, list[str]]]:
        if self._links is None:
            self._links = []
            for u in self.urls:
                try:
                    final, html = await sources.fetch_page(self.client, u)
                    self._links.append((u, sources.page_links(html, final)))
                except sources.Unavailable as e:
                    self.errors.append(str(e))
        return self._links


async def verify_website(client, site: dict, verified_domains: list[str]) -> Outcome:
    domain, token = site["domain"], site["verify_token"]
    for d in verified_domains:
        if under(domain, d):
            return Outcome("verified", "parent_domain", f"Covered by the verified domain {d}.")
    problems = []
    try:
        if any(t.strip() == TXT_PREFIX + token for t in await sources.txt_records(domain)):
            return Outcome("verified", "dns_txt", f"DNS TXT record found on {domain}.")
    except sources.Unavailable as e:
        problems.append(str(e))
    try:
        _final, html = await sources.fetch_page(client, site["url"])
        if token in meta_codes(html):
            return Outcome("verified", "meta_tag", f"Verification tag found on {site['url']}.")
    except sources.Unavailable as e:
        problems.append(str(e))
    if len(problems) == 2:
        return Outcome(None, None, "The check could not finish: " + "; ".join(problems) + ". Try again later.")
    return Outcome("unverified", None, f"No verification code found on {domain} yet. Add the DNS TXT record or the "
                                       f"meta tag below, then check again (DNS changes can take an hour).")


def _same_account(href: str, acct: dict) -> bool:
    try:
        p = parse_profile(href)
    except InvalidInput:
        return False
    if p.platform != acct["platform"]:
        return False
    pid = (acct.get("platform_id") or "").lower()
    return p.handle_key == acct["handle_key"] or bool(pid and (p.platform_id or "").lower() == pid)


async def verify_social(client, settings, acct: dict, verified_domains: list[str], pages: Pages,
                        allow_paid: bool) -> Outcome:
    if acct["platform"] == "bluesky" and "." in acct["handle_key"]:
        for d in verified_domains:
            if under(acct["handle_key"], d):
                return Outcome("verified", "bluesky_domain", f"The Bluesky handle is on the verified domain {d}.")
    for base, hrefs in await pages.links():
        if any(_same_account(h, acct) for h in hrefs):
            return Outcome("verified", "linked_from_website", f"Linked from the home page of {base}.")
    problems = list(pages.errors)
    fill: dict = {}
    try:
        prof = await sources.read_profile(client, settings, acct["platform"], acct["handle"], acct.get("platform_id"),
                                          acct.get("profile_url", ""), allow_paid)
        fill = {"display_name": prof.get("name"), "platform_id": prof.get("id")}
        text = " ".join([prof.get("bio") or "", *prof.get("links", [])]).lower()
        if acct["verify_token"].lower() in text:
            return Outcome("verified", "bio_code", f"Code {acct['verify_token']} found in the bio.", fill)
    except sources.Unavailable as e:
        problems.append(str(e))
        if not pages.urls:
            return Outcome(None, None, f"{e}. Verify a website first and link this account from its home page.")
    where = "your verified website's home page" if pages.urls else "a verified website (verify one first)"
    return Outcome("unverified", None, f"Not linked from {where}, and the code {acct['verify_token']} isn't in the "
                                       f"bio. A bio that only links to your website is not proof."
                   + (f" ({'; '.join(problems)[:200]})" if problems else ""), fill)


def _same_listing(href: str, app: dict) -> bool:
    p = urlsplit(href)
    host = (p.hostname or "").lower()
    if app["platform"] == "android":
        return host == "play.google.com" and app["store_id"] in parse_qs(p.query).get("id", [])
    return host in ("apps.apple.com", "itunes.apple.com") and f"/id{app['store_id']}" in p.path


def _strings(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _strings(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _strings(v)]
    return []


def assetlinks_names(data, package: str) -> bool:
    for stmt in data if isinstance(data, list) else []:
        t = (stmt or {}).get("target") or {}
        if t.get("namespace") == "android_app" and t.get("package_name") == package:
            return True
    return False


def aasa_names(data, bundle: str) -> bool:
    rx = re.compile(rf"^[A-Z0-9]{{10}}\.{re.escape(bundle)}$")
    return any(rx.match(s) for s in _strings(data))


async def verify_app(client, app: dict, verified_urls: list[str], pages: Pages) -> Outcome:
    fill: dict = {}
    try:
        info = await sources.read_store(client, app["platform"], app["store_id"], app.get("market", ""))
        fill = {"name": info.get("name"), "bundle_id": info.get("bundle_id")}
    except sources.Unavailable:
        pass
    for base, hrefs in await pages.links():
        if any(_same_listing(h, app) for h in hrefs):
            return Outcome("verified", "linked_from_website", f"Listing linked from the home page of {base}.", fill)
    bundle = app.get("bundle_id") or fill.get("bundle_id")
    problems = list(pages.errors)
    for u in verified_urls[:MAX_PAGES]:
        root = f"{urlsplit(u).scheme}://{urlsplit(u).netloc}"
        try:
            if app["platform"] == "android":
                if assetlinks_names(await sources.fetch_json_file(client, f"{root}/.well-known/assetlinks.json"),
                                    app["store_id"]):
                    return Outcome("verified", "assetlinks", f"{root}/.well-known/assetlinks.json names the app.", fill)
            elif bundle:
                for path in ("/.well-known/apple-app-site-association", "/apple-app-site-association"):
                    if aasa_names(await sources.fetch_json_file(client, root + path), bundle):
                        return Outcome("verified", "aasa", f"{root}{path} lists {bundle}.", fill)
        except sources.Unavailable as e:
            problems.append(str(e))
    if not verified_urls:
        return Outcome("unverified", None, "Verify a website first: apps are confirmed through the brand's own site.",
                       fill)
    return Outcome("unverified", None, "No link to this listing on your verified website's home page, and no "
                                       "assetlinks/apple-app-site-association entry for it. A listing that names "
                                       "your website is not proof." + (f" ({'; '.join(problems)[:200]})" if problems
                                                                        else ""), fill)
