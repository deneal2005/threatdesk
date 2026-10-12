"""Ownership evidence for a look-alike domain: is it the brand's own defensive registration?

Brands register many names that look like themselves (amazonlogin.com, amazon.xyz) and park or redirect them. Those
must not become "phishing" findings. Three independent facts point at the brand owning a domain:
  * it was registered more than a year ago through a corporate brand-protection registrar (MarkMonitor, CSC, ...),
  * the registrant organisation (when not redacted) is the brand or one of its listed publishers,
  * it uses the same private nameservers as one of the brand's official domains.
Each is counter-evidence with its own points; none of them excludes a domain on its own.
"""
from __future__ import annotations

import time

import dns.exception
import dns.resolver

from threatdesk import constants as C
from threatdesk.brands import publisher_key
from threatdesk.checks.base import Ctx
from threatdesk.checks.domain import registrable_domain
from threatdesk.safety import dns_resolver

PROTECTION_MIN_AGE_DAYS = 365
NS_TTL = 6 * 3600
_ns_cache: dict[str, tuple[float, list[str]]] = {}


async def nameservers(domain: str) -> list[str]:
    """NS host names of a registrable domain ([] when unknown); cached per process."""
    hit = _ns_cache.get(domain)
    if hit and hit[0] > time.monotonic():
        return hit[1]
    try:
        ans = await dns_resolver().resolve(domain, "NS", lifetime=5)
        found = sorted({r.target.to_text().rstrip(".").lower() for r in ans})
    except (dns.exception.DNSException, dns.resolver.NoNameservers):
        found = []
    _ns_cache[domain] = (time.monotonic() + NS_TTL, found)
    return found


def shared_dns(ns: str) -> bool:
    ns = (ns or "").lower()
    return registrable_domain(ns) in C.SHARED_DNS_HOSTS or any(p in ns for p in C.SHARED_DNS_PATTERNS)


def protection_registrar(registrar: str | None, ns: list[str]) -> str | None:
    r = (registrar or "").lower()
    if any(p in r for p in C.BRAND_PROTECTION_REGISTRARS):
        return registrar
    hit = next((n for n in ns if any(p in n for p in C.BRAND_PROTECTION_NS)), None)
    return f"nameserver {hit}" if hit else None


def registrant_matches(registrant: str | None, brand) -> str | None:
    key = publisher_key(registrant or "")
    if len(key) < 3:
        return None
    for name in [brand.name, *brand.official_publishers()]:
        pk = publisher_key(name)
        if pk and (key == pk or key.startswith(pk)):
            return name
    return None


async def check_ownership(ctx: Ctx):
    host = ctx.link.host
    if not ctx.brand.name:
        return ctx.not_possible("ownership", "no brand selected")
    if ctx.brand.is_official_host(host):
        return ctx.ran("ownership", official=True)
    dom = registrable_domain(host)
    rdap = ctx.facts.get("rdap_domain") or {}
    ns = list(rdap.get("nameservers") or []) or await nameservers(dom)
    found: dict = {"domain": dom, "nameservers": ns[:6]}
    age = rdap.get("age_days")
    reg = protection_registrar(rdap.get("registrar"), ns)
    if reg and age is not None and age >= PROTECTION_MIN_AGE_DAYS:
        ctx.card.add("brand_protection_registrar", f"{dom} was registered {str(rdap.get('registered'))[:10]} "
                                                   f"through {reg}, a corporate brand-protection service")
        found["protection_registrar"] = reg
    if who := registrant_matches(rdap.get("registrant"), ctx.brand):
        ctx.card.add("registrant_is_brand", f"{dom} registrant '{rdap.get('registrant')}' matches {who}")
        found["registrant_matches"] = who
    private = [n for n in ns if not shared_dns(n) and not any(p in n for p in C.BRAND_PROTECTION_NS)]
    if private:
        for off in ctx.brand.official_domains[:5]:
            common = sorted(set(private) & set(await nameservers(registrable_domain(off))))
            if common:
                ctx.card.add("shares_official_nameservers", f"{dom} uses the same nameservers as official {off}: "
                                                            f"{', '.join(common[:3])}")
                found["shares_nameservers_with"] = off
                break
    if not rdap:
        found["note"] = "no registration record: only nameservers were compared"
    return ctx.ran("ownership", **found)
