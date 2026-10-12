"""Certificate Transparency for the investigated domain.

crt.sh has the full history (first certificate date); Cert Spotter's free API returns current certificates only,
so it never dates a site. Certificates with few names link sibling domains of the same operator.
"""
from __future__ import annotations

import httpx

from threatdesk.checks.base import Ctx, EvidenceItem, get_json
from threatdesk.checks.domain import registrable_domain
from threatdesk.checks.generic import free_hosting_suffix, known_official
from threatdesk.db import utcnow
from threatdesk.safety import DOMAIN_RE
from threatdesk.scoring_helpers import parse_date

MAX_SIBLINGS = 20
SMALL_CERT = 10


def _names(raw: list[str]) -> set[str]:
    out = set()
    for blob in raw:
        for n in str(blob or "").split("\n"):
            n = n.strip().lower().removeprefix("*.")
            if n and DOMAIN_RE.match(n):
                out.add(n)
    return out


async def _crtsh(ctx: Ctx, domain: str) -> list[dict] | None:
    status, data = await get_json(ctx.client, "https://crt.sh/", params={"q": domain, "output": "json"},
                                  timeout=25, retries=1)
    if status != 200 or not isinstance(data, list):
        return None
    certs: dict[str, dict] = {}
    for row in data:
        if not isinstance(row, dict):
            continue
        key = str(row.get("serial_number") or row.get("id"))
        c = certs.setdefault(key, {"not_before": row.get("not_before"), "issuer": row.get("issuer_name"),
                                   "names": set()})
        c["names"] |= _names([row.get("name_value"), row.get("common_name")])
    return [{**c, "names": sorted(c["names"])} for c in certs.values()]


async def _certspotter(ctx: Ctx, domain: str) -> list[dict] | None:
    status, data = await get_json(ctx.client, "https://api.certspotter.com/v1/issuances",
                                  params={"domain": domain, "include_subdomains": "true",
                                          "expand": "dns_names"}, timeout=20)
    if status != 200 or not isinstance(data, list):
        return None
    return [{"not_before": i.get("not_before"), "issuer": None, "names": sorted(_names(i.get("dns_names") or []))}
            for i in data if isinstance(i, dict)]


async def check_ct(ctx: Ctx):
    host = ctx.link.host
    if free_hosting_suffix(host):
        return ctx.not_possible("ct_history", "shared platform certificate (free hosting): no history of its own")
    dom = registrable_domain(host)
    certs, source, err = None, "crt.sh", None
    for name, fn in (("crt.sh", _crtsh), ("certspotter", _certspotter)):
        try:
            certs, source = await fn(ctx, dom), name
        except httpx.HTTPError as e:          # crt.sh often times out; Cert Spotter is the fallback
            err = e
        if certs is not None:
            break
    if certs is None:
        if err is not None:
            raise err                          # both unreachable: report it as the network error it is
        return ctx.not_possible("ct_history", "certificate logs did not answer (crt.sh and Cert Spotter)")
    earliest = None
    if source == "crt.sh":
        dates = [d for d in (parse_date(c["not_before"]) for c in certs) if d]
        earliest = min(dates) if dates else None
    official = ctx.brand.is_official_host(host) or known_official(host)
    siblings: list[str] = []
    if not official:
        for c in certs:
            if len(c["names"]) > SMALL_CERT:
                continue
            for n in c["names"]:
                reg = registrable_domain(n)
                if reg != dom and reg not in siblings and len(siblings) < MAX_SIBLINGS:
                    siblings.append(reg)
    for s in siblings:
        ctx.indicator("domain", s)
    detail = {"certs": len(certs), "earliest": earliest.isoformat() if earliest else None, "source": source,
              "siblings": siblings}
    ctx.facts["ct"] = detail
    rdap_dated = bool((ctx.facts.get("rdap_domain") or {}).get("registered"))
    if earliest and not rdap_dated and not official and (utcnow() - earliest).days < 30:
        ctx.card.add("first_cert_recent", f"first certificate for {dom} issued {earliest.date().isoformat()}")
    ctx.evidence.append(EvidenceItem("ct_certs", {**detail, "sample": [c["names"][:5] for c in certs[:20]]}))
    return ctx.ran("ct_history", **detail)
