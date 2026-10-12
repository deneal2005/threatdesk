"""Page fetch through the SSRF guard: redirect chain, headers, title/meta, visible text, forms, links, hashes."""
from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

from threatdesk.checks.base import Ctx, EvidenceItem
from threatdesk.checks.domain import registrable_domain
from threatdesk.checks.generic import known_official
from threatdesk.indicators import MESSAGING_RE, extract
from threatdesk.pageparse import input_kinds, parse
from threatdesk.safety import UnsafeURL, safe_fetch


async def fetch_and_parse(ctx: Ctx, url: str) -> dict:
    res = await safe_fetch(ctx.client, url, allow_insecure_tls=True)
    ctype = (res.headers.get("content-type") or res.headers.get("Content-Type") or "").lower()
    body = res.text
    if "html" in ctype or (not ctype and "<html" in body[:2000].lower()):
        parsed = parse(body, res.url)
    else:
        parsed = {"title": "", "meta": {}, "text": body[:2000] if ctype.startswith("text/") else "", "forms": [],
                  "links": [], "outbound_domains": []}
    final_host = (urlsplit(res.url).hostname or "").lower()
    return {
        "requested_url": url, "final_url": res.url, "final_host": final_host, "status": res.status_code,
        "redirect_chain": res.chain, "headers": res.headers, "tls_verified": res.tls_verified,
        "sha256": hashlib.sha256(res.body).hexdigest(), "bytes": len(res.body), "truncated": res.truncated,
        "content_type": ctype[:80], **parsed,
        # messaging links (wa.me/<number>, t.me/<handle>) carry the scammer's contact details
        "indicators": extract(" ".join([parsed["title"], parsed["text"],
                                        *(ln["href"] for ln in parsed["links"] if MESSAGING_RE.search(ln["href"]))])),
        "sensitive_inputs": sorted(input_kinds(parsed["forms"])),
    }


def _same_owner(a: str, b: str) -> bool:
    if registrable_domain(a) == registrable_domain(b):
        return True
    ka, kb = known_official(a), known_official(b)
    return bool(ka and ka == kb)


async def check_page(ctx: Ctx):
    if (ctx.facts.get("dns") or {}).get("state") == "nxdomain":
        return ctx.not_possible("page_fetch", "domain does not exist (NXDOMAIN)")
    try:
        page = await fetch_and_parse(ctx, ctx.link.url)
    except UnsafeURL as e:
        return ctx.not_possible("page_fetch", f"refused by SSRF guard: {e}")
    ctx.facts["page"] = page
    ind = page["indicators"]
    for t in ("phone", "upi", "email"):
        for v in ind.get(t, [])[:20]:
            ctx.indicator(t, v)
    for d in page["outbound_domains"][:30]:
        ctx.indicator("domain", registrable_domain(d))
    host, final_host = ctx.link.host, page["final_host"]
    ctx.indicator("domain", registrable_domain(final_host))
    if final_host != host:
        if ctx.brand.is_official_host(final_host) and not ctx.brand.is_official_host(host):
            ctx.card.add("redirects_to_official", f"{host} redirects to official {final_host}")
        elif not ctx.brand.is_official_host(final_host) and not _same_owner(host, final_host):
            ctx.card.add("redirect_offsite", f"{host} redirects to {final_host}")
    ctx.evidence.append(EvidenceItem("page_capture", {
        "url": page["requested_url"], "final_url": page["final_url"], "status": page["status"],
        "redirect_chain": page["redirect_chain"], "headers": page["headers"], "title": page["title"],
        "meta": page["meta"], "text_excerpt": page["text"][:1500], "forms": page["forms"][:5],
        "bytes": page["bytes"], "truncated": page["truncated"], "body_sha256": page["sha256"],
    }, sha256=page["sha256"]))
    return ctx.ran("page_fetch", status=page["status"], title=page["title"], host=host, final_host=final_host,
                   final_url=page["final_url"], redirects=max(0, len(page["redirect_chain"]) - 1),
                   bytes=page["bytes"], truncated=page["truncated"], tls_verified=page["tls_verified"],
                   forms=len(page["forms"]), sensitive_inputs=page["sensitive_inputs"])
