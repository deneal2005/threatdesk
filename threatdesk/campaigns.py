"""Campaign correlation: findings linked by REAL shared values become connected components (networkx).

Shared infrastructure (CDNs, big clouds, parking services, common script hosts) links unrelated sites, so those
values are skipped and listed instead of used.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import timedelta
from itertools import combinations

import networkx as nx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from threatdesk.images import distance
from threatdesk.models import Campaign, CampaignFinding, CheckResult, Finding, Indicator
from threatdesk.scoring_helpers import parse_date

LINK_TYPES = ("phone", "upi", "email", "developer", "handle", "ip", "asn", "domain")
MAX_SHARED = 8
ICON_DISTANCE = 6
REGISTRATION_WINDOW = timedelta(days=3)
COMMON_ASNS = {"13335", "209242", "16509", "14618", "15169", "396982", "8075", "20940", "16625", "54113", "14061",
               "24940", "63949", "8560", "46606", "26496", "16276", "47583", "202425"}
COMMON_IPS = {"3.33.130.190", "15.197.148.33", "76.76.21.21", "75.2.60.5", "99.83.190.102"}
COMMON_IP_NETS = [ipaddress.ip_network(n) for n in ("91.195.240.0/23", "64.190.62.0/23", "199.59.240.0/22",
                                                     "185.53.176.0/22", "34.102.136.180/32", "103.224.182.0/23")]
COMMON_DOMAINS = {"googleapis.com", "gstatic.com", "google.com", "cloudflare.com", "jquery.com", "jsdelivr.net",
                  "bootstrapcdn.com", "fontawesome.com", "unpkg.com", "cloudfront.net", "amazonaws.com",
                  "facebook.com", "instagram.com", "twitter.com", "x.com", "youtube.com", "whatsapp.com", "wa.me",
                  "t.me", "linkedin.com", "apple.com", "w3.org", "schema.org", "wordpress.org", "wp.com", "gravatar.com",
                  "sedo.com", "dan.com", "afternic.com", "godaddy.com", "namecheap.com", "hugedomains.com",
                  "parkingcrew.net", "bodis.com", "gmail.com", "play.google.com"}


def is_parking_ip(value: str) -> bool:
    if value in COMMON_IPS:
        return True
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in n for n in COMMON_IP_NETS)


def _eligible(db: Session, org_id: int, brand_id: int | None) -> list[Finding]:
    q = select(Finding).where(Finding.org_id == org_id, Finding.in_triage.is_(True), Finding.status != "false_positive")
    if brand_id:
        q = q.where(Finding.brand_id == brand_id)
    return list(db.scalars(q))


def _common(t: str, v: str) -> str | None:
    if t == "asn" and v in COMMON_ASNS:
        return "cloud/CDN network"
    if t == "ip" and is_parking_ip(v):
        return "parking or shared hosting address"
    if t == "domain" and v in COMMON_DOMAINS:
        return "common site or script host"
    return None


def build_graph(findings: list[Finding], indicators: list[tuple[int, str, str]],
                registrations: dict[int, tuple[str, object]]) -> tuple[nx.Graph, list[dict]]:
    g = nx.Graph()
    ids = {f.id for f in findings}
    g.add_nodes_from(ids)
    by_value: dict[tuple[str, str], set[int]] = defaultdict(set)
    icons: dict[int, list[str]] = defaultdict(list)
    skipped: dict[tuple[str, str], str] = {}
    for fid, t, v in indicators:
        if fid not in ids:
            continue
        if t == "icon_hash":
            icons[fid].append(v)
        elif t in LINK_TYPES:
            if why := _common(t, v):
                skipped[(t, v)] = why
            else:
                by_value[(t, v.lower())].add(fid)

    def link(a: int, b: int, t: str, v: str) -> None:
        if not g.has_edge(a, b):
            g.add_edge(a, b, shared=[])
        g[a][b]["shared"].append({"type": t, "value": v})

    for (t, v), fids in by_value.items():
        if len(fids) > MAX_SHARED:
            skipped[(t, v)] = f"on {len(fids)} findings (too common to mean one operator)"
            continue
        ordered = sorted(fids)
        for a, b in zip(ordered, ordered[1:]):
            link(a, b, t, v)
    for a, b in combinations(sorted(icons), 2):
        dists = [d for x in icons[a] for y in icons[b] if (d := distance(x, y)) is not None]
        if dists and min(dists) <= ICON_DISTANCE:
            link(a, b, "icon", f"copied icon (distance {min(dists)})")
    regs = [(fid, (r or "").strip().lower(), parse_date(d)) for fid, (r, d) in registrations.items() if fid in ids]
    for (a, ra, da), (b, rb, db_) in combinations(sorted(regs), 2):
        if ra and ra == rb and da and db_ and abs(da - db_) <= REGISTRATION_WINDOW:
            link(a, b, "registrar", f"{ra} within {REGISTRATION_WINDOW.days} days")
    return g, [{"type": t, "value": v, "reason": why} for (t, v), why in sorted(skipped.items())]


def rebuild(db: Session, org_id: int) -> dict:
    findings = _eligible(db, org_id, None)
    fids = [f.id for f in findings] or [-1]
    indicators = [(i.finding_id, i.type, i.value) for i in
                  db.scalars(select(Indicator).where(Indicator.org_id == org_id, Indicator.finding_id.in_(fids)))]
    registrations = {c.finding_id: ((c.detail or {}).get("registrar"), (c.detail or {}).get("registered"))
                     for c in db.scalars(select(CheckResult).where(CheckResult.org_id == org_id,
                                                                   CheckResult.check == "rdap_domain",
                                                                   CheckResult.status == "ran",
                                                                   CheckResult.finding_id.in_(fids)))}
    g, skipped = build_graph(findings, indicators, registrations)
    db.execute(delete(CampaignFinding).where(CampaignFinding.org_id == org_id))
    db.execute(delete(Campaign).where(Campaign.org_id == org_id))
    brands = {f.id: f.brand_id for f in findings}
    made, members = 0, 0
    for comp in nx.connected_components(g):
        if len(comp) < 2:
            continue
        reach: dict[tuple[str, str], set[int]] = defaultdict(set)
        for a, b, data in g.subgraph(comp).edges(data=True):
            for s in data.get("shared", []):
                reach[(s["type"], s["value"])] |= {a, b}
        shared = [{"type": t, "value": v, "findings": sorted(fs)} for (t, v), fs in
                  sorted(reach.items(), key=lambda kv: (-len(kv[1]), kv[0]))][:50]
        top = shared[0]
        bset = {brands[f] for f in comp}
        camp = Campaign(org_id=org_id, brand_id=bset.pop() if len(bset) == 1 else None,
                        label=f"{len(comp)} findings sharing {top['type']} {top['value']}"[:200], shared=shared)
        db.add(camp)
        db.flush()
        for fid in sorted(comp):
            db.add(CampaignFinding(org_id=org_id, campaign_id=camp.id, finding_id=fid))
        made += 1
        members += len(comp)
    db.commit()
    return {"campaigns": made, "findings": members, "considered": len(findings), "skipped": skipped[:40]}
