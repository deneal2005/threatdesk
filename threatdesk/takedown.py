"""Takedown packet: facts, evidence hashes, impersonation reasons, official assets, recipient blocks.

Recipients come only from RDAP data captured during the investigation and from the user-maintained contacts.yaml.
ThreatDesk never invents an address: a missing contact is shown as missing.
"""
from __future__ import annotations

from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk.config import get_settings
from threatdesk.db import utcnow
from threatdesk.models import Brand, CheckResult, Evidence, Finding, Indicator, Signal
from threatdesk.safety import defang, defang_text
from threatdesk.scoring import RULES

PLATFORM_BY_KIND = {"android_app": "play", "ios_app": "appstore", "youtube": "youtube", "telegram": "telegram",
                    "bluesky": "bluesky"}
PLATFORM_TITLES = {"play": "Google Play", "appstore": "Apple App Store", "youtube": "YouTube", "telegram": "Telegram",
                   "instagram": "Instagram", "x": "X (Twitter)", "facebook": "Facebook", "bluesky": "Bluesky",
                   "tiktok": "TikTok"}


def load_contacts(path: str | None = None) -> dict:
    p = Path(path or get_settings().contacts_path)
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    return data.get("platforms") or {} if isinstance(data, dict) else {}


def platforms_for(f: Finding) -> list[str]:
    if f.kind in PLATFORM_BY_KIND:
        return [PLATFORM_BY_KIND[f.kind]]
    if f.kind == "social_profile":
        return [f.dedupe_key.split(":", 1)[0]]
    return []


def _latest(evidence: list[Evidence], kind: str) -> dict:
    for e in evidence:                               # newest first
        if e.kind == kind:
            return e.content_json or {}
    return {}


def build_packet(db: Session, f: Finding, contacts: dict | None = None) -> dict:
    contacts = load_contacts() if contacts is None else contacts
    evidence = list(db.scalars(select(Evidence).where(Evidence.finding_id == f.id).order_by(Evidence.id.desc())))
    signals = sorted(db.scalars(select(Signal).where(Signal.finding_id == f.id)), key=lambda s: -s.points)
    checks = {c.check: c for c in db.scalars(select(CheckResult).where(CheckResult.finding_id == f.id))}
    rdap = (_latest(evidence, "rdap_domain").get("parsed") or {})
    rdap_ip = (_latest(evidence, "rdap_ip").get("parsed") or {})
    tls = checks["tls"].detail if "tls" in checks and checks["tls"].status == "ran" else {}
    facts = _latest(evidence, "investigation_facts")
    indicators: dict[str, list[str]] = {}
    for i in db.scalars(select(Indicator).where(Indicator.finding_id == f.id).order_by(Indicator.id)):
        indicators.setdefault(i.type, []).append(i.value)
    brand = db.get(Brand, f.brand_id) if f.brand_id else None
    recipients: list[dict] = []
    if f.kind == "website":
        recipients.append({"title": "Domain registrar abuse contact (from RDAP)", "name": rdap.get("registrar"),
                           "email": rdap.get("abuse_email"), "phone": rdap.get("abuse_phone"), "report_url": None,
                           "notes": None})
        recipients.append({"title": "Hosting provider abuse contact (from IP RDAP)",
                           "name": rdap_ip.get("org") or rdap_ip.get("name"), "email": rdap_ip.get("abuse_email"),
                           "phone": rdap_ip.get("abuse_phone"), "report_url": None, "notes": None})
    for p in platforms_for(f):
        c = contacts.get(p) or {}
        recipients.append({"title": f"{PLATFORM_TITLES.get(p, p.capitalize())} (from contacts.yaml)", "name": None,
                           "email": c.get("email") or None, "phone": None, "report_url": c.get("report_url") or None,
                           "notes": c.get("notes") or None, "platform": p})
    for r in recipients:
        r["missing"] = not (r["email"] or r["phone"] or r["report_url"])
    official = {"domains": list(brand.official_domains or []) if brand else [],
                "handles": dict(brand.official_handles or {}) if brand else {},
                "apps": {k: v for k, v in (brand.official_apps or {}).items() if k in ("android", "ios") and v}
                if brand else {}}
    return {"f": f, "brand": brand, "generated": utcnow(), "recipients": recipients, "signals": signals,
            "rules": RULES, "chain": facts.get("redirect_chain") or [], "evidence": evidence, "rdap": rdap,
            "rdap_ip": rdap_ip, "tls": tls, "indicators": indicators, "official": official}


def packet_text(p: dict) -> str:
    f = p["f"]
    out: list[str] = [f"TAKEDOWN PACKET - case {f.id:04d} - generated {p['generated']:%Y-%m-%d %H:%M} UTC", ""]

    def section(n: int, title: str, lines: list[str]) -> None:
        out.extend([f"{n}. {title}", *(lines or ["(none)"]), ""])

    section(1, "WHAT WAS FOUND", [f"Item: {defang_text(f.display_name)}", f"URL: {defang(f.url) or '-'}",
                                  f"Type: {f.kind}", f"Verdict: {f.verdict} (score {f.score}/100, {f.severity})",
                                  f"First seen: {f.first_seen:%Y-%m-%d %H:%M} UTC",
                                  f"Brand: {p['brand'].name if p['brand'] else '-'}"])
    section(2, "REDIRECT CHAIN", [f"{h.get('status')} {defang(h.get('url'))} ({h.get('ip')})" for h in p["chain"]])
    r = p["rdap"]
    section(3, "DOMAIN REGISTRATION (RDAP)", [f"{k}: {v}" for k, v in (
        ("Domain", r.get("domain")), ("Registered", r.get("registered")), ("Registrar", r.get("registrar")),
        ("Registrar abuse email", r.get("abuse_email")), ("Registrant", "redacted" if r.get("redacted") else
                                                           r.get("registrant"))) if v])
    t = p["tls"]
    section(4, "TLS CERTIFICATE", [f"{k}: {v}" for k, v in (
        ("Issuer", t.get("issuer")), ("Valid from", t.get("not_before")), ("Valid until", t.get("not_after")),
        ("Verified", t.get("verified"))) if v not in (None, "")])
    h = p["rdap_ip"]
    section(5, "HOSTING", [f"{k}: {v}" for k, v in (("IP", h.get("ip")), ("Network", h.get("org") or h.get("name")),
                                                     ("Abuse email", h.get("abuse_email"))) if v])
    section(6, "WHY THIS IMPERSONATES THE BRAND",
            [f"{s.points:+d} {RULES.get(s.code, (0, s.code))[1]}: {defang_text(s.evidence)}" for s in p["signals"]])
    section(7, "INDICATORS", [f"{k}: {', '.join(defang_text(v) for v in vs[:30])}" for k, vs in p["indicators"].items()])
    section(8, "EVIDENCE (append-only, SHA-256)",
            [f"#{e.id} {e.kind} {e.captured_at:%Y-%m-%d %H:%M} UTC sha256={e.sha256}" for e in p["evidence"]])
    o = p["official"]
    section(9, "OFFICIAL ASSETS OF THE BRAND", [f"Domains: {', '.join(o['domains']) or '-'}",
                                                *[f"{k}: {', '.join(v)}" for k, v in o["handles"].items()],
                                                *[f"{k} apps: {', '.join(v)}" for k, v in o["apps"].items()]])
    section(10, "RECIPIENTS", [
        f"{x['title']}: " + ("NO CONTACT AVAILABLE (fill contacts.yaml or check the registrar's website)" if x["missing"]
                             else " | ".join(v for v in (x["name"], x["email"], x["phone"], x["report_url"]) if v))
        for x in p["recipients"]])
    return "\n".join(out)
