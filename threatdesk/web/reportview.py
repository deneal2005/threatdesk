"""Assemble everything shown about one finding (report view shared by investigate and findings pages)."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk.models import Brand, CaseEvent, CheckResult, Evidence, Finding, Indicator, ReportIntake, Signal, User
from threatdesk.scoring import RULES

CHECK_ORDER = [
    # websites
    "dns", "domain_name", "rdap_domain", "rdap_ip", "tls", "wayback", "page_fetch", "content_signals",
    "safe_browsing", "virustotal", "urlhaus", "scam_lists", "phishtank", "ct_history",
    # apps
    "play_details", "ios_details", "play_permissions", "icon_vs_logo", "developer_website", "description_signals",
    # social
    "youtube_channel", "telegram_page", "bluesky_profile", "public_og_tags", "social_profile", "user_profile_details",
    "photo_vs_logo",
    # reported text
    "text_rules", "handle_similarity", "ai_text",
]


def report_context(db: Session, f: Finding) -> dict:
    checks = list(db.scalars(select(CheckResult).where(CheckResult.finding_id == f.id)))
    order = {c: i for i, c in enumerate(CHECK_ORDER)}
    checks.sort(key=lambda c: (order.get(c.check, len(order)), c.id))
    signals = sorted(db.scalars(select(Signal).where(Signal.finding_id == f.id)), key=lambda s: (-s.points, s.id))
    evidence = list(db.scalars(select(Evidence).where(Evidence.finding_id == f.id).order_by(Evidence.id.desc())))
    indicators: dict[str, list[str]] = {}
    for i in db.scalars(select(Indicator).where(Indicator.finding_id == f.id).order_by(Indicator.id)):
        indicators.setdefault(i.type, [])
        if len(indicators[i.type]) < 30:
            indicators[i.type].append(i.value)
    events = list(db.scalars(select(CaseEvent).where(CaseEvent.finding_id == f.id).order_by(CaseEvent.id.desc())))
    users = list(db.scalars(select(User).where(User.org_id == f.org_id).order_by(User.email)))
    brand = db.get(Brand, f.brand_id) if f.brand_id else None
    intakes = list(db.scalars(select(ReportIntake).where(ReportIntake.org_id == f.org_id,
                                                         ReportIntake.finding_id == f.id)
                              .order_by(ReportIntake.id.desc()).limit(20)))
    counts = {"ran": sum(c.status == "ran" for c in checks),
              "not_possible": sum(c.status == "not_possible" for c in checks),
              "not_configured": sum(c.status == "not_configured" for c in checks), "total": len(checks)}
    return {"f": f, "checks": checks, "signals": signals, "positives": [s for s in signals if s.points > 0],
            "negatives": [s for s in signals if s.points < 0], "evidence": evidence, "indicators": indicators,
            "events": events, "users": users, "emails": {u.id: u.email for u in users}, "brand": brand,
            "intakes": intakes, "rules": RULES, "counts": counts}
