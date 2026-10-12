"""Job handlers. DB work runs in threads; network work runs on the event loop."""
from __future__ import annotations

import asyncio

from sqlalchemy import select

from threatdesk.brands import BrandContext
from threatdesk.db import session_scope
from threatdesk.investigator import investigate
from threatdesk.models import AssetWhitelist, Brand, ReportIntake
from threatdesk.persistence import save_report
from threatdesk.scoring import VERDICT_INSUFFICIENT

NETWORK_FAILURES = ("network error", "DNS lookup timed out", "DNS servers failed")


class NetworkUnavailable(RuntimeError):
    """Most checks failed for network reasons: retry later instead of saving an empty finding."""


def network_outage(report) -> bool:
    if report.verdict != VERDICT_INSUFFICIENT:
        return False
    attempted = [c for c in report.checks if c["status"] != "not_configured"]
    failed = [c for c in attempted if c["status"] == "not_possible"
              and str(c["detail"].get("reason", "")).startswith(NETWORK_FAILURES)]
    return bool(failed) and 2 * len(failed) >= len(attempted)


def load_brand_ctx(org_id: int, brand_id: int | None) -> BrandContext:
    if not brand_id:
        return BrandContext()
    with session_scope() as db:
        brand = db.scalar(select(Brand).where(Brand.id == brand_id, Brand.org_id == org_id))
        if brand is None:
            return BrandContext()
        wl = db.scalars(select(AssetWhitelist).where(AssetWhitelist.org_id == org_id,
                                                     AssetWhitelist.brand_id == brand_id)).all()
        return BrandContext.from_models(brand, wl)


def _save(org_id: int, brand_id: int | None, report, source: str, in_triage: bool, user_submitted: bool,
          intake_id: int | None) -> dict:
    with session_scope() as db:
        f, created = save_report(db, org_id, brand_id, report, source, in_triage=in_triage,
                                 user_submitted=user_submitted)
        if intake_id:
            intake = db.scalar(select(ReportIntake).where(ReportIntake.id == intake_id, ReportIntake.org_id == org_id))
            if intake is not None:
                intake.finding_id = f.id
        if created and source != "investigate":
            from threatdesk.monitoring import notify_new_finding
            notify_new_finding(db, f)
        return {"finding_id": f.id, "created": created, "verdict": f.verdict, "score": f.score}


async def handle_investigate(jid: int, payload: dict, org_id: int | None) -> dict:
    brand_id = payload.get("brand_id")
    brand = await asyncio.to_thread(load_brand_ctx, org_id, brand_id)
    report = await investigate(payload["url"], brand=brand)
    if network_outage(report):
        raise NetworkUnavailable("most checks failed with network errors; retrying later")
    source = payload.get("source", "investigate")
    if report.excluded_reason and source.startswith("discovery:"):
        return {"skipped": report.excluded_reason, "verdict": report.verdict}
    return await asyncio.to_thread(_save, org_id, brand_id if brand.id else None, report, source,
                                   bool(payload.get("in_triage", source != "investigate")),
                                   bool(payload.get("user_submitted")), payload.get("intake_id"))


async def handle_scan(jid: int, payload: dict, org_id: int | None) -> dict:
    from threatdesk.discovery.scan import run_scan
    return await run_scan(jid, org_id, int(payload["brand_id"]))


async def handle_intake_text(jid: int, payload: dict, org_id: int | None) -> dict:
    from threatdesk.intake import run_text_intake
    return await run_text_intake(org_id, int(payload["intake_id"]), bool(payload.get("link_finding", True)))


async def handle_verify_asset(jid: int, payload: dict, org_id: int | None) -> dict:
    from threatdesk.assets.checking import handle_verify
    return await handle_verify(jid, payload, org_id)


HANDLERS = {"investigate": handle_investigate, "scan": handle_scan, "intake_text": handle_intake_text,
            "verify_asset": handle_verify_asset}
