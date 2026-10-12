"""Text-only customer reports: scam phrases, indicators, handle similarity, optional AI classification."""
from __future__ import annotations

import asyncio
import hashlib

import httpx
from sqlalchemy import select

from threatdesk import llm
from threatdesk.brands import BrandContext
from threatdesk.checks.base import EvidenceItem
from threatdesk.checks.content import text_signals
from threatdesk.checks.domain import registrable_domain
from threatdesk.config import get_settings
from threatdesk.db import session_scope
from threatdesk.indicators import extract, host_of
from threatdesk.investigator import Report
from threatdesk.models import ReportIntake
from threatdesk.scoring import MIN_CHECKS, Scorecard, severity, verdict
from threatdesk.scoring_helpers import handle_similarity, norm


def analyze_text(text: str, brand: BrandContext, ai: dict | None, extra_urls: list[str] | None = None) -> Report:
    card = Scorecard()
    checks: list[dict] = []
    found = text_signals(card, text, brand, brand_mentions=False)
    checks.append({"check": "text_rules", "status": "ran", "detail": {"signals": list(found)}})
    ind = extract(text)
    indicators = {("phone", v) for v in ind["phone"]} | {("upi", v) for v in ind["upi"]} | \
        {("email", v) for v in ind["email"]} | {("handle", v) for v in ind["handle"]}
    for u in ind["url"] + list(extra_urls or []):
        if h := host_of(u):
            indicators.add(("domain", registrable_domain(h)))
    if ind["handle"]:
        best = max(((handle_similarity(h, o), h, o) for h in ind["handle"] for o in brand.all_handles()),
                   default=(0, "", ""))
        sim, h, o = best
        if sim >= 80 and norm(h) != norm(o):
            card.add("handle_similar", f"@{h} in the message resembles official @{o} ({int(sim)}%)")
        checks.append({"check": "handle_similarity", "status": "ran",
                       "detail": {"similar_to": o if sim >= 80 and norm(h) != norm(o) else None, "handles": ind["handle"]}})
    else:
        checks.append({"check": "handle_similarity", "status": "not_possible",
                       "detail": {"reason": "no @handles in the message"}})
    if ai is None:
        reason = "GEMINI_API_KEY not set" if not get_settings().gemini_api_key else "the AI gave no usable answer"
        checks.append({"check": "ai_text", "status": "not_configured" if "not set" in reason else "not_possible",
                       "detail": {"reason": reason}})
    else:
        checks.append({"check": "ai_text", "status": "ran", "detail": {"category": ai["category"],
                                                                      "likelihood": ai["scam_likelihood"]}})
    ran = sum(c["status"] == "ran" for c in checks)
    if ai and ai["scam_likelihood"] >= 0.7 and ran >= MIN_CHECKS:
        card.add("ai_assessment", f"AI: {ai['category']} (likelihood {ai['scam_likelihood']})")
    normalised = " ".join((text or "").lower().split())
    score = card.score
    first = " ".join((text or "").split())[:60]
    return Report(url="", kind="other", link={"kind": "text"}, display_name=f"Reported text: {first}",
                  dedupe_key="text:" + hashlib.sha256(normalised.encode()).hexdigest()[:24], checks=checks,
                  signals=[s.as_dict() for s in card.signals], score=score, severity=severity(score),
                  verdict=verdict(score, ran, False, "other"), checks_ran=ran, indicators=sorted(indicators),
                  evidence=[EvidenceItem("reported_text", {"text": text[:5000], "urls": list(extra_urls or [])})],
                  ai={"status": "ok", **ai} if ai else {"status": llm.UNAVAILABLE})


def _load(org_id: int, intake_id: int) -> dict | None:
    with session_scope() as db:
        r = db.scalar(select(ReportIntake).where(ReportIntake.id == intake_id, ReportIntake.org_id == org_id))
        return {"text": r.text or "", "url": r.url, "brand_id": r.brand_id} if r else None


async def run_text_intake(org_id: int, intake_id: int, link_finding: bool = True) -> dict:
    from threatdesk.handlers import _save, load_brand_ctx
    data = await asyncio.to_thread(_load, org_id, intake_id)
    if not data or not data["text"].strip():
        return {"skipped": "report has no text"}
    brand = await asyncio.to_thread(load_brand_ctx, org_id, data["brand_id"])
    ai = None
    if get_settings().gemini_api_key:
        async with httpx.AsyncClient() as client:
            ai = await llm.assess_text(client, data["text"])
    report = analyze_text(data["text"], brand, ai, [data["url"]] if data["url"] else None)
    return await asyncio.to_thread(_save, org_id, data["brand_id"], report, "intake", True, True,
                                   intake_id if link_finding else None)
