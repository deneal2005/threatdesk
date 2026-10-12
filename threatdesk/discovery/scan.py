"""Discovery scan job for one brand: run every source (each isolated), enqueue investigations, save search hits."""
from __future__ import annotations

import asyncio
import time

import httpx
from sqlalchemy import select

from threatdesk import jobs
from threatdesk.config import get_settings
from threatdesk.db import session_scope, utcnow
from threatdesk.discovery import sources
from threatdesk.discovery.websearch import src_websearch
from threatdesk.handlers import load_brand_ctx
from threatdesk.models import Brand
from threatdesk.persistence import save_report

SCAN_BUDGET = 100
MAX_APIFY_PROFILES = 10


async def _guarded(name: str, coro, deadline: float) -> tuple[str, str, list]:
    """One source's (name, status, items). A failing or slow source never stops the others."""
    try:
        status, items = await asyncio.wait_for(coro, max(1.0, deadline - time.monotonic()))
        return name, status, list(items)
    except asyncio.TimeoutError:
        return name, "failed: ran out of time", []
    except Exception as e:  # noqa: BLE001
        return name, f"failed: {type(e).__name__}", []


def _persist(org_id: int, brand_id: int, url_lists: dict[str, list[str]], search_reports: list,
             scan_id: int | None = None) -> dict:
    from threatdesk.monitoring import notify_new_finding
    enqueued, new_from_search, profiles = 0, 0, 0
    with session_scope() as db:
        brand = db.scalar(select(Brand).where(Brand.id == brand_id, Brand.org_id == org_id))
        if brand is None:                      # deleted while the scan ran: leave nothing behind
            return {"skipped": "brand deleted during the scan", "enqueued": 0, "search_findings_new": 0}
        brand.last_scan_at = utcnow()
        seen: set[str] = set()
        for name, urls in url_lists.items():
            for u in urls:
                if u in seen:
                    continue
                seen.add(u)
                jobs.enqueue(db, "investigate", {"url": u, "brand_id": brand_id, "source": f"discovery:{name}",
                                                 "in_triage": True, "scan_id": scan_id}, org_id, max_attempts=2)
                enqueued += 1
        db.commit()
        for r in search_reports:
            f, created = save_report(db, org_id, brand_id, r, "discovery:websearch", in_triage=True)
            if created:
                new_from_search += 1
                notify_new_finding(db, f)
                db.commit()
            if get_settings().apify_token and profiles < MAX_APIFY_PROFILES and \
                    r.link.get("platform") in ("instagram", "tiktok", "facebook"):
                jobs.enqueue(db, "investigate", {"url": r.url, "brand_id": brand_id, "source": "discovery:websearch",
                                                 "in_triage": True, "scan_id": scan_id}, org_id, max_attempts=2)
                profiles += 1
    return {"enqueued": enqueued, "search_findings_new": new_from_search, "profiles_to_read": profiles}


async def run_scan(jid: int, org_id: int, brand_id: int) -> dict:
    brand = await asyncio.to_thread(load_brand_ctx, org_id, brand_id)
    if not brand.id:
        return {"skipped": "brand not found"}
    settings = get_settings()
    deadline = time.monotonic() + SCAN_BUDGET
    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=20)) as client:
        results = await asyncio.gather(
            _guarded("domains", sources.src_domains(client, brand, settings), deadline),
            _guarded("certificate_transparency", sources.src_crtsh(client, brand, settings), deadline),
            _guarded("ios", sources.src_ios(client, brand, settings), deadline),
            _guarded("android", sources.src_android(client, brand, settings), deadline),
            _guarded("youtube", sources.src_youtube(client, brand, settings), deadline),
            _guarded("bluesky", sources.src_bluesky(client, brand, settings), deadline),
            _guarded("telegram", sources.src_telegram(client, brand, settings, deadline), deadline),
            _guarded("websearch", src_websearch(client, brand, settings), deadline))
    url_lists = {name: items for name, _status, items in results if name != "websearch"}
    search_reports = next(items for name, _s, items in results if name == "websearch")
    persisted = await asyncio.to_thread(_persist, org_id, brand_id, url_lists, search_reports, jid)
    return {"sources": [{"name": n, "status": s, "candidates": len(items)} for n, s, items in results], **persisted}
