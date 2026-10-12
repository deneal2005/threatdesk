"""Job execution without a resident worker (Vercel and other function hosts).

Nothing may run after a response is sent, so queued jobs run inside requests that are waiting anyway:
every HTMX status poll and API job poll runs at most one due job first, and the cron endpoint drains the
queue for as long as its time window allows. Claims stay atomic, so overlapping requests never share a job.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time

from threatdesk import jobs
from threatdesk.config import get_settings
from threatdesk.logs import kv

log = logging.getLogger("threatdesk.serverless")
CRON_WINDOW_SECONDS = 270          # Vercel's default function limit is 300 s; leave room to answer
STALE_GRACE_SECONDS = 60
# HTMX sends the id of the polling element in HX-Trigger; these elements poll only while work is pending.
POLLERS = re.compile(r"(job-\d+|asset-list)")


def wants_pump(method: str, headers, session_cookie: str | None) -> bool:
    """Signed-in HTMX status polls drive the queue (other HTMX clicks never wait on a job).
    API job polls pump through a route dependency instead, after the API key has been checked."""
    if not get_settings().serverless or method != "GET" or not headers.get("hx-request"):
        return False
    if not POLLERS.fullmatch(headers.get("hx-trigger") or ""):
        return False
    from threatdesk.security import read_session
    return read_session(session_cookie) is not None


def _reset_stale() -> int:
    from threatdesk.worker import _db
    db = _db()
    try:
        return jobs.reset_stale(db, older_than_seconds=get_settings().job_timeout + STALE_GRACE_SECONDS)
    finally:
        db.close()


async def run_due(max_jobs: int = 1, window: float | None = None) -> dict:
    """Run due jobs one after another. A new job starts only if it can finish (job timeout) inside the window."""
    from threatdesk.worker import Worker
    worker = Worker(concurrency=1)
    start = time.monotonic()
    stale = await asyncio.to_thread(_reset_stale)
    ran = 0
    while ran < max_jobs:
        if window is not None and time.monotonic() + worker.timeout > start + window:
            break
        claimed = await asyncio.to_thread(Worker._claim)
        if not claimed:
            break
        await worker.run_one(*claimed)
        ran += 1
    if ran or stale:
        log.info("serverless jobs", extra=kv(ran=ran, stale_reset=stale))
    return {"jobs_run": ran, "stale_reset": stale}


async def pump() -> None:
    """One job per poll; a failure here must never break the page that is polling."""
    try:
        await run_due(max_jobs=1)
    except Exception:
        log.exception("serverless pump failed")


async def pump_if_serverless() -> None:
    """Route dependency for authenticated API polls."""
    if get_settings().serverless:
        await pump()


async def drain() -> dict:
    return await run_due(max_jobs=1000, window=CRON_WINDOW_SECONDS)
