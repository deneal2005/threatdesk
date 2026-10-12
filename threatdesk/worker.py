"""In-process asyncio worker: claims jobs atomically, concurrency cap, per-job timeout, retries, stale reset,
and the 5-minute monitoring tick. One app process runs one worker (by design)."""
from __future__ import annotations

import asyncio
import logging

from threatdesk import jobs
from threatdesk.config import get_settings
from threatdesk.db import SessionLocal, get_engine
from threatdesk.logs import job_id_var, kv

log = logging.getLogger("threatdesk.worker")
TICK_SECONDS = 300


def _db():
    get_engine()
    return SessionLocal()


class Worker:
    def __init__(self, concurrency: int | None = None, poll: float = 1.0):
        s = get_settings()
        self.concurrency = concurrency or s.worker_concurrency
        self.timeout = s.job_timeout
        self.poll = poll
        self._sem = asyncio.Semaphore(self.concurrency)
        self._tasks: set[asyncio.Task] = set()
        self._loop_task: asyncio.Task | None = None
        self._tick_task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        n = await asyncio.to_thread(self._reset_stale)
        if n:
            log.info("reset stale jobs", extra=kv(count=n))
        self._loop_task = asyncio.create_task(self._loop())
        self._tick_task = asyncio.create_task(self._ticker())

    async def stop(self) -> None:
        self._stop.set()
        for t in (self._loop_task, self._tick_task, *self._tasks):
            if t:
                t.cancel()

    @staticmethod
    def _reset_stale() -> int:
        db = _db()
        try:
            return jobs.reset_stale(db)
        finally:
            db.close()

    @staticmethod
    def _claim():
        from threatdesk.handlers import HANDLERS
        db = _db()
        try:
            # Only job types this code knows: an older process sharing the DB must not fail newer jobs.
            j = jobs.claim_next(db, types=list(HANDLERS))
            return (j.id, j.type, dict(j.payload or {}), j.org_id, j.attempts) if j else None
        finally:
            db.close()

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self._sem.locked():
                    await asyncio.sleep(self.poll)
                    continue
                claimed = await asyncio.to_thread(self._claim)
                if not claimed:
                    await asyncio.sleep(self.poll)
                    continue
                await self._sem.acquire()
                t = asyncio.create_task(self._run(*claimed))
                self._tasks.add(t)
                t.add_done_callback(self._tasks.discard)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("worker loop error")
                await asyncio.sleep(5)

    async def run_one(self, jid: int, jtype: str, payload: dict, org_id: int | None, attempts: int) -> None:
        """Execute a claimed job (also used directly by tests)."""
        from threatdesk.handlers import HANDLERS
        token = job_id_var.set(str(jid))
        try:
            handler = HANDLERS.get(jtype)
            if handler is None:
                raise RuntimeError(f"unknown job type {jtype}")
            result = await asyncio.wait_for(handler(jid, payload, org_id), timeout=self.timeout)
            await asyncio.to_thread(self._finish, jid, result)
            log.info("job done", extra=kv(type=jtype, attempts=attempts))
        except Exception as e:  # noqa: BLE001
            reason = "timed out" if isinstance(e, asyncio.TimeoutError) else f"{type(e).__name__}: {e}"[:300]
            status = await asyncio.to_thread(self._fail, jid, reason)
            log.warning("job failed", extra=kv(type=jtype, attempts=attempts, new_status=status, error=reason[:120]))
        finally:
            job_id_var.reset(token)

    async def _run(self, *args) -> None:
        try:
            await self.run_one(*args)
        finally:
            self._sem.release()

    @staticmethod
    def _finish(jid: int, result: dict | None) -> None:
        from threatdesk.jsonutil import jsonable
        db = _db()
        try:
            jobs.finish(db, jid, jsonable(result) if result is not None else None)
        finally:
            db.close()

    @staticmethod
    def _fail(jid: int, reason: str) -> str:
        db = _db()
        try:
            return jobs.fail(db, jid, reason)
        finally:
            db.close()

    async def _ticker(self) -> None:
        from threatdesk.monitoring import tick
        while not self._stop.is_set():
            await asyncio.sleep(TICK_SECONDS)
            try:
                await asyncio.to_thread(tick)
            except Exception:
                log.exception("scheduler tick failed")
