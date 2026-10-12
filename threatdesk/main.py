"""ThreatDesk application factory."""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from threatdesk import db
from threatdesk.config import get_settings
from threatdesk.logs import kv, setup_logging
from threatdesk.web import middleware

log = logging.getLogger("threatdesk")


def _migrate_brand_assets() -> None:
    """Brands saved before asset records existed get one row per domain, handle and app (idempotent)."""
    from threatdesk.assets.store import migrate_all
    try:
        with db.session_scope() as s:
            made = migrate_all(s)
        if made:
            log.info("brand assets migrated", extra=kv(rows=made))
    except Exception:
        log.exception("brand asset migration failed; brands keep their previous official lists")


def _scrub_breadcrumb(crumb: dict, _hint: dict) -> dict:
    """Outbound HTTP breadcrumbs: some reputation APIs take their key in the query string."""
    data = crumb.get("data") or {}
    data.pop("http.query", None)
    if isinstance(data.get("url"), str):
        data["url"] = data["url"].split("?", 1)[0]
    return crumb


def init_sentry() -> bool:
    """Error reporting when SENTRY_DSN is set. No request bodies, cookies or user details are sent."""
    settings = get_settings()
    if not settings.sentry_dsn or settings.testing:
        return False
    import sentry_sdk
    sentry_sdk.init(
        dsn=settings.sentry_dsn, environment=os.getenv("VERCEL_ENV") or settings.env,
        release=os.getenv("VERCEL_GIT_COMMIT_SHA") or None, send_default_pii=False, max_request_body_size="never",
        traces_sample_rate=float(os.getenv("SENTRY_TRACES_SAMPLE_RATE") or 0), before_breadcrumb=_scrub_breadcrumb,
    )
    return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    db.create_all()
    _migrate_brand_assets()
    settings = get_settings()
    stop_lists = asyncio.Event()
    lists_task = None
    if settings.scam_lists and not settings.testing:
        from threatdesk import scamlists
        lists_task = asyncio.create_task(scamlists.run_refresher(settings, stop_lists))
    worker = None
    if get_settings().start_worker:
        from threatdesk.worker import Worker
        worker = Worker()
        await worker.start()
    log.info("startup complete")
    yield
    if worker:
        await worker.stop()
    if lists_task:
        stop_lists.set()
        lists_task.cancel()
    log.info("shutdown")


def create_app() -> FastAPI:
    get_settings()
    init_sentry()
    app = FastAPI(title="ThreatDesk", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    middleware.install(app)
    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

    from threatdesk.web import ROUTERS
    for r in ROUTERS:
        app.include_router(r)

    @app.get("/health")
    def health():
        ok = db.ping()
        return JSONResponse({"status": "ok" if ok else "degraded", "db": ok}, status_code=200 if ok else 503)

    return app


app = create_app()
