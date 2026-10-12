"""Machine endpoint for an external scheduler/pinger: POST /cron/tick with header X-Cron-Secret."""
from __future__ import annotations

import asyncio
import hmac

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from threatdesk.config import get_settings
from threatdesk.monitoring import tick

router = APIRouter()


@router.post("/cron/tick")
async def cron_tick(request: Request):
    secret = get_settings().cron_secret
    if not secret:
        return JSONResponse({"error": "cron endpoint disabled (CRON_SECRET not set)"}, status_code=503)
    given = request.headers.get("x-cron-secret") or ""
    if not hmac.compare_digest(given.encode(), secret.encode()):
        return JSONResponse({"error": "wrong or missing X-Cron-Secret"}, status_code=401)
    return JSONResponse(await asyncio.to_thread(tick))
