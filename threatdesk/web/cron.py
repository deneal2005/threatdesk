"""Machine endpoint for a scheduler: POST /cron/tick with header X-Cron-Secret, or GET with
"Authorization: Bearer <CRON_SECRET>" (what Vercel Cron sends). On serverless hosts it also runs queued jobs."""
from __future__ import annotations

import asyncio
import hmac

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from threatdesk.config import get_settings
from threatdesk.monitoring import tick

router = APIRouter()


def _given_secret(request: Request) -> str:
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.headers.get("x-cron-secret") or ""


@router.api_route("/cron/tick", methods=["GET", "POST"])
async def cron_tick(request: Request):
    settings = get_settings()
    secret = settings.cron_secret
    if not secret:
        return JSONResponse({"error": "cron endpoint disabled (CRON_SECRET not set)"}, status_code=503)
    if not hmac.compare_digest(_given_secret(request).encode(), secret.encode()):
        return JSONResponse({"error": "wrong or missing X-Cron-Secret / Authorization"}, status_code=401)
    out = await asyncio.to_thread(tick)
    if settings.serverless:
        from threatdesk.serverless import drain
        out.update(await drain())
    return JSONResponse(out)
