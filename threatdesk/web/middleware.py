"""Request id, CSRF cookie issuance, security headers, friendly error pages."""
from __future__ import annotations

import logging
import secrets
import time

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from threatdesk.logs import kv, request_id
from threatdesk.safety import InvalidInput
from threatdesk.security import CSRF_COOKIE, SESSION_COOKIE, cookie_kwargs, csrf_from_cookie, new_csrf_cookie
from threatdesk.serverless import pump, wants_pump
from threatdesk.web.deps import LoginRequired
from threatdesk.web.templating import render

log = logging.getLogger("threatdesk.http")
MAX_BODY = 3 * 1024 * 1024        # logo/photo uploads are 1 MB; everything else is small form data

CSP = ("default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' https://fonts.googleapis.com; "
       "img-src 'self' data:; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; form-action 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


class CoreMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            length = int(request.headers.get("content-length") or 0)
        except ValueError:
            length = MAX_BODY + 1
        if length > MAX_BODY:
            return JSONResponse({"error": "request body too large"}, status_code=413, headers=HEADERS)
        rid = request.headers.get("x-request-id", "")[:40] or secrets.token_hex(6)
        token = request_id.set(rid)
        start = time.monotonic()
        raw = csrf_from_cookie(request.cookies.get(CSRF_COOKIE))
        new_cookie = None
        if raw is None:
            raw, new_cookie = new_csrf_cookie()
        request.state.csrf_raw = raw
        try:
            if wants_pump(request.method, request.headers, request.cookies.get(SESSION_COOKIE)):
                await pump()
            response = await call_next(request)
        finally:
            request_id.reset(token)
        for k, v in HEADERS.items():
            response.headers.setdefault(k, v)
        response.headers["X-Request-Id"] = rid
        if new_cookie:
            response.set_cookie(CSRF_COOKIE, new_cookie, **cookie_kwargs())
        if request.url.path != "/health":
            log.info("request", extra=kv(method=request.method, path=request.url.path, status=response.status_code,
                                         ms=int((time.monotonic() - start) * 1000), request_id=rid))
        return response


def _wants_json(request: Request) -> bool:
    return request.url.path.startswith(("/api/", "/cron/", "/health"))


def install(app: FastAPI) -> None:
    app.add_middleware(CoreMiddleware)

    @app.exception_handler(LoginRequired)
    async def _login(request: Request, exc: LoginRequired):
        if _wants_json(request):
            return JSONResponse({"error": "authentication required"}, status_code=401)
        if request.headers.get("hx-request"):
            return JSONResponse({"error": "login required"}, status_code=401, headers={"HX-Redirect": "/login"})
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(HTTPException)
    async def _http(request: Request, exc: HTTPException):
        if _wants_json(request):
            return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
        return render(request, "error.html", {"code": exc.status_code, "detail": exc.detail}, exc.status_code)

    @app.exception_handler(InvalidInput)
    async def _invalid(request: Request, exc: InvalidInput):
        if _wants_json(request):
            return JSONResponse({"error": str(exc)}, status_code=400)
        return render(request, "error.html", {"code": 400, "detail": str(exc)}, 400)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        if _wants_json(request):
            return JSONResponse({"error": "invalid request"}, status_code=422)
        return render(request, "error.html", {"code": 422, "detail": "Some fields are missing or invalid."}, 422)

    @app.exception_handler(Exception)
    async def _crash(request: Request, exc: Exception):
        log.exception("unhandled error")
        if _wants_json(request):
            return JSONResponse({"error": "internal error", "request_id": request_id.get()}, status_code=500)
        return render(request, "error.html", {"code": 500, "detail": "Something went wrong. The error was logged."},
                      500)
