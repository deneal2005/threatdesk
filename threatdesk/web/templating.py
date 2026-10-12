"""Jinja2 setup (autoescape on) and the render helper."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from threatdesk.db import utcnow
from threatdesk.safety import defang, defang_text
from threatdesk.web import present

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

MESSAGES = {
    "saved": "Saved.",
    "created": "Created.",
    "deleted": "Removed.",
    "welcome": "Welcome back.",
    "welcome_new": "Welcome to ThreatDesk. Start by adding the brand you protect.",
    "still_running": "That investigation is still running. Delete it once it has finished.",
    "loggedout": "You're logged out.",
    "queued": "Scan started. New findings appear in Findings as each check finishes.",
    "whitelisted": "Added to the allow list.",
    "status": "Status updated.",
    "commented": "Comment added.",
    "assigned": "Assignee updated.",
    "bulk": "Marked as false positive.",
    "key": "API key created. Copy it now; it is shown once.",
    "revoked": "API key revoked.",
    "user": "Teammate added.",
    "details": "Profile details added (user-supplied, unverified).",
    "logged": "Takedown request logged.",
    "alerts": "Alert channels saved.",
    "brand_created": "Brand added. Next: verify your main website, then add any other accounts and apps.",
    "asset_added": "Added. Add another below, or close the form when you're done.",
    "asset_exists": "That one is already on this brand, so nothing was added.",
    "asset_saved": "Changes saved.",
    "asset_removed": "Removed.",
    "asset_primary": "Primary updated.",
    "asset_gone": "That entry was removed in the meantime.",
    "checking": "Checking. The result appears here in a few seconds.",
    "checking_all": "Checking every unverified entry. Results appear here as each check finishes.",
    "nothing_to_check": "Nothing to check: every active entry is verified or already being checked.",
}


def fmt_dt(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC") if value else "-"


def fmt_json(value) -> str:
    return json.dumps(value, indent=1, ensure_ascii=False, default=str, sort_keys=False)[:20000]


def fmt_ago(value: datetime | None) -> str:
    if not value:
        return "-"
    secs = int((utcnow() - value).total_seconds())
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{secs // 60} min ago"
    if secs < 86400:
        return f"{secs // 3600} h ago"
    return f"{secs // 86400} d ago"


def verdict_class(v: str | None) -> str:
    return {"High risk": "high", "Medium risk": "medium", "Insufficient data": "insufficient",
            "Official/whitelisted asset": "excluded"}.get(v or "", "none")


def sentence(value: str | None) -> str:
    """Uppercase only the first letter (Jinja's capitalize lowercases the rest: "Ai assessment")."""
    s = str(value or "")
    return s[:1].upper() + s[1:]


@lru_cache(maxsize=32)
def asset_version(name: str) -> str:
    try:
        return hashlib.sha256((STATIC_DIR / name).read_bytes()).hexdigest()[:10]
    except OSError:
        return "0"


def _platforms() -> dict:
    from threatdesk.assets.platforms import PLATFORMS
    return PLATFORMS


templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
templates.env.autoescape = True
templates.env.filters.update({
    "defang": defang, "dfg": defang_text, "dt": fmt_dt, "ago": fmt_ago, "pjson": fmt_json,
    "verdict_class": verdict_class, "sentence": sentence, **present.FILTERS,
})
templates.env.globals.update({
    "asset_version": asset_version, "check_summary": present.check_summary, "rail": present.rail,
    "STATUS_HELP": present.STATUS_HELP,
})


def render(request: Request, name: str, ctx: dict | None = None, status_code: int = 200):
    if "platforms" not in templates.env.globals:
        templates.env.globals["platforms"] = _platforms()
    data = {
        "user": getattr(request.state, "user", None),
        "csrf_token": getattr(request.state, "csrf_raw", ""),
        "msg": MESSAGES.get(request.query_params.get("m", "")),
        "unread": getattr(request.state, "unread", 0),
        "new_count": getattr(request.state, "new_count", 0),
    }
    data.update(ctx or {})
    return templates.TemplateResponse(request, name, data, status_code=status_code)
