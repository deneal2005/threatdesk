"""Structured JSON logging with request/job ids. Never pass secrets or page bodies to the logger."""
from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import datetime, timezone

try:
    from datetime import UTC
except ImportError:
    UTC = timezone.utc

request_id: ContextVar[str] = ContextVar("request_id", default="")
job_id_var: ContextVar[str] = ContextVar("job_id", default="")

# These log full URLs, and some APIs take keys in the query string.
QUIET = ("httpx", "httpcore", "hpack", "urllib3", "google_play_scraper", "asyncio", "multipart", "watchfiles")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if rid := request_id.get():
            out["request_id"] = rid
        if jid := job_id_var.get():
            out["job_id"] = jid
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            out.update({k: v for k, v in fields.items() if k not in out})
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)[-4000:]
        return json.dumps(out, default=str, ensure_ascii=False)


def setup_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger()
    if any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        return
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    root.handlers[:] = [h]
    root.setLevel(level)
    for name in QUIET:
        logging.getLogger(name).setLevel(logging.WARNING)
    for name in ("uvicorn.access",):            # our middleware writes one access line per request
        logging.getLogger(name).setLevel(logging.WARNING)


def kv(**fields) -> dict:
    """logging extra= helper: log.info("msg", extra=kv(a=1))."""
    return {"fields": fields}
