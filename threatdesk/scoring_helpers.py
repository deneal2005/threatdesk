"""Small shared helpers for checks: date parsing, similarity."""
from __future__ import annotations

import re
from datetime import UTC, date, datetime

from rapidfuzz import fuzz

_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d", "%b %d, %Y", "%B %d, %Y", "%d %b %Y", "%Y%m%d%H%M%S", "%Y%m%d")


def parse_date(value) -> datetime | None:
    """ISO / RDAP / store / epoch values -> naive UTC datetime (None when unknown)."""
    if value in (None, "", 0):
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo else value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    if isinstance(value, (int, float)):
        try:
            secs = value / 1000 if value > 1e11 else value          # milliseconds or seconds
            return datetime.fromtimestamp(secs, UTC).replace(tzinfo=None)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    if re.fullmatch(r"\d{9,13}", s):
        return parse_date(int(s))
    s = re.sub(r"Z$", "+00:00", s)
    try:
        return parse_date(datetime.fromisoformat(s))
    except ValueError:
        pass
    for fmt in _FORMATS:
        try:
            return parse_date(datetime.strptime(s, fmt))
        except ValueError:
            continue
    return None


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def name_similarity(a: str, b: str) -> float:
    return float(fuzz.token_set_ratio((a or "").lower(), (b or "").lower()))


def handle_similarity(a: str, b: str) -> float:
    return float(fuzz.ratio(norm(a), norm(b)))


def company_norm(name: str) -> str:
    from threatdesk.brands import publisher_key
    return publisher_key(name)
