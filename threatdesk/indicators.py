"""Indicator extraction from text: phones, UPI ids, emails, URLs, messaging links, handles."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from threatdesk.constants import SHORTENERS

PHONE_RE = re.compile(r"(?<![\w+])(?:\+?91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)|(?<![\w+])\+\d{1,3}[\s-]?\d[\d\s-]{6,13}\d")
UPI_RE = re.compile(r"(?<![\w.])([\w.\-]{2,64}@[a-zA-Z]{2,20})(?![\w.@-])")
EMAIL_RE = re.compile(r"(?<![\w.+-])([\w.+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24})\b")
URL_RE = re.compile(r"\bhttps?://[^\s<>\"'()]+|\bwww\.[^\s<>\"'()]+", re.I)
BARE_SHORT_RE = re.compile(r"\b(?:" + "|".join(re.escape(s) for s in SHORTENERS) + r")/[\w-]+", re.I)
HANDLE_RE = re.compile(r"(?<![\w@./])@([A-Za-z0-9_.]{3,30})\b")
MESSAGING_RE = re.compile(r"(?:https?://)?(?:wa\.me|api\.whatsapp\.com/send|chat\.whatsapp\.com|t\.me|telegram\.me)"
                          r"/[^\s<>\"'()]+", re.I)


def _norm_phone(p: str) -> str:
    digits = re.sub(r"\D", "", p)
    if len(digits) == 12 and digits.startswith("91"):
        return digits[2:]
    if len(digits) == 11 and digits.startswith("0"):
        return digits[1:]
    return digits


def _uniq(values, cap: int = 20) -> list[str]:
    out: list[str] = []
    for v in values:
        v = v.strip().rstrip(".,;:!?)")
        if v and v not in out:
            out.append(v)
        if len(out) >= cap:
            break
    return out


def extract(text: str) -> dict[str, list[str]]:
    t = text or ""
    emails = _uniq(m.group(1).lower() for m in EMAIL_RE.finditer(t))
    upi = _uniq(m.group(1).lower() for m in UPI_RE.finditer(t) if m.group(1).lower() not in emails)
    urls = _uniq([m.group(0) for m in URL_RE.finditer(t)] + [m.group(0) for m in BARE_SHORT_RE.finditer(t)])
    phones = _uniq(_norm_phone(m.group(0)) for m in PHONE_RE.finditer(t) if 10 <= len(_norm_phone(m.group(0))) <= 15)
    return {
        "phone": phones,
        "upi": upi,
        "email": emails,
        "url": urls,
        "messaging": _uniq(m.group(0) for m in MESSAGING_RE.finditer(t)),
        "handle": _uniq(m.group(1).lower().rstrip(".") for m in HANDLE_RE.finditer(t)),
    }


def host_of(url: str) -> str:
    u = url if re.match(r"^[a-z][a-z0-9+.-]*://", url or "", re.I) else f"https://{url}"
    try:
        return (urlsplit(u).hostname or "").lower()
    except ValueError:
        return ""


def is_shortener(url: str) -> bool:
    h = host_of(url)
    return (h[4:] if h.startswith("www.") else h) in SHORTENERS
