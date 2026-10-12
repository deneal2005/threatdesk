"""Passwords (argon2), signed session cookies, CSRF (signed double-submit), in-memory rate limits."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from itsdangerous import BadSignature, URLSafeTimedSerializer

from threatdesk.config import get_settings

SESSION_COOKIE = "td_session"
CSRF_COOKIE = "td_csrf"
SESSION_MAX_AGE = 7 * 24 * 3600
_ph = PasswordHasher()


# ------------------------------------------------------------------ passwords
def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw_hash: str, pw: str) -> bool:
    try:
        return _ph.verify(pw_hash, pw)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


DUMMY_HASH = _ph.hash("timing-equaliser-not-a-real-password")


# ------------------------------------------------------------------ sessions
def _serializer(salt: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_settings().secret_key, salt=salt)


def make_session(user_id: int, org_id: int) -> str:
    return _serializer("session").dumps({"uid": user_id, "oid": org_id})


def read_session(cookie: str | None) -> dict | None:
    if not cookie:
        return None
    try:
        data = _serializer("session").loads(cookie, max_age=SESSION_MAX_AGE)
    except BadSignature:
        return None
    return data if isinstance(data, dict) and "uid" in data and "oid" in data else None


def cookie_kwargs() -> dict:
    return {"httponly": True, "samesite": "lax", "secure": get_settings().is_prod, "path": "/"}


# ------------------------------------------------------------------ CSRF
def new_csrf_cookie() -> tuple[str, str]:
    """Returns (raw_token, signed_cookie_value)."""
    raw = secrets.token_urlsafe(24)
    return raw, _serializer("csrf").dumps(raw)


def csrf_from_cookie(cookie: str | None) -> str | None:
    if not cookie:
        return None
    try:
        raw = _serializer("csrf").loads(cookie)
    except BadSignature:
        return None
    return raw if isinstance(raw, str) else None


def csrf_valid(cookie: str | None, submitted: str | None) -> bool:
    raw = csrf_from_cookie(cookie)
    return bool(raw and submitted and hmac.compare_digest(raw, submitted))


# ------------------------------------------------------------------ API keys
def new_api_key() -> tuple[str, str, str]:
    """Returns (plaintext shown once, sha256 hash stored, prefix)."""
    key = "td_" + secrets.token_urlsafe(32)
    return key, hash_api_key(key), key[:10]


def hash_api_key(key: str) -> str:
    return hmac.new(get_settings().secret_key.encode(), key.encode(), hashlib.sha256).hexdigest()


# ------------------------------------------------------------------ rate limits
class RateLimiter:
    """Sliding-window limiter, process-local (the app runs as a single process by design)."""

    def __init__(self) -> None:
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: float) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()
LIMITS = {
    "login": (5, 60.0),            # per IP per minute
    "signup": (5, 3600.0),         # per IP per hour
    "investigate": (10, 60.0),     # per user per minute
    "report": (5, 3600.0),         # public report form, per IP per hour
    "api": (60, 60.0),             # per API key per minute
}


def allow(bucket: str, ident: str) -> bool:
    limit, window = LIMITS[bucket]
    return limiter.hit(f"{bucket}:{ident}", limit, window)


def ip_hash(ip: str) -> str:
    return hashlib.sha256((get_settings().secret_key + ip).encode()).hexdigest()[:16]
