"""Settings from environment (.env). Secrets are read here only and never logged."""
from __future__ import annotations

import dataclasses
import logging
import os
import secrets
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger("threatdesk.config")

DEFAULT_DNS = ("1.1.1.1", "8.8.8.8")


def _get(name: str) -> str | None:
    v = os.getenv(name)
    if v is None:
        return None
    v = v.strip()
    return v or None


def _int(name: str, default: int) -> int:
    try:
        return int(_get(name) or default)
    except ValueError:
        return default


def _dns_servers(raw: str | None) -> tuple[str, ...]:
    """Default public resolvers (ISP DNS may rewrite answers); "system" means the OS resolver (empty tuple)."""
    if not raw:
        return DEFAULT_DNS
    if raw.strip().lower() == "system":
        return ()
    return tuple(x.strip() for x in raw.split(",") if x.strip()) or DEFAULT_DNS


# Query parameters added by hosting integrations (Supabase/Vercel/Prisma) that libpq rejects as unknown.
FOREIGN_DB_PARAMS = ("supa", "pgbouncer", "connection_limit", "pool_timeout", "schema")


def normalize_db_url(url: str) -> str:
    """Accept postgres:// and postgresql:// (Supabase pooler strings) and select the psycopg 3 driver."""
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    if url.startswith("postgresql+psycopg://") and "?" in url:
        p = urlsplit(url)
        q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k not in FOREIGN_DB_PARAMS]
        url = urlunsplit(p._replace(query=urlencode(q)))
    return url


def _is_serverless() -> bool:
    """Vercel (and similar) run short-lived functions: no in-process worker, no long background downloads."""
    raw = (_get("SERVERLESS") or "").lower()
    if raw:
        return raw in ("1", "true", "on")
    return bool(_get("VERCEL"))


@dataclass(frozen=True)
class Settings:
    env: str
    testing: bool
    database_url: str
    secret_key: str
    cron_secret: str | None = None
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-3.5-flash-lite"
    youtube_api_key: str | None = None
    safe_browsing_api_key: str | None = None
    vt_api_key: str | None = None
    urlhaus_auth_key: str | None = None
    google_cse_key: str | None = None
    google_cse_cx: str | None = None
    brave_api_key: str | None = None
    webhook_url: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_to: str | None = None
    enable_screenshots: bool = False
    start_worker: bool = True
    worker_concurrency: int = 3
    job_timeout: int = 120
    contacts_path: str = "contacts.yaml"
    public_base_url: str = ""
    dns_servers: tuple[str, ...] = DEFAULT_DNS
    scam_lists: bool = True
    scam_list_exclude: tuple[str, ...] = ()
    cache_dir: str = ".cache"
    phishtank_app_key: str | None = None
    phishtank_username: str = "threatdesk"
    apify_token: str | None = None
    apify_instagram_about: bool = False
    serverless: bool = False
    sentry_dsn: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    def __repr__(self) -> str:          # never print secrets by accident
        return f"Settings(env={self.env!r}, testing={self.testing})"


def load_settings() -> Settings:
    testing = os.getenv("THREATDESK_TESTING") == "1"
    serverless = _is_serverless() and not testing
    env = (_get("ENV") or ("prod" if serverless else "dev")).lower()
    # The Supabase/Neon integrations for Vercel inject POSTGRES_URL (pooled) instead of DATABASE_URL.
    url = _get("DATABASE_URL") or ("" if testing else _get("POSTGRES_URL") or "")
    if testing and not url:
        url = "sqlite+pysqlite:///:memory:"
    url = normalize_db_url(url)
    if not testing and not url.startswith("postgresql+psycopg://"):
        raise RuntimeError("DATABASE_URL must be a PostgreSQL URL (SQLite is allowed only for tests).")
    secret = _get("SECRET_KEY")
    if not secret:
        if env == "prod":
            raise RuntimeError("SECRET_KEY is required when ENV=prod.")
        secret = secrets.token_urlsafe(32)
        if not testing:
            log.warning("SECRET_KEY not set; using a random key (sessions reset on restart).")
    return Settings(
        env=env, testing=testing, database_url=url, secret_key=secret,
        cron_secret=_get("CRON_SECRET"),
        gemini_api_key=_get("GEMINI_API_KEY"), gemini_model=_get("GEMINI_MODEL") or "gemini-3.5-flash-lite",
        youtube_api_key=_get("YOUTUBE_API_KEY"),
        safe_browsing_api_key=_get("SAFE_BROWSING_API_KEY"), vt_api_key=_get("VT_API_KEY"),
        urlhaus_auth_key=_get("URLHAUS_AUTH_KEY"),
        google_cse_key=_get("GOOGLE_CSE_KEY"), google_cse_cx=_get("GOOGLE_CSE_CX"), brave_api_key=_get("BRAVE_API_KEY"),
        webhook_url=_get("WEBHOOK_URL"),
        smtp_host=_get("SMTP_HOST"), smtp_port=_int("SMTP_PORT", 587), smtp_user=_get("SMTP_USER"),
        smtp_password=_get("SMTP_PASSWORD"), smtp_from=_get("SMTP_FROM"), smtp_to=_get("SMTP_TO"),
        enable_screenshots=(_get("ENABLE_SCREENSHOTS") or "").lower() == "true",
        start_worker=not testing and (_get("START_WORKER") or ("false" if serverless else "true")).lower() != "false",
        worker_concurrency=_int("WORKER_CONCURRENCY", 3), job_timeout=_int("JOB_TIMEOUT", 120),
        contacts_path=_get("CONTACTS_PATH") or "contacts.yaml",
        public_base_url=(_get("PUBLIC_BASE_URL") or "").rstrip("/"),
        dns_servers=_dns_servers(_get("DNS_SERVERS")),
        scam_lists=(_get("SCAM_LISTS") or ("off" if serverless else "on")).lower() not in ("off", "false", "0"),
        scam_list_exclude=tuple(x.strip().lower() for x in (_get("SCAM_LIST_EXCLUDE") or "").split(",") if x.strip()),
        cache_dir=_get("CACHE_DIR") or ("/tmp/threatdesk-cache" if serverless else ".cache"),
        phishtank_app_key=_get("PHISHTANK_APP_KEY"), phishtank_username=_get("PHISHTANK_USERNAME") or "threatdesk",
        apify_token=_get("APIFY_TOKEN"),
        apify_instagram_about=(_get("APIFY_INSTAGRAM_ABOUT") or "").lower() == "true",
        serverless=serverless, sentry_dsn=_get("SENTRY_DSN"),
    )


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def override(**kw) -> Settings:
    """Tests: replace some settings for the rest of the test (conftest resets _settings before each test)."""
    global _settings
    _settings = dataclasses.replace(get_settings(), **kw)
    return _settings
