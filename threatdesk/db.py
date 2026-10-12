"""Engine, sessions and table creation. PostgreSQL in all real deployments; SQLite only in tests."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import NullPool, StaticPool

from threatdesk.config import get_settings


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    """Naive UTC timestamps everywhere (portable between PostgreSQL and the SQLite test DB)."""
    return datetime.now(UTC).replace(tzinfo=None)


_engine: Engine | None = None
SessionLocal = sessionmaker(autoflush=False, expire_on_commit=False)


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        return create_engine(url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
    # prepare_threshold=None: required for Supabase's transaction pooler (pgbouncer), harmless elsewhere.
    connect_args = {"prepare_threshold": None, "connect_timeout": 10}
    if get_settings().serverless:
        # Short-lived function instances: let the external pooler (Supabase/Neon) own the connections.
        return create_engine(url, poolclass=NullPool, connect_args=connect_args)
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5, pool_recycle=300,
                         pool_timeout=10, connect_args=connect_args)


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = make_engine(get_settings().database_url)
        SessionLocal.configure(bind=_engine)
    return _engine


def reset_engine(url: str | None = None) -> Engine:
    """Tests: rebuild the engine (fresh in-memory DB)."""
    global _engine
    if _engine is not None:
        _engine.dispose()
    _engine = make_engine(url or get_settings().database_url)
    SessionLocal.configure(bind=_engine)
    return _engine


def create_all() -> None:
    global _schema_ready
    import threatdesk.models  # noqa: F401  (registers tables)
    Base.metadata.create_all(get_engine())
    _schema_ready = True


_schema_ready = False


def ensure_schema() -> None:
    """Serverless hosts may skip the lifespan startup on some instances: create tables on first use instead."""
    if not _schema_ready and get_settings().serverless:
        create_all()


@contextmanager
def session_scope() -> Iterator[Session]:
    get_engine()
    ensure_schema()
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency."""
    get_engine()
    ensure_schema()
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


def ping() -> bool:
    try:
        with get_engine().connect() as c:
            c.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
