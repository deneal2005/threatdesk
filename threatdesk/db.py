"""Engine, sessions and table creation. PostgreSQL in all real deployments; SQLite only in tests."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

import logging

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from threatdesk.config import get_settings

log = logging.getLogger("threatdesk.db")


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
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5, pool_recycle=300,
                         pool_timeout=10, connect_args={"prepare_threshold": None, "connect_timeout": 10})


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


def create_all() -> list[str]:
    import threatdesk.models  # noqa: F401  (registers tables)
    engine = get_engine()
    Base.metadata.create_all(engine)
    return add_missing_columns(engine)


def add_missing_columns(engine: Engine) -> list[str]:
    """Additive-only migration: create nullable columns that newer code defines but an older database lacks.
    Never drops, renames or retypes anything; non-nullable columns still need a manual migration."""
    insp = inspect(engine)
    added: list[str] = []
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            have = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in have or not col.nullable:
                    continue
                ddl = col.type.compile(dialect=engine.dialect)
                prep = engine.dialect.identifier_preparer
                conn.execute(text(f"ALTER TABLE {prep.quote(table.name)} ADD COLUMN {prep.quote(col.name)} {ddl}"))
                added.append(f"{table.name}.{col.name}")
    if added:
        log.warning("added missing columns: %s", ", ".join(added))
    return added


@contextmanager
def session_scope() -> Iterator[Session]:
    get_engine()
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
