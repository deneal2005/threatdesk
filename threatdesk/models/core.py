"""Tenancy, users, brands, whitelist, API keys."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from threatdesk.db import Base, utcnow


class Org(Base):
    __tablename__ = "orgs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    created: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    alert_webhooks: Mapped[str | None] = mapped_column(Text, nullable=True)      # comma-separated https URLs
    alert_email: Mapped[str | None] = mapped_column(String(254), nullable=True)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="analyst")       # admin | analyst
    created: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_findings_visit: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Brand(Base):
    __tablename__ = "brands"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    # Derived matching index, rebuilt from the asset tables by assets.store.sync_index(). Never edit directly.
    official_domains: Mapped[list] = mapped_column(JSON, default=list)
    official_handles: Mapped[dict] = mapped_column(JSON, default=dict)
    official_apps: Mapped[dict] = mapped_column(JSON, default=dict)
    keywords: Mapped[list] = mapped_column(JSON, default=list)
    logo_blob: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    logo_phash: Mapped[str | None] = mapped_column(String(32), nullable=True)
    report_token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scan_interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AssetWhitelist(Base):
    """Not the brand's own, but never report it (partners, resellers)."""
    __tablename__ = "assets_whitelist"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    brand_id: Mapped[int] = mapped_column(ForeignKey("brands.id"), index=True)
    type: Mapped[str] = mapped_column(String(24))          # domain | handle | android | ios | dedupe_key
    value: Mapped[str] = mapped_column(String(300))
    reason: Mapped[str] = mapped_column(Text, default="")
    created: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    key_hash: Mapped[str] = mapped_column(String(128), unique=True)
    prefix: Mapped[str] = mapped_column(String(12))
    label: Mapped[str] = mapped_column(String(80), default="")
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
