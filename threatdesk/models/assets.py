"""Official brand assets: one row per website, social account and app listing.

These tables are the source of truth. brands.official_domains / official_handles / official_apps are a derived
matching index rebuilt by threatdesk.assets.store.sync_index() after every change (checks read the index; keeping it
also lets older code run against the same database).
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, declared_attr, mapped_column

from threatdesk.db import Base, utcnow

VERIFICATION = ("unverified", "pending", "verified")


class AssetMixin:
    """Fields every official asset has: ownership, status, verification, notes, optimistic-lock version."""
    id: Mapped[int] = mapped_column(primary_key=True)

    @declared_attr
    def org_id(cls) -> Mapped[int]:
        return mapped_column(ForeignKey("orgs.id"), index=True)

    @declared_attr
    def brand_id(cls) -> Mapped[int]:
        return mapped_column(ForeignKey("brands.id", ondelete="CASCADE"), index=True)

    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)          # inactive: kept on record, not official
    verification_status: Mapped[str] = mapped_column(String(12), default="unverified")
    verification_method: Mapped[str | None] = mapped_column(String(40), nullable=True)
    verification_note: Mapped[str | None] = mapped_column(Text, nullable=True)   # last check, plain words
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    verify_token: Mapped[str] = mapped_column(String(64))                # code the owner publishes to prove control
    notes: Mapped[str] = mapped_column(Text, default="")
    created: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    version: Mapped[int] = mapped_column(Integer, default=1)

    @declared_attr.directive
    def __mapper_args__(cls):
        return {"version_id_col": cls.version}

    @property
    def verified(self) -> bool:
        return self.verification_status == "verified"


class BrandWebsite(AssetMixin, Base):
    __tablename__ = "brand_websites"
    __table_args__ = (UniqueConstraint("brand_id", "url_key", name="uq_website_brand_url"),)
    url: Mapped[str] = mapped_column(String(500))            # https://www.acmebank.com/in/ (as the owner gave it)
    domain: Mapped[str] = mapped_column(String(253), index=True)   # acmebank.com: what official matching uses
    url_key: Mapped[str] = mapped_column(String(500))        # acmebank.com/in: duplicate detection
    kind: Mapped[str] = mapped_column(String(20), default="main")
    purpose: Mapped[str] = mapped_column(String(120), default="")


class BrandSocialAccount(AssetMixin, Base):
    __tablename__ = "brand_social_accounts"
    __table_args__ = (UniqueConstraint("brand_id", "platform", "handle_key", name="uq_social_brand_handle"),
                      UniqueConstraint("brand_id", "platform", "platform_id", name="uq_social_brand_pid"))
    platform: Mapped[str] = mapped_column(String(24), index=True)
    handle: Mapped[str] = mapped_column(String(160))          # as the owner wrote it (AcmeBank)
    handle_key: Mapped[str] = mapped_column(String(160))      # normalised for matching (acmebank)
    platform_id: Mapped[str | None] = mapped_column(String(120), nullable=True)   # stable id (UC..., page id)
    profile_url: Mapped[str] = mapped_column(String(500), default="")
    display_name: Mapped[str] = mapped_column(String(120), default="")
    purpose: Mapped[str] = mapped_column(String(120), default="")   # support, careers, a product...
    region: Mapped[str] = mapped_column(String(60), default="")


class BrandApp(AssetMixin, Base):
    __tablename__ = "brand_apps"
    __table_args__ = (UniqueConstraint("brand_id", "platform", "store_id", name="uq_app_brand_store"),)
    platform: Mapped[str] = mapped_column(String(10), index=True)   # android|ios
    store_id: Mapped[str] = mapped_column(String(160))       # package name / App Store numeric id
    bundle_id: Mapped[str | None] = mapped_column(String(160), nullable=True)    # iOS only
    name: Mapped[str] = mapped_column(String(120), default="")
    product: Mapped[str] = mapped_column(String(120), default="")   # groups the Android and iOS versions
    store_url: Mapped[str] = mapped_column(String(500), default="")
    market: Mapped[str] = mapped_column(String(60), default="")
    category: Mapped[str] = mapped_column(String(60), default="")
