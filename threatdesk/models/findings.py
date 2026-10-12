"""Findings and everything attached to them. Evidence is append-only (enforced below)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, event
from sqlalchemy.orm import Mapped, mapped_column

from threatdesk.db import Base, utcnow

KINDS = ("domain", "android_app", "ios_app", "youtube", "telegram", "bluesky", "social_profile", "website", "other")
STATUSES = ("new", "investigating", "confirmed", "takedown_requested", "taken_down", "false_positive", "monitoring")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("org_id", "scope_key", name="uq_finding_scope"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    brand_id: Mapped[int | None] = mapped_column(ForeignKey("brands.id"), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(40))
    kind: Mapped[str] = mapped_column(String(20))
    dedupe_key: Mapped[str] = mapped_column(String(300))
    scope_key: Mapped[str] = mapped_column(String(320))          # "<brand_id or 0>:<dedupe_key>"
    display_name: Mapped[str] = mapped_column(String(300))
    url: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    score: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(10), default="Low")
    verdict: Mapped[str] = mapped_column(String(40), default="Insufficient data")
    status: Mapped[str] = mapped_column(String(24), default="new", index=True)
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    summary_ai: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    is_user_submitted: Mapped[bool] = mapped_column(Boolean, default=False)
    in_triage: Mapped[bool] = mapped_column(Boolean, default=True)      # False: ad-hoc investigation not saved yet
    checks_ran: Mapped[int] = mapped_column(Integer, default=0)


class CheckResult(Base):
    """Latest run only (replaced on every re-investigation)."""
    __tablename__ = "check_results"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    check: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(16))          # ran | not_possible | not_configured
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ran_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Signal(Base):
    """Latest run only (replaced on every re-investigation)."""
    __tablename__ = "signals"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    code: Mapped[str] = mapped_column(String(60))
    points: Mapped[int] = mapped_column(Integer)
    evidence: Mapped[str] = mapped_column(Text, default="")


class Evidence(Base):
    """Append-only capture (page, RDAP, certificate...). sha256 makes later tampering detectable."""
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    captured_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    sha256: Mapped[str] = mapped_column(String(64))
    content_json: Mapped[dict] = mapped_column(JSON, default=dict)


class EvidenceIsAppendOnly(Exception):
    pass


@event.listens_for(Evidence, "before_update")
def _no_update(mapper, connection, target):
    raise EvidenceIsAppendOnly("evidence rows cannot be modified")


@event.listens_for(Evidence, "before_delete")
def _no_delete(mapper, connection, target):
    raise EvidenceIsAppendOnly("evidence rows cannot be deleted")


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("finding_id", "type", "value", name="uq_indicator"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(300), index=True)


class Campaign(Base):
    __tablename__ = "campaigns"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    brand_id: Mapped[int | None] = mapped_column(ForeignKey("brands.id"), nullable=True, index=True)
    label: Mapped[str] = mapped_column(String(200))
    shared: Mapped[list] = mapped_column(JSON, default=list)     # [{"type","value","findings":[ids]}]
    created: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class CampaignFinding(Base):
    __tablename__ = "campaign_findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)


class CaseEvent(Base):
    """Audit trail: status changes, comments, assignment, takedown requests sent."""
    __tablename__ = "case_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    type: Mapped[str] = mapped_column(String(16))            # status | comment | assign | takedown
    body: Mapped[str] = mapped_column(Text, default="")
    to_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
