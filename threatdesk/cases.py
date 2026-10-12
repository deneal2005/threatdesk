"""Case workflow: allowed status transitions (reason required), assignment, comments, audit trail."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk.models import AssetWhitelist, CaseEvent, Finding, User
from threatdesk.safety import InvalidInput, clean_text

TRANSITIONS: dict[str, set[str]] = {
    "new": {"investigating", "confirmed", "false_positive", "monitoring"},
    "investigating": {"confirmed", "false_positive", "monitoring", "new"},
    "confirmed": {"takedown_requested", "monitoring", "false_positive", "investigating"},
    "takedown_requested": {"taken_down", "confirmed", "monitoring"},
    "taken_down": {"monitoring", "confirmed"},
    "false_positive": {"new", "investigating"},
    "monitoring": {"investigating", "confirmed", "false_positive", "taken_down"},
}


def _event(db: Session, f: Finding, user: User | None, type_: str, body: str, to: str | None = None) -> CaseEvent:
    ev = CaseEvent(org_id=f.org_id, finding_id=f.id, user_id=user.id if user else None, type=type_, body=body,
                   to_status=to)
    db.add(ev)
    db.flush()
    return ev


def change_status(db: Session, f: Finding, user: User, to: str, reason: str) -> CaseEvent:
    reason = clean_text(reason, 1000, label="Reason")
    if not reason:
        raise InvalidInput("Reason is required.")
    if to not in TRANSITIONS.get(f.status, set()):
        raise InvalidInput(f"Cannot move a finding from '{f.status}' to '{to}'.")
    ev = _event(db, f, user, "status", f"{f.status} -> {to}: {reason}", to)
    f.status = to
    f.in_triage = True
    return ev


def assign(db: Session, f: Finding, actor: User, assignee: User | None) -> CaseEvent:
    if assignee is not None and assignee.org_id != f.org_id:
        raise InvalidInput("That person is not in your organisation.")
    f.assignee_id = assignee.id if assignee else None
    return _event(db, f, actor, "assign", f"assigned to {assignee.email}" if assignee else "unassigned")


def comment(db: Session, f: Finding, user: User, body: str) -> CaseEvent:
    return _event(db, f, user, "comment", clean_text(body, 4000, required=True, label="Comment"))


def whitelist_value(f: Finding) -> tuple[str, str]:
    """The most specific allow-list entry for a finding (its dedupe key decides)."""
    prefix, _, rest = f.dedupe_key.partition(":")
    if prefix == "host":
        return "domain", rest
    if prefix == "android":
        return "android", rest
    if prefix == "ios":
        return "ios", rest
    if prefix in ("youtube", "telegram", "bluesky", "instagram", "x", "facebook", "tiktok") and rest \
            and not rest.startswith("video:"):
        return "handle", rest.lstrip("@")
    return "dedupe_key", f.dedupe_key


def add_to_whitelist(db: Session, f: Finding, reason: str) -> AssetWhitelist | None:
    if not f.brand_id:
        return None
    t, v = whitelist_value(f)
    existing = db.scalar(select(AssetWhitelist).where(AssetWhitelist.org_id == f.org_id,
                                                      AssetWhitelist.brand_id == f.brand_id,
                                                      AssetWhitelist.type == t, AssetWhitelist.value == v.lower()))
    if existing:
        return existing
    row = AssetWhitelist(org_id=f.org_id, brand_id=f.brand_id, type=t, value=v.lower()[:300],
                         reason=f"false positive: {reason}"[:500])
    db.add(row)
    db.flush()
    return row
