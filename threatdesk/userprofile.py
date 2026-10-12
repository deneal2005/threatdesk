"""USER-SUPPLIED, UNVERIFIED profile details for closed-platform profiles (Instagram/X/Facebook).

Anything a person types about a profile is labelled as such in every signal and in the evidence, so a case
never presents it as something ThreatDesk verified.
"""
from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk import images, jobs
from threatdesk.cases import comment
from threatdesk.checks.social import social_signals
from threatdesk.handlers import load_brand_ctx
from threatdesk.linkdetect import detect
from threatdesk.models import CheckResult, Finding, Signal, User
from threatdesk.persistence import add_evidence, rescore
from threatdesk.safety import InvalidInput, clean_text, defang
from threatdesk.scoring import Scorecard
from threatdesk.scoring_helpers import parse_date

LABEL = "USER-SUPPLIED UNVERIFIED"


def _num(v: str | None) -> int | None:
    s = (v or "").strip().lower().replace(",", "").replace(" ", "")
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([km]?)", s)
    if not m:
        return None
    n = float(m.group(1)) * {"": 1, "k": 1_000, "m": 1_000_000}[m.group(2)]
    return int(n)


def apply_profile_details(db: Session, f: Finding, user: User, form: dict, photo: bytes | None) -> None:
    if f.kind != "social_profile":
        raise InvalidInput("Profile details can only be added to social profile findings.")
    platform, _, handle = f.dedupe_key.partition(":")
    brand = load_brand_ctx(f.org_id, f.brand_id)
    data = {"display_name": clean_text(form.get("display_name"), 120, label="Display name"),
            "joined": clean_text(form.get("joined"), 60, label="Joined"),
            "bio": clean_text(form.get("bio"), 2000, label="Bio"),
            "followers": _num(form.get("followers")), "following": _num(form.get("following")),
            "posts": _num(form.get("posts")),
            "link_in_bio": clean_text(form.get("link_in_bio"), 500, label="Link in bio"),
            "verified_badge": form.get("verified_badge") if form.get("verified_badge") in ("yes", "no") else "unknown"}
    card = Scorecard()
    detail = social_signals(card, brand, platform, handle, data["display_name"], data["bio"],
                            parse_date(data["joined"]), data["followers"], prefix=f"{LABEL}: ")
    if photo:
        img = images.decode(photo)
        ph = images.phash_hex(img)
        dist = images.distance(ph, brand.logo_phash)
        match = dist is not None and dist <= images.PHASH_MATCH_DISTANCE
        if match:
            card.add("icon_matches_logo", f"{LABEL}: profile photo matches the brand logo (distance {dist})")
        db.add(CheckResult(org_id=f.org_id, finding_id=f.id, check="photo_vs_logo", status="ran",
                           detail={"distance": dist, "match": match, "phash": ph, "user_supplied": True,
                                   "note": None if brand.logo_phash else "no brand logo to compare with"}))
    add_evidence(db, f, "user_supplied_profile", {**data, "label": LABEL, "entered_by": user.email,
                                                  "photo_supplied": bool(photo)})
    db.add(CheckResult(org_id=f.org_id, finding_id=f.id, check="user_profile_details", status="ran",
                       detail={"name": data["display_name"], "followers": data["followers"], "created": data["joined"],
                               "user_supplied": True, **{k: v for k, v in detail.items() if k != "text_signals"}}))
    have = {code for (code,) in db.execute(select(Signal.code).where(Signal.finding_id == f.id))}
    for s in card.signals:
        if s.code not in have:
            db.add(Signal(org_id=f.org_id, finding_id=f.id, code=s.code, points=s.points, evidence=s.evidence))
    if data["link_in_bio"]:
        try:
            link = detect(data["link_in_bio"])
            jobs.enqueue(db, "investigate", {"url": link.url, "brand_id": f.brand_id, "source": "link_in_bio",
                                             "in_triage": True}, f.org_id, created_by=user.id, max_attempts=3)
            comment(db, f, user, f"link in bio queued for investigation: {defang(link.url)}")
        except InvalidInput:
            pass
    comment(db, f, user, "profile details recorded (user-supplied, unverified)")
    db.flush()
    rescore(db, f)
