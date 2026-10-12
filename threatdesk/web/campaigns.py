"""Campaigns page: connected components of findings and the shared values that link them."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk import campaigns as svc
from threatdesk.db import get_db
from threatdesk.models import Brand, Campaign, CampaignFinding, Finding, User
from threatdesk.tenancy import scoped
from threatdesk.web.deps import csrf_protect, current_user
from threatdesk.web.templating import render

router = APIRouter()


def _page(request: Request, db: Session, user: User, rebuild_info: dict | None = None):
    camps = list(db.scalars(scoped(Campaign, user.org_id).order_by(Campaign.id)))
    links = db.execute(select(CampaignFinding.campaign_id, CampaignFinding.finding_id)
                       .where(CampaignFinding.org_id == user.org_id)).all()
    fids = {fid for _c, fid in links}
    findings = {f.id: f for f in db.scalars(scoped(Finding, user.org_id).where(Finding.id.in_(fids or {-1})))}
    members: dict[int, list[Finding]] = {}
    for cid, fid in links:
        if fid in findings:
            members.setdefault(cid, []).append(findings[fid])
    for ms in members.values():
        ms.sort(key=lambda f: -f.score)
    camps.sort(key=lambda c: -len(members.get(c.id, [])))
    names = {b.id: b.name for b in db.scalars(scoped(Brand, user.org_id))}
    return render(request, "campaigns.html", {"camps": camps, "members": members, "names": names,
                                              "info": rebuild_info})


@router.get("/campaigns")
def campaigns_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _page(request, db, user)


@router.post("/campaigns/rebuild", dependencies=[Depends(csrf_protect)])
def campaigns_rebuild(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    info = svc.rebuild(db, user.org_id)
    return _page(request, db, user, info)
