"""Takedown packet views (HTML + plain text download), takedown-sent log, optional screenshot capture."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy.orm import Session

from threatdesk.cases import _event
from threatdesk.db import get_db
from threatdesk.models import Finding, User
from threatdesk.persistence import add_evidence
from threatdesk.safety import clean_text
from threatdesk.takedown import build_packet, packet_text
from threatdesk.tenancy import get_owned
from threatdesk.web.deps import csrf_protect, current_user
from threatdesk.web.templating import render

router = APIRouter()
CSRF = Depends(csrf_protect)


@router.get("/findings/{fid:int}/takedown")
def takedown_page(fid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = get_owned(db, Finding, fid, user.org_id)
    return render(request, "takedown.html", build_packet(db, f))


@router.get("/findings/{fid:int}/takedown.txt")
def takedown_text(fid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = get_owned(db, Finding, fid, user.org_id)
    return PlainTextResponse(packet_text(build_packet(db, f)),
                             headers={"Content-Disposition": f'attachment; filename="takedown-{f.id:04d}.txt"'})


@router.post("/findings/{fid:int}/takedown/sent", dependencies=[CSRF])
def takedown_sent(fid: int, recipient: str = Form(""), note: str = Form(""), user: User = Depends(current_user),
                  db: Session = Depends(get_db)):
    f = get_owned(db, Finding, fid, user.org_id)
    who = clean_text(recipient, 200, required=True, label="Recipient")
    what = clean_text(note, 2000, label="Note")
    _event(db, f, user, "takedown", f"takedown request sent to {who}" + (f": {what}" if what else ""))
    db.commit()
    return RedirectResponse(f"/findings/{f.id}/takedown?m=logged", status_code=303)


@router.post("/findings/{fid:int}/screenshot", dependencies=[CSRF])
async def take_screenshot(fid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    from threatdesk.screenshot import ScreenshotUnavailable, capture
    f = get_owned(db, Finding, fid, user.org_id)
    if f.kind != "website":
        raise HTTPException(400, "Screenshots are only taken of websites.")
    try:
        shot = await capture(f.url)
    except ScreenshotUnavailable as e:
        raise HTTPException(400, str(e))
    add_evidence(db, f, "screenshot", shot)
    db.commit()
    return RedirectResponse(f"/findings/{f.id}?m=saved", status_code=303)
