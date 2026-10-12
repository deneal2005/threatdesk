"""Public customer report form /report/<token>: no login, honeypot, 5/hour/IP, neutral receipt."""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatdesk import jobs
from threatdesk.db import get_db
from threatdesk.linkdetect import detect
from threatdesk.models import Brand, ReportIntake
from threatdesk.safety import InvalidInput, clean_text
from threatdesk.security import allow, ip_hash
from threatdesk.web.deps import client_ip, csrf_protect
from threatdesk.web.templating import render

router = APIRouter()


@router.get("/intake")
def intake_index_redirect():
    return RedirectResponse("/brands", status_code=303)



def _brand(db: Session, token: str) -> Brand:
    brand = db.scalar(select(Brand).where(Brand.report_token == token)) if 8 <= len(token) <= 64 else None
    if brand is None:
        raise HTTPException(404, "Not found.")
    return brand


@router.get("/report/{token}")
def report_form(token: str, request: Request, db: Session = Depends(get_db)):
    return render(request, "report_form.html", {"brand": _brand(db, token), "v": {}})


@router.post("/report/{token}", dependencies=[Depends(csrf_protect)])
def report_submit(token: str, request: Request, url: str = Form(""), text: str = Form(""), contact: str = Form(""),
                  website: str = Form(""), db: Session = Depends(get_db)):
    brand = _brand(db, token)
    v = {"url": url[:2000], "text": text[:5000], "contact": contact[:200]}
    if not allow("report", ip_hash(client_ip(request))):
        return render(request, "report_form.html", {"brand": brand, "v": v, "error":
                      "Too many reports from your network. Please try again in an hour."}, 429)
    if website.strip():                       # honeypot: bots fill every field; nothing is stored
        return render(request, "report_receipt.html", {"brand": brand, "ref": 10_000 + secrets.randbelow(90_000)})
    try:
        body = clean_text(text, 5000, label="The message")
        who = clean_text(contact, 200, label="Your email or phone")
        if not url.strip() and not body:
            raise InvalidInput("Paste the suspicious link, the message text, or both.")
        link = detect(url) if url.strip() else None
    except InvalidInput as e:
        return render(request, "report_form.html", {"brand": brand, "v": v, "error": str(e)}, 400)
    intake = ReportIntake(org_id=brand.org_id, brand_id=brand.id, reporter_contact=who or None,
                          url=link.url if link else None, text=body or None)
    db.add(intake)
    db.flush()
    if link:
        job = jobs.enqueue(db, "investigate", {"url": link.url, "brand_id": brand.id, "source": "intake",
                                               "in_triage": True, "user_submitted": True, "intake_id": intake.id},
                           brand.org_id, max_attempts=3)
        intake.job_id = job.id
    if body:
        job = jobs.enqueue(db, "intake_text", {"intake_id": intake.id, "link_finding": link is None},
                           brand.org_id, max_attempts=3)
        intake.job_id = intake.job_id or job.id
    db.commit()
    return render(request, "report_receipt.html", {"brand": brand, "ref": intake.id})
