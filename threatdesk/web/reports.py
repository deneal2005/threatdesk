"""Reports index (brand summaries, customer reports), printable brand summary, CSV export."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from threatdesk.db import get_db
from threatdesk.models import Brand, Finding, ReportIntake, User
from threatdesk.reporting import brand_summary, findings_csv
from threatdesk.riskview import tiers_for
from threatdesk.tenancy import get_owned, scoped
from threatdesk.web.deps import current_user
from threatdesk.web.templating import render

router = APIRouter()


@router.get("/reports")
def reports_index(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    brands = list(db.scalars(scoped(Brand, user.org_id).order_by(Brand.name)))
    intakes = list(db.scalars(scoped(ReportIntake, user.org_id).order_by(ReportIntake.id.desc()).limit(50)))
    return render(request, "reports.html", {"brands": brands, "intakes": intakes,
                                            "names": {b.id: b.name for b in brands}})


@router.get("/reports/brand/{brand_id:int}")
def brand_report(brand_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    brand = get_owned(db, Brand, brand_id, user.org_id)
    return render(request, "brand_report.html", {"brand": brand, "s": brand_summary(db, user.org_id, brand.id)})


@router.get("/reports/findings.csv")
def export_csv(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = scoped(Finding, user.org_id).where(Finding.in_triage.is_(True))
    bid = request.query_params.get("brand_id", "")
    name = "findings"
    if bid.isdigit():
        brand = get_owned(db, Brand, int(bid), user.org_id)
        q = q.where(Finding.brand_id == brand.id)
        name = f"findings-brand-{brand.id}"
    rows = list(db.scalars(q.order_by(Finding.score.desc(), Finding.id)))
    return Response(findings_csv(rows, tiers_for(db, rows)), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}.csv"'})
