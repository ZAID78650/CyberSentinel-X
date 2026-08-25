"""Incident report routes."""
import logging
import traceback
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.investigation import IncidentReport
from app.models.security import Incident
from app.models.user import User
from app.reports.generator import generate_report
from app.schemas.common import Paginated
from app.schemas.report import ReportDetail, ReportOut

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("", response_model=Paginated[ReportOut])
def list_reports(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    stmt = select(IncidentReport).order_by(IncidentReport.created_at.desc())
    total = len(list(db.scalars(stmt).all()))
    rows = list(db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all())
    pages = max((total + page_size - 1) // page_size, 1)
    return Paginated[ReportOut](
        items=[ReportOut.model_validate(r) for r in rows], total=total, page=page, page_size=page_size, pages=pages
    )


@router.post("/{incident_id}/generate", response_model=ReportDetail)
def generate(incident_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Generate a report for a specific incident. Accepts UUID pk, incident_id string, or 'latest'."""
    try:
        report = generate_report(db, str(incident_id), actor=user.email)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("Report generation failed unexpectedly: %s\n%s", exc, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(exc)[:200]}")
    return ReportDetail(
        report=ReportOut.model_validate(report),
        content=report.content,
        pdf_available=bool(report.pdf_path),
        pdf_url=f"/api/reports/{report.id}/pdf" if report.pdf_path else None,
    )


@router.post("/generate-latest", response_model=ReportDetail)
def generate_latest(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Generate a report for the most recent incident. No incident ID needed."""
    try:
        # Find the most recent incident
        incident = db.scalar(select(Incident).order_by(Incident.created_at.desc()))
        if incident is None:
            raise HTTPException(status_code=404, detail="No incidents found. Run a simulation or ingest a dataset first.")
        report = generate_report(db, str(incident.id), actor=user.email)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Report generation failed: %s\n%s", exc, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(exc)[:200]}")
    return ReportDetail(
        report=ReportOut.model_validate(report),
        content=report.content,
        pdf_available=bool(report.pdf_path),
        pdf_url=f"/api/reports/{report.id}/pdf" if report.pdf_path else None,
    )


@router.get("/{report_id}", response_model=ReportDetail)
def get_report(report_id: UUID, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    report = db.get(IncidentReport, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return ReportDetail(
        report=ReportOut.model_validate(report),
        content=report.content,
        pdf_available=bool(report.pdf_path),
        pdf_url=f"/api/reports/{report.id}/pdf" if report.pdf_path else None,
    )


@router.get("/{report_id}/pdf")
def report_pdf(report_id: UUID, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    report = db.get(IncidentReport, report_id)
    if report is None or not report.pdf_path:
        raise HTTPException(status_code=404, detail="PDF not available")
    return FileResponse(report.pdf_path, media_type="application/pdf",
                        filename=f"{report.report_id}.pdf")


@router.get("/{report_id}/html", response_class=HTMLResponse)
def report_html(report_id: UUID, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    report = db.get(IncidentReport, report_id)
    if report is None or not report.html_content:
        raise HTTPException(status_code=404, detail="HTML not available")
    return HTMLResponse(report.html_content)
