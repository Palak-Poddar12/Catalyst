from pathlib import Path
from tempfile import NamedTemporaryFile
import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.database.models import Analysis, Email
from app.analysis.router import serialize
from enchancements.pdf_report import generate_forensic_pdf

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("")
def list_reports(db: Session = Depends(get_db)):
    rows = db.query(Analysis).order_by(Analysis.id.desc()).all()
    result = []
    for x in rows:
        email = db.get(Email, x.email_id)
        result.append({
            "id": x.id,
            "case_id": x.case_id,
            "type": "forensic_pdf",
            "generated_at": x.created_at,
            "generated_by": "SatGuard",
            "integrity_hash": json.loads(email.raw_metadata or "{}").get("sha256") if email else None,
            "status": "READY",
            "classification": x.classification,
            "risk_level": x.risk_level,
        })
    return {"items": result, "count": len(result)}

@router.get("/{analysis_id}")
def get_report(analysis_id: int, db: Session = Depends(get_db)):
    analysis = db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    email = db.get(Email, analysis.email_id)
    return serialize(analysis, email)

@router.get("/{analysis_id}/pdf")
def get_report_pdf(analysis_id: int, db: Session = Depends(get_db)):
    analysis = db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    email = db.get(Email, analysis.email_id)
    metadata = json.loads(email.raw_metadata or "{}")
    forensic = metadata.get("raw_forensic_result")
    if not forensic:
        raise HTTPException(409, "Forensic report data is not available")
    with NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        output = Path(tmp.name)
    generate_forensic_pdf(forensic, output)
    return FileResponse(output, media_type="application/pdf", filename=f"satguard-analysis-{analysis_id}.pdf")

@router.get("/{analysis_id}/download")
def download_report(analysis_id: int, db: Session = Depends(get_db)):
    return get_report_pdf(analysis_id, db)
