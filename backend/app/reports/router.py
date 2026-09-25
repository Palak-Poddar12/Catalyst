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
