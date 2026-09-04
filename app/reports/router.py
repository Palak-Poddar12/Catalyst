from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.database.models import Analysis, Email
from app.analysis.router import serialize

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("/{analysis_id}")
def get_report(analysis_id: int, db: Session = Depends(get_db)):
    analysis = db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    email = db.get(Email, analysis.email_id)
    return serialize(analysis, email)
