import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.database.models import Analysis, Email

router = APIRouter(prefix="/analysis", tags=["Analysis"])

def serialize(x, email=None):
    return {
        "id": x.id,
        "case_id": x.case_id,
        "email_id": x.email_id,
        "classification": x.classification,
        "ml_status": x.ml_status,
        "ml_risk_score": x.ml_risk_score,
        "ml_confidence": x.ml_confidence,
        "forensic_score": x.forensic_score,
        "final_risk_score": x.final_risk_score,
        "risk_level": x.risk_level,
        "email": {
            "filename": email.filename,
            "message_id": email.message_id,
            "sender": email.sender,
            "recipient": email.recipient,
            "subject": email.subject,
            "date": email.email_date,
            "metadata": json.loads(email.raw_metadata or "{}"),
        } if email else None,
        "findings": json.loads(x.findings_json or "[]"),
        "iocs": json.loads(x.iocs_json or "[]"),
        "timeline": json.loads(x.timeline_json or "[]"),
        "graph": json.loads(x.graph_json or "{}"),
        "created_at": x.created_at,
    }

@router.get("/{analysis_id}")
def get_analysis(analysis_id: int, db: Session = Depends(get_db)):
    analysis = db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    email = db.get(Email, analysis.email_id)
    return serialize(analysis, email)

@router.get("/case/{case_id}")
def get_case_analyses(case_id: int, db: Session = Depends(get_db)):
    rows = db.query(Analysis).filter(Analysis.case_id == case_id).order_by(Analysis.id.desc()).all()
    return {"case_id": case_id, "count": len(rows), "analyses": [
        {
            "id": x.id,
            "classification": x.classification,
            "final_risk_score": x.final_risk_score,
            "risk_level": x.risk_level,
            "ml_status": x.ml_status,
            "created_at": x.created_at,
        } for x in rows
    ]}
