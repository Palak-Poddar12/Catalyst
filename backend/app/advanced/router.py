from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.database.models import Analysis, Case, Email

router = APIRouter(prefix="/advanced", tags=["Advanced Intelligence"])

@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):
    analyses = db.query(Analysis).all()
    return {
        "cases": db.query(Case).count(),
        "analyses": len(analyses),
        "high_risk": sum(1 for x in analyses if str(x.risk_level).upper() in {"HIGH", "CRITICAL"}),
        "critical_risk": sum(1 for x in analyses if str(x.risk_level).upper() == "CRITICAL"),
        "phishing": sum(1 for x in analyses if "PHISH" in str(x.classification).upper()),
        "latest_analysis_id": analyses[-1].id if analyses else None,
    }

@router.get("/analysis/{analysis_id}")
def advanced_analysis(analysis_id: int, db: Session = Depends(get_db)):
    analysis = db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    email = db.get(Email, analysis.email_id)
    return {
        "analysis_id": analysis.id,
        "case_id": analysis.case_id,
        "classification": analysis.classification,
        "risk_level": analysis.risk_level,
        "risk_score": analysis.final_risk_score,
        "ml": {"status": analysis.ml_status, "score": analysis.ml_risk_score, "confidence": analysis.ml_confidence},
        "forensic_score": analysis.forensic_score,
        "findings": __import__('json').loads(analysis.findings_json or "[]"),
        "iocs": __import__('json').loads(analysis.iocs_json or "[]"),
        "timeline": __import__('json').loads(analysis.timeline_json or "[]"),
        "graph": __import__('json').loads(analysis.graph_json or "{}"),
        "email": {"filename": email.filename, "sender": email.sender, "subject": email.subject} if email else None,
    }
