from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.cases.schemas import CaseCreate, CaseResponse
from app.database.database import get_db
from app.database.models import Case, Email, Analysis

router = APIRouter(prefix="/cases", tags=["Cases"])

def _summary(case: Case, db: Session) -> dict:
    emails = db.query(Email).filter(Email.case_id == case.id).order_by(Email.id.desc()).all()
    latest_email = emails[0] if emails else None
    latest_analysis = (
        db.query(Analysis)
        .filter(Analysis.case_id == case.id)
        .order_by(Analysis.id.desc())
        .first()
    )
    analysis = None
    if latest_analysis:
        analysis = {
            "id": latest_analysis.id,
            "email_id": latest_analysis.email_id,
            "classification": latest_analysis.classification,
            "ml_status": latest_analysis.ml_status,
            "ml_risk_score": latest_analysis.ml_risk_score,
            "ml_confidence": latest_analysis.ml_confidence,
            "forensic_score": latest_analysis.forensic_score,
            "final_risk_score": latest_analysis.final_risk_score,
            "risk_level": latest_analysis.risk_level,
            "created_at": latest_analysis.created_at,
        }
    return {
        "id": case.id,
        "case_id": case.id,
        "title": case.title,
        "name": case.name,
        "description": case.description,
        "severity": case.severity,
        "subject": latest_email.subject if latest_email else case.title,
        "sender": latest_email.sender if latest_email else "",
        "recipient": latest_email.recipient if latest_email else "",
        "classification": latest_analysis.classification if latest_analysis else None,
        "risk_score": latest_analysis.final_risk_score if latest_analysis else None,
        "risk_level": latest_analysis.risk_level if latest_analysis else case.severity,
        "status": "ANALYZED" if latest_analysis else "OPEN",
        "email_count": len(emails),
        "latest_analysis_id": latest_analysis.id if latest_analysis else None,
        "latest_email_id": latest_email.id if latest_email else None,
        "created_at": case.created_at,
        "updated_at": case.updated_at,
        "analysis": analysis,
    }

@router.post("", response_model=CaseResponse)
def create_case(data: CaseCreate, db: Session = Depends(get_db)):
    case = Case(**data.model_dump())
    db.add(case)
    db.commit()
    db.refresh(case)
    return _summary(case, db)

@router.get("", response_model=list[CaseResponse])
def list_cases(db: Session = Depends(get_db)):
    return [_summary(case, db) for case in db.query(Case).order_by(Case.id.desc()).all()]

@router.get("/{case_id}", response_model=CaseResponse)
def get_case(case_id: int, db: Session = Depends(get_db)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    return _summary(case, db)
