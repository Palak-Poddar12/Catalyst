from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.cases.schemas import CaseCreate, CaseResponse
from app.database.database import get_db
from app.database.models import Case

router = APIRouter(prefix="/cases", tags=["Cases"])

@router.post("", response_model=CaseResponse)
def create_case(data: CaseCreate, db: Session = Depends(get_db)):
    case = Case(**data.model_dump())
    db.add(case)
    db.commit()
    db.refresh(case)
    return case

@router.get("", response_model=list[CaseResponse])
def list_cases(db: Session = Depends(get_db)):
    return db.query(Case).order_by(Case.id.desc()).all()

@router.get("/{case_id}", response_model=CaseResponse)
def get_case(case_id: int, db: Session = Depends(get_db)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    return case
