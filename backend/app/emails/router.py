from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.database import get_db
from app.database.models import Case
from app.emails.service import process_email

router = APIRouter(prefix="/emails", tags=["Emails"])

@router.post("/upload/{case_id}")
def upload_email(case_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(400, "Only .eml files are supported")

    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")

    max_bytes = settings.max_upload_mb * 1024 * 1024
    data = file.file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(413, f"File exceeds {settings.max_upload_mb} MB limit")

    try:
        return process_email(
            filename=file.filename,
            content=data,
            case_id=case_id,
            db=db,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from exc
    except Exception:
        db.rollback()
        raise HTTPException(500, "Email analysis failed")
