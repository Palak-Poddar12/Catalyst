from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.database import get_db
from app.database.models import Case
from app.emails.service import process_email


router = APIRouter(prefix="/emails", tags=["Emails"])


@router.post("/upload/{case_id}")
def upload_email(
    case_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    # Validate file type
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported",
        )

    # Check case exists
    case = db.get(Case, case_id)

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Case not found",
        )

    # Read uploaded file
    max_bytes = settings.max_upload_mb * 1024 * 1024

    data = file.file.read(max_bytes + 1)

    # Check file size
    if len(data) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {settings.max_upload_mb} MB limit",
        )

    try:
        result = process_email(
            filename=file.filename,
            content=data,
            case_id=case_id,
            db=db,
        )

        return result

    except ValueError as exc:
        db.rollback()

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Email analysis failed",
        )