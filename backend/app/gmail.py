import hashlib
import json
import os
from datetime import datetime, timedelta
from email import policy
from email.parser import BytesParser
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database.database import SessionLocal, get_db
from app.database.models import Case, Email, GmailConnection, GmailOAuthState
from app.emails.service import process_email
from gmail_client import (
    GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REDIRECT_URI,
    exchange_code_for_tokens, get_credentials_from_token,
    get_gmail_authorization_url, get_gmail_profile_email,
    get_message_raw, list_recent_message_ids,
)

router = APIRouter(prefix="/gmail", tags=["Gmail Ingestion"])
_FRONTEND_URL = os.getenv("FRONTEND_URL", "http://127.0.0.1:5173")
_SYNC_JOBS = {}
STATE_TTL_MINUTES = 10

def _state_hash(state: str) -> str:
    return hashlib.sha256(state.encode("utf-8")).hexdigest()

def _save_connection(db: Session, credentials, email_address: str) -> None:
    row = db.get(GmailConnection, 1)
    if row is None:
        row = GmailConnection(id=1, email_address=email_address, token_json=credentials.to_json())
        db.add(row)
    else:
        row.email_address = email_address
        row.token_json = credentials.to_json()
    db.commit()

@router.get("/auth-url")
def auth_url(db: Session = Depends(get_db)):
    if not GMAIL_CLIENT_ID or not GMAIL_CLIENT_SECRET:
        raise HTTPException(503, "Gmail OAuth is not configured. Set GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET.")
    url, state, verifier = get_gmail_authorization_url()
    db.query(GmailOAuthState).filter(GmailOAuthState.expires_at < datetime.utcnow()).delete(synchronize_session=False)
    db.add(GmailOAuthState(
        state_hash=_state_hash(state),
        code_verifier=verifier,
        expires_at=datetime.utcnow() + timedelta(minutes=STATE_TTL_MINUTES),
    ))
    db.commit()
    return {"authorization_url": url}

@router.get("/callback")
def callback(code: str, state: str, db: Session = Depends(get_db)):
    row = db.query(GmailOAuthState).filter(GmailOAuthState.state_hash == _state_hash(state)).first()
    if row is None or row.expires_at < datetime.utcnow():
        if row is not None:
            db.delete(row); db.commit()
        raise HTTPException(400, "Gmail OAuth state is missing or expired. Start a fresh Gmail connection.")
    try:
        credentials = exchange_code_for_tokens(code, row.code_verifier)
        email_address = get_gmail_profile_email(credentials)
        _save_connection(db, credentials, email_address)
        db.delete(row)
        db.commit()
        return RedirectResponse(url=f"{_FRONTEND_URL}/gmail?connected=1", status_code=303)
    except Exception as exc:
        db.rollback()
        raise HTTPException(400, f"Gmail OAuth failed while exchanging the authorization code. Verify the redirect URI {GMAIL_REDIRECT_URI}. Details: {exc}") from exc

@router.get("/status")
def status(db: Session = Depends(get_db)):
    row = db.get(GmailConnection, 1)
    return {"connected": bool(row), "email": row.email_address if row else None}

def _gmail_case(db: Session) -> Case:
    case = db.query(Case).filter(Case.name == "Gmail Inbox").order_by(Case.id.desc()).first()
    if case is None:
        case = Case(title="Gmail Threat Triage", name="Gmail Inbox", description="Mailbox-ingested forensic investigations", severity="MEDIUM")
        db.add(case); db.commit(); db.refresh(case)
    return case

def _header(msg, name: str) -> str:
    return str(msg.get(name, "") or "")

def _run_sync(job_id: str, max_emails: int) -> None:
    db = SessionLocal()
    _SYNC_JOBS[job_id] = {"status": "running", "synced": [], "failed": []}
    try:
        connection = db.get(GmailConnection, 1)
        if connection is None:
            raise RuntimeError("Connect Gmail first.")
        credentials = get_credentials_from_token(json.loads(connection.token_json))
        case = _gmail_case(db)
        ids = list_recent_message_ids(credentials, max_results=max_emails)
        existing = {row[0] for row in db.query(Email.message_id).filter(Email.message_id.in_(ids)).all() if row[0]}
        results = []
        for mid in ids:
            if mid in existing:
                existing_email = db.query(Email).filter(Email.message_id == mid).first()
                results.append({"message_id": mid, "status": "already_synced", "email_id": existing_email.id if existing_email else None, "case_id": case.id})
                _SYNC_JOBS[job_id]["synced"] = results
                continue
            try:
                raw = get_message_raw(credentials, mid)
                parsed = BytesParser(policy=policy.default).parsebytes(raw)
                result = process_email(f"gmail-{mid}.eml", raw, case.id, db)
                results.append({
                    "message_id": mid, "status": "analyzed", "email_id": result.get("email_id"),
                    "analysis_id": result.get("analysis_id"), "case_id": case.id,
                    "subject": _header(parsed, "Subject"), "sender": _header(parsed, "From"),
                    "date": _header(parsed, "Date"), "classification": result.get("classification"),
                    "risk_score": result.get("risk_score"), "risk_level": result.get("risk_level"),
                })
            except Exception as exc:
                db.rollback()
                results.append({"message_id": mid, "status": "failed", "error": str(exc), "case_id": case.id})
            _SYNC_JOBS[job_id]["synced"] = results
        _SYNC_JOBS[job_id].update({"status": "completed", "case_id": case.id, "count": len([x for x in results if x["status"] in ("analyzed", "already_synced")]), "synced": results})
    except Exception as exc:
        db.rollback()
        _SYNC_JOBS[job_id].update({"status": "failed", "error": str(exc)})
    finally:
        db.close()

@router.post("/sync", status_code=202)
def sync(background_tasks: BackgroundTasks, max_emails: int = 10, db: Session = Depends(get_db)):
    if db.get(GmailConnection, 1) is None:
        raise HTTPException(401, "Connect Gmail first.")
    max_emails = max(1, min(max_emails, 25))
    job_id = uuid4().hex
    _SYNC_JOBS[job_id] = {"status": "queued", "synced": []}
    background_tasks.add_task(_run_sync, job_id, max_emails)
    return {"job_id": job_id, "status": "queued"}

@router.get("/sync/{job_id}")
def sync_status(job_id: str):
    job = _SYNC_JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "Sync job not found. Start a new sync.")
    return {"job_id": job_id, **job}
