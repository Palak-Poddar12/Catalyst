import hashlib
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database.database import SessionLocal, get_db
from app.database.models import Case, Email, GmailOAuthState
from app.emails.service import process_email
from gmail_client import (
    GMAIL_CLIENT_ID,
    GMAIL_CLIENT_SECRET,
    GMAIL_REDIRECT_URI,
    get_gmail_authorization_data,
    get_credentials_from_token,
    exchange_code_for_tokens,
    list_recent_message_ids,
    get_message_raw,
)

router = APIRouter(prefix="/gmail", tags=["Gmail Ingestion"])
_TOKEN = None
_FRONTEND_URL = os.getenv("FRONTEND_URL", "http://127.0.0.1:5173")
_DEFAULT_TOKEN_PATH = Path(__file__).resolve().parents[1] / ".gmail_token.json"
_configured_token_path = os.getenv("GMAIL_TOKEN_PATH")
_TOKEN_PATH = Path(_configured_token_path) if _configured_token_path else _DEFAULT_TOKEN_PATH
_SYNC_JOBS = {}

if not _TOKEN_PATH.is_file() and _DEFAULT_TOKEN_PATH.is_file():
    _TOKEN_PATH = _DEFAULT_TOKEN_PATH
try:
    _TOKEN = _TOKEN_PATH.read_text(encoding="utf-8")
except (FileNotFoundError, OSError):
    _TOKEN = None


def _save_token(token: str) -> None:
    _TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = _TOKEN_PATH.with_suffix(".tmp")
    temporary_path.write_text(token, encoding="utf-8")
    temporary_path.replace(_TOKEN_PATH)


def _hash_state(state: str) -> str:
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


def _cleanup_oauth_states(db: Session) -> None:
    now = datetime.utcnow()
    db.query(GmailOAuthState).filter(GmailOAuthState.expires_at < now).delete(synchronize_session=False)
    db.commit()


@router.get("/auth-url")
def auth_url(db: Session = Depends(get_db)):
    if not GMAIL_CLIENT_ID or not GMAIL_CLIENT_SECRET:
        raise HTTPException(503, "Gmail OAuth is not configured. Set GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET.")
    try:
        _cleanup_oauth_states(db)
        authorization_url, state, code_verifier = get_gmail_authorization_data()
        db.add(GmailOAuthState(
            state_hash=_hash_state(state),
            code_verifier=code_verifier,
            redirect_uri=GMAIL_REDIRECT_URI,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        ))
        db.commit()
        return {"authorization_url": authorization_url}
    except Exception:
        db.rollback()
        raise


@router.get("/callback")
def callback(code: str, state: str, db: Session = Depends(get_db)):
    global _TOKEN
    row = None
    try:
        _cleanup_oauth_states(db)
        row = (
            db.query(GmailOAuthState)
            .filter(
                GmailOAuthState.state_hash == _hash_state(state),
                GmailOAuthState.redirect_uri == GMAIL_REDIRECT_URI,
                GmailOAuthState.expires_at >= datetime.utcnow(),
                GmailOAuthState.consumed_at.is_(None),
            )
            .first()
        )
        if row is None:
            raise ValueError("OAuth state is missing or expired. Start a new Gmail connection.")

        credentials = exchange_code_for_tokens(code, state, row.code_verifier)
        _TOKEN = credentials.to_json()
        _save_token(_TOKEN)
        row.consumed_at = datetime.utcnow()
        db.commit()
        return RedirectResponse(url=f"{_FRONTEND_URL}/gmail?connected=1", status_code=303)
    except Exception as exc:
        db.rollback()
        _TOKEN = None
        raise HTTPException(
            400,
            "Gmail OAuth failed while exchanging the authorization code. "
            "Use a fresh consent flow and verify the Google OAuth redirect URI "
            f"matches {GMAIL_REDIRECT_URI}. Details: {exc}",
        ) from exc


@router.get("/status")
def status():
    return {"connected": _TOKEN is not None}


def _run_sync(job_id: str, max_emails: int) -> None:
    db = SessionLocal()
    _SYNC_JOBS[job_id] = {"status": "running", "synced": []}
    try:
        if _TOKEN is None:
            raise RuntimeError("Gmail is not connected.")
        creds = get_credentials_from_token(json.loads(_TOKEN))
        case = Case(title="Gmail Threat Triage", name="Gmail Inbox", description="Mailbox-ingested forensic investigations", severity="MEDIUM")
        db.add(case)
        db.commit()
        db.refresh(case)
        ids = list_recent_message_ids(creds, max_results=max_emails)
        existing_ids = {row[0] for row in db.query(Email.message_id).filter(Email.message_id.in_(ids)).all() if row[0]}
        results = []
        for mid in ids:
            if mid in existing_ids:
                results.append({"message_id": mid, "status": "already_synced"})
                _SYNC_JOBS[job_id]["synced"] = results
                continue
            try:
                raw = get_message_raw(creds, mid)
                result = process_email(f"gmail-{mid}.eml", raw, case.id, db)
                results.append({"message_id": mid, "status": "analyzed", "analysis_id": result["analysis_id"]})
            except Exception as exc:
                db.rollback()
                results.append({"message_id": mid, "status": "failed", "error": str(exc)})
            _SYNC_JOBS[job_id]["synced"] = results
        _SYNC_JOBS[job_id].update({"status": "completed", "case_id": case.id, "synced": results})
    except Exception as exc:
        db.rollback()
        _SYNC_JOBS[job_id].update({"status": "failed", "error": str(exc)})
    finally:
        db.close()


@router.post("/sync", status_code=202)
def sync(background_tasks: BackgroundTasks, max_emails: int = 10):
    if _TOKEN is None:
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
        raise HTTPException(404, "Sync job not found.")
    return {"job_id": job_id, **job}
