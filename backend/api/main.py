from __future__ import annotations

import os
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from typing import Any, Dict

from dotenv import load_dotenv
load_dotenv()

from fastapi.responses import RedirectResponse
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from member1_forensic_analyzer import (
    analyze_eml_file,
    save_forensic_result,
)
from enchancements.pdf_report import generate_forensic_pdf
from gmail_client import (
    get_gmail_authorization_url,
    exchange_code_for_tokens,
    list_recent_message_ids,
    get_message_raw,
    get_credentials_from_token,
)


app = FastAPI(
    title="SatGuard Email Forensic API",
    version="1.1.0",
    description="Background email-forensics analysis API.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent.parent

UPLOAD_DIRECTORY = BASE_DIR / "data" / "uploads"
UPLOAD_DIRECTORY.mkdir(parents=True, exist_ok=True)
REPORT_DIRECTORY = BASE_DIR / "output" / "forensic_results"
REPORT_DIRECTORY.mkdir(parents=True, exist_ok=True)

MAX_EMAIL_SIZE_BYTES = 20 * 1024 * 1024

# MVP-only in-memory job store.
# Replace with PostgreSQL + Redis/Celery for production.
analysis_jobs: dict[str, dict] = {}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
def get_case_risk_summary(forensic_result: dict) -> dict:
    """
    Build a small display summary for the case-history list.

    This is for Member 6 visualization only. Member 3 can later replace
    it with the final ML-based risk score.
    """
    findings = forensic_result.get("forensic_findings", [])

    critical_count = sum(
        1
        for item in findings
        if item.get("severity") == "critical"
    )

    high_count = sum(
        1
        for item in findings
        if item.get("severity") == "high"
    )

    medium_count = sum(
        1
        for item in findings
        if item.get("severity") == "medium"
    )

    score = min(
        critical_count * 35
        + high_count * 15
        + medium_count * 7,
        100,
    )

    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 35:
        severity = "medium"
    elif score > 0:
        severity = "low"
    else:
        severity = "safe"

    return {
        "score": score,
        "severity": severity,
        "critical_findings": critical_count,
        "high_findings": high_count,
        "medium_findings": medium_count,
    }


def build_case_summary(
    report_path: Path,
    forensic_result: dict,
) -> dict:
    """Create lightweight metadata for the frontend case list."""
    sender_identity = forensic_result.get(
        "sender_identity",
        {},
    )

    from_data = sender_identity.get("from", {})

    metadata = forensic_result.get(
        "message_metadata",
        {},
    )

    evidence = forensic_result.get("evidence", {})

    findings = forensic_result.get(
        "forensic_findings",
        [],
    )

    return {
        "case_id": forensic_result.get("case_id", ""),
        "report_filename": report_path.name,
        "source_name": evidence.get("source_name", ""),
        "subject": metadata.get("subject", ""),
        "from_address": from_data.get(
            "email_address",
            "",
        ),
        "from_domain": from_data.get("domain", ""),
        "analysis_timestamp_utc": evidence.get(
            "analysis_timestamp_utc",
            "",
        ),
        "evidence_hash_sha256": evidence.get(
            "evidence_hash_sha256",
            "",
        ),
        "finding_count": len(findings),
        "risk": get_case_risk_summary(forensic_result),
    }


def load_case_file(report_path: Path) -> dict:
    """Load one saved forensic JSON report safely."""
    try:
        return json.loads(
            report_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Unable to read saved forensic report: "
                f"{error}"
            ),
        ) from error

def calculate_visual_risk(
    forensic_result: dict,
) -> dict:
    """
    Basic visualization risk label for the frontend.

    Member 3 can later replace this with the actual ML/risk engine.
    """
    findings = forensic_result.get("forensic_findings", [])

    critical_count = sum(
        1
        for item in findings
        if item.get("severity") == "critical"
    )

    high_count = sum(
        1
        for item in findings
        if item.get("severity") == "high"
    )

    medium_count = sum(
        1
        for item in findings
        if item.get("severity") == "medium"
    )

    score = min(
        critical_count * 35
        + high_count * 15
        + medium_count * 7,
        100,
    )

    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 35:
        severity = "medium"
    elif score > 0:
        severity = "low"
    else:
        severity = "safe"

    return {
        "score": score,
        "severity": severity,
        "critical_findings": critical_count,
        "high_findings": high_count,
        "medium_findings": medium_count,
        "source": "mvp_visual_risk_rule",
    }


async def run_analysis_job(
    job_id: str,
    upload_path: Path,
) -> None:
    """
    Run forensic analysis in the background.

    Note: For a production implementation, use Celery/RQ/Redis or a
    dedicated worker. This is suitable for the local hackathon MVP.
    """
    analysis_jobs[job_id]["status"] = "analyzing"
    analysis_jobs[job_id]["started_at"] = utc_now()

    try:
        forensic_result = await asyncio.to_thread(
            analyze_eml_file,
            upload_path,
            {
                "mx.company.example",
                "mx.example.com",
            },
        )

        saved_report_path = await asyncio.to_thread(
            save_forensic_result,
            forensic_result,
        )

        risk = calculate_visual_risk(forensic_result)

        analysis_jobs[job_id].update({
            "status": "completed",
            "completed_at": utc_now(),
            "case_id": forensic_result["case_id"],
            "risk": risk,
            "saved_report_path": str(saved_report_path),
            "forensic_result": forensic_result,
            "error": "",
        })

    except Exception as error:
        analysis_jobs[job_id].update({
            "status": "failed",
            "completed_at": utc_now(),
            "error": str(error),
        })

    finally:
        if upload_path.exists():
            upload_path.unlink()
async def analyze_raw_mime_string(
    raw_mime: str,
    source_name: str,
    trusted_internal_mx: set[str] | None = None,
) -> dict:
    """
    Analyze a raw RFC822 email string (from Gmail or other source)
    using the existing forensic pipeline.

    Returns the full forensic_result dict (with case_id, etc.).
    """
    if trusted_internal_mx is None:
        trusted_internal_mx = {
            "mx.company.example",
            "mx.example.com",
        }

    job_id = str(uuid4())
    temp_filename = f"{job_id}_gmail.eml"
    upload_path = UPLOAD_DIRECTORY / temp_filename

    # Write raw MIME to temp file
    upload_path.write_text(raw_mime, encoding="utf-8")

    try:
        forensic_result = await asyncio.to_thread(
            analyze_eml_file,
            upload_path,
            trusted_internal_mx,
        )

        # Optionally enrich evidence source info
        evidence = forensic_result.get("evidence", {})
        evidence["source_name"] = source_name or "Gmail"
        forensic_result["evidence"] = evidence

        saved_report_path = await asyncio.to_thread(
            save_forensic_result,
            forensic_result,
        )

        # Attach PDF path info (PDF will be generated on demand in /cases/{id}/pdf)
        forensic_result["_saved_report_path"] = str(saved_report_path)

        return forensic_result

    finally:
        if upload_path.exists():
            upload_path.unlink()

def _load_gmail_tokens() -> Dict[str, Any]:
    if not GMAIL_TOKEN_PATH.exists():
        return {}
    return json.loads(GMAIL_TOKEN_PATH.read_text(encoding="utf-8"))


def _save_gmail_tokens(tokens: Dict[str, Any]) -> None:
    GMAIL_TOKEN_PATH.write_text(
        json.dumps(tokens, indent=2),
        encoding="utf-8",
    )


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "satguard-member1-forensic-api",
        "jobs_in_memory": len(analysis_jobs),
    }


@app.post("/api/v1/emails/analyze-jobs")
async def create_analysis_job(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    filename = file.filename or ""

    if not filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml email files are supported.",
        )

    raw_email = await file.read()

    if not raw_email:
        raise HTTPException(
            status_code=400,
            detail="The uploaded email file is empty.",
        )

    if len(raw_email) > MAX_EMAIL_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Email file exceeds the 20 MB upload limit.",
        )

    job_id = str(uuid4())

    upload_path = UPLOAD_DIRECTORY / f"{job_id}_{filename}"
    upload_path.write_bytes(raw_email)

    analysis_jobs[job_id] = {
        "job_id": job_id,
        "original_filename": filename,
        "status": "queued",
        "created_at": utc_now(),
        "started_at": "",
        "completed_at": "",
        "case_id": "",
        "risk": {},
        "saved_report_path": "",
        "forensic_result": None,
        "error": "",
    }

    background_tasks.add_task(
        run_analysis_job,
        job_id,
        upload_path,
    )

    return {
        "job_id": job_id,
        "status": "queued",
        "message": "Forensic analysis job created.",
    }


@app.get("/api/v1/emails/analyze-jobs/{job_id}")
def get_analysis_job(job_id: str):
    job = analysis_jobs.get(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Analysis job was not found.",
        )

    # IMPORTANT: the frontend polls this endpoint until the job is
    # completed. Always return the current job object as JSON.
    return job


@app.get("/api/v1/cases")
def list_cases():
    """
    Return saved forensic cases, newest first.

    In production, replace directory scanning with PostgreSQL case records.
    """
    case_summaries: list[dict] = []

    for report_path in REPORT_DIRECTORY.glob("*.json"):
        try:
            forensic_result = load_case_file(report_path)

            case_summaries.append(
                build_case_summary(
                    report_path,
                    forensic_result,
                )
            )

        except HTTPException:
            continue

    case_summaries.sort(
        key=lambda item: item.get(
            "analysis_timestamp_utc",
            "",
        ),
        reverse=True,
    )

    return {
        "total_cases": len(case_summaries),
        "cases": case_summaries,
    }


@app.get("/api/v1/cases/{case_id}")
def get_case(case_id: str):
    """Return one complete forensic case by case ID."""
    for report_path in REPORT_DIRECTORY.glob("*.json"):
        forensic_result = load_case_file(report_path)

        if forensic_result.get("case_id") == case_id:
            return forensic_result

    raise HTTPException(
        status_code=404,
        detail="Forensic case was not found.",
    )


@app.get("/api/v1/cases/{case_id}/pdf")
def download_case_pdf(case_id: str):
    """Generate and download a human-readable forensic PDF report."""
    for report_path in REPORT_DIRECTORY.glob("*.json"):
        forensic_result = load_case_file(report_path)

        if forensic_result.get("case_id") == case_id:
            pdf_path = REPORT_DIRECTORY / f"{case_id}.pdf"

            try:
                generate_forensic_pdf(
                    forensic_result,
                    pdf_path,
                )
            except Exception as error:
                raise HTTPException(
                    status_code=500,
                    detail=f"Unable to generate forensic PDF: {error}",
                ) from error

            return FileResponse(
                path=pdf_path,
                media_type="application/pdf",
                filename=pdf_path.name,
            )

    raise HTTPException(
        status_code=404,
        detail="Forensic case report was not found.",
    )


@app.get("/api/v1/cases/{case_id}/download")
def download_case_json(case_id: str):
    """Download one stored forensic case as JSON evidence."""
    for report_path in REPORT_DIRECTORY.glob("*.json"):
        forensic_result = load_case_file(report_path)

        if forensic_result.get("case_id") == case_id:
            return FileResponse(
                path=report_path,
                media_type="application/json",
                filename=report_path.name,
            )

    raise HTTPException(
        status_code=404,
        detail="Forensic case report was not found.",
    )
@app.get("/api/v1/gmail/auth-url")
async def gmail_auth_url():
    """
    Return the Gmail OAuth2 authorization URL.
    Frontend can redirect the user to this URL to connect their Gmail account.
    """
    auth_url = get_gmail_authorization_url()
    return {"authorization_url": auth_url}


@app.get("/auth/gmail/callback")
async def gmail_oauth_callback(request: Request, code: str = Query(None)):
    """
    OAuth2 callback from Google.
    Exchanges code for tokens and stores them locally (demo).
    """
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    credentials = exchange_code_for_tokens(code)

    token_data = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
    }

    _save_gmail_tokens(token_data)

    # In a real app, associate this token with a user ID.
    return JSONResponse(
        content={"status": "gmail_connected"},
        headers={"Location": "http://localhost:5173"},  # adjust to your frontend
    )
@app.post("/api/v1/gmail/sync")
async def gmail_sync(
    background_tasks: BackgroundTasks,
    max_emails: int = 5,
):
    """
    Fetch recent emails from the connected Gmail account and run them
    through the existing forensic analysis pipeline.

    Each email becomes a forensic case (JSON + PDF on demand),
    exactly like .eml uploads.
    """
    tokens = _load_gmail_tokens()
    if not tokens:
        raise HTTPException(
            status_code=400,
            detail="Gmail account not connected. Call /api/v1/gmail/auth-url first.",
        )

    credentials = get_credentials_from_token(tokens)

    message_ids = list_recent_message_ids(
        credentials,
        max_results=max_emails,
        label_ids=["INBOX"],
    )

    results = []

    for msg_id in message_ids:
        raw_mime = get_message_raw(credentials, msg_id)

        try:
            forensic_result = await analyze_raw_mime_string(
                raw_mime=raw_mime,
                source_name="Gmail",
            )

            results.append(
                {
                    "gmail_message_id": msg_id,
                    "status": "analyzed",
                    "case_id": forensic_result.get("case_id"),
                    "subject": forensic_result.get("message_metadata", {}).get(
                        "subject", ""
                    ),
                    "from_address": forensic_result.get("sender_identity", {})
                    .get("from", {})
                    .get("email_address", ""),
                }
            )

        except Exception as error:
            results.append(
                {
                    "gmail_message_id": msg_id,
                    "status": "failed",
                    "error": str(error),
                }
            )

    return {"synced": results}