from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 hash of bytes as a hexadecimal string."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(file_path: str | Path) -> str:
    """Calculate the SHA-256 hash of a file without loading all bytes at once."""
    digest = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def create_case_id() -> str:
    """Create a unique forensic case ID."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    random_suffix = uuid.uuid4().hex[:8].upper()

    return f"CASE-{timestamp}-{random_suffix}"


def create_evidence_record(raw_email: bytes, source_name: str) -> dict:
    """
    Create an evidence-integrity record for the original email file.

    This does not modify the email. It records its SHA-256 hash, source name,
    timestamp, size, and generated case ID.
    """
    return {
        "case_id": create_case_id(),
        "source_name": source_name,
        "evidence_hash_sha256": sha256_bytes(raw_email),
        "analysis_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "evidence_size_bytes": len(raw_email),
        "hash_algorithm": "SHA-256",
    }