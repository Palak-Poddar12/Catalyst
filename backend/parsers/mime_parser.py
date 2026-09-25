from __future__ import annotations

import hashlib
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any


DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".js", ".jse", ".vbs", ".vbe", ".ps1", ".msi",
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".xltm", ".potm",
}


def parse_address(value: str | None) -> dict[str, str]:
    display_name, email_address = parseaddr(value or "")
    domain = ""

    if "@" in email_address:
        domain = email_address.rsplit("@", 1)[1].lower().strip()

    return {
        "raw": value or "",
        "display_name": display_name,
        "email_address": email_address.lower(),
        "domain": domain,
    }


def detect_attachment_flags(filename: str) -> list[str]:
    normalized = filename.lower().strip()
    flags: list[str] = []

    parts = normalized.split(".")
    extension = f".{parts[-1]}" if len(parts) > 1 else ""

    if extension in DANGEROUS_EXTENSIONS:
        flags.append("dangerous_extension")

    if extension in MACRO_EXTENSIONS:
        flags.append("macro_enabled_file")

    if len(parts) >= 3:
        previous_extension = f".{parts[-2]}"
        if previous_extension in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png"}:
            if extension in DANGEROUS_EXTENSIONS:
                flags.append("double_extension")

    if extension in {".zip", ".rar", ".7z"}:
        flags.append("archive_attachment")

    return flags


def extract_mime_content(raw_email: bytes) -> dict[str, Any]:
    message = BytesParser(policy=policy.default).parsebytes(raw_email)

    plain_body_parts: list[str] = []
    html_body_parts: list[str] = []
    attachments: list[dict[str, Any]] = []

    for part in message.walk():
        content_disposition = part.get_content_disposition()
        content_type = part.get_content_type()
        filename = part.get_filename()

        if content_disposition == "attachment" or filename:
            payload = part.get_payload(decode=True) or b""
            safe_filename = filename or "unnamed_attachment"

            attachments.append({
                "filename": safe_filename,
                "mime_type": content_type,
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "risk_flags": detect_attachment_flags(safe_filename),
            })
            continue

        if content_type == "text/plain" and content_disposition != "attachment":
            try:
                plain_body_parts.append(part.get_content())
            except Exception:
                pass

        if content_type == "text/html" and content_disposition != "attachment":
            try:
                html_body_parts.append(part.get_content())
            except Exception:
                pass

    return {
        "subject": str(message.get("Subject", "")),
        "from": parse_address(str(message.get("From", ""))),
        "reply_to": parse_address(str(message.get("Reply-To", ""))),
        "return_path": parse_address(str(message.get("Return-Path", ""))),
        "sender": parse_address(str(message.get("Sender", ""))),
        "message_id": str(message.get("Message-ID", "")),
        "date": str(message.get("Date", "")),
        "x_originating_ip": str(message.get("X-Originating-IP", "")),
        "x_mailer": str(message.get("X-Mailer", "")),
        "user_agent": str(message.get("User-Agent", "")),
        "plain_text_body": "\n".join(plain_body_parts),
        "html_body": "\n".join(html_body_parts),
        "attachments": attachments,
        "received_headers": message.get_all("Received", []),
        "authentication_results_headers": message.get_all(
            "Authentication-Results", []
        ),
        "arc_authentication_results_headers": message.get_all(
            "ARC-Authentication-Results", []
        ),
        "dkim_signatures": message.get_all("DKIM-Signature", []),
    }