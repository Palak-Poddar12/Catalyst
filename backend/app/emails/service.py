from __future__ import annotations

from datetime import datetime
import hashlib
import json
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup

from app.database.models import Email, Analysis, IOC, Finding
from app.forensics.service import analyze_eml_bytes
from app.analysis.risk_engine import aggregate_risk
from app.ml.client import MLClient


def process_email(filename: str, content: bytes, case_id: int, db):
    forensic = analyze_eml_bytes(content, filename)
    raw = forensic.get("raw_forensic_result", {})
    metadata = raw.get("message_metadata") or {}
    sender = (raw.get("sender_identity") or {}).get("from") or {}
    reply_to = (raw.get("sender_identity") or {}).get("reply_to") or {}

    # The real NLP model analyzes the email body. Header/IOC features remain
    # the forensic model input and are still combined by the central risk engine.
    message = BytesParser(policy=policy.default).parsebytes(content)
    plain_parts = []
    html_parts = []
    for part in message.walk():
        if part.get_content_disposition() == "attachment":
            continue
        try:
            if part.get_content_type() == "text/plain":
                plain_parts.append(part.get_content())
            elif part.get_content_type() == "text/html":
                html_parts.append(BeautifulSoup(part.get_content(), "html.parser").get_text(" "))
        except Exception:
            continue
    email_text = "\n".join(plain_parts).strip() or "\n".join(html_parts).strip()

    ml_features = dict(forensic["ml_features"])
    ml_features["email_text"] = email_text
    ml = MLClient().predict(ml_features)

    email = Email(
        case_id=case_id,
        filename=filename,
        message_id=metadata.get("message_id", ""),
        sender=sender.get("email_address", ""),
        recipient="",
        subject=metadata.get("subject", ""),
        email_date=metadata.get("date", ""),
        raw_metadata=json.dumps({
            "sha256": hashlib.sha256(content).hexdigest(),
            "reply_to": reply_to,
            "evidence": raw.get("evidence", {}),
            "message_metadata": metadata,
            "sender_identity": raw.get("sender_identity", {}),
            "email_authentication": raw.get("email_authentication", {}),
            "relay_analysis": raw.get("relay_analysis", {}),
            "indicators": raw.get("indicators", {}),
            "forensic_limitations": raw.get("forensic_limitations", []),
            "ml_result": ml,
        }, ensure_ascii=False),
    )
    db.add(email)
    db.flush()

    final = aggregate_risk(forensic, ml)

    # Keep the complete Member 1 forensic JSON in the existing metadata field
    # so the MVP can expose all forensic evidence without a schema migration.
    analysis = Analysis(
        case_id=case_id,
        email_id=email.id,
        classification=final["classification"],
        ml_status=ml["status"],
        ml_risk_score=ml["risk_score"],
        ml_confidence=ml["confidence"],
        forensic_score=final["forensic_score"],
        final_risk_score=final["final_risk_score"],
        risk_level=final["risk_level"],
        findings_json=json.dumps(forensic["findings"], ensure_ascii=False),
        iocs_json=json.dumps(forensic["iocs"], ensure_ascii=False),
        timeline_json=json.dumps(forensic["timeline"], ensure_ascii=False),
        graph_json=json.dumps(forensic["graph"], ensure_ascii=False),
    )
    db.add(analysis)
    db.flush()

    for item in forensic["iocs"]:
        db.add(IOC(
            analysis_id=analysis.id,
            ioc_type=item["type"],
            ioc_value=item["value"],
            source="member1_forensics",
            confidence=float(item.get("confidence", 1.0)),
        ))

    for item in forensic["findings"]:
        db.add(Finding(
            analysis_id=analysis.id,
            finding_type=item["type"],
            title=item["title"],
            description=item["description"],
            severity=item["severity"],
            evidence=item.get("evidence", ""),
        ))

    # Add a compact pointer to the complete result to avoid another DB column.
    current_metadata = json.loads(email.raw_metadata or "{}")
    current_metadata["raw_forensic_result"] = raw
    email.raw_metadata = json.dumps(current_metadata, ensure_ascii=False)

    db.commit()

    return {
        "message": "Email analyzed successfully",
        "analysis_id": analysis.id,
        "case_id": case_id,
        "classification": analysis.classification,
        "risk_score": analysis.final_risk_score,
        "risk_level": analysis.risk_level,
        "ml_status": analysis.ml_status,
    }
