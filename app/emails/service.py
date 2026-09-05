from datetime import datetime
import json
import hashlib
from app.database.models import Email, Analysis, IOC, Finding
from app.forensics.parser import parse_eml_bytes
from app.forensics.service import build_forensic_result
from app.analysis.risk_engine import aggregate_risk
from app.ml.client import MLClient

def process_email(filename: str, content: bytes, case_id: int, db):
    parsed = parse_eml_bytes(content)
    forensic = build_forensic_result(parsed)

    email = Email(
        case_id=case_id,
        filename=filename,
        message_id=parsed.get("message_id", ""),
        sender=parsed.get("from", ""),
        recipient=parsed.get("to", ""),
        subject=parsed.get("subject", ""),
        email_date=parsed.get("date", ""),
        raw_metadata=json.dumps({
            "headers": parsed.get("headers", {}),
            "sha256": hashlib.sha256(content).hexdigest(),
        }),
    )
    db.add(email)
    db.flush()

    ml = MLClient().predict(forensic["ml_features"])
    final = aggregate_risk(forensic, ml)

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
        findings_json=json.dumps(forensic["findings"]),
        iocs_json=json.dumps(forensic["iocs"]),
        timeline_json=json.dumps(forensic["timeline"]),
        graph_json=json.dumps(forensic["graph"]),
    )
    db.add(analysis)
    db.flush()

    for item in forensic["iocs"]:
        db.add(IOC(
            analysis_id=analysis.id,
            ioc_type=item["type"],
            ioc_value=item["value"],
            source="email",
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

    db.commit()

    return {
        "message": "Email analyzed successfully",
        "analysis_id": analysis.id,
        "case_id": case_id,
        "classification": analysis.classification,
        "risk_score": analysis.final_risk_score,
        "risk_level": analysis.risk_level,
        "ml_status": analysis.ml_status,
        "score_breakdown": ml.get("score_breakdown", {}),
    }
