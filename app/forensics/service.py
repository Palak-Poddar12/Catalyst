import ipaddress
import re
from urllib.parse import urlparse

URL_RE = re.compile(r'https?://[^\s<>"\']+', re.I)
IP_RE = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
DOMAIN_RE = re.compile(r'\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b')

def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def build_forensic_result(email: dict) -> dict:
    text = f"{email.get('subject','')}\n{email.get('plain_body','')}\n{email.get('html_body','')}"
    urls = sorted(set(URL_RE.findall(text)))
    ips = sorted(set(x for x in IP_RE.findall(text) if valid_ip(x)))
    emails = sorted(set(EMAIL_RE.findall(text)))
    domains = sorted(set(DOMAIN_RE.findall(text)))

    subject = email.get("subject", "").lower()
    body = text.lower()

    suspicious_subject = any(x in subject for x in [
        "urgent", "verify", "password", "account suspended",
        "action required", "security alert", "immediately"
    ])
    urgent_language = any(x in body for x in [
        "urgent", "immediately", "verify now", "action required",
        "account suspended", "click here"
    ])

    auth = email.get("authentication_results", "").lower()
    auth_failure = any(x in auth for x in ["spf=fail", "dkim=fail", "dmarc=fail"])

    findings = []
    if suspicious_subject:
        findings.append({
            "type": "suspicious_subject",
            "title": "Suspicious subject language",
            "description": "Subject contains common urgency or credential-verification language.",
            "severity": "MEDIUM",
            "evidence": email.get("subject", ""),
        })
    if urls:
        findings.append({
            "type": "url_present",
            "title": "URL detected in email",
            "description": f"{len(urls)} URL(s) were extracted from the message.",
            "severity": "MEDIUM",
            "evidence": ", ".join(urls[:10]),
        })
    if urgent_language:
        findings.append({
            "type": "urgent_language",
            "title": "Urgent language detected",
            "description": "The email body contains urgency or immediate-action language.",
            "severity": "MEDIUM",
            "evidence": "Matched urgency indicators.",
        })
    if auth_failure:
        findings.append({
            "type": "authentication_failure",
            "title": "Email authentication failure",
            "description": "Authentication-Results contains an SPF/DKIM/DMARC failure.",
            "severity": "HIGH",
            "evidence": email.get("authentication_results", ""),
        })
    if email.get("reply_to") and email.get("sender_email"):
        reply_domain = email["reply_to"].split("@")[-1].lower()
        sender_domain = email["sender_email"].split("@")[-1].lower()
        if reply_domain and sender_domain and reply_domain != sender_domain:
            findings.append({
                "type": "reply_to_mismatch",
                "title": "Reply-To domain differs from sender domain",
                "description": "Reply-To and From addresses use different domains.",
                "severity": "HIGH",
                "evidence": f"From={email['sender_email']} Reply-To={email['reply_to']}",
            })

    iocs = []
    for x in urls:
        iocs.append({"type": "URL", "value": x, "confidence": 1.0})
    for x in ips:
        iocs.append({"type": "IP", "value": x, "confidence": 1.0})
    for x in emails:
        iocs.append({"type": "EMAIL", "value": x, "confidence": 1.0})
    for attachment in email.get("attachments", []):
        iocs.append({"type": "HASH", "value": attachment["sha256"], "confidence": 1.0})

    forensic_flags = {
        "suspicious_subject": suspicious_subject,
        "contains_url": bool(urls),
        "urgent_language": urgent_language,
        "authentication_failure": auth_failure,
        "reply_to_mismatch": any(f["type"] == "reply_to_mismatch" for f in findings),
        "has_attachment": bool(email.get("attachments")),
    }

    weights = {
        "suspicious_subject": .20,
        "contains_url": .20,
        "urgent_language": .15,
        "authentication_failure": .25,
        "reply_to_mismatch": .15,
        "has_attachment": .05,
    }
    forensic_score = round(min(sum(w for k, w in weights.items() if forensic_flags[k]), 1.0), 4)

    timeline = []
    if email.get("date"):
        timeline.append({"event": "email_date", "value": email["date"]})
    for item in email.get("received", []):
        timeline.append({"event": "received_header", "value": str(item)})

    nodes = [
        {"id": "sender", "type": "email", "label": email.get("sender_email", "")},
        {"id": "recipient", "type": "email", "label": email.get("recipient_email", "")},
    ]
    edges = [{"source": "sender", "target": "recipient", "relationship": "sent_to"}]
    for i, domain in enumerate(domains[:30]):
        nodes.append({"id": f"domain_{i}", "type": "domain", "label": domain})
        edges.append({"source": "sender", "target": f"domain_{i}", "relationship": "associated_domain"})

    # These fields are intentionally generic. Adapt them to the exact ML contract.
    ml_features = {
        **forensic_flags,
        "url_count": len(urls),
        "ip_count": len(ips),
        "attachment_count": len(email.get("attachments", [])),
        "subject_length": len(email.get("subject", "")),
        "body_length": len(email.get("plain_body", "")),
    }

    return {
        "forensic_score": forensic_score,
        "findings": findings,
        "iocs": iocs,
        "timeline": timeline,
        "graph": {"nodes": nodes, "edges": edges},
        "ml_features": ml_features,
    }
