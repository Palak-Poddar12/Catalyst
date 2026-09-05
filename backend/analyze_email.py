import json
import uuid
import sys
import os
from typing import Dict, Any

# Add backend directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parsers.email_parser import parse_email_headers
from enrichment.ioc_enrichment import enrich_iocs
from parsers.forensic_summary import build_forensic_summary

def analyze_email(raw_email: str) -> Dict[str, Any]:
    """Main analysis function that produces the complete forensics JSON."""
    email_id = str(uuid.uuid4())
    headers = parse_email_headers(raw_email)

    body = ""
    if "\n\n" in raw_email:
        body = raw_email.split("\n\n", 1)[-1]

    attachments = []
    iocs = enrich_iocs(headers, body, attachments)
    forensic_summary = build_forensic_summary(headers, iocs)

    result = {
        "email_id": email_id,
        "headers": headers,
        "iocs": iocs,
        "forensic_summary": forensic_summary
    }

    return result

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sample_path = os.path.join(script_dir, "..", "sample-emails", "phishing.eml")

    with open(sample_path, "r", encoding="utf-8") as f:
        raw_email = f.read()

    result = analyze_email(raw_email)
    print(json.dumps(result, indent=2))