import re
import hashlib
from email import message_from_string
from email.header import decode_header
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

def decode_mime_header(value: str) -> str:
    """Decode MIME-encoded header values."""
    if not value:
        return ""
    decoded_parts = decode_header(value)
    result = []
    for text, encoding in decoded_parts:
        if isinstance(text, bytes):
            enc = encoding or "utf-8"
            result.append(text.decode(enc, errors="replace"))
        else:
            result.append(text)
    return "".join(result)

def extract_ip_from_received(received_line: str) -> Optional[str]:
    """Extract IP address from a Received header line."""
    ipv4_pattern = r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]"
    match = re.search(ipv4_pattern, received_line)
    if match:
        return match.group(1)
    ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    match = re.search(ip_pattern, received_line)
    if match:
        return match.group(1)
    return None

def extract_timestamp_from_received(received_line: str) -> str:
    """Extract timestamp from Received header."""
    date_pattern = r"([A-Za-z]{3},\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4})"
    match = re.search(date_pattern, received_line)
    if match:
        date_str = match.group(1)
        try:
            dt = datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %z")
            return dt.isoformat()
        except:
            return date_str
    return datetime.now(timezone.utc).isoformat()

def extract_from_host(received_line: str) -> str:
    """Extract 'from' host from Received header."""
    from_pattern = r"from\s+([^\s(]+)"
    match = re.search(from_pattern, received_line, re.IGNORECASE)
    if match:
        return match.group(1)
    return "unknown"

def extract_by_host(received_line: str) -> str:
    """Extract 'by' host from Received header."""
    by_pattern = r"by\s+([^\s(]+)"
    match = re.search(by_pattern, received_line, re.IGNORECASE)
    if match:
        return match.group(1)
    return "unknown"

def parse_authentication_results(auth_header: str) -> Dict[str, str]:
    """Parse Authentication-Results header."""
    result = {
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
        "dmarc_policy": "none",
        "alignment": "pass"
    }

    if not auth_header:
        return result

    auth_lower = auth_header.lower()

    if "spf=pass" in auth_lower:
        result["spf"] = "pass"
    elif "spf=fail" in auth_lower:
        result["spf"] = "fail"
    elif "spf=softfail" in auth_lower:
        result["spf"] = "softfail"
    elif "spf=neutral" in auth_lower:
        result["spf"] = "neutral"

    if "dkim=pass" in auth_lower:
        result["dkim"] = "pass"
    elif "dkim=fail" in auth_lower:
        result["dkim"] = "fail"

    if "dmarc=pass" in auth_lower:
        result["dmarc"] = "pass"
    elif "dmarc=fail" in auth_lower:
        result["dmarc"] = "fail"

    if "p=quarantine" in auth_lower:
        result["dmarc_policy"] = "quarantine"
    elif "p=reject" in auth_lower:
        result["dmarc_policy"] = "reject"
    elif "p=none" in auth_lower:
        result["dmarc_policy"] = "none"

    if result["spf"] == "fail" or result["dkim"] == "fail" or result["dmarc"] == "fail":
        result["alignment"] = "fail"

    return result

def parse_email_headers(raw_email: str) -> Dict[str, Any]:
    """Parse raw .eml email content and extract key headers."""
    msg = message_from_string(raw_email)

    from_field = decode_mime_header(msg.get("From", ""))
    reply_to = decode_mime_header(msg.get("Reply-To", "")) or from_field
    return_path = decode_mime_header(msg.get("Return-Path", "")) or from_field

    received_headers = msg.get_all("Received", [])

    received_chain = []
    for i, hop in enumerate(reversed(received_headers), start=1):
        ip = extract_ip_from_received(hop) or "0.0.0.0"
        received_chain.append({
            "hop": i,
            "from_host": extract_from_host(hop),
            "by_host": extract_by_host(hop),
            "ip": ip,
            "timestamp": extract_timestamp_from_received(hop)
        })

    auth_results_header = msg.get("Authentication-Results", "")
    auth_results = parse_authentication_results(auth_results_header)

    return {
        "from": from_field,
        "reply_to": reply_to,
        "return_path": return_path,
        "received": received_chain,
        "authentication_results": auth_results
    }