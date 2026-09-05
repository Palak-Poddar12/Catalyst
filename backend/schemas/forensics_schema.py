from pydantic import BaseModel, Field
from typing import List, Optional, Literal
from datetime import datetime
from typing import Dict, Any, List

# Authentication results
class AuthenticationResults(BaseModel):
    spf: Literal["pass", "fail", "softfail", "neutral", "none"]
    dkim: Literal["pass", "fail", "none"]
    dmarc: Literal["pass", "fail", "none"]
    dmarc_policy: Literal["none", "quarantine", "reject"]
    alignment: Literal["pass", "fail"]

# Received hop
class ReceivedHop(BaseModel):
    hop: int
    from_host: str
    by_host: str
    ip: str
    timestamp: str  # ISO8601 string

# Headers section
class HeadersSection(BaseModel):
    from_field: str = Field(..., alias="from")
    reply_to: str
    return_path: str
    received: List[ReceivedHop]
    authentication_results: AuthenticationResults

# IOC: IP
class IPIndicator(BaseModel):
    ip: str
    country: str
    city: str
    asn: str
    isp: str
    risk_flags: List[str]

# IOC: Domain
class DomainIndicator(BaseModel):
    domain: str
    age_days: int
    registrar: str
    risk_flags: List[str]

# IOC: URL
class URLIndicator(BaseModel):
    url: str
    final_url: str
    domain: str
    risk_flags: List[str]

# IOC: Attachment
class AttachmentIndicator(BaseModel):
    filename: str
    mime_type: str
    sha256: str
    risk_flags: List[str]

# IOCs section
class IOCsSection(BaseModel):
    ips: List[IPIndicator]
    domains: List[DomainIndicator]
    urls: List[URLIndicator]
    attachments: List[AttachmentIndicator]

# Probable origin
class ProbableOrigin(BaseModel):
    country: str
    city: str
    asn: str
    confidence: Literal["low", "medium", "high"]

# Forensic summary
class ForensicSummary(BaseModel):
    earliest_reliable_ip: str
    probable_origin: ProbableOrigin
    key_findings: List[str]

# Full forensics schema
class ForensicsResult(BaseModel):
    email_id: str
    headers: HeadersSection
    iocs: IOCsSection
    forensic_summary: ForensicSummary
def find_earliest_reliable_ip(received_chain: List[Dict[str, Any]]) -> str:
    """
    Find the earliest reliable IP from the Received header chain.
    Simplified logic: skip private IPs and take the first public-looking IP.
    """
    for hop in received_chain:
        ip = hop.get("ip", "")
        if not ip or ip.startswith("0.0.0.0"):
            continue

        # Skip private IP ranges
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            continue

        # Skip localhost
        if ip.startswith("127."):
            continue

        return ip

    return "unknown"

def estimate_confidence(headers: Dict[str, Any], iocs: Dict[str, Any]) -> str:
    """
    Estimate confidence level for probable origin.
    Simplified logic based on available evidence.
    """
    # Count evidence signals
    evidence_count = 0

    # Auth results
    auth = headers.get("authentication_results", {})
    if auth.get("dmarc") != "none":
        evidence_count += 1
    if auth.get("spf") != "none":
        evidence_count += 1
    if auth.get("dkim") != "none":
        evidence_count += 1

    # IOC evidence
    if len(iocs.get("ips", [])) > 0:
        evidence_count += 1
    if len(iocs.get("domains", [])) > 0:
        evidence_count += 1

    # Received chain length
    if len(headers.get("received", [])) >= 3:
        evidence_count += 1

    # Determine confidence
    if evidence_count >= 5:
        return "high"
    elif evidence_count >= 3:
        return "medium"
    else:
        return "low"

def generate_key_findings(headers: Dict[str, Any], iocs: Dict[str, Any]) -> List[str]:
    """
    Generate human-readable key findings based on analysis.
    """
    findings = []

    # Authentication findings
    auth = headers.get("authentication_results", {})

    if auth.get("dmarc") == "fail":
        findings.append("DMARC failed")
    if auth.get("spf") == "fail":
        findings.append("SPF failed")
    if auth.get("dkim") == "fail":
        findings.append("DKIM failed")

    # Sender mismatch
    from_domain = headers.get("from", "").split("@")[-1].split(">")[-1].strip().lower() if "@" in headers.get("from", "") else ""
    reply_domain = headers.get("reply_to", "").split("@")[-1].split(">")[-1].strip().lower() if "@" in headers.get("reply_to", "") else ""

    if from_domain and reply_domain and from_domain != reply_domain:
        findings.append("From and Reply-To domains differ")

    # IOC findings
    for ip in iocs.get("ips", []):
        if "abuse" in ip.get("risk_flags", []):
            findings.append(f"IP {ip['ip']} has abuse history")
            break

    for domain in iocs.get("domains", []):
        if "lookalike" in domain.get("risk_flags", []):
            findings.append("Suspicious lookalike domain detected")
            break
        if "new_domain" in domain.get("risk_flags", []):
            findings.append("Sender domain is newly registered")
            break

    for url in iocs.get("urls", []):
        if "phishing_feed" in url.get("risk_flags", []):
            findings.append("URL matched phishing feed")
            break
        if "malicious" in url.get("risk_flags", []):
            findings.append("Malicious URL detected")
            break

    for att in iocs.get("attachments", []):
        if "double_extension" in att.get("risk_flags", []):
            findings.append("Suspicious double extension attachment")
            break
        if "macro_enabled" in att.get("risk_flags", []):
            findings.append("Macro-enabled attachment detected")
            break

    return findings

def build_forensic_summary(headers: Dict[str, Any], iocs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build the forensic_summary section of our schema.
    """
    earliest_ip = find_earliest_reliable_ip(headers.get("received", []))

    # Find geo info for earliest IP
    probable_origin = {
        "country": "unknown",
        "city": "unknown",
        "asn": "unknown",
        "confidence": "low"
    }

    if earliest_ip != "unknown":
        for ip_info in iocs.get("ips", []):
            if ip_info["ip"] == earliest_ip:
                probable_origin = {
                    "country": ip_info["country"],
                    "city": ip_info["city"],
                    "asn": ip_info["asn"],
                    "confidence": estimate_confidence(headers, iocs)
                }
                break

    key_findings = generate_key_findings(headers, iocs)

    return {
        "earliest_reliable_ip": earliest_ip,
        "probable_origin": probable_origin,
        "key_findings": key_findings
    }