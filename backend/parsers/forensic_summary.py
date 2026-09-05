from typing import Dict, Any, List

def find_earliest_reliable_ip(received_chain: List[Dict[str, Any]]) -> str:
    """Find the earliest reliable IP from the Received header chain."""
    for hop in received_chain:
        ip = hop.get("ip", "")
        if not ip or ip.startswith("0.0.0.0"):
            continue
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            continue
        if ip.startswith("127."):
            continue
        return ip
    return "unknown"

def estimate_confidence(headers: Dict[str, Any], iocs: Dict[str, Any]) -> str:
    """Estimate confidence level for probable origin."""
    evidence_count = 0
    auth = headers.get("authentication_results", {})
    if auth.get("dmarc") != "none":
        evidence_count += 1
    if auth.get("spf") != "none":
        evidence_count += 1
    if auth.get("dkim") != "none":
        evidence_count += 1
    if len(iocs.get("ips", [])) > 0:
        evidence_count += 1
    if len(iocs.get("domains", [])) > 0:
        evidence_count += 1
    if len(headers.get("received", [])) >= 3:
        evidence_count += 1

    if evidence_count >= 5:
        return "high"
    elif evidence_count >= 3:
        return "medium"
    else:
        return "low"

def generate_key_findings(headers: Dict[str, Any], iocs: Dict[str, Any]) -> List[str]:
    """Generate human-readable key findings."""
    findings = []
    auth = headers.get("authentication_results", {})

    if auth.get("dmarc") == "fail":
        findings.append("DMARC failed")
    if auth.get("spf") == "fail":
        findings.append("SPF failed")
    if auth.get("dkim") == "fail":
        findings.append("DKIM failed")

    from_email = headers.get("from", "")
    reply_to = headers.get("reply_to", "")

    from_domain = from_email.split("@")[-1].split(">")[-1].strip().lower() if "@" in from_email else ""
    reply_domain = reply_to.split("@")[-1].split(">")[-1].strip().lower() if "@" in reply_to else ""

    if from_domain and reply_domain and from_domain != reply_domain:
        findings.append("From and Reply-To domains differ")

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
    """Build the forensic_summary section."""
    earliest_ip = find_earliest_reliable_ip(headers.get("received", []))

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