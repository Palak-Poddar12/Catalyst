import re
import hashlib
from typing import List, Dict, Any

def extract_urls_from_body(body: str) -> List[str]:
    """Extract URLs from email body text."""
    url_pattern = r"https?://[\w./?=&#%-]+"
    urls = re.findall(url_pattern, body, re.IGNORECASE)
    return list(set(urls))  # Remove duplicates

def extract_domains_from_emails(emails: List[str]) -> List[str]:
    """Extract domains from list of email addresses."""
    domains = []
    for email in emails:
        match = re.search(r"@([\w.-]+\.[a-zA-Z]{2,})", email)
        if match:
            domains.append(match.group(1).lower())
    return list(set(domains))

def calculate_sha256(content: bytes) -> str:
    """Calculate SHA-256 hash of content."""
    return hashlib.sha256(content).hexdigest()

# Mock enrichment functions (replace with real API calls later)

def mock_geoip_lookup(ip: str) -> Dict[str, str]:
    """
    Mock GeoIP lookup. Replace with MaxMind or ipinfo.io later.
    Returns country, city, ASN, ISP.
    """
    # Deterministic mock based on IP
    if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172."):
        return {
            "country": "Private Network",
            "city": "N/A",
            "asn": "N/A",
            "isp": "Private Network"
        }

    # Simple hash-based mock for demo IPs
    ip_hash = sum(int(x) for x in ip.split(".")) % 3

    if ip_hash == 0:
        return {
            "country": "United States",
            "city": "New York",
            "asn": "AS15169",
            "isp": "Google LLC"
        }
    elif ip_hash == 1:
        return {
            "country": "India",
            "city": "Mumbai",
            "asn": "AS9498",
            "isp": "Bharti Airtel"
        }
    else:
        return {
            "country": "Germany",
            "city": "Frankfurt",
            "asn": "AS16509",
            "isp": "Amazon.com Inc."
        }

def mock_ip_reputation(ip: str) -> List[str]:
    """
    Mock IP reputation check. Replace with AbuseIPDB later.
    Returns list of risk flags.
    """
    risk_flags = []

    # Mock: mark some IPs as abusive based on last octet
    try:
        last_octet = int(ip.split(".")[-1])
        if last_octet % 7 == 0:
            risk_flags.append("abuse")
        if last_octet % 11 == 0:
            risk_flags.append("proxy")
        if last_octet % 13 == 0:
            risk_flags.append("tor_exit")
    except:
        pass

    return risk_flags

def mock_domain_intelligence(domain: str) -> Dict[str, Any]:
    """
    Mock domain intelligence. Replace with WHOIS/RDAP later.
    Returns age_days, registrar, risk_flags.
    """
    risk_flags = []

    # Mock: mark lookalike domains
    suspicious_keywords = ["bank", "secure", "login", "verify", "account"]
    if any(kw in domain.lower() for kw in suspicious_keywords):
        risk_flags.append("lookalike")

    # Mock: mark new domains (short names)
    if len(domain.split(".")[0]) < 6:
        risk_flags.append("new_domain")

    return {
        "age_days": 30 if "new_domain" in risk_flags else 365,
        "registrar": "Example Registrar Inc.",
        "risk_flags": risk_flags
    }

def mock_url_reputation(url: str) -> List[str]:
    """
    Mock URL reputation check. Replace with URLhaus/PhishTank later.
    Returns list of risk flags.
    """
    risk_flags = []

    # Mock: mark shortened URLs
    shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl"]
    if any(s in url.lower() for s in shorteners):
        risk_flags.append("shortened")

    # Mock: mark suspicious URLs
    suspicious = ["login", "verify", "account", "secure", "bank"]
    if any(s in url.lower() for s in suspicious):
        risk_flags.append("phishing_feed")
        risk_flags.append("malicious")

    return risk_flags

def mock_attachment_analysis(filename: str, content: bytes) -> Dict[str, Any]:
    """
    Mock attachment analysis. Replace with oletools/ClamAV later.
    Returns mime_type, sha256, risk_flags.
    """
    risk_flags = []

    # Determine MIME type (simplified)
    if filename.lower().endswith(".exe"):
        mime_type = "application/x-msdownload"
        risk_flags.append("executable")
    elif filename.lower().endswith(".pdf"):
        mime_type = "application/pdf"
    elif filename.lower().endswith(".doc") or filename.lower().endswith(".docx"):
        mime_type = "application/msword"
        if filename.lower().endswith(".docm"):
            risk_flags.append("macro_enabled")
    else:
        mime_type = "application/octet-stream"

    # Check for double extension
    parts = filename.lower().split(".")
    if len(parts) > 2 and parts[-1] in ["exe", "scr", "bat", "cmd"]:
        risk_flags.append("double_extension")

    sha256 = calculate_sha256(content)

    return {
        "mime_type": mime_type,
        "sha256": sha256,
        "risk_flags": risk_flags
    }

def enrich_iocs(headers: Dict[str, Any], body: str, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Enrich extracted IOCs with mock intelligence.
    Returns IOCs section matching our schema.
    """
    # Extract IPs from Received headers
    ips = []
    seen_ips = set()
    for hop in headers.get("received", []):
        ip = hop.get("ip", "")
        if ip and ip not in seen_ips and not ip.startswith("0.0.0.0"):
            seen_ips.add(ip)
            geo = mock_geoip_lookup(ip)
            rep = mock_ip_reputation(ip)
            ips.append({
                "ip": ip,
                "country": geo["country"],
                "city": geo["city"],
                "asn": geo["asn"],
                "isp": geo["isp"],
                "risk_flags": rep
            })

    # Extract domains
    domains = []
    from_email = headers.get("from", "")
    reply_to = headers.get("reply_to", "")
    return_path = headers.get("return_path", "")

    domain_list = extract_domains_from_emails([from_email, reply_to, return_path])
    seen_domains = set()

    for domain in domain_list:
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            intel = mock_domain_intelligence(domain)
            domains.append({
                "domain": domain,
                "age_days": intel["age_days"],
                "registrar": intel["registrar"],
                "risk_flags": intel["risk_flags"]
            })

    # Extract URLs
    urls = []
    url_list = extract_urls_from_body(body)
    seen_urls = set()

    for url in url_list:
        if url and url not in seen_urls:
            seen_urls.add(url)
            rep = mock_url_reputation(url)
            # Extract domain from URL
            domain_match = re.search(r"https?://([\w.-]+)", url)
            domain = domain_match.group(1) if domain_match else ""

            urls.append({
                "url": url,
                "final_url": url,  # In real implementation, follow redirects
                "domain": domain,
                "risk_flags": rep
            })

    # Process attachments
    processed_attachments = []
    for att in attachments:
        filename = att.get("filename", "unknown")
        content = att.get("content", b"")
        analysis = mock_attachment_analysis(filename, content)
        processed_attachments.append({
            "filename": filename,
            "mime_type": analysis["mime_type"],
            "sha256": analysis["sha256"],
            "risk_flags": analysis["risk_flags"]
        })

    return {
        "ips": ips,
        "domains": domains,
        "urls": urls,
        "attachments": processed_attachments
    }