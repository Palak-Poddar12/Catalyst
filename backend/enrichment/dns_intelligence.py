from __future__ import annotations

from typing import Any

import dns.exception
import dns.resolver


DNS_TIMEOUT_SECONDS = 4


def clean_domain(domain: str) -> str:
    """Normalize a domain for DNS lookup."""
    return (domain or "").strip().lower().rstrip(".")


def create_resolver() -> dns.resolver.Resolver:
    """Create a resolver with safe timeouts."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT_SECONDS
    resolver.lifetime = DNS_TIMEOUT_SECONDS

    return resolver


def query_dns_records(
    domain: str,
    record_type: str,
) -> dict[str, Any]:
    """
    Query one DNS record type safely.

    Returns records, status, and error instead of raising errors to callers.
    """
    clean_name = clean_domain(domain)

    if not clean_name:
        return {
            "query_name": "",
            "record_type": record_type,
            "status": "invalid_domain",
            "records": [],
            "error": "Domain is empty",
        }

    resolver = create_resolver()

    try:
        answers = resolver.resolve(
            clean_name,
            record_type,
            raise_on_no_answer=False,
        )

        if answers.rrset is None:
            return {
                "query_name": clean_name,
                "record_type": record_type,
                "status": "no_answer",
                "records": [],
                "error": "",
            }

        records = [answer.to_text() for answer in answers]

        return {
            "query_name": clean_name,
            "record_type": record_type,
            "status": "ok",
            "records": records,
            "error": "",
        }

    except dns.resolver.NXDOMAIN:
        return {
            "query_name": clean_name,
            "record_type": record_type,
            "status": "nxdomain",
            "records": [],
            "error": "Domain does not exist",
        }

    except dns.resolver.NoNameservers:
        return {
            "query_name": clean_name,
            "record_type": record_type,
            "status": "no_nameservers",
            "records": [],
            "error": "No usable DNS nameservers",
        }

    except dns.exception.Timeout:
        return {
            "query_name": clean_name,
            "record_type": record_type,
            "status": "timeout",
            "records": [],
            "error": "DNS lookup timed out",
        }

    except dns.exception.DNSException as error:
        return {
            "query_name": clean_name,
            "record_type": record_type,
            "status": "dns_error",
            "records": [],
            "error": str(error),
        }


def get_txt_records(domain: str) -> dict[str, Any]:
    """Return TXT records with quotation marks removed."""
    result = query_dns_records(domain, "TXT")

    result["records"] = [
        record.replace('"', "")
        for record in result["records"]
    ]

    return result


def find_spf_record(domain: str) -> dict[str, Any]:
    """
    Find Sender Policy Framework record from a domain TXT record.

    SPF records begin with: v=spf1
    """
    txt_result = get_txt_records(domain)

    spf_records = [
        record
        for record in txt_result["records"]
        if record.lower().startswith("v=spf1")
    ]

    return {
        "domain": clean_domain(domain),
        "status": txt_result["status"],
        "spf_found": len(spf_records) > 0,
        "spf_records": spf_records,
        "error": txt_result["error"],
    }


def parse_tagged_record(record: str) -> dict[str, str]:
    """
    Convert a semicolon-separated DNS policy record into key/value tags.

    Example:
    v=DMARC1; p=reject; rua=mailto:reports@example.com
    """
    tags: dict[str, str] = {}

    for part in record.split(";"):
        part = part.strip()

        if "=" not in part:
            continue

        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()

    return tags


def find_dmarc_record(domain: str) -> dict[str, Any]:
    """
    Look up a DMARC record from _dmarc.<domain> TXT.

    This function reports the record it finds. Full organizational-domain
    discovery/tree-walk logic can be added later.
    """
    clean_name = clean_domain(domain)

    if not clean_name:
        return {
            "domain": "",
            "query_name": "",
            "status": "invalid_domain",
            "dmarc_found": False,
            "record": "",
            "tags": {},
            "policy": "none",
            "error": "Domain is empty",
        }

    query_name = f"_dmarc.{clean_name}"
    txt_result = get_txt_records(query_name)

    dmarc_records = [
        record
        for record in txt_result["records"]
        if record.lower().startswith("v=dmarc1")
    ]

    if not dmarc_records:
        return {
            "domain": clean_name,
            "query_name": query_name,
            "status": txt_result["status"],
            "dmarc_found": False,
            "record": "",
            "tags": {},
            "policy": "none",
            "error": txt_result["error"],
        }

    selected_record = dmarc_records[0]
    tags = parse_tagged_record(selected_record)

    return {
        "domain": clean_name,
        "query_name": query_name,
        "status": "ok",
        "dmarc_found": True,
        "record": selected_record,
        "tags": tags,
        "policy": tags.get("p", "none").lower(),
        "subdomain_policy": tags.get("sp", "").lower(),
        "adkim": tags.get("adkim", "r").lower(),
        "aspf": tags.get("aspf", "r").lower(),
        "error": "",
    }


def get_domain_dns_intelligence(domain: str) -> dict[str, Any]:
    """
    Gather DNS indicators relevant to email forensics.

    This is a passive lookup only. It does not send email or modify DNS.
    """
    clean_name = clean_domain(domain)

    if not clean_name:
        return {
            "domain": "",
            "risk_flags": ["invalid_domain"],
        }

    a_records = query_dns_records(clean_name, "A")
    aaaa_records = query_dns_records(clean_name, "AAAA")
    mx_records = query_dns_records(clean_name, "MX")
    ns_records = query_dns_records(clean_name, "NS")
    spf_result = find_spf_record(clean_name)
    dmarc_result = find_dmarc_record(clean_name)

    risk_flags: list[str] = []

    if a_records["status"] == "nxdomain":
        risk_flags.append("domain_does_not_exist")

    if mx_records["status"] in {"no_answer", "nxdomain"}:
        risk_flags.append("no_mx_record")

    if not spf_result["spf_found"]:
        risk_flags.append("spf_record_missing")

    if not dmarc_result["dmarc_found"]:
        risk_flags.append("dmarc_record_missing")

    if dmarc_result.get("policy") == "none":
        risk_flags.append("dmarc_monitoring_only")

    return {
        "domain": clean_name,
        "a_records": a_records,
        "aaaa_records": aaaa_records,
        "mx_records": mx_records,
        "ns_records": ns_records,
        "spf": spf_result,
        "dmarc": dmarc_result,
        "risk_flags": sorted(set(risk_flags)),
    }