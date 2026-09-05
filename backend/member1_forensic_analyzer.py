from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from auth_checks.email_authentication import (
    analyze_email_authentication,
)
from enrichment.dns_intelligence import (
    get_domain_dns_intelligence,
)
from enrichment.geoip_intelligence import (
    enrich_ip_list,
)
from enrichment.threat_intelligence import (
    lookup_ip_reputation,
    lookup_url_reputation,
)
from evidence.evidence_integrity import (
    create_evidence_record,
)
from parsers.ioc_extractor import (
    extract_all_urls,
    get_domains_from_urls,
)
from parsers.mime_parser import (
    extract_mime_content,
)
from parsers.received_parser import (
    find_earliest_visible_public_hop,
    parse_received_headers,
)
from rules.sender_identity_rules import (
    compare_sender_identities,
)


def get_sender_domains(mime_data: dict[str, Any]) -> list[str]:
    """Collect unique domains from sender-related email headers."""
    domains = {
        mime_data["from"]["domain"],
        mime_data["reply_to"]["domain"],
        mime_data["return_path"]["domain"],
        mime_data["sender"]["domain"],
    }

    return sorted(domain for domain in domains if domain)


def build_domain_intelligence(
    domains: list[str],
) -> list[dict[str, Any]]:
    """Perform passive DNS intelligence for every extracted domain."""
    results: list[dict[str, Any]] = []

    for domain in domains:
        try:
            results.append(
                get_domain_dns_intelligence(domain)
            )
        except Exception as error:
            results.append({
                "domain": domain,
                "risk_flags": [
                    "domain_intelligence_error"
                ],
                "error": str(error),
            })

    return results


def build_ip_intelligence(
    received_hops: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Enrich unique IPs found in the Received chain.

    Combines:
    - GeoIP / ASN lookup
    - IP reputation lookup
    """
    ip_addresses = [
        hop["ip"]
        for hop in received_hops
        if hop.get("ip")
    ]

    geoip_results = enrich_ip_list(ip_addresses)

    combined_results: list[dict[str, Any]] = []

    for geoip_result in geoip_results:
        ip_value = geoip_result["ip"]

        try:
            reputation_result = lookup_ip_reputation(
                ip_value
            )
        except Exception as error:
            reputation_result = {
                "indicator": ip_value,
                "source": "error_handler",
                "status": "lookup_error",
                "risk_flags": [
                    "ip_reputation_error"
                ],
                "error": str(error),
            }

        combined_risk_flags = sorted(set(
            geoip_result.get("risk_flags", [])
            + reputation_result.get("risk_flags", [])
        ))

        combined_results.append({
            "ip": ip_value,
            "ip_scope": geoip_result.get(
                "ip_scope",
                "unknown",
            ),
            "geolocation": geoip_result,
            "reputation": reputation_result,
            "risk_flags": combined_risk_flags,
        })

    return combined_results


def build_url_intelligence(
    url_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Enrich each extracted URL with reputation intelligence.

    URL lookup only submits a URL string to the provider.
    It does not open or visit the link.
    """
    results: list[dict[str, Any]] = []

    for url_item in url_items:
        url_value = url_item["url"]

        try:
            reputation_result = lookup_url_reputation(
                url_value
            )
        except Exception as error:
            reputation_result = {
                "indicator": url_value,
                "source": "error_handler",
                "status": "lookup_error",
                "risk_flags": [
                    "url_reputation_error"
                ],
                "error": str(error),
            }

        combined_risk_flags = sorted(set(
            url_item.get("risk_flags", [])
            + reputation_result.get("risk_flags", [])
        ))

        results.append({
            **url_item,
            "reputation": reputation_result,
            "risk_flags": combined_risk_flags,
        })

    return results


def build_forensic_findings(
    identity_analysis: dict[str, Any],
    received_hops: list[dict[str, Any]],
    url_intelligence: list[dict[str, Any]],
    attachments: list[dict[str, Any]],
    authentication_analysis: dict[str, Any],
    domain_intelligence: list[dict[str, Any]],
    ip_intelligence: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Convert technical indicators into human-readable findings."""
    findings: list[dict[str, str]] = []

    for finding in identity_analysis.get("findings", []):
        findings.append({
            "severity": "medium",
            "category": finding.get("type", "identity"),
            "message": finding.get("reason", "Identity anomaly"),
        })

    reported_auth = authentication_analysis.get(
        "reported_results",
        {},
    )

    if reported_auth.get("spf") == "fail":
        findings.append({
            "severity": "high",
            "category": "email_authentication",
            "message": "Receiver-reported SPF validation failed.",
        })

    if reported_auth.get("dkim") == "fail":
        findings.append({
            "severity": "high",
            "category": "email_authentication",
            "message": "Receiver-reported DKIM verification failed.",
        })

    if reported_auth.get("dmarc") == "fail":
        findings.append({
            "severity": "high",
            "category": "email_authentication",
            "message": "Receiver-reported DMARC validation failed.",
        })

    dmarc_assessment = authentication_analysis.get(
        "dmarc_forensic_assessment",
        {},
    )

    if dmarc_assessment.get("assessment") == "likely_fail":
        findings.append({
            "severity": "high",
            "category": "dmarc_alignment",
            "message": (
                "Forensic DMARC alignment assessment indicates "
                "likely failure."
            ),
        })

    for hop in received_hops:
        for risk_flag in hop.get("risk_flags", []):
            findings.append({
                "severity": "low",
                "category": "relay_path",
                "message": (
                    f"Relay hop {hop['hop']} ({hop.get('ip', '')}) "
                    f"flagged: {risk_flag}."
                ),
            })

    for url in url_intelligence:
        flags = url.get("risk_flags", [])

        if "visible_link_destination_mismatch" in flags:
            findings.append({
                "severity": "high",
                "category": "url_deception",
                "message": (
                    "Visible hyperlink text and actual destination "
                    "domain do not match."
                ),
            })

        if "punycode_domain" in flags:
            findings.append({
                "severity": "medium",
                "category": "url_deception",
                "message": (
                    f"Punycode/IDN URL domain detected: "
                    f"{url.get('hostname', '')}."
                ),
            })

        if "shortened_url" in flags:
            findings.append({
                "severity": "medium",
                "category": "url_deception",
                "message": (
                    f"Shortened URL detected: {url.get('url', '')}."
                ),
            })

        if "known_malicious_url" in flags:
            findings.append({
                "severity": "critical",
                "category": "threat_intelligence",
                "message": (
                    f"URL matched threat-intelligence data: "
                    f"{url.get('url', '')}."
                ),
            })

    for attachment in attachments:
        for risk_flag in attachment.get("risk_flags", []):
            severity = (
                "high"
                if risk_flag in {
                    "dangerous_extension",
                    "double_extension",
                    "macro_enabled_file",
                }
                else "medium"
            )

            findings.append({
                "severity": severity,
                "category": "attachment",
                "message": (
                    f"Attachment '{attachment['filename']}' "
                    f"flagged: {risk_flag}."
                ),
            })

    for domain_data in domain_intelligence:
        for risk_flag in domain_data.get("risk_flags", []):
            severity = (
                "medium"
                if risk_flag in {
                    "domain_does_not_exist",
                    "no_mx_record",
                }
                else "low"
            )

            findings.append({
                "severity": severity,
                "category": "domain_dns",
                "message": (
                    f"Domain '{domain_data.get('domain', '')}' "
                    f"flagged: {risk_flag}."
                ),
            })

    for ip_data in ip_intelligence:
        for risk_flag in ip_data.get("risk_flags", []):
            if risk_flag in {
                "high_abuse_confidence",
                "reported_abuse",
            }:
                severity = "high"
            else:
                severity = "low"

            findings.append({
                "severity": severity,
                "category": "ip_intelligence",
                "message": (
                    f"IP '{ip_data.get('ip', '')}' "
                    f"flagged: {risk_flag}."
                ),
            })

    return findings


def analyze_eml_file(
    eml_path: str | Path,
    trusted_receiving_hosts: set[str] | None = None,
) -> dict[str, Any]:
    """
    Main Member 1 forensic-analysis function.

    It reads a local .eml file and produces a structured forensic record.
    """
    path = Path(eml_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Email file not found: {path}"
        )

    raw_email = path.read_bytes()

    evidence = create_evidence_record(
        raw_email=raw_email,
        source_name=path.name,
    )

    mime_data = extract_mime_content(raw_email)

    received_hops = parse_received_headers(
        received_headers=mime_data["received_headers"],
        trusted_receiving_hosts=trusted_receiving_hosts,
    )

    earliest_public_hop = find_earliest_visible_public_hop(
        received_hops
    )

    identity_analysis = compare_sender_identities(
        from_data=mime_data["from"],
        reply_to_data=mime_data["reply_to"],
        return_path_data=mime_data["return_path"],
        sender_data=mime_data["sender"],
    )

    extracted_urls = extract_all_urls(
        plain_text_body=mime_data["plain_text_body"],
        html_body=mime_data["html_body"],
    )

    sender_domains = get_sender_domains(mime_data)
    url_domains = get_domains_from_urls(extracted_urls)

    all_domains = sorted(set(
        sender_domains + url_domains
    ))

    domain_intelligence = build_domain_intelligence(
        all_domains
    )

    dmarc_dns_result = next(
        (
            domain_result.get("dmarc", {})
            for domain_result in domain_intelligence
            if domain_result.get("domain")
            == mime_data["from"]["domain"]
        ),
        {},
    )

    authentication_analysis = analyze_email_authentication(
        raw_email=raw_email,
        received_hops=received_hops,
        dmarc_dns_result=dmarc_dns_result,
    )

    ip_intelligence = build_ip_intelligence(
        received_hops
    )

    url_intelligence = build_url_intelligence(
        extracted_urls
    )

    forensic_findings = build_forensic_findings(
        identity_analysis=identity_analysis,
        received_hops=received_hops,
        url_intelligence=url_intelligence,
        attachments=mime_data["attachments"],
        authentication_analysis=authentication_analysis,
        domain_intelligence=domain_intelligence,
        ip_intelligence=ip_intelligence,
    )

    probable_source = {
        "earliest_visible_public_hop": earliest_public_hop,
        "confidence": (
            "medium"
            if earliest_public_hop
            and earliest_public_hop.get("trusted")
            else "low"
        ),
        "limitation": (
            "Visible email relay infrastructure is not proof of a "
            "person's identity or exact physical location."
        ),
    }

    return {
        "case_id": evidence["case_id"],
        "evidence": evidence,
        "message_metadata": {
            "subject": mime_data["subject"],
            "message_id": mime_data["message_id"],
            "date": mime_data["date"],
            "x_originating_ip": mime_data[
                "x_originating_ip"
            ],
            "x_mailer": mime_data["x_mailer"],
            "user_agent": mime_data["user_agent"],
        },
        "sender_identity": {
            "from": mime_data["from"],
            "reply_to": mime_data["reply_to"],
            "return_path": mime_data["return_path"],
            "sender": mime_data["sender"],
            "analysis": identity_analysis,
        },
        "email_authentication": authentication_analysis,
        "relay_analysis": {
            "received_hops": received_hops,
            "probable_source": probable_source,
        },
        "indicators": {
            "domains": all_domains,
            "urls": url_intelligence,
            "attachments": mime_data["attachments"],
            "ips": ip_intelligence,
        },
        "forensic_findings": forensic_findings,
        "forensic_limitations": [
            (
                "IP geolocation and ASN data describe approximate "
                "network infrastructure context, not a confirmed "
                "human sender or attacker location."
            ),
            (
                "Authentication-Results headers are receiver-reported "
                "evidence and may differ from independent checks."
            ),
            (
                "A single indicator is not enough to prove malicious "
                "intent; findings should be evaluated together."
            ),
        ],
    }


def save_forensic_result(
    result: dict[str, Any],
    output_directory: str | Path = (
        "output/forensic_results"
    ),
) -> Path:
    """Save forensic JSON to a local file."""
    output_path = Path(output_directory)
    output_path.mkdir(parents=True, exist_ok=True)

    case_id = result.get("case_id", "unknown_case")

    report_path = output_path / f"{case_id}.json"

    report_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return report_path


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(
            "Usage: python member1_forensic_analyzer.py "
            "<path-to-email.eml>"
        )
        raise SystemExit(1)

    result = analyze_eml_file(
        eml_path=sys.argv[1],
        trusted_receiving_hosts={"mx.example.com"},
    )

    saved_path = save_forensic_result(result)

    print(json.dumps(result, indent=2))
    print(f"\nForensic report saved to: {saved_path}")