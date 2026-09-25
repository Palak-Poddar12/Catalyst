from __future__ import annotations

import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any

try:
    import dkim
    DKIMPY_AVAILABLE = True
except ImportError:
    DKIMPY_AVAILABLE = False

try:
    import spf
    PYSPF_AVAILABLE = True
except ImportError:
    PYSPF_AVAILABLE = False


AUTH_RESULT_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)=("
    r"pass|fail|softfail|neutral|none|temperror|permerror"
    r")",
    re.IGNORECASE,
)

SMTP_MAILFROM_PATTERN = re.compile(
    r"\bsmtp\.mailfrom=([^\s;]+)",
    re.IGNORECASE,
)

HEADER_FROM_PATTERN = re.compile(
    r"\bheader\.from=([^\s;]+)",
    re.IGNORECASE,
)

HEADER_D_PATTERN = re.compile(
    r"\bheader\.d=([^\s;]+)",
    re.IGNORECASE,
)

DKIM_D_PATTERN = re.compile(
    r"\bd=([^;\s]+)",
    re.IGNORECASE,
)

DKIM_S_PATTERN = re.compile(
    r"\bs=([^;\s]+)",
    re.IGNORECASE,
)


def extract_domain_from_address(value: str) -> str:
    """Extract normalized domain from an email-address header."""
    _, email_address = parseaddr(value or "")

    if "@" not in email_address:
        return ""

    return email_address.rsplit("@", 1)[1].lower().strip()


def get_visible_from_domain(raw_email: bytes) -> str:
    """Extract the user-visible From domain."""
    message = BytesParser(policy=policy.default).parsebytes(raw_email)

    return extract_domain_from_address(
        str(message.get("From", ""))
    )


def get_return_path_domain(raw_email: bytes) -> str:
    """Extract the envelope sender / Return-Path domain if available."""
    message = BytesParser(policy=policy.default).parsebytes(raw_email)

    return extract_domain_from_address(
        str(message.get("Return-Path", ""))
    )


def parse_dkim_signature_domains(raw_email: bytes) -> list[dict[str, str]]:
    """Extract d= signing domain and s= selector from DKIM-Signature headers."""
    message = BytesParser(policy=policy.default).parsebytes(raw_email)

    signatures = message.get_all("DKIM-Signature", [])

    parsed_signatures: list[dict[str, str]] = []

    for signature in signatures:
        domain_match = DKIM_D_PATTERN.search(signature)
        selector_match = DKIM_S_PATTERN.search(signature)

        parsed_signatures.append({
            "signing_domain": (
                domain_match.group(1).lower()
                if domain_match
                else ""
            ),
            "selector": (
                selector_match.group(1).lower()
                if selector_match
                else ""
            ),
            "raw_signature": signature,
        })

    return parsed_signatures


def parse_reported_authentication_results(
    raw_email: bytes,
) -> dict[str, Any]:
    """
    Parse receiver-reported Authentication-Results headers.

    These results are useful evidence but should be tagged as receiver-reported.
    """
    message = BytesParser(policy=policy.default).parsebytes(raw_email)

    headers = message.get_all(
        "Authentication-Results",
        [],
    )

    results = {
        "source": "receiver_reported",
        "headers_found": len(headers),
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
        "smtp_mailfrom_domain": "",
        "header_from_domain": "",
        "header_d_domain": "",
        "raw_headers": headers,
    }

    for header in headers:
        for mechanism, status in AUTH_RESULT_PATTERN.findall(header):
            mechanism = mechanism.lower()
            status = status.lower()

            results[mechanism] = status

        mailfrom_match = SMTP_MAILFROM_PATTERN.search(header)

        if mailfrom_match:
            results["smtp_mailfrom_domain"] = (
                extract_domain_from_address(
                    mailfrom_match.group(1)
                )
            )

        header_from_match = HEADER_FROM_PATTERN.search(header)

        if header_from_match:
            results["header_from_domain"] = (
                header_from_match.group(1)
                .lower()
                .strip()
            )

        header_d_match = HEADER_D_PATTERN.search(header)

        if header_d_match:
            results["header_d_domain"] = (
                header_d_match.group(1)
                .lower()
                .strip()
            )

    return results


def get_connecting_ip_from_hops(
    received_hops: list[dict[str, Any]],
) -> str:
    """
    Select earliest visible public IP from already-parsed Received hops.

    Call this after your received_parser module has classified IP scopes.
    """
    for hop in received_hops:
        if hop.get("ip_scope") == "public":
            return hop.get("ip", "")

    return ""


def perform_spf_check(
    connecting_ip: str,
    envelope_sender: str,
    helo_host: str,
) -> dict[str, Any]:
    """
    Perform an independent SPF query using pyspf.

    Requires:
    - Public connecting IP
    - Envelope sender / Return-Path email
    - HELO/EHLO hostname when available
    """
    result = {
        "source": "independent_pyspf",
        "available": PYSPF_AVAILABLE,
        "status": "not_checked",
        "explanation": "",
        "connecting_ip": connecting_ip,
        "envelope_sender": envelope_sender,
        "helo_host": helo_host,
        "envelope_sender_domain": extract_domain_from_address(
            envelope_sender
        ),
    }

    if not PYSPF_AVAILABLE:
        result["status"] = "library_unavailable"
        result["explanation"] = (
            "pyspf is not installed or unavailable in this environment."
        )
        return result

    if not connecting_ip:
        result["status"] = "missing_connecting_ip"
        result["explanation"] = (
            "No earliest visible public relay IP was available."
        )
        return result

    if not envelope_sender or "@" not in envelope_sender:
        result["status"] = "missing_envelope_sender"
        result["explanation"] = (
            "Return-Path/envelope sender is unavailable or invalid."
        )
        return result

    try:
        status, explanation = spf.check2(
            i=connecting_ip,
            s=envelope_sender,
            h=helo_host or "unknown",
        )

        result["status"] = status.lower()
        result["explanation"] = explanation

    except Exception as error:
        result["status"] = "lookup_error"
        result["explanation"] = str(error)

    return result


def perform_dkim_check(raw_email: bytes) -> dict[str, Any]:
    """
    Perform independent DKIM signature verification with dkimpy.

    dkimpy uses the DKIM selector and signing domain to retrieve the public
    key from DNS. It verifies signed headers and body integrity.
    """
    signature_details = parse_dkim_signature_domains(raw_email)

    result = {
        "source": "independent_dkimpy",
        "available": DKIMPY_AVAILABLE,
        "status": "not_checked",
        "signature_present": len(signature_details) > 0,
        "signature_details": signature_details,
        "error": "",
    }

    if not signature_details:
        result["status"] = "none"
        return result

    if not DKIMPY_AVAILABLE:
        result["status"] = "library_unavailable"
        result["error"] = (
            "dkimpy is not installed or unavailable in this environment."
        )
        return result

    try:
        verified = dkim.verify(raw_email)

        result["status"] = "pass" if verified else "fail"

    except Exception as error:
        result["status"] = "verification_error"
        result["error"] = str(error)

    return result


def domains_align(
    visible_from_domain: str,
    authenticated_domain: str,
    mode: str = "relaxed",
) -> bool:
    """
    Test domain alignment.

    Strict:
    exact domain match only.

    Relaxed:
    authenticated domain may be a subdomain of visible From domain.
    """
    visible_from_domain = (
        visible_from_domain or ""
    ).lower().strip().rstrip(".")

    authenticated_domain = (
        authenticated_domain or ""
    ).lower().strip().rstrip(".")

    if not visible_from_domain or not authenticated_domain:
        return False

    if mode == "strict":
        return visible_from_domain == authenticated_domain

    return (
        visible_from_domain == authenticated_domain
        or authenticated_domain.endswith(
            f".{visible_from_domain}"
        )
    )


def assess_dmarc_alignment(
    visible_from_domain: str,
    spf_result: dict[str, Any],
    dkim_result: dict[str, Any],
    dmarc_dns_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Produce a forensic DMARC alignment assessment.

    DMARC can pass when either:
    - SPF passes and the envelope sender aligns with From, OR
    - DKIM passes and signing domain aligns with From.
    """
    dmarc_dns_result = dmarc_dns_result or {}

    aspf_mode = (
        dmarc_dns_result.get("aspf", "r")
        .lower()
        .strip()
    )

    adkim_mode = (
        dmarc_dns_result.get("adkim", "r")
        .lower()
        .strip()
    )

    spf_alignment_mode = (
        "strict" if aspf_mode == "s" else "relaxed"
    )

    dkim_alignment_mode = (
        "strict" if adkim_mode == "s" else "relaxed"
    )

    spf_domain = spf_result.get(
        "envelope_sender_domain",
        "",
    )

    spf_passed = spf_result.get("status") == "pass"

    spf_aligned = (
        spf_passed
        and domains_align(
            visible_from_domain,
            spf_domain,
            spf_alignment_mode,
        )
    )

    signing_domains = [
        signature.get("signing_domain", "")
        for signature in dkim_result.get(
            "signature_details",
            [],
        )
    ]

    dkim_passed = dkim_result.get("status") == "pass"

    aligned_dkim_domains = [
        signing_domain
        for signing_domain in signing_domains
        if domains_align(
            visible_from_domain,
            signing_domain,
            dkim_alignment_mode,
        )
    ]

    dkim_aligned = dkim_passed and len(
        aligned_dkim_domains
    ) > 0

    if spf_aligned or dkim_aligned:
        assessment = "likely_pass"

    elif (
        spf_result.get("status") in {
            "not_checked",
            "library_unavailable",
            "missing_connecting_ip",
            "missing_envelope_sender",
            "lookup_error",
        }
        and dkim_result.get("status") in {
            "not_checked",
            "library_unavailable",
            "verification_error",
        }
    ):
        assessment = "inconclusive"

    else:
        assessment = "likely_fail"

    return {
        "source": "forensic_alignment_assessment",
        "visible_from_domain": visible_from_domain,
        "dmarc_dns_policy": dmarc_dns_result.get(
            "policy",
            "unknown",
        ),
        "spf_alignment_mode": spf_alignment_mode,
        "dkim_alignment_mode": dkim_alignment_mode,
        "spf": {
            "status": spf_result.get("status", ""),
            "authenticated_domain": spf_domain,
            "aligned": spf_aligned,
        },
        "dkim": {
            "status": dkim_result.get("status", ""),
            "signing_domains": signing_domains,
            "aligned_domains": aligned_dkim_domains,
            "aligned": dkim_aligned,
        },
        "assessment": assessment,
        "limitation": (
            "This is a forensic alignment assessment. "
            "A receiving mail system remains the authoritative system "
            "for final DMARC enforcement decisions."
        ),
    }


def analyze_email_authentication(
    raw_email: bytes,
    received_hops: list[dict[str, Any]],
    dmarc_dns_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Perform full authentication evidence analysis.

    Combine:
    - Receiver-reported Authentication-Results
    - Independent SPF check
    - Independent DKIM verification
    - DMARC alignment assessment
    """
    message = BytesParser(policy=policy.default).parsebytes(raw_email)

    visible_from_domain = get_visible_from_domain(raw_email)
    envelope_sender = str(message.get("Return-Path", ""))
    helo_host = ""

    for hop in received_hops:
        if hop.get("ip_scope") == "public":
            helo_host = hop.get("from_host", "")
            break

    connecting_ip = get_connecting_ip_from_hops(
        received_hops
    )

    reported_results = parse_reported_authentication_results(
        raw_email
    )

    spf_result = perform_spf_check(
        connecting_ip=connecting_ip,
        envelope_sender=envelope_sender,
        helo_host=helo_host,
    )

    dkim_result = perform_dkim_check(raw_email)

    dmarc_assessment = assess_dmarc_alignment(
        visible_from_domain=visible_from_domain,
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_dns_result=dmarc_dns_result,
    )

    return {
        "visible_from_domain": visible_from_domain,
        "reported_results": reported_results,
        "independent_spf": spf_result,
        "independent_dkim": dkim_result,
        "dmarc_forensic_assessment": dmarc_assessment,
    }