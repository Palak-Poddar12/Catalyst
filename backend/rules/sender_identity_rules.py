from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any


PROTECTED_BRANDS = {
    "google": {
        "domains": {"google.com"},
        "display_names": {"google", "google security", "gmail"},
    },
    "microsoft": {
        "domains": {"microsoft.com", "office.com", "outlook.com"},
        "display_names": {
            "microsoft",
            "microsoft security",
            "microsoft account",
            "outlook",
        },
    },
    "amazon": {
        "domains": {"amazon.com", "amazon.in"},
        "display_names": {"amazon", "amazon india", "amazon support"},
    },
    "sbi": {
        "domains": {"sbi.co.in", "onlinesbi.sbi"},
        "display_names": {
            "state bank of india",
            "sbi",
            "sbi bank",
            "sbi security",
        },
    },
    "hdfc": {
        "domains": {"hdfcbank.com"},
        "display_names": {
            "hdfc bank",
            "hdfc",
            "hdfc security",
        },
    },
    "icici": {
        "domains": {"icicibank.com"},
        "display_names": {
            "icici bank",
            "icici",
            "icici security",
        },
    },
    "government_india": {
        "domains": {"gov.in", "nic.in"},
        "display_names": {
            "government of india",
            "income tax department",
            "indian government",
        },
    },
}


CHARACTER_SUBSTITUTIONS = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
})


SUSPICIOUS_DOMAIN_WORDS = {
    "secure",
    "security",
    "verify",
    "verification",
    "login",
    "signin",
    "account",
    "update",
    "support",
    "payment",
    "invoice",
    "alert",
    "confirm",
}


def normalize_text(value: str) -> str:
    """Normalize text for safe brand comparison."""
    return re.sub(
        r"[^a-z0-9]",
        "",
        (value or "").lower().translate(CHARACTER_SUBSTITUTIONS),
    )


def decode_idna_label(label: str) -> str:
    """
    Decode one hostname label if it is ACE/Punycode.

    Returns original label if decoding fails.
    """
    try:
        if label.lower().startswith("xn--"):
            return label.encode("ascii").decode("idna")
    except UnicodeError:
        pass

    return label


def decode_idna_domain(domain: str) -> str:
    """Decode hostname labels separately, never a whole URL."""
    labels = (domain or "").lower().split(".")

    return ".".join(decode_idna_label(label) for label in labels)


def get_domain_labels(domain: str) -> list[str]:
    """Return normalized domain labels without the top-level suffix."""
    labels = domain.lower().strip().split(".")

    if len(labels) <= 1:
        return labels

    return labels[:-1]


def similarity_score(value_a: str, value_b: str) -> float:
    """Return a normalized 0–100 similarity score."""
    clean_a = normalize_text(value_a)
    clean_b = normalize_text(value_b)

    if not clean_a or not clean_b:
        return 0.0

    return round(
        SequenceMatcher(None, clean_a, clean_b).ratio() * 100,
        2,
    )


def detect_punycode(domain: str) -> bool:
    """Flag domains containing an xn-- ACE/Punycode label."""
    return any(
        label.lower().startswith("xn--")
        for label in (domain or "").split(".")
    )


def detect_suspicious_domain_words(domain: str) -> list[str]:
    """Return suspicious words found inside a domain."""
    normalized_domain = domain.lower().replace("-", ".")

    return sorted(
        word
        for word in SUSPICIOUS_DOMAIN_WORDS
        if word in normalized_domain
    )


def brand_domain_similarity(domain: str) -> list[dict[str, Any]]:
    """
    Compare a domain with known protected-brand domains.

    This is a risk indicator, not proof that the domain is malicious.
    """
    findings: list[dict[str, Any]] = []

    decoded_domain = decode_idna_domain(domain)
    domain_labels = get_domain_labels(decoded_domain)

    for brand, profile in PROTECTED_BRANDS.items():
        brand_name = normalize_text(brand)

        for label in domain_labels:
            score = similarity_score(label, brand_name)

            # 75 is deliberately conservative for a simple MVP.
            if score >= 75 and normalize_text(label) != brand_name:
                findings.append({
                    "brand": brand,
                    "suspicious_label": label,
                    "matched_protected_domains": sorted(
                        profile["domains"]
                    ),
                    "similarity_score": score,
                    "reason": "lookalike_domain_label",
                })

    return findings


def detect_display_name_impersonation(
    display_name: str,
    sender_domain: str,
) -> list[dict[str, Any]]:
    """
    Flag when a display name resembles a protected brand but sender domain
    is not one of that brand's approved domains.
    """
    findings: list[dict[str, Any]] = []

    normalized_display_name = normalize_text(display_name)

    if not normalized_display_name:
        return findings

    for brand, profile in PROTECTED_BRANDS.items():
        protected_domains = profile["domains"]

        for protected_name in profile["display_names"]:
            score = similarity_score(
                normalized_display_name,
                protected_name,
            )

            if score >= 85 and sender_domain not in protected_domains:
                findings.append({
                    "brand": brand,
                    "display_name": display_name,
                    "sender_domain": sender_domain,
                    "approved_domains": sorted(protected_domains),
                    "similarity_score": score,
                    "reason": "display_name_brand_impersonation",
                })
                break

    return findings


def compare_sender_identities(
    from_data: dict[str, str],
    reply_to_data: dict[str, str],
    return_path_data: dict[str, str],
    sender_data: dict[str, str],
) -> dict[str, Any]:
    """
    Compare visible From, Reply-To, Return-Path, and Sender identities.
    """
    from_domain = from_data.get("domain", "")
    reply_domain = reply_to_data.get("domain", "")
    return_path_domain = return_path_data.get("domain", "")
    sender_domain = sender_data.get("domain", "")

    findings: list[dict[str, Any]] = []
    risk_flags: list[str] = []

    if from_domain and reply_domain and from_domain != reply_domain:
        risk_flags.append("from_reply_to_domain_mismatch")
        findings.append({
            "type": "identity_mismatch",
            "reason": "Visible From domain differs from Reply-To domain",
            "from_domain": from_domain,
            "reply_to_domain": reply_domain,
        })

    if (
        from_domain
        and return_path_domain
        and from_domain != return_path_domain
    ):
        risk_flags.append("from_return_path_domain_mismatch")
        findings.append({
            "type": "identity_mismatch",
            "reason": "Visible From domain differs from Return-Path domain",
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
        })

    if from_domain and sender_domain and from_domain != sender_domain:
        risk_flags.append("from_sender_domain_mismatch")
        findings.append({
            "type": "identity_mismatch",
            "reason": "Visible From domain differs from Sender domain",
            "from_domain": from_domain,
            "sender_domain": sender_domain,
        })

    all_domains = {
        "from": from_domain,
        "reply_to": reply_domain,
        "return_path": return_path_domain,
        "sender": sender_domain,
    }

    for identity_field, domain in all_domains.items():
        if not domain:
            continue

        if detect_punycode(domain):
            risk_flags.append("punycode_domain")
            findings.append({
                "type": "domain_encoding",
                "field": identity_field,
                "domain": domain,
                "decoded_domain": decode_idna_domain(domain),
                "reason": "Punycode/IDN domain detected",
            })

        suspicious_words = detect_suspicious_domain_words(domain)

        if suspicious_words:
            findings.append({
                "type": "suspicious_domain_structure",
                "field": identity_field,
                "domain": domain,
                "matched_words": suspicious_words,
                "reason": "Suspicious domain keywords found",
            })

        for lookalike in brand_domain_similarity(domain):
            risk_flags.append("brand_lookalike_domain")
            findings.append({
                "type": "brand_lookalike",
                "field": identity_field,
                "domain": domain,
                **lookalike,
            })

    display_name_findings = detect_display_name_impersonation(
        display_name=from_data.get("display_name", ""),
        sender_domain=from_domain,
    )

    if display_name_findings:
        risk_flags.append("display_name_impersonation")
        findings.extend({
            "type": "display_name_impersonation",
            **item,
        } for item in display_name_findings)

    return {
        "from_domain": from_domain,
        "reply_to_domain": reply_domain,
        "return_path_domain": return_path_domain,
        "sender_domain": sender_domain,
        "risk_flags": sorted(set(risk_flags)),
        "findings": findings,
    }