from __future__ import annotations

import ipaddress
import re
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Any


IPV4_PATTERN = re.compile(
    r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])"
)

IPV6_PATTERN = re.compile(
    r"(?<![0-9a-fA-F:])"
    r"([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})"
    r"(?![0-9a-fA-F:])"
)

FROM_PATTERN = re.compile(
    r"\bfrom\s+([^\s(;]+)",
    re.IGNORECASE,
)

BY_PATTERN = re.compile(
    r"\bby\s+([^\s(;]+)",
    re.IGNORECASE,
)


def classify_ip(ip_value: str) -> str:
    """
    Classify an IP address before attempting reputation or geolocation.

    Returns:
    public, private, loopback, link_local, multicast, reserved,
    documentation, unspecified, invalid
    """
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        return "invalid"

    if ip.is_loopback:
        return "loopback"

    if ip.is_private:
        return "private"

    if ip.is_link_local:
        return "link_local"

    if ip.is_multicast:
        return "multicast"

    if ip.is_unspecified:
        return "unspecified"

    if ip.is_reserved:
        return "reserved"

    documentation_networks = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32"),
    ]

    if any(ip in network for network in documentation_networks):
        return "documentation"

    return "public"


def extract_ip(header_value: str) -> str:
    """Extract one IPv4 or IPv6 address from a Received header."""
    ipv4_match = IPV4_PATTERN.search(header_value)

    if ipv4_match:
        return ipv4_match.group(1)

    ipv6_match = IPV6_PATTERN.search(header_value)

    if ipv6_match:
        return ipv6_match.group(1)

    return ""


def extract_host(pattern: re.Pattern, header_value: str) -> str:
    """Extract source or receiving host from a Received header."""
    match = pattern.search(header_value)

    if match:
        return match.group(1)

    return "unknown"


def extract_received_timestamp(header_value: str) -> str:
    """Extract the timestamp after the final semicolon in a Received header."""
    if ";" not in header_value:
        return ""

    raw_timestamp = header_value.rsplit(";", 1)[-1].strip()

    try:
        parsed = parsedate_to_datetime(raw_timestamp)
        return parsed.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError, IndexError):
        return ""


def parse_received_headers(
    received_headers: list[str],
    trusted_receiving_hosts: set[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Convert raw Received headers into chronological relay hops.

    The oldest header is shown first because it usually represents the
    earliest visible point in the path.
    """
    trusted_receiving_hosts = {
        host.lower()
        for host in (trusted_receiving_hosts or set())
    }

    parsed_hops: list[dict[str, Any]] = []

    for hop_number, raw_header in enumerate(
        reversed(received_headers),
        start=1,
    ):
        from_host = extract_host(FROM_PATTERN, raw_header)
        by_host = extract_host(BY_PATTERN, raw_header)
        ip_value = extract_ip(raw_header)
        ip_scope = classify_ip(ip_value) if ip_value else "missing"

        trusted = (
            by_host.lower() in trusted_receiving_hosts
            and ip_scope == "public"
        )

        risk_flags: list[str] = []

        if ip_scope in {"private", "loopback", "link_local"}:
            risk_flags.append("non_routable_ip")

        elif ip_scope in {"documentation", "reserved"}:
            risk_flags.append("non_live_or_reserved_ip")

        elif ip_scope == "missing":
            risk_flags.append("missing_ip")

        elif ip_scope == "invalid":
            risk_flags.append("invalid_ip")

        if from_host == "unknown" or by_host == "unknown":
            risk_flags.append("incomplete_received_header")

        parsed_hops.append({
            "hop": hop_number,
            "raw_header": raw_header,
            "from_host": from_host,
            "by_host": by_host,
            "ip": ip_value,
            "ip_scope": ip_scope,
            "timestamp_utc": extract_received_timestamp(raw_header),
            "trusted": trusted,
            "risk_flags": risk_flags,
        })

    return parsed_hops


def find_earliest_visible_public_hop(
    received_hops: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """
    Return the earliest visible public IP hop.

    This is an infrastructure clue only. It is not proof of attacker identity
    or an exact physical origin.
    """
    for hop in received_hops:
        if hop["ip_scope"] == "public":
            return hop

    return None
