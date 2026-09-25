from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent

ENV_PATH = BASE_DIR / ".env"

FALLBACK_FILE_PATH = (
    BASE_DIR / "data" / "threat_intel" / "offline_fallback.json"
)

CACHE_FILE_PATH = (
    BASE_DIR / "data" / "threat_intel" / "threat_intel_cache.json"
)

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

URLHAUS_URL_LOOKUP = "https://urlhaus-api.abuse.ch/v1/url/"

DEFAULT_TIMEOUT_SECONDS = 5


load_dotenv(ENV_PATH)


def get_timeout_seconds() -> int:
    """Read a safe HTTP timeout from environment configuration."""
    raw_timeout = os.getenv(
        "THREAT_INTEL_TIMEOUT_SECONDS",
        str(DEFAULT_TIMEOUT_SECONDS),
    )

    try:
        return max(1, int(raw_timeout))
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS


def is_public_ip(ip_value: str) -> bool:
    """Return True only for globally routable, non-documentation IPs."""
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        return False

    documentation_networks = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32"),
    ]

    if any(ip in network for network in documentation_networks):
        return False

    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def normalize_url(url: str) -> str:
    """Normalize URL only for lookup and cache keys; never visit it."""
    value = (url or "").strip()

    if not value:
        return ""

    parsed = urlparse(value)

    if parsed.scheme.lower() not in {"http", "https"}:
        return ""

    return value.rstrip("/")


def load_json_file(file_path: Path) -> dict[str, Any]:
    """Load JSON safely; return empty dict if missing or invalid."""
    if not file_path.exists():
        return {}

    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_json_file(file_path: Path, data: dict[str, Any]) -> None:
    """Persist JSON cache safely."""
    file_path.parent.mkdir(parents=True, exist_ok=True)

    file_path.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )


def get_cached_result(category: str, indicator: str) -> dict[str, Any] | None:
    """Return cached indicator result if available."""
    cache = load_json_file(CACHE_FILE_PATH)

    return cache.get(category, {}).get(indicator)


def set_cached_result(
    category: str,
    indicator: str,
    result: dict[str, Any],
) -> None:
    """Store a result in local cache."""
    cache = load_json_file(CACHE_FILE_PATH)

    cache.setdefault(category, {})
    cache[category][indicator] = result

    save_json_file(CACHE_FILE_PATH, cache)


def get_offline_fallback(
    category: str,
    indicator: str,
) -> dict[str, Any] | None:
    """Return controlled demo fallback result if available."""
    fallback_data = load_json_file(FALLBACK_FILE_PATH)

    return fallback_data.get(category, {}).get(indicator)


def build_ip_result(
    ip_value: str,
    source: str,
    status: str,
    risk_flags: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Create a consistent IP reputation result."""
    return {
        "indicator_type": "ip",
        "indicator": ip_value,
        "source": source,
        "status": status,
        "abuse_confidence_score": 0,
        "total_reports": 0,
        "last_reported_at": "",
        "usage_type": "",
        "isp": "",
        "country_code": "",
        "risk_flags": risk_flags or [],
        "error": "",
        **extra,
    }


def lookup_ip_reputation(ip_value: str) -> dict[str, Any]:
    """
    Query AbuseIPDB for public IP reputation.

    Order:
    1. Local cache
    2. Offline fallback
    3. Real AbuseIPDB API if API key exists
    4. Graceful unavailable result
    """
    ip_value = (ip_value or "").strip()

    if not is_public_ip(ip_value):
        return build_ip_result(
            ip_value,
            source="local_validation",
            status="not_applicable",
            risk_flags=["non_public_or_reserved_ip"],
        )

    cached = get_cached_result("ip_reputation", ip_value)

    if cached:
        cached["source"] = "local_cache"
        return cached

    fallback = get_offline_fallback("ip_reputation", ip_value)

    if fallback:
        result = build_ip_result(
            ip_value,
            source="offline_fallback",
            status="ok",
            **fallback,
        )
        set_cached_result("ip_reputation", ip_value, result)
        return result

    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()

    if not api_key:
        return build_ip_result(
            ip_value,
            source="abuseipdb",
            status="api_key_missing",
            risk_flags=["reputation_not_queried"],
            error="ABUSEIPDB_API_KEY is not configured",
        )

    try:
        response = requests.get(
            ABUSEIPDB_CHECK_URL,
            headers={
                "Key": api_key,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip_value,
                "maxAgeInDays": 90,
                "verbose": "true",
            },
            timeout=get_timeout_seconds(),
        )

        response.raise_for_status()

        payload = response.json().get("data", {})

        abuse_score = int(
            payload.get("abuseConfidenceScore", 0)
        )

        risk_flags: list[str] = []

        if abuse_score >= 75:
            risk_flags.append("high_abuse_confidence")
        elif abuse_score >= 25:
            risk_flags.append("reported_abuse")

        usage_type = payload.get("usageType", "") or ""

        if any(
            term in usage_type.lower()
            for term in {"data center", "hosting", "commercial"}
        ):
            risk_flags.append("hosting_or_datacenter_network")

        result = build_ip_result(
            ip_value,
            source="abuseipdb",
            status="ok",
            risk_flags=risk_flags,
            abuse_confidence_score=abuse_score,
            total_reports=payload.get("totalReports", 0),
            last_reported_at=payload.get("lastReportedAt", "") or "",
            usage_type=usage_type,
            isp=payload.get("isp", "") or "",
            country_code=payload.get("countryCode", "") or "",
        )

        set_cached_result("ip_reputation", ip_value, result)

        return result

    except requests.Timeout:
        return build_ip_result(
            ip_value,
            source="abuseipdb",
            status="timeout",
            risk_flags=["reputation_lookup_timeout"],
            error="AbuseIPDB request timed out",
        )

    except requests.RequestException as error:
        return build_ip_result(
            ip_value,
            source="abuseipdb",
            status="request_error",
            risk_flags=["reputation_lookup_error"],
            error=str(error),
        )

    except ValueError as error:
        return build_ip_result(
            ip_value,
            source="abuseipdb",
            status="invalid_response",
            risk_flags=["reputation_lookup_error"],
            error=str(error),
        )


def build_url_result(
    url: str,
    source: str,
    status: str,
    risk_flags: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Create a consistent URL intelligence result."""
    return {
        "indicator_type": "url",
        "indicator": url,
        "source": source,
        "status": status,
        "threat": "",
        "tags": [],
        "date_added": "",
        "url_status": "",
        "risk_flags": risk_flags or [],
        "error": "",
        **extra,
    }

def lookup_url_reputation(url: str) -> dict[str, Any]:
    """
    Query URLhaus for known malicious URL intelligence.

    This function submits only the URL string to the reputation provider.
    It never opens, fetches, or follows the URL itself.
    """
    normalized_url = normalize_url(url)

    if not normalized_url:
        return build_url_result(
            url,
            source="local_validation",
            status="invalid_url",
            risk_flags=["invalid_url"],
        )

    cached = get_cached_result(
        "url_reputation",
        normalized_url,
    )

    if cached:
        cached["source"] = "local_cache"
        return cached

    fallback = get_offline_fallback(
        "url_reputation",
        normalized_url,
    )

    if fallback:
        result = build_url_result(
            normalized_url,
            source="offline_fallback",
            status="ok",
            **fallback,
        )

        set_cached_result(
            "url_reputation",
            normalized_url,
            result,
        )

        return result

    try:
        response = requests.post(
            URLHAUS_URL_LOOKUP,
            data={"url": normalized_url},
            timeout=get_timeout_seconds(),
        )

        response.raise_for_status()

        payload = response.json()
        query_status = payload.get("query_status", "")

        if query_status == "ok":
            result = build_url_result(
                normalized_url,
                source="urlhaus",
                status="ok",
                threat=payload.get("threat", "") or "",
                tags=payload.get("tags", []) or [],
                date_added=payload.get("date_added", "") or "",
                url_status=payload.get("url_status", "") or "",
                risk_flags=[
                    "known_malicious_url",
                    "urlhaus_match",
                ],
            )

        else:
            result = build_url_result(
                normalized_url,
                source="urlhaus",
                status=query_status or "no_result",
                risk_flags=[],
            )

        set_cached_result(
            "url_reputation",
            normalized_url,
            result,
        )

        return result

    except requests.HTTPError as error:
        status_code = (
            error.response.status_code
            if error.response is not None
            else 0
        )

        if status_code == 401:
            status = "authentication_required"
            flags = [
                "url_reputation_authentication_required"
            ]

        elif status_code == 403:
            status = "access_forbidden"
            flags = [
                "url_reputation_access_forbidden"
            ]

        elif status_code == 429:
            status = "rate_limited"
            flags = [
                "url_reputation_rate_limited"
            ]

        elif 500 <= status_code <= 599:
            status = "provider_unavailable"
            flags = [
                "url_reputation_provider_unavailable"
            ]

        else:
            status = "http_error"
            flags = [
                "url_reputation_lookup_error"
            ]

        return build_url_result(
            normalized_url,
            source="urlhaus",
            status=status,
            risk_flags=flags,
            error=str(error),
            http_status_code=status_code,
        )

    except requests.Timeout:
        return build_url_result(
            normalized_url,
            source="urlhaus",
            status="timeout",
            risk_flags=[
                "url_reputation_lookup_timeout"
            ],
            error="URLhaus request timed out",
        )

    except requests.RequestException as error:
        return build_url_result(
            normalized_url,
            source="urlhaus",
            status="request_error",
            risk_flags=[
                "url_reputation_lookup_error"
            ],
            error=str(error),
        )

    except ValueError as error:
        return build_url_result(
            normalized_url,
            source="urlhaus",
            status="invalid_response",
            risk_flags=[
                "url_reputation_lookup_error"
            ],
            error=str(error),
        )