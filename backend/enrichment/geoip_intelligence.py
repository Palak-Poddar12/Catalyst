from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import geoip2.database
import geoip2.errors


BASE_DIR = Path(__file__).resolve().parent.parent

CITY_DATABASE_PATH = (
    BASE_DIR / "data" / "geoip" / "GeoLite2-City.mmdb"
)

ASN_DATABASE_PATH = (
    BASE_DIR / "data" / "geoip" / "GeoLite2-ASN.mmdb"
)


def classify_ip_for_lookup(ip_value: str) -> str:
    """
    Decide whether an IP can be safely looked up in GeoLite2.

    GeoIP lookups are only meaningful for a public, globally routable address.
    """
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        return "invalid"

    documentation_networks = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32"),
    ]

    if any(ip in network for network in documentation_networks):
        return "documentation"

    if ip.is_loopback:
        return "loopback"

    if ip.is_private:
        return "private"

    if ip.is_link_local:
        return "link_local"

    if ip.is_multicast:
        return "multicast"

    if ip.is_reserved:
        return "reserved"

    if ip.is_unspecified:
        return "unspecified"

    return "public"


def database_status() -> dict[str, Any]:
    """Return database availability information for diagnostics."""
    return {
        "city_database_path": str(CITY_DATABASE_PATH),
        "city_database_found": CITY_DATABASE_PATH.exists(),
        "asn_database_path": str(ASN_DATABASE_PATH),
        "asn_database_found": ASN_DATABASE_PATH.exists(),
    }


def get_city_intelligence(ip_value: str) -> dict[str, Any]:
    """Get approximate geographic context from GeoLite2-City."""
    result = {
        "country": "",
        "country_iso_code": "",
        "subdivision": "",
        "city": "",
        "postal_code": "",
        "latitude": None,
        "longitude": None,
        "accuracy_radius_km": None,
        "timezone": "",
        "city_lookup_status": "not_queried",
        "city_lookup_error": "",
    }

    if not CITY_DATABASE_PATH.exists():
        result["city_lookup_status"] = "database_missing"
        result["city_lookup_error"] = (
            f"GeoLite2 City database not found: {CITY_DATABASE_PATH}"
        )
        return result

    try:
        with geoip2.database.Reader(CITY_DATABASE_PATH) as reader:
            response = reader.city(ip_value)

        result.update({
            "country": response.country.name or "",
            "country_iso_code": response.country.iso_code or "",
            "subdivision": (
                response.subdivisions.most_specific.name or ""
            ),
            "city": response.city.name or "",
            "postal_code": response.postal.code or "",
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
            "accuracy_radius_km": response.location.accuracy_radius,
            "timezone": response.location.time_zone or "",
            "city_lookup_status": "ok",
        })

    except geoip2.errors.AddressNotFoundError:
        result["city_lookup_status"] = "address_not_found"

    except Exception as error:
        result["city_lookup_status"] = "lookup_error"
        result["city_lookup_error"] = str(error)

    return result


def get_asn_intelligence(ip_value: str) -> dict[str, Any]:
    """Get ASN and network organization from GeoLite2-ASN."""
    result = {
        "asn": None,
        "asn_organization": "",
        "network": "",
        "asn_lookup_status": "not_queried",
        "asn_lookup_error": "",
    }

    if not ASN_DATABASE_PATH.exists():
        result["asn_lookup_status"] = "database_missing"
        result["asn_lookup_error"] = (
            f"GeoLite2 ASN database not found: {ASN_DATABASE_PATH}"
        )
        return result

    try:
        with geoip2.database.Reader(ASN_DATABASE_PATH) as reader:
            response = reader.asn(ip_value)

        result.update({
            "asn": response.autonomous_system_number,
            "asn_organization": (
                response.autonomous_system_organization or ""
            ),
            "network": str(response.network) if response.network else "",
            "asn_lookup_status": "ok",
        })

    except geoip2.errors.AddressNotFoundError:
        result["asn_lookup_status"] = "address_not_found"

    except Exception as error:
        result["asn_lookup_status"] = "lookup_error"
        result["asn_lookup_error"] = str(error)

    return result


def enrich_ip_geolocation(ip_value: str) -> dict[str, Any]:
    """
    Enrich a single IP with approximate location and ASN context.

    This function does not identify a person, household, or confirmed attacker.
    """
    ip_scope = classify_ip_for_lookup(ip_value)

    base_result = {
        "ip": ip_value,
        "ip_scope": ip_scope,
        "lookup_performed": False,
        "country": "",
        "country_iso_code": "",
        "subdivision": "",
        "city": "",
        "postal_code": "",
        "latitude": None,
        "longitude": None,
        "accuracy_radius_km": None,
        "timezone": "",
        "asn": None,
        "asn_organization": "",
        "network": "",
        "city_lookup_status": "not_queried",
        "asn_lookup_status": "not_queried",
        "risk_flags": [],
        "limitation": (
            "IP geolocation estimates network infrastructure context. "
            "It does not prove a person's identity or exact physical location."
        ),
    }

    if ip_scope != "public":
        base_result["risk_flags"].append(
            f"geoip_not_applicable_{ip_scope}"
        )
        return base_result

    city_result = get_city_intelligence(ip_value)
    asn_result = get_asn_intelligence(ip_value)

    base_result.update(city_result)
    base_result.update(asn_result)
    base_result["lookup_performed"] = True

    organization = base_result["asn_organization"].lower()

    cloud_keywords = {
        "amazon",
        "google",
        "microsoft",
        "cloudflare",
        "digitalocean",
        "ovh",
        "hetzner",
        "linode",
        "vultr",
        "oracle",
    }

    if any(keyword in organization for keyword in cloud_keywords):
        base_result["risk_flags"].append("cloud_hosting_infrastructure")

    return base_result


def enrich_ip_list(ip_addresses: list[str]) -> list[dict[str, Any]]:
    """Enrich unique IPs while maintaining original order."""
    seen: set[str] = set()
    enriched: list[dict[str, Any]] = []

    for ip_value in ip_addresses:
        normalized_ip = (ip_value or "").strip()

        if not normalized_ip or normalized_ip in seen:
            continue

        seen.add(normalized_ip)
        enriched.append(enrich_ip_geolocation(normalized_ip))

    return enriched