from fastapi import APIRouter, HTTPException

from enrichment.dns_intelligence import get_domain_dns_intelligence
from enrichment.geoip_intelligence import enrich_ip_geolocation
from enrichment.threat_intelligence import lookup_ip_reputation, lookup_url_reputation

router = APIRouter(prefix="/intel", tags=["Threat Intelligence"])

@router.get("/ip/{ip_value:path}")
def lookup_ip(ip_value: str):
    ip_value = ip_value.strip()
    if not ip_value:
        raise HTTPException(400, "IP address is required")
    geo = enrich_ip_geolocation(ip_value)
    reputation = lookup_ip_reputation(ip_value)
    return {"ip": ip_value, "geolocation": geo, "reputation": reputation}

@router.get("/domain/{domain:path}")
def lookup_domain(domain: str):
    domain = domain.strip()
    if not domain:
        raise HTTPException(400, "Domain is required")
    return get_domain_dns_intelligence(domain)

@router.get("/url")
def lookup_url(url: str):
    if not url.strip():
        raise HTTPException(400, "URL is required")
    return lookup_url_reputation(url)
