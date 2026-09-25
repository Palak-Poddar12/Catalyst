from __future__ import annotations

from typing import Any


def _severity(value: Any) -> str:
    value = str(value or "medium").upper()
    return value if value in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "MEDIUM"


def _safe_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _build_findings(raw: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for item in _safe_list(raw.get("forensic_findings")):
        category = str(item.get("category") or "forensic")
        message = str(item.get("message") or "Forensic finding")
        result.append({
            "type": category,
            "title": category.replace("_", " ").title(),
            "description": message,
            "severity": _severity(item.get("severity")),
            "evidence": message,
        })
    return result


def _build_iocs(raw: dict[str, Any]) -> list[dict[str, Any]]:
    indicators = raw.get("indicators") or {}
    result: list[dict[str, Any]] = []

    for item in _safe_list(indicators.get("ips")):
        if isinstance(item, dict) and item.get("ip"):
            flags = item.get("risk_flags") or []
            result.append({
                "type": "IP",
                "value": item["ip"],
                "confidence": 1.0,
                "risk_flags": flags,
                "details": item,
            })

    for item in _safe_list(indicators.get("domains")):
        if isinstance(item, dict):
            value = item.get("domain", "")
            details = item
        else:
            value = str(item)
            details = {"domain": value}
        if value:
            result.append({
                "type": "DOMAIN",
                "value": value,
                "confidence": 1.0,
                "risk_flags": details.get("risk_flags", []),
                "details": details,
            })

    for item in _safe_list(indicators.get("urls")):
        if isinstance(item, dict) and item.get("url"):
            result.append({
                "type": "URL",
                "value": item["url"],
                "confidence": 1.0,
                "risk_flags": item.get("risk_flags", []),
                "details": item,
            })

    for item in _safe_list(indicators.get("attachments")):
        if isinstance(item, dict) and item.get("sha256"):
            result.append({
                "type": "HASH",
                "value": item["sha256"],
                "confidence": 1.0,
                "risk_flags": item.get("risk_flags", []),
                "details": item,
            })

    return result


def _build_features(raw: dict[str, Any], findings: list[dict[str, Any]], iocs: list[dict[str, Any]]) -> dict[str, Any]:
    auth = raw.get("email_authentication") or {}
    reported = auth.get("reported_results") or {}
    independent_spf = auth.get("independent_spf") or {}
    independent_dkim = auth.get("independent_dkim") or {}
    dmarc_assessment = auth.get("dmarc_forensic_assessment") or {}
    identity = (raw.get("sender_identity") or {}).get("analysis") or {}
    indicators = raw.get("indicators") or {}
    urls = _safe_list(indicators.get("urls"))
    ips = _safe_list(indicators.get("ips"))
    domains = _safe_list(indicators.get("domains"))
    attachments = _safe_list(indicators.get("attachments"))
    relay = raw.get("relay_analysis") or {}
    hops = _safe_list(relay.get("received_hops"))

    def has_flag(items):
        return any(bool((x or {}).get("risk_flags")) for x in items if isinstance(x, dict))

    return {
        "spf_failed": reported.get("spf") == "fail" or independent_spf.get("status") == "fail",
        "dkim_failed": reported.get("dkim") == "fail" or independent_dkim.get("status") == "fail",
        "dmarc_failed": reported.get("dmarc") == "fail" or dmarc_assessment.get("assessment") == "likely_fail",
        "from_reply_to_mismatch": "from_reply_to_domain_mismatch" in identity.get("risk_flags", []),
        "identity_anomaly": bool(identity.get("risk_flags")),
        "suspicious_url": has_flag(urls),
        "suspicious_ip": has_flag(ips),
        "suspicious_domain": has_flag([x for x in domains if isinstance(x, dict)]) or any(
            str(f.get("category", "")) == "domain_dns"
            and str(f.get("severity", "")).lower() in {"medium", "high", "critical"}
            for f in _safe_list(raw.get("forensic_findings")) if isinstance(f, dict)
        ),
        "suspicious_attachment": has_flag(attachments),
        "url_count": len(urls),
        "ip_count": len(ips),
        "domain_count": len(domains),
        "attachment_count": len(attachments),
        "relay_hop_count": len(hops),
        "finding_count": len(findings),
    }


def _forensic_score(features: dict[str, Any]) -> float:
    weights = {
        "spf_failed": 0.15,
        "dkim_failed": 0.15,
        "dmarc_failed": 0.20,
        "from_reply_to_mismatch": 0.15,
        "identity_anomaly": 0.10,
        "suspicious_url": 0.10,
        "suspicious_ip": 0.05,
        "suspicious_domain": 0.05,
        "suspicious_attachment": 0.05,
    }
    return round(min(sum(weight for key, weight in weights.items() if features.get(key)), 1.0), 4)


def normalize_member1_result(raw: dict[str, Any]) -> dict[str, Any]:
    findings = _build_findings(raw)
    iocs = _build_iocs(raw)
    features = _build_features(raw, findings, iocs)
    score = _forensic_score(features)

    relay = raw.get("relay_analysis") or {}
    timeline = [
        {"event": "received_hop", "value": hop}
        for hop in _safe_list(relay.get("received_hops"))
    ]
    metadata = raw.get("message_metadata") or {}
    if metadata.get("date"):
        timeline.insert(0, {"event": "email_date", "value": metadata["date"]})

    sender = raw.get("sender_identity") or {}
    sender_from = sender.get("from") or {}
    nodes = []
    edges = []
    if sender_from.get("email_address"):
        nodes.append({"id": "sender", "type": "email", "label": sender_from["email_address"]})
    for idx, item in enumerate(iocs):
        node_id = f"ioc_{idx}"
        nodes.append({"id": node_id, "type": item["type"].lower(), "label": item["value"]})
        if nodes and any(n["id"] == "sender" for n in nodes):
            edges.append({"source": "sender", "target": node_id, "relationship": "contains_ioc"})

    return {
        "forensic_score": score,
        "findings": findings,
        "iocs": iocs,
        "timeline": timeline,
        "graph": {"nodes": nodes, "edges": edges},
        "ml_features": features,
    }
