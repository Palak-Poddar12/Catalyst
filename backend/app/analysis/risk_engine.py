def aggregate_risk(forensic: dict, ml: dict) -> dict:
    forensic_score = float(forensic.get("forensic_score", 0.0))

    if ml.get("status") == "success":
        ml_score = max(0.0, min(float(ml.get("risk_score", 0.0)), 1.0))
        final_score = round((ml_score * 0.70) + (forensic_score * 0.30), 4)
        classification = ml.get("classification", "UNKNOWN")
    else:
        ml_score = 0.0
        final_score = forensic_score
        classification = "FORENSIC_REVIEW_REQUIRED"

    if final_score >= .85:
        level = "CRITICAL"
    elif final_score >= .65:
        level = "HIGH"
    elif final_score >= .40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "classification": classification,
        "forensic_score": forensic_score,
        "final_risk_score": final_score,
        "risk_level": level,
    }
