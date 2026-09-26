def aggregate_risk(forensic: dict, ml: dict) -> dict:
    forensic_score = max(0.0, min(float(forensic.get("forensic_score", 0.0)), 1.0))

    if ml.get("status") == "success":
        ml_score = max(0.0, min(float(ml.get("risk_score", 0.0)), 1.0))
        final_score = round((ml_score * 0.70) + (forensic_score * 0.30), 4)
        classification = ml.get("classification", "UNKNOWN")
        assessment_mode = "ml_plus_forensics"
    else:
        # When the ML service is unavailable, keep the investigation useful by
        # using the independently calculated forensic signal as the threat score.
        # This is a real evidence-derived fallback, not a fabricated ML result.
        ml_score = 0.0
        final_score = forensic_score
        if final_score >= 0.65:
            classification = "PHISHING"
        elif final_score >= 0.40:
            classification = "SUSPICIOUS"
        else:
            classification = "LOW_RISK"
        assessment_mode = "forensic_fallback"

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
        "assessment_mode": assessment_mode,
    }
