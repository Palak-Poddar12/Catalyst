# REPLACE THIS ADAPTER WITH YOUR REAL ML TEAM MODEL.
#
# The backend/ML boundary is stable:
# POST /predict
# {"features": {...}}
#
# Your actual model may require a scaler/vectorizer/encoder.
# Load those artifacts here and preserve the team's preprocessing.

class Predictor:
    def status(self):
        return "adapter_ready"

    def predict(self, features: dict):
        # Development-only placeholder so the service can be tested end-to-end.
        # It must be replaced with the real model inference before final SIH demo.
        weights = {
            "suspicious_subject": 0.20,
            "contains_url": 0.20,
            "urgent_language": 0.15,
            "authentication_failure": 0.25,
            "reply_to_mismatch": 0.15,
            "has_attachment": 0.05,
        }
        score = min(sum(
            weight for key, weight in weights.items() if bool(features.get(key))
        ), 1.0)

        if score >= 0.70:
            label = "PHISHING"
        elif score >= 0.40:
            label = "SUSPICIOUS"
        else:
            label = "LEGITIMATE"

        return {
            "classification": label,
            "risk_score": round(score, 4),
            "confidence": round(score, 4),
        }

predictor = Predictor()
