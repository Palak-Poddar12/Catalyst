import httpx
from app.core.config import settings

class MLClient:
    def predict(self, features: dict) -> dict:
        if not settings.ml_service_url:
            return {
                "status": "unavailable",
                "classification": "UNKNOWN",
                "risk_score": 0.0,
                "confidence": 0.0,
                "nlp_risk_score": 0.0,
                "detected_triggers": [],
            }

        try:
            url = settings.ml_service_url.rstrip("/") + "/predict"
            response = httpx.post(
                url,
                json={"features": features},
                timeout=settings.ml_service_timeout,
            )
            response.raise_for_status()
            data = response.json()
            return {
                "status": str(data.get("status", "success")),
                "classification": str(data.get("classification", "UNKNOWN")),
                "risk_score": float(data.get("risk_score", 0.0)),
                "confidence": float(data.get("confidence", 0.0)),
                "nlp_risk_score": float(data.get("nlp_risk_score", 0.0)),
                "detected_triggers": list(data.get("detected_triggers", [])),
                "model": str(data.get("model", "")),
            }
        except Exception as exc:
            return {
                "status": "unavailable",
                "classification": "UNKNOWN",
                "risk_score": 0.0,
                "confidence": 0.0,
                "nlp_risk_score": 0.0,
                "detected_triggers": [],
                "error": str(exc),
            }
