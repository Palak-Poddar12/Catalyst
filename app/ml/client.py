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
                "status": "success",
                "classification": str(data["classification"]),
                "risk_score": float(data.get("risk_score", data.get("confidence", 0.0))),
                "confidence": float(data.get("confidence", 0.0)),
            }
        except Exception:
            return {
                "status": "unavailable",
                "classification": "UNKNOWN",
                "risk_score": 0.0,
                "confidence": 0.0,
            }
