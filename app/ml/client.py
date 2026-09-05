import importlib.util
from pathlib import Path
import sys

import httpx
from app.core.config import settings


_local_classifier = None
_local_classifier_path = None


class MLClient:
    def predict(self, features: dict) -> dict:
        if settings.ml_service_url:
            url = settings.ml_service_url.rstrip("/") + "/predict"
            try:
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
                return self._unavailable()

        if settings.ml_model_path:
            try:
                result = self._local_predict(features)
                return {
                    "status": "success",
                    "classification": result["predicted_label"],
                    "risk_score": float(result["nlp_risk_score"]) / 100.0,
                    "confidence": float(result["confidence_score"]),
                    "score_breakdown": result.get("score_breakdown", {}),
                }
            except Exception:
                return self._unavailable()

        return self._unavailable()

    @staticmethod
    def _unavailable() -> dict:
        return {
            "status": "unavailable",
            "classification": "UNKNOWN",
            "risk_score": 0.0,
            "confidence": 0.0,
        }

    @staticmethod
    def _local_predict(features: dict) -> dict:
        global _local_classifier, _local_classifier_path
        if _local_classifier is None or _local_classifier_path != settings.ml_model_path:
            classifier_path = settings.ml_classifier_path
            if not classifier_path:
                classifier_path = str(
                    Path(settings.ml_model_path).resolve().parents[1]
                    / "backend" / "app" / "modules" / "ml" / "nlp_classifier.py"
                )
            module_spec = importlib.util.spec_from_file_location(
                "catalyst_local_nlp_classifier", classifier_path
            )
            if module_spec is None or module_spec.loader is None:
                raise ImportError(f"Unable to load classifier from {classifier_path}")
            module = importlib.util.module_from_spec(module_spec)
            sys.modules[module_spec.name] = module
            module_spec.loader.exec_module(module)

            _local_classifier = module.NLPPhishingClassifier(weights_path=settings.ml_model_path)
            _local_classifier_path = settings.ml_model_path
        return _local_classifier.predict(features.get("text", ""))
