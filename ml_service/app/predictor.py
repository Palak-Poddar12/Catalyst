from __future__ import annotations

import os
import threading
from pathlib import Path

from app.model.nlp_classifier import NLPPhishingClassifier


class Predictor:
    """Singleton real NLP inference adapter for the SIH26106 ML service."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._classifier: NLPPhishingClassifier | None = None
        self._error: str | None = None
        bundled_weights = Path(__file__).resolve().parents[1] / "models" / "best_model.pt"
        configured_weights = os.getenv("MODEL_WEIGHTS_PATH")
        self._weights_path = str(
            Path(configured_weights)
            if configured_weights and Path(configured_weights).is_file()
            else bundled_weights
        )
        self._model_name = os.getenv("MODEL_NAME", "distilbert-base-uncased")
        self._load()

    def _load(self) -> None:
        if not Path(self._weights_path).is_file():
            self._error = (
                f"Real ML weights not found at {self._weights_path}. "
                "Download best_model.pt and place it there, or set MODEL_WEIGHTS_PATH."
            )
            return

        try:
            with self._lock:
                self._classifier = NLPPhishingClassifier(
                    model_name_or_path=self._model_name,
                    weights_path=self._weights_path,
                    device=os.getenv("MODEL_DEVICE") or None,
                )
            self._error = None
        except Exception as exc:
            self._classifier = None
            self._error = f"ML model failed to load: {exc}"

    def status(self) -> dict:
        return {
            "loaded": self._classifier is not None,
            "weights_path": self._weights_path,
            "model": self._model_name,
            "error": self._error,
        }

    def predict(self, features: dict) -> dict:
        if self._classifier is None:
            raise RuntimeError(self._error or "ML model is not loaded")

        text = str(features.get("email_text") or "")
        result = self._classifier.predict(text)

        # Central backend stores risk scores on a 0..1 scale.
        nlp_risk = float(result["nlp_risk_score"]) / 100.0
        return {
            "classification": result["predicted_label"],
            "risk_score": round(max(0.0, min(1.0, nlp_risk)), 4),
            "confidence": float(result["confidence_score"]),
            "nlp_risk_score": float(result["nlp_risk_score"]),
            "detected_triggers": result["detected_triggers"],
            "model": self._model_name,
            "status": "success",
        }


predictor = Predictor()
