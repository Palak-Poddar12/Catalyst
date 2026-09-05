from __future__ import annotations
import re, time, logging
from dataclasses import dataclass, field
from typing import Optional
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel

logger = logging.getLogger(__name__)
_MAX_LEN = 128

LABEL_MAP = {0: "LEGITIMATE", 1: "PHISHING", 2: "BUSINESS_EMAIL_COMPROMISE", 3: "CREDENTIAL_HARVESTING"}

_CLASS_RISK_BASE = {0: 0.0, 1: 75.0, 2: 90.0, 3: 85.0}

_TRIGGER_PATTERNS = [
    (re.compile(r"\burgent(ly)?\b", re.I), "urgency:urgent"),
    (re.compile(r"\bimmediately\b", re.I), "urgency:immediately"),
    (re.compile(r"\baction required\b", re.I), "urgency:action_required"),
    (re.compile(r"\bwithin\s+\d+\s+hours?\b", re.I), "urgency:time_window"),
    (re.compile(r"\bdeadline\b", re.I), "urgency:deadline"),
    (re.compile(r"\bfinal\s+notice\b", re.I), "urgency:final_notice"),
    (re.compile(r"\bwire\s+transfer\b", re.I), "financial:wire_transfer"),
    (re.compile(r"\bbank\s+account\b", re.I), "financial:bank_account"),
    (re.compile(r"\binvoice\b", re.I), "financial:invoice"),
    (re.compile(r"\bchange\s+of\s+bank\b", re.I), "financial:change_of_bank"),
    (re.compile(r"\bverify\s+your\s+(account|identity|email|password)\b", re.I), "credential:verify_account"),
    (re.compile(r"\bpassword\s+(reset|expired|expiring)\b", re.I), "credential:password_reset"),
    (re.compile(r"\byour\s+account\s+(has\s+been\s+)?(suspended|locked)\b", re.I), "credential:account_locked"),
    (re.compile(r"\bunusual\s+(sign-?in|activity|login)\b", re.I), "credential:unusual_activity"),
    (re.compile(r"\bclaim\s+your\s+(prize|reward|gift)\b", re.I), "phishing:claim_prize"),
    (re.compile(r"\bclick\s+the\s+link\s+below\b", re.I), "phishing:click_link"),
]


def _extract_triggers(text):
    found, seen = [], set()
    for pattern, label in _TRIGGER_PATTERNS:
        if label not in seen and pattern.search(text):
            found.append(label)
            seen.add(label)
    return found


class _TransformerClassifier(nn.Module):
    def __init__(self, encoder, num_labels, dropout=0.2):
        super().__init__()
        self.encoder = encoder
        hidden = encoder.config.hidden_size
        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(hidden, hidden // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden // 2, num_labels),
        )

    def forward(self, input_ids, attention_mask):
        out = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        cls = out.last_hidden_state[:, 0, :]
        return self.classifier(cls)


@dataclass
class ClassificationResult:
    predicted_label: str
    confidence_score: float
    nlp_risk_score: float
    detected_triggers: list = field(default_factory=list)

    def to_dict(self):
        return {
            "predicted_label": self.predicted_label,
            "confidence_score": round(self.confidence_score, 4),
            "nlp_risk_score": round(self.nlp_risk_score, 2),
            "detected_triggers": self.detected_triggers,
        }


class NLPPhishingClassifier:
    """
    Training dataset: Phishing_Email.csv
    Columns: text_combined (input X), label (0=LEGITIMATE, 1=PHISHING)
    Rows: 82,486 | Nulls: 0
    """

    def __init__(self, model_name_or_path="distilbert-base-uncased", weights_path=None, device=None):
        self._device = torch.device(
            device if device else
            ("cuda" if torch.cuda.is_available() else
             "mps" if torch.backends.mps.is_available() else "cpu")
        )
        self._tokenizer = AutoTokenizer.from_pretrained(model_name_or_path)
        encoder = AutoModel.from_pretrained(model_name_or_path)
        if weights_path:
            state = torch.load(weights_path, map_location=self._device, weights_only=True)
            output_bias = state.get("classifier.4.bias")
            if output_bias is None or output_bias.ndim != 1:
                raise ValueError("weights_path does not contain a supported classifier head.")
            num_labels = output_bias.shape[0]
            if num_labels not in (2, len(LABEL_MAP)):
                raise ValueError(f"Unsupported checkpoint label count: {num_labels}.")
        else:
            state = None
            num_labels = len(LABEL_MAP)
        self._model = _TransformerClassifier(encoder=encoder, num_labels=num_labels)
        if state is not None:
            self._model.load_state_dict(state)
            print(f"✅ Weights loaded from {weights_path}")
        else:
            print("⚠️  No weights loaded — using random init (for testing only)")
        self._model.to(self._device)
        self._model.eval()

    def predict(self, text):
        if not isinstance(text, str) or not text.strip():
            return {"predicted_label": "LEGITIMATE", "confidence_score": 1.0,
                    "nlp_risk_score": 0.0, "detected_triggers": []}
        text = re.sub(r"[ \t]+", " ", text.strip())
        label_idx, confidence = self._infer(text)
        triggers = _extract_triggers(text)
        base = _CLASS_RISK_BASE[label_idx]
        risk = max(0.0, min(100.0, base * confidence + min(len(triggers) * 3.0, 15.0)))
        return ClassificationResult(
            predicted_label=LABEL_MAP[label_idx],
            confidence_score=confidence,
            nlp_risk_score=risk,
            detected_triggers=triggers,
        ).to_dict()

    @torch.inference_mode()
    def _infer(self, text):
        enc = self._tokenizer(text, max_length=_MAX_LEN, truncation=True,
                              padding="max_length", return_tensors="pt")
        logits = self._model(enc["input_ids"].to(self._device),
                             enc["attention_mask"].to(self._device))
        probs = torch.softmax(logits, dim=-1).squeeze(0)
        idx = int(probs.argmax().item())
        return idx, float(probs[idx].item())