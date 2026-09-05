"""
PS106 — Model Verification Script
Run this to confirm best_model.pt loaded correctly.

Usage:
  python models/predict_example.py

Expected: 3 predictions printed with non-random, sensible results.
Only imports nlp_classifier.py — no training pipeline required.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.app.modules.ml.nlp_classifier import NLPPhishingClassifier

WEIGHTS_PATH = os.path.join(os.path.dirname(__file__), "best_model.pt")

# ── Load model ────────────────────────────────────────────────────────────────

print("Loading NLPPhishingClassifier...")
clf = NLPPhishingClassifier(weights_path=WEIGHTS_PATH)
print("Model loaded.\n")

# ── Test emails ───────────────────────────────────────────────────────────────

TEST_EMAILS = [
    (
        "LEGITIMATE",
        "Hi team, just a reminder that our weekly standup is tomorrow at 10am. "
        "Please come prepared with your updates. See you all there.",
    ),
    (
        "PHISHING",
        "URGENT: Your account has been suspended due to unusual activity. "
        "Click the link below immediately to verify your identity and restore access. "
        "Failure to act within 24 hours will result in permanent account closure.",
    ),
    (
        "BEC / Payment Diversion",
        "Dear Finance Team, please be advised that our bank account details have changed. "
        "Kindly update your records and send the pending invoice payment of $48,500 "
        "via wire transfer to the new account number provided below. This is urgent.",
    ),
    (
        "CREDENTIAL HARVESTING",
        "Your Microsoft 365 password has expired. "
        "Please confirm your login credentials by clicking here to avoid losing access "
        "to your email and files. This verification is required immediately.",
    ),
    (
        "EMPTY INPUT (edge case)",
        "",
    ),
]

# ── Run predictions ───────────────────────────────────────────────────────────

print("=" * 60)
for expected, body in TEST_EMAILS:
    result = clf.predict(body)
    print(f"Expected : {expected}")
    print(f"  predicted_label   : {result['predicted_label']}")
    print(f"  confidence_score  : {result['confidence_score']}")
    print(f"  nlp_risk_score    : {result['nlp_risk_score']}")
    print(f"  detected_triggers : {result['detected_triggers']}")
    print()

print("=" * 60)
print("✅ predict_example.py ran successfully.")
print("   If predictions look sensible — handoff to Member 2 is cleared.")
