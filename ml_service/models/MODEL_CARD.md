# PS106 — NLP Phishing Classifier — Model Card

> Member 3 handoff document for Member 2 (Backend API).
> Read this before integrating the model into FastAPI.

---

## Model Summary

| Field | Value |
|---|---|
| Base model | distilbert-base-uncased |
| Task | Binary phishing email classification |
| Classes | 0 = LEGITIMATE, 1 = PHISHING |
| Max input tokens | 256 |
| Inference latency | < 100ms on CPU |
| Weights file | best_model.pt (254.3 MB) |

---

## Performance Metrics

See `eval_report.json` for exact numbers after training.

| Metric | Target | Achieved |
|---|---|---|
| Validation Macro F1 | > 0.92 | see eval_report.json |
| False Negative Rate | < 5% | see eval_report.json |
| Independent Test F1 | > 0.88 | see independent_test_report.json |
| Stress Test F1 | > 0.80 | see stress_test_report.json |

---

## How to Load the Model

```python
from backend.app.modules.ml.nlp_classifier import NLPPhishingClassifier

# Load once at app startup — NOT per request
clf = NLPPhishingClassifier(
    weights_path="models/best_model.pt"
)
```

---

## How to Run Inference

```python
result = clf.predict("Your account has been suspended. Click here immediately.")

print(result)
# {
#   "predicted_label"  : "PHISHING",
#   "confidence_score" : 0.9341,
#   "nlp_risk_score"   : 84.2,
#   "detected_triggers": ["urgency:urgent", "credential:account_locked"]
# }
```

---

## Input Format

| Field | Type | Description |
|---|---|---|
| text | str | Raw email body — plain text or HTML stripped |

- Empty string or None → returns LEGITIMATE with risk 0.0 (safe fallback)
- Text longer than 256 tokens → automatically truncated
- No preprocessing needed — model handles it internally

---

## Output Format

| Field | Type | Range | Description |
|---|---|---|---|
| predicted_label | str | 4 values | Classification result |
| confidence_score | float | 0.0 – 1.0 | Softmax probability of winning class |
| nlp_risk_score | float | 0.0 – 100.0 | Composite risk score |
| detected_triggers | list[str] | — | Matched red flag patterns |

### predicted_label values

| Label | Meaning | Typical risk score |
|---|---|---|
| LEGITIMATE | Safe, benign email | 0 – 15 |
| PHISHING | Standard phishing attack | 60 – 85 |
| BUSINESS_EMAIL_COMPROMISE | Payment diversion / fake invoice | 75 – 100 |
| CREDENTIAL_HARVESTING | Login or password theft attempt | 70 – 95 |

### nlp_risk_score thresholds (recommended)

| Score | Action |
|---|---|
| 0 – 33 | Allow — low risk |
| 34 – 66 | Flag for review — medium risk |
| 67 – 100 | Block / alert — high risk |

---

## FastAPI Integration Example

```python
from fastapi import FastAPI
from pydantic import BaseModel
from backend.app.modules.ml.nlp_classifier import NLPPhishingClassifier
import time

app = FastAPI()

# Singleton — load once at startup
clf = NLPPhishingClassifier(weights_path="models/best_model.pt")

class EmailRequest(BaseModel):
    email_text: str

@app.post("/api/analyze")
def analyze_email(req: EmailRequest):
    t0     = time.perf_counter()
    result = clf.predict(req.email_text)
    result["processing_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return result
```

---

## Required pip Packages

```
torch>=2.2.0
transformers>=4.40.0
scikit-learn>=1.4.0
pandas>=2.0.0
```

Install:
```bash
pip install -r requirements.txt
```

---

## Known Limitations

1. **Binary training** — model was trained on 2 classes (LEGITIMATE / PHISHING).
   BEC and CREDENTIAL_HARVESTING labels come from the rule-based trigger layer,
   not from separate training data. Confidence for these two classes may be lower.

2. **Text only** — model does not see email headers, attachments, or URLs directly.
   Pass the full body text including any header strings for best results.

3. **Max 256 tokens** — very long emails are truncated. The most important
   signals (urgency cues, financial terms) usually appear early in the body.

4. **Language** — trained on English emails only. Non-English emails will
   produce unreliable results.

---

## Files Checklist for Member 2

```
[✓] models/best_model.pt              — download from Drive (see DOWNLOAD_WEIGHTS.md)
[✓] models/MODEL_CARD.md              — this file
[✓] models/predict_example.py         — run to verify setup
[✓] models/eval_report.json           — validation metrics
[✓] models/independent_test_report.json
[✓] models/stress_test_report.json
[✓] backend/app/modules/ml/nlp_classifier.py
```

---

## Contact

Any model-related issues → Member 3 (ML & Architecture)
API integration issues   → Member 2 (Backend API)
