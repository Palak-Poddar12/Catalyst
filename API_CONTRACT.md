# SIH26106 API Contract

## Backend

GET /
GET /health

POST /api/v1/cases
GET /api/v1/cases
GET /api/v1/cases/{case_id}

POST /api/v1/emails/upload/{case_id}

GET /api/v1/analysis/{analysis_id}
GET /api/v1/analysis/case/{case_id}

GET /api/v1/reports/{analysis_id}

## ML

GET /health

POST /predict

Request:
{
  "features": {}
}

Response:
{
  "classification": "PHISHING",
  "risk_score": 0.94,
  "confidence": 0.94
}

The exact feature object must be changed to the real ML team's model contract.
