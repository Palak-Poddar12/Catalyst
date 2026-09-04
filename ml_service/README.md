# SIH26106 ML Service

Independent FastAPI inference service.

## Contract
POST /predict

Request:
{"features": {...}}

Response:
{"classification":"PHISHING","risk_score":0.94,"confidence":0.94}

## Replace predictor
Put the team's real model loading/preprocessing/inference in `app/predictor.py`.
Do not change the API contract unless the backend adapter is updated too.
