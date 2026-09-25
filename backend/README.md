# SIH26106 Backend

FastAPI orchestration layer for:
React -> FastAPI -> Forensics + ML Service -> PostgreSQL -> Analysis/Reports.

## Local
1. Copy `.env.example` to `.env`.
2. Put your PostgreSQL URL in `DATABASE_URL`.
3. Set `ML_SERVICE_URL` to the running ML API.
4. `python -m venv venv`
5. Activate the venv.
6. `pip install -r requirements.txt`
7. `uvicorn app.main:app --reload`

Swagger: http://127.0.0.1:8000/docs

## Main API
POST /api/v1/cases
GET /api/v1/cases
POST /api/v1/emails/upload/{case_id}
GET /api/v1/analysis/{analysis_id}
GET /api/v1/analysis/case/{case_id}
GET /api/v1/reports/{analysis_id}

## Important
`app/forensics/service.py` contains generic forensic features and an ML feature adapter.
Replace/adapt `ml_features` to the exact feature schema of the real ML model.
Do not import the trained model into this backend if the team architecture requires a separate ML deployment.
