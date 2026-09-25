# SIH26106 — Member 1 + Member 2 Integration

## What was merged
Member 1's forensic engine is now used by the central Member 2 FastAPI backend. The standalone Member 1 FastAPI app, in-memory job store, and Gmail API server are intentionally not used as the central API because PostgreSQL and the separate ML service are the system architecture.

## Forensic engine
`member1_forensic_analyzer.py` remains the main forensic entry point. Its supporting modules live in:
- `auth_checks/`
- `enrichment/`
- `evidence/`
- `parsers/`
- `rules/`

`app/forensics/service.py` writes the uploaded EML to a temporary file, calls Member 1's analyzer, and converts the result through `app/forensics/member1_adapter.py`.

## Pipeline
```
POST /api/v1/emails/upload/{case_id}
        ↓
Member 1 forensic engine
        ↓
normalized findings / IOCs / timeline / graph / ML features
        ↓
separate ML service POST /predict
        ↓
risk aggregation
        ↓
PostgreSQL
        ↓
GET /api/v1/analysis/{analysis_id}
```

## Local run
Terminal 1 (ML):
```powershell
cd ml_service
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001
```

Terminal 2 (backend):
```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
# create .env from .env.example and set DATABASE_URL
uvicorn app.main:app --reload --port 8000
```

Swagger: `http://127.0.0.1:8000/docs`

## First test
1. Create a case with `POST /api/v1/cases`.
2. Upload a `.eml` using `POST /api/v1/emails/upload/{case_id}`.
3. Read the returned `analysis_id`.
4. Call `GET /api/v1/analysis/{analysis_id}`.

## Threat intelligence and GeoIP
Member 1's threat-intelligence code falls back to `backend/data/threat_intel/offline_fallback.json` when appropriate. `ABUSEIPDB_API_KEY` is optional. GeoLite2 databases are not included; without them, GeoIP/ASN fields report `database_missing` rather than breaking the whole analysis.

## Important
The ML service in this repository is still the architecture adapter/placeholder. Replace only `ml_service/app/predictor.py` with the team's real model loading + preprocessing + inference while keeping the `/predict` contract, unless you intentionally update both sides.
