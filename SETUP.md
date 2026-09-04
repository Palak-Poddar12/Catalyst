# SIH26106 — Complete MVP Setup

## Architecture

React Frontend
→ FastAPI Backend
→ Forensic Processing
→ Separate ML Service
→ PostgreSQL
→ Analysis / Reports / Graph JSON

## 1. PostgreSQL

Create a PostgreSQL database online, for example on Render.

Copy its connection URL into `backend/.env`:

DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST/DATABASE?sslmode=require

Do not add `check_same_thread`.

Tables are created by SQLAlchemy on backend startup for this MVP:
- cases
- emails
- analyses
- iocs
- findings

## 2. Run ML

Open terminal in `ml_service`:

Windows:
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001

Check:
http://127.0.0.1:8001/health

IMPORTANT: replace `app/predictor.py` with your real trained ML integration. The included predictor only verifies the architecture.

## 3. Run Backend

Open another terminal in `backend`:

python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

Copy `.env.example` to `.env`.

Set:
DATABASE_URL=...
ML_SERVICE_URL=http://127.0.0.1:8001
CORS_ORIGINS=http://localhost:5173

Run:
uvicorn app.main:app --reload --port 8000

Open:
http://127.0.0.1:8000/docs

## 4. Test

GET /health

POST /api/v1/cases

Then:
POST /api/v1/emails/upload/{case_id}

Then:
GET /api/v1/analysis/{analysis_id}

## 5. Run Frontend

Open terminal in `frontend`:

npm install
copy `.env.example` to `.env`
npm run dev

Open the Vite URL, normally:
http://localhost:5173

## 6. Render

Deploy four resources:

1. PostgreSQL
2. ML service
3. Backend
4. Frontend

ML Render:
Build: pip install -r requirements.txt
Start: uvicorn app.main:app --host 0.0.0.0 --port $PORT

Backend Render:
Build: pip install -r requirements.txt
Start: uvicorn app.main:app --host 0.0.0.0 --port $PORT

Backend environment:
DATABASE_URL=<Render PostgreSQL URL>
ML_SERVICE_URL=https://YOUR-ML-SERVICE.onrender.com
CORS_ORIGINS=https://YOUR-FRONTEND.onrender.com

Frontend environment:
VITE_API_BASE_URL=https://YOUR-BACKEND.onrender.com/api/v1

## 7. Real ML

The only file that must be adapted to the real model is primarily:

ml_service/app/predictor.py

And the exact feature adapter is:

backend/app/forensics/service.py → `ml_features`

The exact model feature schema supplied by the ML team is the source of truth.

Do not claim the placeholder predictor is the team's trained model.

## 8. Important production upgrades

Before final production:
- Alembic migrations
- Authentication/authorization
- Persistent object storage for original EML evidence
- Rate limiting
- audit logging
- secure secrets
- malware-safe attachment handling
- proper async/background jobs for heavy ML/forensics
