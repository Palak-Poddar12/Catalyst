# SatGuard / Catalyst — Render Deployment

This package contains the backend and frontend prepared to deploy as two Render services.

## Render services
- Backend: `backend-ie2s`
- Frontend: `catalyst-key6`

## Backend environment
Required:
- `DATABASE_URL` — Render PostgreSQL / Neon / Supabase connection string
- `CORS_ORIGINS` — `https://catalyst-key6.onrender.com`
- `ML_SERVICE_URL` — optional; leave empty if ML service is not deployed yet
- `GMAIL_CLIENT_ID` / `GMAIL_CLIENT_SECRET` — only for Gmail OAuth
- `GMAIL_REDIRECT_URI` — `https://backend-ie2s.onrender.com/api/v1/gmail/callback`

## Frontend environment
`VITE_API_URL=https://backend-ie2s.onrender.com`

## Important
Do not commit `.env`, credentials, Gmail client secrets, database passwords, model weights, or local virtual environments.

The frontend has been aligned with the backend actually present in this package:
- POST `/api/v1/cases`
- POST `/api/v1/emails/upload/{case_id}`
- GET `/api/v1/analysis/{analysis_id}`
- GET `/api/v1/analysis/case/{case_id}`
- GET `/api/v1/reports/{analysis_id}`
- GET `/api/v1/reports/{analysis_id}/pdf`
