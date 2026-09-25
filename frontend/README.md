# SATGUARD Frontend

React/Vite frontend for SATGUARD — Email Threat Intelligence & Forensics.

## Run locally

```bash
npm install
npm run dev
```

## Render

- Static Site
- Root Directory: `frontend` if this repository contains the app under `frontend/`; otherwise the app directory itself.
- Build Command: `npm install && npm run build`
- Publish Directory: `dist`
- Environment variable: `VITE_API_BASE_URL=https://YOUR-BACKEND.onrender.com/api/v1`

Add an SPA rewrite from `/*` to `/index.html` with action `Rewrite`.

## Frontend-only prototype authentication

Authentication is intentionally independent of the FastAPI backend. The four prototype accounts are defined in `src/utils/auth.js` and determine the frontend role and permissions:

- ADMIN — admin@satguard.local / admin123
- ANALYST — analyst@satguard.local / analyst123
- INVESTIGATOR — investigator@satguard.local / invest123
- VIEWER — viewer@satguard.local / viewer123

There is no role selector. The role is derived from the matched account. `Remember me` stores the selected prototype credentials in localStorage because this is a demo-only authentication mechanism. Do not use these credentials or this authentication implementation for a real production security system.

The frontend uses a local session token only for route protection. It does not send the local prototype token to FastAPI as a bearer token. Backend APIs remain available through `VITE_API_BASE_URL` for investigation data and other features.
