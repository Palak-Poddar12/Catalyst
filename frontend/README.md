# SATGUARD Frontend

Production-oriented React/Vite frontend for the SATGUARD email threat intelligence and digital-forensics platform.

## Run

```bash
npm install
cp .env.example .env
npm run dev
```

Set `VITE_API_BASE_URL` to the existing FastAPI base URL. The frontend does not hardcode a Render backend URL.

## Build

```bash
npm run build
npm run preview
```

## Backend contract

API calls are centralized under `src/api/` and target the existing route families:

- `/cases`
- `/emails`
- `/analysis`
- `/reports`
- `/intel`
- `/gmail`
- `/advanced`
- `/auth`
- `/admin`

The UI intentionally does not fabricate threat-intelligence or forensic evidence. Empty/loading/error states are shown when the backend does not return data.

## Demo accounts

- ADMIN — `admin@satguard.local` / `admin123`
- ANALYST — `analyst@satguard.local` / `analyst123`
- INVESTIGATOR — `investigator@satguard.local` / `invest123`
- VIEWER — `viewer@satguard.local` / `viewer123`

The login page does not offer role selection; these credentials are convenience buttons for a prototype environment and authentication is still delegated to the backend.
