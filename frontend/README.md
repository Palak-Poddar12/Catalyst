# SatGuard — SIH26106 Frontend

React/Vite frontend for the SIH26106 email threat detection, geolocation and forensic intelligence prototype.

## Included
- Local demo login with saved session and four demo roles.
- Dashboard, EML analysis, Gmail ingestion, cases, case investigation, IOC intelligence, reports.
- 17-feature Advanced Intelligence page.
- Leaflet + OpenStreetMap threat map with demo points; no Google Maps API key.
- Case-level Leaflet map with GeoIP points when backend returns coordinates.
- API base controlled by `VITE_API_BASE_URL`.

## Demo credentials
- `admin / admin123` — National Cyber Admin
- `analyst / analyst123` — Forensic Analyst
- `investigator / invest123` — Investigator
- `viewer / viewer123` — Viewer

These are prototype-only frontend credentials. They are not secure production authentication.

## Run
```bash
npm install
npm run dev
```

For Vercel/Render set:
`VITE_API_BASE_URL=https://YOUR-BACKEND/api/v1`

Leaflet uses public OpenStreetMap tiles. This requires internet access during the demo but no provider API key.
