# SatGuard Map + Responsive Update

## Map implementation
- Added a dedicated `/map` Infrastructure & Origin Map route.
- Replaced the dashboard infrastructure placeholder with the real Leaflet map.
- Uses existing FastAPI analysis data and `/intel/ip/{ip}`-compatible data structures.
- Maps public IP/relay geolocation when latitude/longitude are available.
- Highlights suspicious infrastructure and probable origin context.
- Draws relay relationships as dashed lines when multiple geolocated points belong to the same analysis.
- Popups show IP, city/region/country, ASN, provider, accuracy radius and risk context.
- Includes a clear infrastructure-geolocation disclaimer.

## Important backend requirement
The backend already supports GeoLite2 City/ASN lookup, but the project documentation says the `.mmdb` databases are not included. For real coordinates, provide:
- `backend/data/geoip/GeoLite2-City.mmdb`
- `backend/data/geoip/GeoLite2-ASN.mmdb`

Without those files the UI intentionally does not invent real coordinates; it shows that no geolocated public IPs are available.

## Responsive update
- Map height adapts for desktop/tablet/mobile.
- Map controls, legend, stats and toolbar wrap on narrow screens.
- Dashboard grids collapse cleanly.
- Tables remain locally horizontally scrollable instead of causing page overflow.
- Header actions and page headers wrap on tablet/mobile.
- 320–380px layouts use single-column cards where needed.
