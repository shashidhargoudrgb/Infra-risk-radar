# Infra Risk Radar — SIH 2026 Problem Statement 26103

AI-Powered Infrastructure Project Conflict & Dependency Risk Radar

## What this version fixes

- India-wide route analysis: any Indian place → any Indian place.
- Actual driving route geometry using OSRM.
- India-only geocoding using Nominatim.
- Exact spatial matching against verified Point/LineString/MultiLineString project geometry.
- `<=500 m` = On / overlapping route; `500 m–2 km` = Near route; `>2 km` = hidden.
- OSM mapped-construction discovery with a second Overpass endpoint fallback.
- No project is route-matched from a district name, tender, project name or guessed coordinate.
- No fabricated progress, cost, risk or completion values for route evidence.
- GIS Data & Sources page for controlled GeoJSON import.
- Add Project page now asks for verified coordinates before a project becomes route-eligible.
- Route-result caching reduces repeated external API calls during a demo.
- Verified registry validation script and schema/template included.

## Exact folder

```text
Infra_Risk_Radar_SIH_26103_Final/
├── backend/
│   ├── server.js
│   ├── package.json
│   ├── .env.example
│   ├── schema.sql
│   └── data/
│       ├── verified-projects.geojson
│       ├── verified-projects.template.geojson
│       ├── verified-projects.README.txt
│       └── project-import.schema.json
├── frontend/
│   ├── index.html
│   ├── package.json
│   ├── .env.example
│   ├── vite.config.js
│   └── src/
│       ├── main.jsx
│       └── styles.css
├── scripts/
│   └── validate-registry.mjs
├── docs/
│   └── ARCHITECTURE.md
├── setup.bat
├── start-all.bat
├── start-backend.bat
├── start-frontend.bat
├── README.md
├── README_RUN.txt
└── .gitignore
```

## Run on Windows

1. Install Node.js 18+.
2. Open this folder in VS Code.
3. Run `setup.bat` once.
4. Run `start-all.bat`.
5. Open `http://localhost:3000/login`.

There are no built-in production credentials. Use Register to create a local project-officer account for this deployment.

## Route workflow

Example only: `Any Indian place → Any Indian place`

```text
Kamareddy + Lingampet
        ↓
Nominatim (India-only geocoding)
        ↓
OSRM driving route
        ↓
Full route GeoJSON
        ↓
2 km corridor
   ┌──────────────┐
   │ Verified GIS  │
   │ OSM mapped    │
   └──────────────┘
        ↓
Spatial distance test
        ↓
≤500m / 500m–2km / >2km
        ↓
Map markers + project details + source evidence
```

## Important data truth

The official MoSPI/IPMD public dashboard is the PAIMANA monitoring context. MoSPI's site now also points users to the current PAIMANA site at https://paimana-proj.mospi.gov.in/. Its current public dashboard snapshot shows 1,981 ongoing projects, revised cost ₹42.78 lakh crore and cumulative expenditure ₹20.36 lakh crore as of April 2026. The April 2026 official flash report also states 17 Central Ministries/Departments and 55 projects newly brought under PAIMANA monitoring during the month. The public project table does not itself constitute a universal all-India GIS layer. Therefore this application deliberately requires verified geometry for exact route conflicts.

OSM is used only as mapped-construction evidence. It is not treated as official government progress. Tender listings are not treated as proof of active construction.

## Import verified GIS

Use the **GIS Data & Sources** page or:

`POST /api/projects/import`

Accepted body:
- GeoJSON FeatureCollection
- array of project records
- `{ "projects": [...] }`

Each route-eligible record must contain verified Point, LineString or MultiLineString geometry. The server sets `routeEligible=true` and `sourceVerified=true` only through the controlled import flow.

Run the registry validator:

```bash
node scripts/validate-registry.mjs
```

## Production deployment

The frontend can be deployed separately from the Node backend. Set `VITE_API_URL` to the deployed backend URL. Keep the backend behind a proper rate-limited production proxy and replace public Nominatim/Overpass/OSRM services with approved/hosted infrastructure for high-volume use.

## SIH positioning

This is an intelligence layer on top of PAIMANA-style monitoring, not a replacement for PAIMANA. The route module adds geospatial conflict/dependency discovery; the predictive modules add early warning, EVM, cost/time risk and recommended actions.

The statistical-vs-ML metrics in the prototype are illustrative. A final SIH claim of model performance must be trained and validated against an authorized historical project dataset with a proper train/test split.

## Real-world data mode (v5)

The default build is now **source-backed mode**, not demo mode.

- `DEMO_MODE=false` on the backend and `VITE_DEMO_MODE=false` on the frontend.
- Demo route fixtures are excluded from route results unless demo mode is explicitly enabled.
- `POST /api/paimana/sync` fetches the current public PAIMANA dashboard and imports official project metadata into the server project register.
- PAIMANA metadata is **not** converted into fake map coordinates. Exact route matching still requires authoritative Point/LineString/MultiLineString GIS geometry.
- `POST /api/projects/import` is the controlled route-GIS import endpoint. Records must carry `sourceVerified=true` and a real `sourceUrl`.
- User-created projects are stored in the project register but are **not** automatically route-eligible. This prevents a typed latitude/longitude from being presented as government-verified GIS.
- OpenStreetMap construction features are displayed separately as mapped evidence and are never presented as official government progress.

### Example: Kamareddy → Lingampet

The route engine can calculate the road route between these locations. It will show only:
1. independently verified project geometries inside the 2 km corridor, and
2. separately labelled OSM construction features when available.

A tender notice, project name, district name or geocoded place name alone is not enough to claim that a project is physically ongoing at an exact point. This is intentional and is required for a defensible real-world implementation.

### PAIMANA scope

MoSPI states that IPMD monitors Central Sector infrastructure projects of ₹150 crore and above and captures implementation, financial, schedule and slippage information through OCMS/PAIMANA. The public dashboard currently exposes portfolio/project metadata, but it is not a universal national GIS layer. The application therefore treats PAIMANA as the official monitoring source and the verified GIS registry as the geographic route layer.

### Production deployment note

For an actual government/enterprise deployment, move the server-side JSON persistence to a managed PostgreSQL/MySQL database and host OSRM/Overpass/Nominatim or use approved internal equivalents. Add authenticated source connectors for departmental GIS, PAIMANA/authorized feeds and state project systems. Do not scrape protected/internal systems without authorization.

### Telangana official GIS adapter

For Telangana routes, the backend now queries the Telangana TGRAC Roads & Buildings ArcGIS service for the **Ongoing Road** and **Proposed Road** layers and spatially matches those geometries to the selected route corridor. This is source-backed state GIS data, not a fabricated point. The adapter is intentionally state-specific; additional Indian states/UTs and Central agencies can be added as separate official GIS adapters without changing the India-wide route engine. See docs/NATIONAL_COVERAGE.md.

## Real-world route impact vs live traffic

The Map & Conflict page is now India-wide and uses a 5 km route corridor. It combines verified government GIS, PAIMANA project metadata, and OpenStreetMap mapped construction evidence. The route impact score and added-delay estimate are infrastructure-impact forecasts. They are deliberately not labelled as Google-style live traffic because this build does not have a licensed live-traffic speed feed. See `docs/TRAFFIC_MODEL.md` for the production integration path.

## v6.0 government-work accuracy update
- Telangana R&B/TGRAC official ongoing and proposed road GIS is queried at runtime.
- Ongoing route matching uses official geometry rather than tender-title text.
- Tender/eProcurement sources are explicitly separated from physical construction status.
- Route construction sampling was tightened to 2 km so the full corridor is checked more safely.
- Official road ID, district, mandal and chainage fields are retained when supplied by TGRAC.
- Added `/api/work-sources` and `docs/GOVERNMENT_WORK_DATA_PIPELINE.md`.

## Fast routing fix
- Initial route calculation no longer waits for OpenStreetMap/Overpass.
- OSRM requests one primary driving route with full GeoJSON geometry but without heavy steps/annotations/alternative-route calculations.
- OSM construction lookup runs separately through POST `/api/route-osm`.
- An Overpass timeout can no longer make the route-analysis request fail or make the user wait for the routing response.
- OSM remains supplementary evidence; official/state GIS and government records are handled independently.

## Route Analysis: real-first minimum 5 display

Route Analysis prioritizes real geographically matched project records. When fewer than five real records are available for a selected corridor, clearly labelled `DEMO / SIMULATED` cards are placed along the actual route until five project cards are available. Demo records are excluded from verified-project counts and route-impact evidence scoring.
