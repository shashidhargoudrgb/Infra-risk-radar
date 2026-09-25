# NHAI / Bhoomi Rashi — findings and design decision

## What Bhoomi Rashi actually is
Bhoomi Rashi (bhoomirashi.gov.in) is MoRTH's **land acquisition workflow portal** — it
digitizes the 3(a)/3A/3D gazette notification process and pays compensation via PFMS.
Most of it sits behind login at `/auth/revamp/...`. It is not a GIS/mapping service and does
not expose project alignment geometry through a public, unauthenticated API.

## Where real NH alignment geometry actually lives
Per MoRTH's own internal circulars to NHAI/state PWD units, alignment KML/KMZ files are
collected and forwarded to **BISAG-N** for the **PM GatiShakti National Master Plan (NMP)**
portal. That portal is a government-internal GIS system; it is not publicly queryable the way
Telangana's TGRAC ArcGIS service is. As of the most recent circular found, several states had
still not submitted their alignment files.

`data.gov.in`'s NHAI-tagged datasets are static tables transcribed from Parliament Q&A replies
(state-wise totals/counts) — several explicitly state "The API for this resource does not exist."

## Decision
Building an "adapter" against Bhoomi Rashi would mean either (a) scraping an authenticated
portal, which isn't a stable or permitted integration, or (b) geocoding a project name into a
guessed point — exactly what `docs/ACCURACY_AND_DATA_POLICY.md` forbids. Neither is acceptable.

Instead, `backend/server.js` now includes `fetchNationalHighwayReference()`, which pulls **real
NH road geometry from OpenStreetMap** (`ref` tags like `NH44`) along a route. This is genuinely
public and live, and is surfaced on every route result as `nationalHighways[]`. It carries
**no project or construction status** — it only answers "which NH does this route follow, and
what are its exact coordinates."

To actually add an ongoing NH project to the registry:
1. Find a citable official status statement (PIB release, Lok Sabha/Rajya Sabha reply, or
   NHAI's project-transparency releases) for a specific NH section.
2. Call `/api/route-analysis` for a route through that section and read the matching entry in
   `nationalHighways[].segments[].coords` for real coordinates.
3. Fill in `backend/data/nhai-known-projects.template.geojson` with both, and import via
   `/api/projects/import`.

This keeps the same rule the rest of the app already follows: status and geometry must each be
independently sourced, and neither is ever invented to fill in for the other.
