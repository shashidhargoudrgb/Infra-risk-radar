# India-wide dynamic route project detection

The route engine is now **source-driven, not KMR→Lingampet hard-coded**.

## Route flow
1. From/To are geocoded inside India.
2. OSRM calculates the primary driving route.
3. A 2 km corridor is evaluated using route-to-project geometry distance.
4. Exact matches come from:
   - imported verified government GIS geometry;
   - state GIS adapters (Telangana adapter included; more can be configured);
   - `government-work-records.geojson` records with source coordinates/geometry;
   - OSM mapped construction as supplementary evidence.
5. PAIMANA public portfolio data is refreshed/cached and route-locality candidates are shown separately when only project-name/location evidence exists.

## Accuracy rule
A PAIMANA project-name match is **not** presented as exact GIS placement. It is a `monitoring candidate` until authoritative project geometry is imported.

## KMR → Lingampet
The three KMR/Lingampet government work records are now seed records in the generic government-work registry. The route engine matches them by geometry; there is no `if (KMR && Lingampet)` condition.

## Extending to all India
Add official state/department GIS feeds or project GeoJSON records to the registry/adapters. The route matcher itself is already national and does not require a route-specific code path.

Bharat Maps provides national base GIS layers, but it is not a universal live project-status database. PAIMANA provides national central-sector project monitoring data but does not guarantee universal project GIS geometry. Therefore the UI keeps source and location precision explicit.
