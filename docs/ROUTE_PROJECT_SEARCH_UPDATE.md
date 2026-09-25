# Route Project Search Update — SIH 26103

## What changed

- Every **Find Route** request performs a fresh route and project-source lookup; previous route results are not reused.
- OSRM requests `overview=full&geometries=geojson`, so matching uses the complete driving-route geometry rather than a straight line.
- Official/verified project geometry is matched within **2 km** of the complete route.
- Supplementary OpenStreetMap construction is searched within **5 km** of the complete route.
- OSM queries use route points every **2 km**. With a 5 km query radius, adjacent query areas overlap, preventing intentional gaps while avoiding hundreds of uncontrolled requests.
- Official GIS/work records are checked against the complete route geometry with geographic distance/intersection calculations.
- OSM construction, PAIMANA candidates, and official project records are deduplicated by stable ID or normalized name + coordinates.
- OSM and PAIMANA records are explicitly separated from verified government project records.
- A project is **Verified Ongoing** only when the source itself supplies an ongoing/current-construction status.
- No fallback/random/fake project is generated when a source has no matching record.
- The right-side panel now shows route search counters and an honest zero-state.

## Source adapter policy

`backend/data/source-adapters.json` defines the source roles and extension points. The application currently connects the bundled verified GIS registry, Telangana R&B GIS, the bundled government work registry, PAIMANA metadata, and OpenStreetMap supplementary construction.

Nationwide official coverage is only as complete as the authoritative GIS/API datasets connected to the application. The architecture is ready for additional NHAI, Railways, Jal Shakti, state R&B and other departmental feeds without changing the route-matching engine.

## Important limitation

PAIMANA's portfolio count is **not** treated as project geometry. A PAIMANA record with only a project name/locality can appear as `PAIMANA Candidate – Verification Required`; it is not claimed to intersect the route. Exact PAIMANA route matching requires project coordinates/geometry from an authoritative source.

OpenStreetMap is a supplementary map source. Its construction tag does not prove government ownership, current activity, funding, or official status.
