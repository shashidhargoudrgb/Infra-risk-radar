# Live Ongoing Project Pipeline

The route page now calculates the road route first and then fetches ongoing/construction evidence asynchronously.

Sources:
1. Telangana TGRAC/R&B official GIS: Ongoing Road layer (Layer 19) for Telangana.
2. Government work registry: records explicitly marked ongoing/construction.
3. OpenStreetMap Overpass: supplementary mapped construction, including roads, bridges and explicitly elevated/flyover construction tags.

Rules:
- Tender/procurement alone is not treated as physical ongoing construction.
- Planned/proposed records are not returned by `/api/route-live-projects`.
- OSM is explicitly labeled supplementary, not official government progress.
- Project geometry must be within the selected corridor before it is displayed.
- OSM timeouts never block route calculation.
