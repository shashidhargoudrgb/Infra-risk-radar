# Infra Risk Radar — SIH 26103 architecture

## Route-to-project pipeline

1. User enters any two places in India.
2. Nominatim geocodes the two place names with `countrycodes=in`.
3. OSRM calculates the actual driving route and returns full GeoJSON road geometry.
4. The backend scans the route corridor for mapped construction features through Overpass/OpenStreetMap.
5. The backend loads the verified national GIS registry from `backend/data/verified-projects.geojson`.
6. Point projects use point-to-route distance; line projects use line-to-route distance.
7. `<= 0.2 km` is **On / overlapping route**; `0.5–2 km` is **Near route**; `> 2 km` is excluded.
8. The UI displays evidence/source provenance and never fabricates missing progress or cost data.

## Why PAIMANA is separate

PAIMANA/OCMS is the official MoSPI/IPMD project-monitoring context for Central Sector infrastructure projects in its scope. A public project row is not automatically a GIS line/point, so the application does not turn a project name, district, tender or guessed geocode into an exact route conflict. A verified government GIS record must be imported before route matching.

## Data layers

- **Official PAIMANA context:** portfolio/monitoring fields and public dashboard.
- **Verified Government GIS Registry:** exact project geometry + source verification; this is the authoritative route-match layer inside the prototype.
- **OSM mapped construction:** discovery/evidence layer; it is not treated as official government progress.
- **Demo project register:** dashboard-only sample records; these are intentionally not route-eligible.

## Production path

For deployment beyond the SIH prototype, connect authorized PAIMANA/departmental GIS feeds or signed exports to the import endpoint. Preserve source URL, source verification, last-updated timestamp and geometry precision for every record.
