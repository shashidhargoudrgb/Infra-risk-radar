# Map & Route Accuracy Update

This build changes the route workflow to use an explicit location-selection step before routing.

## What is now enforced

- India-only Nominatim geocoding.
- Up to 10 place candidates for every From/To query.
- Candidate shows locality/village/town/city, district, state and coordinates.
- If the user selects a candidate, its exact coordinates are passed to routing; the backend does not re-guess the place.
- OSRM driving route uses full GeoJSON road geometry, up to 3 alternatives, route steps and annotations.
- Project matching uses the complete route geometry and a configurable 2 km corridor.
- OpenStreetMap construction queries now cover the entire route in chunks instead of stopping after the first ~420 km.
- Exact project records require Point/LineString/MultiLineString geometry.
- PAIMANA records without project GIS geometry remain explicitly labelled as approximate monitoring candidates.
- Tender/work records are not automatically labelled as physical construction.
- Standard OpenStreetMap tiles are used, removing the previous Carto API-key watermark.

## Important accuracy boundary

No public service provides a complete, live, authoritative GIS layer for every infrastructure project in every Indian state, district, village and department. Therefore this application must not fabricate a project when a source has no geometry.

For the strongest nationwide coverage, import authoritative state/department GIS work layers into `backend/data/verified-projects.geojson` using `/api/projects/import`, or configure additional state GIS adapters. The route engine itself is India-wide.

## External services

- Nominatim: place search/geocoding
- OSRM: driving routes
- Overpass/OpenStreetMap: mapped construction evidence
- PAIMANA: MoSPI/IPMD monitored-project portfolio context
- State GIS adapters: authoritative geometry where available

## Production recommendation

For production/SIH demonstration at scale, use a dedicated routing/geocoding provider or self-host these services rather than relying on public community endpoints. Public endpoints have usage limits and no availability SLA.
