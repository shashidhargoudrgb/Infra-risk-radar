# Accuracy and Data Policy

## Exact map result rule
A project is shown as an **exact route match** only when its authoritative source provides usable Point, LineString or MultiLineString geometry. The backend calculates the minimum geographic distance between that geometry and the selected driving route. The configured corridor is **2 km on each side**.

A place-name match such as “Lingampet” is not treated as proof that a project is inside the corridor.

## National data strategy
The application is designed to consume official GIS/project services from:

- NIC Bharat Maps / National Map Services
- NIC State GIS Portal (all States and Union Territories)
- Survey of India geospatial products
- PM GatiShakti / ministry project GIS services where access is available
- State Roads & Buildings, PRED, Irrigation, Power/Transmission and other official department GIS/works services
- PAIMANA/MoSPI for monitored Central Sector project attributes, only when authoritative project geometry is available for exact spatial matching
- OpenStreetMap as supplementary mapped-construction evidence; it is never presented as official government project progress

Bharat Maps provides nationwide base/transport GIS layers, but it is not by itself a universal live database of every ongoing construction project. Official project geometry must therefore be connected source-by-source where available.

## Accuracy labels
- **Verified GIS**: authoritative geometry + source URL.
- **Official State GIS**: authoritative state/department geometry + source URL.
- **Mapped construction**: OpenStreetMap construction feature; not official project status.
- **Monitoring record / PAIMANA**: official project attributes, but not an exact route match unless project geometry is supplied.

## No fabricated values
If cost, progress, status, completion date, or exact project geometry is absent from the source, the UI does not invent it. It shows the source-backed fields that exist and identifies unavailable attributes.

## Performance
Find Route does not synchronously download/sync the PAIMANA public table. Route geocoding, routing and route-critical GIS/construction lookups are kept separate and live source calls are parallelized. Results are cached for repeated route searches.
