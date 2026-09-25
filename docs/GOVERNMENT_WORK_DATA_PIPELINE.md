# Government Work Data Pipeline — SIH 26103

The route engine now separates **procurement evidence** from **physical project geometry**.

## Exact route results
A project is counted in the 2 km corridor only when it has a Point, LineString or MultiLineString geometry and the geometry is within 2 km of the calculated road route.

## Telangana official GIS
The application queries the Telangana R&B/TGRAC ArcGIS service at runtime. Layer 19 is the official `Ongoing Road` layer and layer 20 is the `Proposed Road` layer. The service also exposes road IDs, road names, district/mandal fields and chainage fields where supplied by the source.

Source: https://tgrac.telangana.gov.in/arcgis/rest/services/RnB_Folder/RnB_Roads/MapServer

## Tender records
Telangana eProcurement is an official procurement source, but a tender notice is **not** treated as proof that construction is physically underway. Tender metadata must be imported/linked to independently verified GIS geometry before it becomes an exact route project.

Source: https://tender.telangana.gov.in/

## Why this matters
A search result saying “Nizamabad” is not enough to place a work on the Kamareddy → Nizamabad route. The application must first establish the work's actual geometry, then perform the corridor-distance test.

This prevents false positives while allowing more state/department GIS adapters to be added without changing the route engine.
