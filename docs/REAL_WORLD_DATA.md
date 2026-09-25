# Real-world data integration

## Official source layers

### PAIMANA / MoSPI / IPMD
Public monitoring source for Central Sector infrastructure projects in scope.

- Public dashboard: https://ipm.mospi.gov.in/Home/PublicDashboard
- Current PAIMANA site: https://paimana-proj.mospi.gov.in/
- Use `/api/paimana/sync` to synchronize official public project metadata.
- PAIMANA records are not automatically assigned coordinates. Exact route matching requires verified GIS geometry.

### Telangana state GIS
The application includes a Telangana adapter for the TGRAC/R&B ArcGIS service:

- Service: https://tgrac.telangana.gov.in/arcgis/rest/services/RnB_Folder/RnB_Roads/MapServer
- Layer 19: Ongoing Road
- Layer 20: Proposed Road

For routes that pass through Telangana, these layers are queried using the route bounding box and then spatially matched to the 2 km corridor. The source remains attached to every returned feature.

## Data trust model

1. Official source + verified geometry = route eligible.
2. Official source without geometry = project-register only.
3. OSM construction mapping = supplementary mapped evidence, not official progress.
4. Tender/procurement notice = procurement evidence, not proof of physical construction.
5. User-entered project = project-register only until independently verified.

## Adding another Indian state

Create a state adapter following the Telangana adapter pattern in `backend/server.js`:

- official MapServer/FeatureServer URL
- layer IDs for ongoing/planned infrastructure
- query by route envelope
- convert ArcGIS geometry to GeoJSON
- attach `sourceClass`, `sourceVerified`, `sourceUrl`, `lastUpdated`
- spatially match the geometry to the route corridor

Do not use a guessed latitude/longitude from a place name as authoritative geometry.
