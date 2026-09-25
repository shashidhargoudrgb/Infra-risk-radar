# India-wide / National Coverage

Infra Risk Radar is designed as an **India-wide route-analysis platform**. The route engine is not restricted to Telangana: a user can enter any two Indian locations and the backend uses India-only geocoding plus an OSRM driving route.

## National project sources

### 1. PAIMANA / MoSPI
PAIMANA is the primary national monitoring context for Central Sector infrastructure projects monitored by MoSPI/IPMD. Its public dashboard provides project code, project name, ministry/sector, approved/revised cost, expenditure and dates. These records are synchronized as monitoring metadata.

**Important:** PAIMANA's public project table is not a universal GIS geometry layer. A PAIMANA record is therefore not treated as being on a route merely because its state/district/name matches. Exact route matching requires authoritative Point, LineString or MultiLineString geometry.

### 2. National verified GIS registry
The application contains a national registry that accepts verified government GIS/project geometry from any Indian state, Union Territory, Central ministry, department or implementing agency. Once imported with `sourceVerified=true` and a real `sourceUrl`, the same route engine can match it against routes anywhere in India.

Supported geometry: Point, LineString, MultiLineString.

### 3. Official state/department GIS adapters
The architecture supports independent adapters for official GIS services. Telangana TGRAC/R&B is currently included as one adapter; it is **not the national route engine** and does not limit other states. Additional official services can be added without changing route calculation or conflict matching.

### 4. OpenStreetMap supplementary evidence
Mapped construction features may be used as supplementary geographic evidence. They are explicitly not presented as official government project progress.

## Accuracy rule

The system never claims that it has found every project in India. It reports projects that are present in the connected/verified datasets. A project missing from those datasets cannot be discovered reliably by the software.

The correct product claim is:

> "India-wide route-based infrastructure project monitoring using PAIMANA monitoring metadata and verified government GIS/project datasets, with conflict, dependency and risk analysis."
