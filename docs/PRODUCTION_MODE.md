# Production / Real-World Mode

Infra Risk Radar is configured with demo fixtures disabled.

## Route coverage
- Any two Indian locations can be submitted as From and To.
- The backend obtains a driving route and evaluates a 2 km corridor on both sides.
- Route matching is source-driven; there is no KMR/Lingampet special case.
- Exact project matches require verified project point/line geometry.
- PAIMANA portfolio records without published project geometry are shown as monitoring candidates rather than falsely claimed as exact corridor matches.

## Data integrity
- No fabricated project is inserted into the route results.
- Tender/award records are not automatically labelled as physical construction.
- Missing authoritative values remain unavailable instead of being invented.
- New Project records are stored separately and are not treated as verified route evidence until their geometry/source is verified.

## Connected sources
- PAIMANA / MoSPI-IPMD public portfolio
- Government GIS registry import
- Configured state/department GIS adapters
- National government work registry
- OpenStreetMap construction mapping as supplementary evidence

The route engine is designed so additional official state/department feeds can be added without changing the From-To corridor algorithm.

## Map and routing behavior

The map base layer uses the standard OpenStreetMap raster tiles with visible attribution; the previous Carto raster/label layer was removed so the application does not depend on a Carto API key. Routing uses OSRM road geometry, with up to three available alternatives. Place search uses Nominatim address results with India filtering and address details.
