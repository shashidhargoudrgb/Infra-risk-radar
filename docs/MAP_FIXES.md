# Map & Routing Fixes

- Replaced the Carto raster/label layer that displayed an API-key-required watermark with the standard OpenStreetMap raster layer and visible attribution.
- Kept Esri World Imagery for Satellite mode.
- Increased route viewport max zoom so towns/villages are easier to inspect.
- Route geocoding now requests multiple India-only address candidates, ranks settlements/administrative places, and returns locality, district and state details.
- Start/end popups now show resolved locality, district and state.
- OSRM route requests now request full geometry, steps and up to three available alternatives; the map can switch between alternatives.
- Construction feature classification now prioritizes bridge construction tags before generic road construction.
- No Carto API key is required by the map page.

## Important source rule

A map tile can show geographic labels, but it cannot prove that a project is ongoing. Project status is only reported from a source that provides construction/project evidence. Exact route conflict matching uses project geometry where available.
