# Routing accuracy and speed fix

- Geocoding is India-scoped through Nominatim's `countrycodes=in` filter.
- Coordinates are validated before routing.
- OSRM receives coordinates in the required longitude,latitude order.
- Full GeoJSON route geometry is requested and the map fits to the returned geometry.
- Old route state is cleared before each request.
- Geocoding and route responses are cached to reduce repeat latency.
- Project discovery runs after the route is rendered so slow evidence sources do not block routing.
- Users should select a suggestion when a place name is ambiguous; the selected suggestion preserves exact coordinates.

Nominatim country filtering and OSRM route geometry behavior follow their public API documentation.
