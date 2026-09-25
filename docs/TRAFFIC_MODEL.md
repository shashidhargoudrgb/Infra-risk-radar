# Real-world route impact and traffic model

Infra Risk Radar separates **live traffic speed** from **infrastructure impact**.

## What the current build does

For any Indian From -> To route it:

1. Geocodes the two places in India.
2. Calculates a real road route with OSRM.
3. Searches a 2 km corridor around the route for mapped construction evidence.
4. Matches verified government GIS geometry exactly where available.
5. Enriches with PAIMANA monitored-project metadata when a project name contains an endpoint place and the place match falls inside the corridor. These records are explicitly labelled as place-name candidates until authoritative project geometry is imported.
6. Calculates a transparent infrastructure-impact score from proximity, route overlap, project type and construction evidence.
7. Estimates additional route disruption minutes. This is an **infrastructure-impact forecast**, not a live traffic-speed claim.

## Why it is not called Google-style live traffic

Google Maps-style traffic prediction depends on proprietary/current traffic observations such as probe-device speeds, historical speed patterns and other traffic feeds. This project does not fabricate those observations.

For production deployment, add a licensed live-traffic provider (for example a government-approved or commercial traffic API) and feed its segment speeds into the route engine. The UI already presents the infrastructure-impact forecast separately so that a future live-traffic layer can be added without mixing evidence types.

## Risk interpretation

- High: substantial route overlap and/or multiple high-impact construction records.
- Medium: nearby or partially overlapping construction with moderate disruption potential.
- Low: limited mapped construction evidence in the corridor.

Every project retains its source class and location precision. A PAIMANA place-name candidate is never presented as an exact GIS footprint.
