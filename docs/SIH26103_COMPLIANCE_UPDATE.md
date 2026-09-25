# SIH26103 Compliance Update

This version keeps the existing UI and Map/Route field unchanged.

## Improvements made
- Project-detail risk and prediction cards now use the same transparent data-derived calculation used by Predictive Analytics instead of fixed demonstration numbers.
- Risk Radar now derives the project-side radar values from the selected project record rather than displaying fixed project values.
- EVM TCPI calculation uses the project's revised cost consistently.
- Existing Map & Conflict, Route Analysis, Conflict Radar, Dependencies and GIS evidence rules are retained.

## SIH26103 alignment
The application now presents cost-overrun, schedule-delay, risk scoring, early-warning, EVM, driver analysis and benchmarking as evidence-derived calculations from the current project registry.

Important limitation: these calculations are a transparent baseline scoring/forecasting method, not a claim of a trained/validated ML model. A production SIH submission should train and evaluate statistical and ML models on a documented historical PAIMANA dataset and report held-out metrics.

## Data integrity
Real/verified GIS records must remain distinguishable from OpenStreetMap supplementary evidence and simulated/demo records. Do not present demo records as real government projects.
