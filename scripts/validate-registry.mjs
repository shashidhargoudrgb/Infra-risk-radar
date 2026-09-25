import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const file = process.env.VERIFIED_GEOJSON_FILE || path.join(root, 'backend', 'data', 'verified-projects.geojson');
const data = JSON.parse(fs.readFileSync(file, 'utf8'));
if (data.type !== 'FeatureCollection' || !Array.isArray(data.features)) throw new Error('Invalid GeoJSON FeatureCollection');
const allowed = new Set(['Point','LineString','MultiLineString']);
for (const [i,f] of data.features.entries()) {
  if (!f.geometry || !allowed.has(f.geometry.type)) throw new Error(`Feature ${i+1}: unsupported geometry`);
  if (!f.properties?.id || !f.properties?.name) throw new Error(`Feature ${i+1}: id and name are required`);
  if (f.properties.sourceVerified !== true) throw new Error(`Feature ${i+1}: sourceVerified must be true`);
  if (f.properties.routeEligible !== true) throw new Error(`Feature ${i+1}: routeEligible must be true`);
}
console.log(`OK: ${data.features.length} verified GIS feature(s)`);
