const base=process.env.API_BASE||'http://127.0.0.1:5000/api';
const cases=[
  ['Nirmal','Kamareddy'],
  ['Kamareddy','Kompally'],
  ['Hyderabad','Warangal'],
  ['Nizamabad','Medchal']
];
for(const [start,end] of cases){
  const q=new URLSearchParams({start,end,radiusKm:'2'});
  const r=await fetch(`${base}/route-analysis?${q}`);
  const d=await r.json();
  const route=d.options?.A;
  if(!route) throw new Error(`${start} -> ${end}: ${d.error||'no route returned'}`);
  console.log(JSON.stringify({
    start,end,routeKm:Number(route.distance?.toFixed?.(1)),routeVertices:route.coords?.length||0,
    initialOfficialMatches:route.projects?.length||0
  }));
}
console.log('Route corridor smoke test completed. For a full project-source test, use the live backend with internet access to OSRM, Nominatim, Overpass and connected government GIS sources.');
