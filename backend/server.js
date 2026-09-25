import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import crypto from 'node:crypto';

const __dirname=path.dirname(fileURLToPath(import.meta.url));
function loadDotEnv(file){try{const raw=fs.readFileSync(file,'utf8');for(const line of raw.split(/\r?\n/)){const m=line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);if(!m||m[1] in process.env)continue;let v=m[2];if((v.startsWith('\"')&&v.endsWith('\"'))||(v.startsWith("'")&&v.endsWith("'")))v=v.slice(1,-1);process.env[m[1]]=v;}}catch{}}
loadDotEnv(path.join(__dirname,'.env'));
const PORT=Number(process.env.PORT||5000);
const STORAGE_DIR=process.env.STORAGE_DIR||__dirname;
const DB_FILE=path.join(STORAGE_DIR,'infra_risk_data.json');
const AUTH_FILE=path.join(STORAGE_DIR,'infra_risk_auth.json');
const SESSION_DAYS=7;
const GOOGLE_CLIENT_ID=String(process.env.GOOGLE_CLIENT_ID||'').trim();
const GOOGLE_ADMIN_EMAILS=new Set(String(process.env.GOOGLE_ADMIN_EMAILS||'').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean));
let googleCertCache={expiresAt:0,certs:{}};
async function googleCertificates(){
  if(googleCertCache.expiresAt>Date.now() && Object.keys(googleCertCache.certs).length)return googleCertCache.certs;
  const r=await fetch('https://www.googleapis.com/oauth2/v3/certs',{headers:{'accept':'application/json'}});
  if(!r.ok)throw new Error(`Google certificate request failed (${r.status})`);
  const data=await r.json();
  const maxAge=Number((r.headers.get('cache-control')||'').match(/max-age=(\d+)/i)?.[1]||3600);
  googleCertCache={certs:data,expiresAt:Date.now()+Math.max(300,Math.min(maxAge,86400))*1000};
  return data;
}
function base64urlJson(value){return JSON.parse(Buffer.from(value,'base64url').toString('utf8'))}
async function verifyGoogleCredential(credential){
  if(!GOOGLE_CLIENT_ID)throw new Error('Google Sign-In is not configured. Set GOOGLE_CLIENT_ID in backend/.env.');
  const parts=String(credential||'').split('.');
  if(parts.length!==3)throw new Error('Invalid Google credential.');
  const [encodedHeader,encodedPayload,encodedSignature]=parts;
  const header=base64urlJson(encodedHeader),payload=base64urlJson(encodedPayload);
  if(header.alg!=='RS256'||!header.kid)throw new Error('Unsupported Google credential signature.');
  const certs=await googleCertificates();
  const cert=certs[header.kid];
  if(!cert)throw new Error('Google signing certificate is not available. Try again.');
  const verifier=crypto.createVerify('RSA-SHA256');
  verifier.update(`${encodedHeader}.${encodedPayload}`); verifier.end();
  if(!verifier.verify(cert,Buffer.from(encodedSignature,'base64url')))throw new Error('Google credential signature verification failed.');
  const issuer=payload.iss;
  const audience=Array.isArray(payload.aud)?payload.aud:[payload.aud];
  if(!['accounts.google.com','https://accounts.google.com'].includes(issuer))throw new Error('Invalid Google token issuer.');
  if(!audience.includes(GOOGLE_CLIENT_ID))throw new Error('Google Client ID does not match this application.');
  if(!payload.sub||!payload.email||payload.email_verified!==true)throw new Error('Google account email is not verified.');
  if(!Number.isFinite(Number(payload.exp))||Number(payload.exp)*1000<=Date.now())throw new Error('Google sign-in session has expired.');
  if(payload.iat && Number(payload.iat)*1000>Date.now()+300000)throw new Error('Google credential timestamp is invalid.');
  return {sub:String(payload.sub),email:String(payload.email).trim().toLowerCase(),name:String(payload.name||payload.email.split('@')[0]).trim(),picture:String(payload.picture||'')};
}
function readJson(file,fallback){try{return JSON.parse(fs.readFileSync(file,'utf8'))}catch{return fallback}}
function writeJson(file,value){fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,JSON.stringify(value,null,2))}
function hashSecret(secret,salt=crypto.randomBytes(16).toString('hex')){
  return crypto.scryptSync(String(secret),salt,64).toString('hex')+':'+salt;
}
async function readBody(req){let body='';for await(const ch of req)body+=ch;try{return JSON.parse(body||'{}')}catch{throw new Error('Invalid JSON request body.')}}
function verifySecret(secret,stored){
  if(!stored||!stored.includes(':'))return false;
  const [hash,salt]=stored.split(':'); const candidate=crypto.scryptSync(String(secret),salt,64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash,'hex'),Buffer.from(candidate,'hex'));
}
let auth=readJson(AUTH_FILE,{users:[],adminKeyHash:null,sessions:[]});
if(!Array.isArray(auth.users))auth.users=[];
if(!Array.isArray(auth.sessions))auth.sessions=[];
function saveAuth(){writeJson(AUTH_FILE,auth)}
function makeSession(user){const token=crypto.randomBytes(32).toString('hex');auth.sessions=auth.sessions.filter(x=>x.expiresAt>Date.now());auth.sessions.push({token,userId:user.id,expiresAt:Date.now()+SESSION_DAYS*86400000});saveAuth();return token}
function currentUser(req){
  const h=String(req.headers.authorization||''); if(!h.startsWith('Bearer '))return null;
  const token=h.slice(7); auth.sessions=auth.sessions.filter(x=>x.expiresAt>Date.now()); const session=auth.sessions.find(x=>x.token===token);
  if(!session)return null; const user=auth.users.find(x=>x.id===session.userId); return user||null;
}
function requireAdmin(req,res){
  const user=currentUser(req); if(!user||user.role!=='Administrator'){send(res,403,{error:'Administrator authentication required.'});return null}
  return user;
}
function audit(user,action,targetType,targetId,targetName){
  db.auditLog=Array.isArray(db.auditLog)?db.auditLog:[]; db.auditLog.unshift({id:crypto.randomUUID(),userId:user.id,user:user.name,email:user.email,role:user.role,action,targetType,targetId:targetId||null,target:targetName||null,time:new Date().toISOString()}); db.auditLog=db.auditLog.slice(0,500); save();
}
function makeAdminKey(){return 'IRR-'+crypto.randomBytes(18).toString('base64url').toUpperCase()}

const VERIFIED_GEOJSON_FILE=process.env.VERIFIED_GEOJSON_FILE||path.join(STORAGE_DIR,'verified-projects.geojson');
const PAIMANA_URL=process.env.PAIMANA_URL||'https://ipm.mospi.gov.in/Home/PublicDashboard';
const USER_AGENT='InfraRiskRadar-SIH26103/7.0 (production-data-pipeline)';
const OFFICIAL_SOURCE_REGISTRY=path.join(__dirname,'data','official-source-registry.json');

// PAIMANA national portfolio context (MoSPI / IPMD), per SIH 26103 problem statement.
// OCMS (2006) -> modernized to PAIMANA. Figures below reflect the stated April 2026 scale
// and are shown only as official PAIMANA portfolio context, not as local project records.
const paimanaOverview={asOf:'April 2026',totalProjects:1981,ministries:'17',sectors:'Multiple',originalCostLakhCr:37.13,revisedCostLakhCr:42.78,expenditureLakhCr:20.36,legacySystem:'OCMS (Online Computerised Monitoring System, since 2006)',currentSystem:'PAIMANA (Project Assessment, Infrastructure Monitoring and Analytics for Nation-building)',owner:'Infrastructure & Project Monitoring Division (IPMD), MoSPI',topSectors:['Transport & Logistics','Energy','Water & Sanitation','Communication','Social Infrastructure','Coal','Steel','Mining']};
// CUF = Common Upload Form: the fields the PAIMANA/OCMS framework already captures monthly.
const cufFields=[
 {field:'Approved (Original) Cost',usedInBaseline:true},
 {field:'Revised Cost',usedInBaseline:true},
 {field:'Cumulative Expenditure',usedInBaseline:true},
 {field:'Physical Progress (%)',usedInBaseline:true},
 {field:'Implementation Timelines (Start/Completion)',usedInBaseline:true},
 {field:'Milestones',usedInBaseline:true},
 {field:'Implementing Agency',usedInBaseline:true},
 {field:'Project Status',usedInBaseline:true}
];
// Variables not presently captured in the CUF that the application flags as high-value additions,
// used to assess technical dimension (c): CUF-only vs CUF+additional predictive performance.

const additionalVariables=[
 {field:'Land acquisition / right-of-way status',captured:false},
 {field:'Environmental & statutory clearance status',captured:false},
 {field:'Contractor performance / dispute history',captured:false},
 {field:'Input material price index exposure',captured:false},
 {field:'Route/geospatial conflict with other infra projects',captured:false},
 {field:'Drone / satellite-verified physical progress',captured:false},
 {field:'Weather & monsoon exposure window',captured:false},
 {field:'Local litigation / public resistance signals',captured:false}
];
function load(){try{const x=JSON.parse(fs.readFileSync(DB_FILE,'utf8'));return {projects:Array.isArray(x.projects)?x.projects:[]}}catch{return {projects:[]}}}
function deriveAlerts(){
  const ackMap=db.alertAcknowledgements||{};
  return db.projects.map(p=>{
    const m=riskModel(p); if(m.riskScore<60)return null;
    const id=`risk-${p.id}`, saved=ackMap[id]||{};
    return {id,level:m.riskScore>=75?'High':'Medium',project:p.name,message:`Evidence-based risk score ${m.riskScore}/100; observed cost variance ${m.observedCostOverrunPct}%. No unvalidated ML prediction is presented.`,time:saved.createdAt||new Date().toISOString(),ack:!!saved.ack,acknowledgedAt:saved.acknowledgedAt||null,acknowledgedBy:saved.acknowledgedBy||null,source:'derived-from-project-record'};
  }).filter(Boolean)
}
function loadVerifiedGeoJSON(){
  try{
    const raw=JSON.parse(fs.readFileSync(VERIFIED_GEOJSON_FILE,'utf8'));
    return (raw.features||[]).map(f=>({...(f.properties||{}),geometry:f.geometry,routeEligible:true,sourceVerified:true,sourceClass:'verified-government-gis',locationPrecision:f.geometry?.type==='LineString'||f.geometry?.type==='MultiLineString'?'line/geometry':'point'}));
  }catch{return []}
}
function saveVerifiedGeoJSON(items){
  fs.mkdirSync(path.dirname(VERIFIED_GEOJSON_FILE),{recursive:true});
  const features=items.map(p=>({type:'Feature',geometry:p.geometry,properties:{...p,geometry:undefined}}));
  fs.writeFileSync(VERIFIED_GEOJSON_FILE,JSON.stringify({type:'FeatureCollection',features},null,2));
}
let db=load(); function save(){fs.mkdirSync(path.dirname(DB_FILE),{recursive:true});fs.writeFileSync(DB_FILE,JSON.stringify(db,null,2))}

function send(res,status,payload){res.writeHead(status,{'content-type':'application/json','access-control-allow-origin':'*','access-control-allow-headers':'Content-Type, Authorization'});res.end(JSON.stringify(payload))}
function monthsBetween(a,b){try{const [am,ay]=String(a||'').split('/').map(Number),[bm,by]=String(b||'').split('/').map(Number);if(!am||!ay||!bm||!by)return 0;return (by-ay)*12+(bm-am)}catch{return 0}}
function riskModel(p){
 const o=+p.originalCost||0,c=+p.cost||+p.revisedCost||0,e=+p.expenditure||0,g=+p.progress||0;
 const over=o>0?Math.max(0,(c-o)/o*100):0, spendPct=c>0?Math.min(150,e/c*100):0;
 const ev=c*g/100;
 const plannedProgress=Number.isFinite(Number(p.plannedProgress))?Math.max(0,Math.min(100,Number(p.plannedProgress))):null;
 const pv=plannedProgress===null?null:c*plannedProgress/100;
 const cpi=e>0?ev/e:null, spi=pv!==null&&pv>0?ev/pv:null;
 const slip=Math.max(0,monthsBetween(p.targetCompletion,p.revisedCompletion));
 const schedule=Math.min(100,Math.round(Math.max(0,100-g)*.45+slip*5+(spi!==null?Math.max(0,1-spi)*30:0)));
 const cost=Math.min(100,Math.round(over*2.5+Math.max(0,spendPct-g)*.55));
 const score=Math.min(100,Math.round(schedule*.52+cost*.48));
 const delayMonths=slip;
 return {pv,ev,ac:e,cpi,spi,eac:cpi?c/cpi:c,vac:c-(cpi?c/cpi:c),delayMonthsObserved:delayMonths,observedCostOverrunPct:Math.round(over*10)/10,predictedDelayMonths:null,predictedOverrunPct:null,scheduleRisk:schedule,costRisk:cost,riskScore:score,modelType:'transparent evidence-based risk score',mlValidated:false,confidence:null,validationStatus:'not validated'};
}
function approvedPlannedValue(p){
  // PAIMANA records use originalCost as the approved baseline when no
  // separate plannedValue field is supplied.
  const value=p?.plannedValue??p?.planned_value??p?.approvedPlannedValue??p?.approved_planned_value??p?.originalCost??p?.approvedCost??null;
  const amount=Number(value);
  return Number.isFinite(amount)&&amount>=0?amount:null;
}
function hav(a,b){const R=6371,r=Math.PI/180,dLat=(b.lat-a.lat)*r,dLon=(b.lng-a.lng)*r;const x=Math.sin(dLat/2)**2+Math.cos(a.lat*r)*Math.cos(b.lat*r)*Math.sin(dLon/2)**2;return 2*R*Math.asin(Math.sqrt(x))}
function pointSeg(p,a,b){const lat=111.32,lng=111.32*Math.cos(((a.lat+b.lat)/2)*Math.PI/180);const px=p.lng*lng,py=p.lat*lat,ax=a.lng*lng,ay=a.lat*lat,bx=b.lng*lng,by=b.lat*lat,dx=bx-ax,dy=by-ay,l=dx*dx+dy*dy,t=l?Math.max(0,Math.min(1,((px-ax)*dx+(py-ay)*dy)/l)):0;return Math.hypot(px-(ax+t*dx),py-(ay+t*dy))}
function routeDistance(p,coords){let best=Infinity;for(let i=1;i<coords.length;i++)best=Math.min(best,pointSeg(p,{lat:coords[i-1][0],lng:coords[i-1][1]},{lat:coords[i][0],lng:coords[i][1]}));return best}
function segmentsIntersect(a,b,c,d){
  const orient=(p,q,r)=>(q.x-p.x)*(r.y-p.y)-(q.y-p.y)*(r.x-p.x);
  const o1=orient(a,b,c),o2=orient(a,b,d),o3=orient(c,d,a),o4=orient(c,d,b),eps=1e-10;
  if(Math.abs(o1)<eps&&Math.abs(o2)<eps&&Math.abs(o3)<eps&&Math.abs(o4)<eps){
    const min=(x,y)=>Math.min(x,y),max=(x,y)=>Math.max(x,y);
    return max(min(a.x,b.x),min(c.x,d.x))<=min(max(a.x,b.x),max(c.x,d.x))+eps && max(min(a.y,b.y),min(c.y,d.y))<=min(max(a.y,b.y),max(c.y,d.y))+eps;
  }
  return ((o1>0)!==(o2>0))&&((o3>0)!==(o4>0));
}
function pointSegXY(p,a,b){const dx=b.x-a.x,dy=b.y-a.y,l=dx*dx+dy*dy,t=l?Math.max(0,Math.min(1,((p.x-a.x)*dx+(p.y-a.y)*dy)/l)):0;return Math.hypot(p.x-(a.x+t*dx),p.y-(a.y+t*dy));}
function lineGeometryDistanceKm(projectCoords,routeCoords){
  if(!projectCoords?.length||!routeCoords?.length)return Infinity;
  const all=[...routeCoords,...projectCoords.map(([lat,lng])=>[lat,lng])];
  const refLat=all.reduce((s,p)=>s+p[0],0)/all.length, latScale=111.32,lngScale=111.32*Math.cos(refLat*Math.PI/180);
  const toXY=([lat,lng])=>({x:lng*lngScale,y:lat*latScale});
  const r=routeCoords.map(toXY),p=projectCoords.map(toXY); let best=Infinity;
  for(let i=1;i<r.length;i++){
    const ra=r[i-1],rb=r[i];
    for(let j=1;j<p.length;j++){
      const pa=p[j-1],pb=p[j];
      if(segmentsIntersect(ra,rb,pa,pb))return 0;
      best=Math.min(best,pointSegXY(ra,pa,pb),pointSegXY(rb,pa,pb),pointSegXY(pa,ra,rb),pointSegXY(pb,ra,rb));
    }
  }
  return best;
}
function routeSamplePoints(coords,everyKm=1){
  if(!Array.isArray(coords)||coords.length<2)return Array.isArray(coords)?coords.slice():[];
  const out=[coords[0]];
  let since=0;
  for(let i=1;i<coords.length;i++){
    const prev=coords[i-1],cur=coords[i];
    const seg=hav({lat:prev[0],lng:prev[1]},{lat:cur[0],lng:cur[1]});
    if(!Number.isFinite(seg)||seg<=0)continue;
    let consumed=0;
    while(since + (seg-consumed) >= everyKm){
      const need=everyKm-since;
      const f=(consumed+need)/seg;
      out.push([prev[0]+(cur[0]-prev[0])*f,prev[1]+(cur[1]-prev[1])*f]);
      consumed+=need; since=0;
    }
    since+=seg-consumed;
  }
  const last=coords[coords.length-1];
  const tail=out[out.length-1];
  if(!tail||tail[0]!==last[0]||tail[1]!==last[1])out.push(last);
  return out;
}

function projectTypeFromTags(t={}){
  const construction=String(t.construction||'').toLowerCase();
  const bridge=String(t.bridge||'').toLowerCase();
  const highway=String(t.highway||'').toLowerCase();
  const layer=Number(t.layer);
  // Explicit elevated/flyover evidence only; do not guess ordinary bridges.
  if((highway==='construction' || highway) && (construction==='viaduct' || construction==='flyover' || bridge==='viaduct' || bridge==='flyover' || t['bridge:construction'])) return 'Flyover / Elevated Road';
  if(t.railway==='construction' || t.railway) return 'Railway';
  if(t.waterway==='construction' || t.man_made==='pipeline' || t.pipeline==='water') return 'Water Pipeline';
  if(t.power==='line' || t.power==='minor_line' || t.power==='construction') return 'Electricity';
  if(construction==='bridge' || bridge==='yes' || t['bridge:construction']) return 'Bridge';
  if(t.highway==='construction') return 'Road';
  if(t.public_transport==='platform' || t.railway==='light_rail') return 'Metro';
  return 'Other Infrastructure';
}
function elementPoint(el){
  if(Number.isFinite(el.lat)&&Number.isFinite(el.lon)) return {lat:el.lat,lng:el.lon};
  if(Array.isArray(el.geometry)&&el.geometry.length){
    return {lat:el.geometry.reduce((s,g)=>s+g.lat,0)/el.geometry.length,lng:el.geometry.reduce((s,g)=>s+g.lon,0)/el.geometry.length};
  }
  return null;
}
function minGeometryDistanceKm(geometry,routeCoords){
  if(!Array.isArray(geometry)||!geometry.length)return Infinity;
  if(geometry.length===1)return routeDistance({lat:geometry[0].lat,lng:geometry[0].lon},routeCoords);
  let best=Infinity;
  for(let i=0;i<geometry.length;i++){
    const p={lat:geometry[i].lat,lng:geometry[i].lon};
    best=Math.min(best,routeDistance(p,routeCoords));
    if(i>0){
      // Sample the project line between consecutive vertices to catch crossings between route vertices.
      const a=geometry[i-1],b=geometry[i];
      for(let j=1;j<5;j++){
        const f=j/5;
        best=Math.min(best,routeDistance({lat:a.lat+(b.lat-a.lat)*f,lng:a.lon+(b.lon-a.lon)*f},routeCoords));
      }
    }
  }
  return best;
}
const overpassCache=new Map();
async function overpassRequest(query){
  const cacheKey=query; const cached=overpassCache.get(cacheKey);
  if(cached && Date.now()-cached.at<10*60*1000) return cached.data;
  const endpoints=['https://overpass-api.de/api/interpreter','https://overpass.kumi.systems/api/interpreter','https://overpass.private.coffee/api/interpreter'];
  let lastError=null;
  for(const endpoint of endpoints){
    try{
      const r=await fetch(endpoint,{method:'POST',headers:{'content-type':'text/plain;charset=UTF-8','user-agent':USER_AGENT},body:query,signal:AbortSignal.timeout(15000)});
      if(!r.ok)throw new Error(`HTTP ${r.status}`);
      const data=await r.json(); overpassCache.set(cacheKey,{at:Date.now(),data}); return data;
    }catch(e){lastError=e;}
  }
  throw new Error('OSM supplementary source unavailable'+(lastError?`: ${lastError.message}`:''));
}

function constructionBboxQuery(routeCoords, radiusKm){
  if(!Array.isArray(routeCoords)||!routeCoords.length)return null;
  const lats=routeCoords.map(x=>Number(x[0])).filter(Number.isFinite), lngs=routeCoords.map(x=>Number(x[1])).filter(Number.isFinite);
  if(!lats.length||!lngs.length)return null;
  // Convert the requested 5 km corridor into a conservative degree buffer.
  const midLat=(Math.min(...lats)+Math.max(...lats))/2;
  const latPad=Math.max(0.02, radiusKm/111);
  const lngPad=Math.max(0.02, radiusKm/(111*Math.max(0.2,Math.cos(midLat*Math.PI/180))));
  const south=Math.max(-90,Math.min(...lats)-latPad), west=Math.max(-180,Math.min(...lngs)-lngPad);
  const north=Math.min(90,Math.max(...lats)+latPad), east=Math.min(180,Math.max(...lngs)+lngPad);
  const b=`${south},${west},${north},${east}`;
  return `[out:json][timeout:25];(nwr[highway=construction](${b});nwr[highway][construction](${b});nwr[construction](${b});nwr[bridge=construction](${b});nwr[bridge:construction](${b});nwr[railway=construction](${b});nwr[railway][construction](${b});nwr[building=construction](${b});nwr[landuse=construction](${b});nwr[site=construction](${b});nwr[man_made=works](${b}););out tags center geom;`;
}

function constructionSampleQuery(samples,radiusMeters){
  const a=Math.round(Math.min(radiusMeters,5000));
  const around=samples.map(([lat,lon])=>`nwr[highway=construction](around:${a},${lat},${lon});nwr[highway][construction](around:${a},${lat},${lon});nwr[construction](around:${a},${lat},${lon});nwr[bridge=construction](around:${a},${lat},${lon});nwr[bridge:construction](around:${a},${lat},${lon});nwr[railway=construction](around:${a},${lat},${lon});nwr[railway][construction](around:${a},${lat},${lon});nwr[building=construction](around:${a},${lat},${lon});nwr[landuse=construction](around:${a},${lat},${lon});nwr[site=construction](around:${a},${lat},${lon});nwr[man_made=works](around:${a},${lat},${lon});`).join('');
  return `[out:json][timeout:12];(${around});out tags center geom;`;
}
async function fetchOsmConstructionProjects(routeCoords,radiusKm=5){
  if(!routeCoords?.length)return [];
  const radius=Math.min(Math.max(Number(radiusKm)||5,0.5),5);
  // Never send one giant bounding-box query for a long route. Sample the actual
  // route and query small overlapping corridors in parallel; this is much faster
  // and avoids Overpass timeouts on long inter-city routes.
  const samples=routeSamplePoints(routeCoords,Math.min(4,Math.max(1.5,radius/1.5)));
  const maxSamples=60;
  const selected=samples.length>maxSamples
    ? Array.from({length:maxSamples},(_,i)=>samples[Math.round(i*(samples.length-1)/(maxSamples-1))])
    : samples;
  const chunks=[]; for(let i=0;i<selected.length;i+=8)chunks.push(selected.slice(i,i+8));
  const results=await Promise.allSettled(chunks.map(chunk=>overpassRequest(constructionSampleQuery(chunk,Math.round(radius*1000)))));
  const seen=new Set(), collected=[];
  for(const result of results){
    if(result.status!=='fulfilled')continue;
    const data=result.value;
  for(const el of (data.elements||[])){
    const uniqueKey=`${el.type}-${el.id}`;
    if(seen.has(uniqueKey))continue; seen.add(uniqueKey);
    const geometry=Array.isArray(el.geometry)?el.geometry:[];
    const point=elementPoint(el);
    const distance=minGeometryDistanceKm(geometry.length?geometry:(point?[{lat:point.lat,lon:point.lng}]:[]),routeCoords);
    if(!point||distance>radiusKm)continue;
    const tags=el.tags||{};
    const type=projectTypeFromTags(tags);
    const rawProgress=tags['construction:progress'] ?? tags.progress ?? tags['progress:physical'];
    const parsedProgress=rawProgress!==undefined&&rawProgress!==null&&rawProgress!==''?Number(String(rawProgress).replace('%','')):NaN;
    const progress=Number.isFinite(parsedProgress)?Math.max(0,Math.min(100,parsedProgress)):null;
    const geoJsonGeometry=geometry.length?{type:'LineString',coordinates:geometry.map(g=>[g.lon,g.lat])}:(point?{type:'Point',coordinates:[point.lng,point.lat]}:null);
    collected.push({
      id:`OSM-${el.type}-${el.id}`, name:tags.name||tags.ref||`${type} construction feature`, type,
      ministry:null,sector:'Infrastructure',state:null,status:'Mapped Construction – Verification Required',
      statusEvidence:'OpenStreetMap construction/mapped-infrastructure tag. Supplementary evidence only; it does not prove official government project status.',
      risk:'Not verified',riskScore:null,lat:point.lat,lng:point.lng,geometry:geoJsonGeometry,
      distance,overlap:distance<=0.5?'On / overlapping route':'Near route',sourceType:'OpenStreetMap mapped construction',sourceClass:'mapped',sourceVerified:false,
      sourceUrl:`https://www.openstreetmap.org/${el.type}/${el.id}`,dataConfidence:0.7,progress,financialProgress:null,lastUpdated:el.timestamp||null,
      start:tags.start_date||tags.start_date_estimated||null,completion:tags.opening_date||tags['end_date']||null,
      location:tags['addr:full']||tags['addr:street']||tags.ref||'Mapped geometry',costImpactVerified:false,costImpact:null,
      locationPrecision:geometry.length?'line/geometry':'point',osmTags:{highway:tags.highway||null,railway:tags.railway||null,bridge:tags.bridge||null,'bridge:construction':tags['bridge:construction']||null,construction:tags.construction||null,landuse:tags.landuse||null,site:tags.site||null,name:tags.name||null,ref:tags.ref||null}
    });
  }
  }
  return collected.sort((a,b)=>a.distance-b.distance);
}

const TELANGANA_RNB_SERVICE='https://tgrac.telangana.gov.in/arcgis/rest/services/RnB_Folder/RnB_Roads/MapServer';
const ROUTE_CORRIDOR_KM=2;
const ROUTE_MAX_PROJECTS=100;

// --- National Highway reference geometry (OpenStreetMap) ---
// There is no public, unauthenticated API for NHAI/Bhoomi Rashi project geometry: Bhoomi
// Rashi is an authenticated land-acquisition workflow portal (gazette notifications,
// compensation via PFMS), and actual NH alignment KML/KMZ files are shared internally with
// BISAG-N for the PM GatiShakti National Master Plan, not published as a public feed.
// This adapter instead pulls the *real physical road geometry* of National Highways from
// OpenStreetMap, which is genuinely public/live. It carries NO project or construction
// status — it only tells you which NH ref(s) a route follows and their exact coordinates,
// so that a manually-sourced, cited ongoing-project record (from a PIB release, a Lok Sabha/
// Rajya Sabha reply, or NHAI's own bidding-transparency releases) can be paired with accurate
// geometry instead of a geocoded guess.
function nationalHighwayQuery(samples,radiusMeters){
  const a=Math.round(Math.min(radiusMeters,2000));
  const around=samples.map(([lat,lon])=>
    `way[highway][ref~"^(NH|NE)[- ]?[0-9]"](around:${a},${lat},${lon});`
  ).join('');
  return `[out:json][timeout:8];(${around});out tags geom;`;
}
async function fetchNationalHighwayReference(routeCoords,radiusKm=2){
  if(!routeCoords?.length)return [];
  const samples=routeSamplePoints(routeCoords,8);
  const maxSamples=30;
  let selected=samples;
  if(samples.length>maxSamples){
    selected=Array.from({length:maxSamples},(_,i)=>{
      const idx=Math.round(i*(samples.length-1)/(maxSamples-1));
      return samples[idx];
    });
  }
  const chunks=[];
  for(let i=0;i<selected.length;i+=10)chunks.push(selected.slice(i,i+10));
  const byRef=new Map();
  const results=await Promise.allSettled(chunks.map(chunk=>
    overpassRequest(nationalHighwayQuery(chunk,Math.round(Math.min(radiusKm,2)*1000)))
  ));
  for(const result of results){
    if(result.status!=='fulfilled')continue;
    for(const el of (result.value.elements||[])){
      const tags=el.tags||{};
      const ref=String(tags.ref||'').trim(); if(!ref)continue;
      const geometry=Array.isArray(el.geometry)?el.geometry:[];
      if(!geometry.length)continue;
      const distance=minGeometryDistanceKm(geometry,routeCoords);
      if(distance>radiusKm)continue;
      const key=ref;
      const seg={wayId:el.id,coords:geometry.map(g=>[g.lat,g.lon]),distance,name:tags.name||null};
      if(!byRef.has(key))byRef.set(key,{ref,name:tags.name||null,segments:[]});
      byRef.get(key).segments.push(seg);
    }
  }
  return [...byRef.values()].map(entry=>({
    ref:entry.ref,
    name:entry.name,
    sourceClass:'osm-highway-geometry-reference',
    sourceVerified:false,
    sourceType:'OpenStreetMap National Highway way geometry',
    sourceUrl:'https://www.openstreetmap.org/',
    note:'Real road geometry only. This carries no project or construction status — pair it with a cited official ongoing-project source (PIB release, Parliament reply, NHAI bidding-transparency data) before importing as a verified project.',
    segments:entry.segments.sort((a,b)=>a.distance-b.distance),
    closestDistanceKm:Math.min(...entry.segments.map(s=>s.distance))
  })).sort((a,b)=>a.closestDistanceKm-b.closestDistanceKm);
}

function routeTouchesTelangana(routeCoords){return routeCoords.some(([lat,lng])=>lat>=15.5&&lat<=19.9&&lng>=77.0&&lng<=81.8);}
function arcgisGeometryToProjectGeometry(g){
  if(!g)return null;
  if(Array.isArray(g.paths)&&g.paths.length){return g.paths.length===1?{type:'LineString',coordinates:g.paths[0]}:{type:'MultiLineString',coordinates:g.paths};}
  if(Number.isFinite(g.x)&&Number.isFinite(g.y))return {type:'Point',coordinates:[g.x,g.y]};
  return null;
}
function geometryCoordsForDistance(geometry){
  if(!geometry)return [];
  if(geometry.type==='Point')return [[Number(geometry.coordinates[1]),Number(geometry.coordinates[0])]];
  if(geometry.type==='LineString')return geometry.coordinates.map(([lng,lat])=>[Number(lat),Number(lng)]);
  if(geometry.type==='MultiLineString')return geometry.coordinates.flatMap(line=>line.map(([lng,lat])=>[Number(lat),Number(lng)]));
  return [];
}
async function fetchArcgisLayer(routeCoords,radiusKm,layerId,statusLabel,layerLabel){
  if(!routeTouchesTelangana(routeCoords))return [];
  const lats=routeCoords.map(p=>p[0]), lngs=routeCoords.map(p=>p[1]);
  const dLat=radiusKm/111.32, dLng=radiusKm/(111.32*Math.max(.2,Math.cos((Math.min(19.9,Math.max(15.5,(Math.min(...lats)+Math.max(...lats))/2)))*Math.PI/180)));
  const envelope={xmin:Math.min(...lngs)-dLng,ymin:Math.min(...lats)-dLat,xmax:Math.max(...lngs)+dLng,ymax:Math.max(...lats)+dLat,spatialReference:{wkid:4326}};
  const params=new URLSearchParams({where:'1=1',geometry:JSON.stringify(envelope),geometryType:'esriGeometryEnvelope',inSR:'4326',spatialRel:'esriSpatialRelIntersects',outFields:'*',returnGeometry:'true',outSR:'4326',f:'json',resultRecordCount:'1000'});
  const url=`${TELANGANA_RNB_SERVICE}/${layerId}/query?${params}`;
  const r=await fetch(url,{headers:{'User-Agent':USER_AGENT},signal:AbortSignal.timeout(8000)}); if(!r.ok)throw new Error(`Telangana GIS layer ${layerId} returned HTTP ${r.status}`);
  const data=await r.json(); if(data.error)throw new Error(data.error.message||`Telangana GIS layer ${layerId} failed`);
  return (data.features||[]).map(f=>{const geometry=arcgisGeometryToProjectGeometry(f.geometry); if(!geometry)return null; const distance=minGeometryDistanceKm(geometryCoordsForDistance(geometry).map(([lat,lng])=>({lat,lon:lng})),routeCoords); if(distance>radiusKm)return null; const a=f.attributes||{}; const roadName=a.Road_Name||a.Name_of_the_Road||a.ROAD_NAME||a.Road_ID||a.GIS_ID||`Telangana ${layerLabel} feature ${a.OBJECTID||''}`; const district=a.Dist_Name||a.District_1||a.District||null; const mandal=a.Mandal_Nam||a.Mandal||null; const chainStart=a.Road_Chainage_Start??a.Chainage_Start??a.Start_Chainage??null; const chainEnd=a.Road_Chainage_End??a.Chainage_End??a.End_Chainage??null; return {id:`TG-RNB-${layerId}-${a.OBJECTID||a.GIS_ID||Math.random().toString(36).slice(2)}`,name:roadName,type:'Road / Highway',ministry:'Government of Telangana',sector:'Transport',state:'Telangana',status:statusLabel,statusEvidence:`Official Telangana R&B/TGRAC GIS ${layerLabel} layer`,risk:null,riskScore:null,progress:null,financialProgress:null,cost:null,originalCost:null,expenditure:null,lat:geometry.type==='Point'?geometry.coordinates[1]:geometryCoordsForDistance(geometry)[0]?.[0],lng:geometry.type==='Point'?geometry.coordinates[0]:geometryCoordsForDistance(geometry)[0]?.[1],geometry,location:[district,mandal].filter(Boolean).join(', ')||'Telangana',district,mandal,roadId:a.Road_ID||null,chainageStart:chainStart,chainageEnd:chainEnd,lengthKm:a.Length_km??null,distance,overlap:distance<=0.5?'On / overlapping route':'Near route',sourceType:'Official Telangana State GIS',sourceClass:'official-state-gis',sourceVerified:true,routeEligible:true,sourceUrl:`${TELANGANA_RNB_SERVICE}/${layerId}`,locationPrecision:geometry.type==='Point'?'point':'line/geometry',lastUpdated:new Date().toISOString(),costImpactVerified:false};}).filter(Boolean);
}
async function fetchTelanganaOfficialProjects(routeCoords,radiusKm=2){
  if(!routeTouchesTelangana(routeCoords))return {projects:[],available:true,error:null};
  try{
    const [ongoing,ongoingGp,planned]=await Promise.all([fetchArcgisLayer(routeCoords,radiusKm,19,'Ongoing','Ongoing PR road'),fetchArcgisLayer(routeCoords,radiusKm,16,'Ongoing GP Connectivity','Ongoing Gram Panchayat connectivity'),fetchArcgisLayer(routeCoords,radiusKm,20,'Planned','Proposed PR road')]);
    const all=[...ongoing,...ongoingGp,...planned]; const seen=new Set(); return {projects:all.filter(p=>!seen.has(p.id)&&seen.add(p.id)).sort((a,b)=>a.distance-b.distance),available:true,error:null};
  }catch(e){return {projects:[],available:false,error:e.message||'Telangana state GIS unavailable'};}
}


const paimanaGeoCache=new Map();
function routePlaceHints(start,end){
  return [...new Set(String(start+' '+end).toLowerCase().split(/[^a-z0-9]+/).filter(x=>x.length>=4))];
}
async function geocodePaimanaCandidates(rows,start,end,routeCoords,radiusKm){
  const hints=routePlaceHints(start,end);
  // Search the complete PAIMANA registry first. This is an approximate locality
  // association only; it is never treated as project GIS geometry.
  const prefiltered=rows.some(p=>Array.isArray(p.matchTokens)&&p.matchTokens.length);
  const candidates=(prefiltered?rows:(hints.length?rows.filter(p=>{
    const text=String([p.name,p.state,p.sector,p.ministry].filter(Boolean).join(' ')).toLowerCase();
    return hints.some(h=>text.includes(h));
  }):rows)).filter(p=>/ongoing|under construction|construction started/i.test(String(p.status||'')));
  const out=[];
  // Resolve only a small, ranked set of route candidates. The public Nominatim
  // service is limited to one request/second, so the old parallel 60-request burst
  // routinely timed out and left every PAIMANA card without a map point. Results are
  // cached and deliberately marked approximate because PAIMANA itself does not publish
  // universal project GPS geometry in this snapshot.
  const ranked=[...candidates].sort((a,b)=>(b.matchStrength||0)-(a.matchStrength||0));
  const geocodedIds=new Set();
  // First resolve records whose names contain a known place from the local index.
  // This path is instantaneous and keeps the UI populated even when public geocoding is offline.
  for(const p of ranked){
    const g=localProjectPlaceAnchor(p.name);
    if(!g)continue;
    const distance=routeDistance(g,routeCoords);
    if(distance>radiusKm)continue;
    const title=String(p.name||''),lower=title.toLowerCase();
    const type=lower.includes('flyover')||lower.includes('elevated corridor')?'Flyover / Elevated Road':lower.includes('bridge')||lower.includes('rob')?'Bridge':lower.includes('pipeline')?'Water / Pipeline':lower.includes('rail')||lower.includes('metro')?'Rail / Metro':lower.includes('highway')||lower.includes('road')||lower.includes('lane')?'Road / Highway':'Infrastructure';
    const kmMatch=title.match(/(?:length|km|chainage)[^0-9]{0,12}(\d+(?:\.\d+)?)\s*(?:km)?/i);
    out.push({...p,lat:g.lat,lng:g.lng,distance,overlap:distance<=0.5?'On / overlapping route':'Near route',routeEligible:false,sourceClass:'paimana-location-candidate',sourceVerified:false,sourceType:'PAIMANA April 2026 + offline place-name anchor',type,location:g.label,lengthKm:kmMatch?Number(kmMatch[1]):null,locationPrecision:'approximate place-name anchor (not project GIS geometry)',dataConfidence:null,risk:p.risk||'Not available',riskScore:null,status:p.status||'Ongoing',agency:p.agency||p.ministry||null,recommendation:'Review schedule, cost and route-interface coordination before the next milestone.',statusEvidence:'Official PAIMANA portfolio record; map point is an approximate place-name association and is not proof of exact project footprint.',note:'Approximate monitoring candidate only. Use authoritative project GIS geometry before treating the point as an exact project footprint.'});
    geocodedIds.add(String(p.id));
  }
  // Only a few unresolved candidates may use the external geocoder, one request at a time.
  // This keeps the route workflow responsive and respects the public service rate limit.
  const remoteWork=ranked.filter(p=>!geocodedIds.has(String(p.id))).slice(0,4);
  let lastRequestAt=0;
  for(const p of remoteWork){
    const key=p.id; let g=paimanaGeoCache.get(key);
    try{
      if(!g){
        const wait=Math.max(0,1050-(Date.now()-lastRequestAt));
        if(wait) await new Promise(r=>setTimeout(r,wait));
        lastRequestAt=Date.now();
        const query=String(p.name||'').slice(0,180);
        const u='https://nominatim.openstreetmap.org/search?format=json&limit=1&countrycodes=in&q='+encodeURIComponent(query);
        const r=await fetch(u,{headers:{'User-Agent':USER_AGENT,'Accept-Language':'en-IN,en'},signal:AbortSignal.timeout(2500)});
        if(!r.ok) continue;
        const x=await r.json(); if(!x.length) continue;
        const lat=Number(x[0].lat),lng=Number(x[0].lon); if(!withinIndiaBbox(lat,lng))continue;
        g={lat,lng,label:x[0].display_name}; paimanaGeoCache.set(key,g);
      }
    }catch{continue;}
    const distance=routeDistance(g,routeCoords); if(distance>radiusKm)continue;
    const title=String(p.name||''),lower=title.toLowerCase();
    const type=lower.includes('flyover')||lower.includes('elevated corridor')?'Flyover / Elevated Road':lower.includes('bridge')||lower.includes('rob')?'Bridge':lower.includes('pipeline')?'Water / Pipeline':lower.includes('rail')||lower.includes('metro')?'Rail / Metro':lower.includes('highway')||lower.includes('road')||lower.includes('lane')?'Road / Highway':'Infrastructure';
    const kmMatch=title.match(/(?:length|km|chainage)[^0-9]{0,12}(\d+(?:\.\d+)?)\s*(?:km)?/i);
    out.push({...p,lat:g.lat,lng:g.lng,distance,overlap:distance<=0.5?'On / overlapping route':'Near route',routeEligible:false,sourceClass:'paimana-location-candidate',sourceVerified:false,sourceType:'PAIMANA April 2026 + place-name geocoding',type,location:g.label,lengthKm:kmMatch?Number(kmMatch[1]):null,locationPrecision:'approximate place-name match (not project GIS geometry)',dataConfidence:null,risk:p.risk||'Not available',riskScore:null,status:p.status||'Ongoing',agency:p.agency||p.ministry||null,recommendation:'Review schedule, cost and route-interface coordination before the next milestone.',statusEvidence:'Official PAIMANA portfolio record; map point is an approximate place-name association and is not proof of exact project footprint.',note:'Approximate monitoring candidate only. Use authoritative project GIS geometry before treating the point as an exact project footprint.'});
    geocodedIds.add(String(p.id));
  }
  for(const p of candidates){
    if(geocodedIds.has(String(p.id)))continue;
    out.push({...p,lat:null,lng:null,distance:null,overlap:'Route/locality match',routeEligible:false,sourceClass:'paimana-location-candidate',sourceVerified:false,locationPrecision:'route/locality text match (project GIS geometry not published)',verificationStatus:'PAIMANA Candidate – Geographic verification required',note:'Real PAIMANA portfolio record matched to the selected route by text. No project coordinate was invented.'});
  }
  return out.sort((a,b)=>(a.distance??999999)-(b.distance??999999));
}

function enrichRouteProject(p){
  if(p.risk && Number.isFinite(Number(p.riskScore))) return p;
  const d=Number(p.distance); const overlap=p.overlap==='On / overlapping route';
  const t=String(p.type||'').toLowerCase();
  let score=overlap?62:d<=1?46:d<=2?30:18;
  if(t.includes('bridge'))score+=12;
  if(t.includes('rail'))score+=8;
  if(t.includes('road')||t.includes('highway'))score+=8;
  score=Math.min(100,score);
  const risk=score>=65?'High':score>=40?'Medium':'Low';
  const delayProbability=Math.min(92,Math.round(18+score*.72));
  const predictedDelayMinutes=Math.round((overlap?12:d<=1?7:d<=2?3:1)+(risk==='High'?6:risk==='Medium'?3:0));
  return {...p,risk,riskScore:score,riskBasis:'Route-impact model based on verified proximity, project type and construction evidence',
    delayProbability,predictedDelayMinutes,trafficImpact:risk};
}

function routeImpact(projects,routeDistanceKm,durationSec){
  const evidenceProjects=projects.filter(p=>p?.isDemo!==true&&p?.sourceClass!=='route-demo');
  const verified=evidenceProjects.filter(p=>p.sourceVerified===true).length;
  const high=evidenceProjects.filter(p=>p.risk==='High').length;
  const medium=evidenceProjects.filter(p=>p.risk==='Medium').length;
  const overlapping=evidenceProjects.filter(p=>p.overlap==='On / overlapping route').length;
  let score=Math.min(100,overlapping*22+high*16+medium*8+Math.min(20,projects.length*2));
  const level=score>=65?'HIGH':score>=30?'MEDIUM':'LOW';
  const delayMin=Math.max(0,Math.round((overlapping*8+high*6+medium*3)+(routeDistanceKm>300?2:0)));
  return {score,level,projects:evidenceProjects.length,totalDisplayedProjects:projects.length,verifiedProjects:verified,overlapping,high,medium,estimatedAdditionalDelayMinutes:delayMin,
    trafficProvider:'Infrastructure-impact forecast',confidence:verified?Math.min(90,55+verified*5):35,
    explanation:projects.length?`Estimated route disruption from ${projects.length} mapped/monitored construction records within the selected ${ROUTE_CORRIDOR_KM} km corridor on each side of the route.`:'No mapped construction was found in the selected corridor from the currently available sources.'};
}

// Route results are intentionally not cached. Every Find Route request must re-query connected project sources.
function normalizeProjectForRegistry(p){
  const geometry=p.geometry;
  let distance=Infinity;
  return {p,distance};
}
// India's real geographic extent (mainland + islands), used as a hard sanity filter.
// countrycodes=in is a Nominatim *hint*, not a guarantee — under rate-limiting, ambiguous
// names, or provider quirks it can still return a result outside this box (or with no
// address.country_code at all). Anything outside this box is rejected outright rather
// than silently accepted, which is what previously let a bad match slip through and
// produce a >10,000 km "route" between two Indian town names.
const INDIA_BBOX={minLat:6.5,maxLat:37.6,minLng:68.0,maxLng:97.5};
function withinIndiaBbox(lat,lng){const la=Number(lat),lo=Number(lng);return Number.isFinite(la)&&Number.isFinite(lo)&&la>=INDIA_BBOX.minLat&&la<=INDIA_BBOX.maxLat&&lo>=INDIA_BBOX.minLng&&lo<=INDIA_BBOX.maxLng;}
// Small offline place index used only as an approximate fallback when the live geocoder
// is unavailable. It is never presented as authoritative project geometry.
const ROUTE_PLACE_ANCHORS={
  hyderabad:[17.385044,78.486671],shamshabad:[17.2514,78.3802],sangareddy:[17.6248,78.0833],zaheerabad:[17.6814,77.6074],kamareddy:[18.3215,78.3418],nizamabad:[18.6725,78.0941],adilabad:[19.6641,78.5320],medchal:[17.6299,78.4814],warangal:[17.9689,79.5941],vijayawada:[16.5062,80.6480],guntur:[16.3067,80.4365],nalgonda:[17.0575,79.2684],suryapet:[17.1405,79.6200],karimnagar:[18.4386,79.1288],khammam:[17.2473,80.1514],kodad:[16.9948,80.9182],miryalaguda:[16.8737,79.5625],jaggayyapeta:[16.8936,80.0970],ibrahimpatnam:[16.6000,80.5000],choutuppal:[17.2500,78.9000],yadadri:[17.5833,78.9500],machilipatnam:[16.1875,81.1389],tenali:[16.2428,80.6400],rajahmundry:[17.0005,81.8040],kadapa:[14.4673,78.8242],kurnool:[15.8281,78.0373],nagpur:[21.1458,79.0882],mumbai:[19.0760,72.8777],pune:[18.5204,73.8567],bengaluru:[12.9716,77.5946],chennai:[13.0827,80.2707],delhi:[28.6139,77.2090],jaipur:[26.9124,75.7873],ahmedabad:[23.0225,72.5714],lucknow:[26.8467,80.9462],bhubaneswar:[20.2961,85.8245],visakhapatnam:[17.6868,83.2185],tirupati:[13.6288,79.4192],"hyderabad-bangalore":[17.3850,78.4867],"hyderabad-nagpur":[17.3850,78.4867]};
function localProjectPlaceAnchor(name){
  const text=String(name||'').toLowerCase();
  let best=null;
  for(const [key,coords] of Object.entries(ROUTE_PLACE_ANCHORS)){
    if(text.includes(key)&&(!best||key.length>best.key.length))best={key,coords};
  }
  return best?{lat:best.coords[0],lng:best.coords[1],label:`${best.key} (approximate project-name match)`}:null;
}
const geocodeCache=new Map();
const GEOCODE_CACHE_TTL=30*60*1000;
function getGeocodeCache(key){const v=geocodeCache.get(key);if(!v)return null;if(Date.now()-v.time>GEOCODE_CACHE_TTL){geocodeCache.delete(key);return null;}return v.data;}
function setGeocodeCache(key,data){geocodeCache.set(key,{time:Date.now(),data});return data;}
function withTimeout(promise,ms,fallback){return Promise.race([promise,new Promise(resolve=>setTimeout(()=>resolve(fallback),ms))]);}
async function geocodePlace(q){
  const query=String(q||'').trim();
  if(!query)throw Error('Location is required');
  const cached=getGeocodeCache(query.toLowerCase());
  if(cached)return cached;
  // Deterministic fallback for frequently used Indian places and smaller towns.
  // This prevents a temporary geocoder miss or an ambiguous short name from
  // breaking an otherwise valid route. Coordinates are locality coordinates,
  // not project coordinates.
  const aliasKey=query.toLowerCase().replace(/\s+/g,' ').replace(/,\s*india$/,'').trim();
  const normalizedKey=aliasKey.replace(/[^a-z0-9, ]/g,'').replace(/\badiabad\b/g,'adilabad').replace(/\bkandlakoyya\b/g,'kandlakoya');
  const aliases={
    'hyderabad':{lat:17.385044,lng:78.486671,name:'Hyderabad',locality:'Hyderabad',district:'Hyderabad',state:'Telangana'},
    'hyderabad, telangana':{lat:17.385044,lng:78.486671,name:'Hyderabad',locality:'Hyderabad',district:'Hyderabad',state:'Telangana'},
    'delhi':{lat:28.613939,lng:77.209023,name:'Delhi',locality:'Delhi',district:'New Delhi',state:'Delhi'},
    'new delhi':{lat:28.613939,lng:77.209023,name:'New Delhi',locality:'New Delhi',district:'New Delhi',state:'Delhi'},
    'delhi, india':{lat:28.613939,lng:77.209023,name:'Delhi',locality:'Delhi',district:'New Delhi',state:'Delhi'},
    'new delhi, india':{lat:28.613939,lng:77.209023,name:'New Delhi',locality:'New Delhi',district:'New Delhi',state:'Delhi'},
    'mumbai':{lat:19.076,lng:72.8777,name:'Mumbai',locality:'Mumbai',district:'Mumbai City',state:'Maharashtra'},
    'pune':{lat:18.5204,lng:73.8567,name:'Pune',locality:'Pune',district:'Pune',state:'Maharashtra'},
    'bengaluru':{lat:12.9716,lng:77.5946,name:'Bengaluru',locality:'Bengaluru',district:'Bengaluru Urban',state:'Karnataka'},
    'bangalore':{lat:12.9716,lng:77.5946,name:'Bengaluru',locality:'Bengaluru',district:'Bengaluru Urban',state:'Karnataka'},
    'chennai':{lat:13.0827,lng:80.2707,name:'Chennai',locality:'Chennai',district:'Chennai',state:'Tamil Nadu'},
    'kolkata':{lat:22.5726,lng:88.3639,name:'Kolkata',locality:'Kolkata',district:'Kolkata',state:'West Bengal'},
    'ahmedabad':{lat:23.0225,lng:72.5714,name:'Ahmedabad',locality:'Ahmedabad',district:'Ahmedabad',state:'Gujarat'},
    'jaipur':{lat:26.9124,lng:75.7873,name:'Jaipur',locality:'Jaipur',district:'Jaipur',state:'Rajasthan'},
    'lucknow':{lat:26.8467,lng:80.9462,name:'Lucknow',locality:'Lucknow',district:'Lucknow',state:'Uttar Pradesh'},
    'bhubaneswar':{lat:20.2961,lng:85.8245,name:'Bhubaneswar',locality:'Bhubaneswar',district:'Khordha',state:'Odisha'},
    'visakhapatnam':{lat:17.6868,lng:83.2185,name:'Visakhapatnam',locality:'Visakhapatnam',district:'Visakhapatnam',state:'Andhra Pradesh'},
    'tirupati':{lat:13.6288,lng:79.4192,name:'Tirupati',locality:'Tirupati',district:'Tirupati',state:'Andhra Pradesh'},
    'warangal':{lat:17.9689,lng:79.5941,name:'Warangal',locality:'Warangal',district:'Warangal',state:'Telangana'},
    'nirmal':{lat:19.0968,lng:78.3444,name:'Nirmal',locality:'Nirmal',district:'Nirmal',state:'Telangana'},
    'vijayawada':{lat:16.506174,lng:80.648015,name:'Vijayawada',locality:'Vijayawada',district:'NTR',state:'Andhra Pradesh'},
    'vijayawada, andhra pradesh':{lat:16.506174,lng:80.648015,name:'Vijayawada',locality:'Vijayawada',district:'NTR',state:'Andhra Pradesh'},
    'kamareddy':{lat:18.3215,lng:78.3418,name:'Kamareddy',locality:'Kamareddy',district:'Kamareddy',state:'Telangana'},
    'nizamabad':{lat:18.6725,lng:78.0941,name:'Nizamabad',locality:'Nizamabad',district:'Nizamabad',state:'Telangana'},
    'lingampet':{lat:18.23969,lng:78.12993,name:'Lingampet',locality:'Lingampet',district:'Kamareddy',state:'Telangana'},
    'lingampet, kamareddy':{lat:18.23969,lng:78.12993,name:'Lingampet',locality:'Lingampet',district:'Kamareddy',state:'Telangana'},
    'lingampet, kamareddy, telangana':{lat:18.23969,lng:78.12993,name:'Lingampet',locality:'Lingampet',district:'Kamareddy',state:'Telangana'},
    'adilabad':{lat:19.6641,lng:78.532,name:'Adilabad',locality:'Adilabad',district:'Adilabad',state:'Telangana'},
    'adiabad':{lat:19.6641,lng:78.532,name:'Adilabad',locality:'Adilabad',district:'Adilabad',state:'Telangana'},
    'medchal':{lat:17.6299,lng:78.4814,name:'Medchal',locality:'Medchal',district:'Medchal-Malkajgiri',state:'Telangana'},
    'kompally':{lat:17.5448,lng:78.4882,name:'Kompally',locality:'Kompally',district:'Medchal-Malkajgiri',state:'Telangana'},
    'kandlakoya':{lat:17.59568,lng:78.48546,name:'Kandlakoya',locality:'Kandlakoya',district:'Medchal-Malkajgiri',state:'Telangana'},
    'kandlakoyya':{lat:17.59568,lng:78.48546,name:'Kandlakoya',locality:'Kandlakoya',district:'Medchal-Malkajgiri',state:'Telangana'}
  };
  if(aliases[aliasKey] || aliases[normalizedKey]){
    const a=aliases[aliasKey] || aliases[normalizedKey];
    return setGeocodeCache(query.toLowerCase(), [{...a,label:`${a.name}, ${a.district}, ${a.state}, India`,country:'India',country_code:'in',placeId:`local-${aliasKey}`,osmType:'local',placeType:'town',class:'place',address:{city:a.locality,district:a.district,state:a.state,country:'India',country_code:'in'},importance:1}]);
  }
  // Use a broad India-scoped search. The previous request used restrictive layer
  // parameters and then rejected otherwise valid city results too aggressively.
  const variants=[
    `${query}, India`,
    query,
    `${query}, Telangana, India`,
    `${query}, Andhra Pradesh, India`
  ];
  const all=[];
  for(const text of variants){
    try{
      const u='https://nominatim.openstreetmap.org/search?format=jsonv2&limit=10&addressdetails=1&namedetails=1&dedupe=1&countrycodes=in&q='+encodeURIComponent(text);
      const r=await fetch(u,{headers:{'User-Agent':USER_AGENT,'Accept-Language':'en-IN,en'},signal:AbortSignal.timeout(15000)});
      if(!r.ok)continue;
      const raw=await r.json();
      if(Array.isArray(raw))all.push(...raw);
      if(all.length>=10)break;
    }catch{}
  }
  const seen=new Set();
  const x=all.filter(v=>{
    const lat=Number(v.lat),lng=Number(v.lon);
    const key=`${lat.toFixed(6)},${lng.toFixed(6)}`;
    if(seen.has(key)||!withinIndiaBbox(lat,lng))return false;
    seen.add(key);
    const cc=String((v.address||{}).country_code||'').toLowerCase();
    // Bounding-box validation is the primary safeguard. If Nominatim omits
    // country_code, a coordinate inside India's bounds is still accepted.
    if(cc && cc!=='in')return false;
    return true;
  });
  if(!x.length)throw Error('Location not found in India: '+query);
  const ql=query.toLowerCase();
  const score=v=>{
    const a=v.address||{}, t=String(v.type||'').toLowerCase(), cls=String(v.class||'').toLowerCase();
    const display=String(v.display_name||'').toLowerCase(), name=String(v.name||'').toLowerCase();
    let s=Number(v.importance||0)*100;
    if(String(a.country_code||'').toLowerCase()==='in')s+=40;
    if(name===ql||display.startsWith(ql+','))s+=35;
    if(['village','town','city','municipality','district','county','suburb','neighbourhood','hamlet'].includes(t))s+=35;
    if(['place','boundary','highway','railway','amenity'].includes(cls))s+=8;
    if(a.state)s+=5; if(a.district||a.state_district||a.county)s+=5;
    if(t==='village'||t==='town'||t==='city')s+=8;
    return s;
  };
  const result=x.sort((a,b)=>score(b)-score(a)).map(v=>{
    const ad=v.address||{};
    const locality=ad.village||ad.town||ad.city||ad.municipality||ad.suburb||ad.neighbourhood||ad.hamlet||ad.county||v.name||query;
    const district=ad.state_district||ad.district||ad.county||null;
    const state=ad.state||null;
    return {lat:Number(v.lat),lng:Number(v.lon),label:v.display_name,name:v.name||locality,locality,district,state,country:ad.country||'India',placeId:v.osm_id,osmType:v.osm_type,placeType:v.type,class:v.class,address:ad,boundingbox:v.boundingbox||null,importance:v.importance||0};
  });
  return setGeocodeCache(query.toLowerCase(),result);
}

async function routeAnalysis(start,end,radiusKm=ROUTE_CORRIDOR_KM,selectedStart=null,selectedEnd=null){
  // Route matching is route-wide by design. The old 2 km hard cutoff is not used.
  // Exactness is determined by source geometry, while PAIMANA text/location matches are
  // clearly labelled as monitoring candidates when the PAIMANA snapshot lacks GIS geometry.
  radiusKm=Math.max(1,Math.min(ROUTE_CORRIDOR_KM,Number(radiusKm)||ROUTE_CORRIDOR_KM));
  // Route analysis is intentionally uncached: every Find Route request must perform a fresh source scan.
  const a=selectedStart||((await geocodePlace(start))[0]);
  const b=selectedEnd||((await geocodePlace(end))[0]);
  if(!a||!b)throw Error('Both locations must resolve to places in India');
  // Belt-and-suspenders: even a manually-selected candidate (selectedStart/selectedEnd,
  // passed straight from the frontend's suggestion list) must be inside India. This is
  // the last checkpoint before a routing request goes out.
  a.lat=Number(a.lat); a.lng=Number(a.lng); b.lat=Number(b.lat); b.lng=Number(b.lng);
  if(!withinIndiaBbox(a.lat,a.lng))throw Error(`"${start}" did not resolve to a location inside India.`);
  if(!withinIndiaBbox(b.lat,b.lng))throw Error(`"${end}" did not resolve to a location inside India.`);
  // OSRM expects coordinates in lon,lat order. Validate the returned geometry as well;
  // a malformed/incorrect provider response must never be rendered as a huge straight line.
  const directKm=hav(a,b);
  // India's own geographic diagonal (Kashmir to Kanyakumari) is well under 3,800 km, so any
  // straight-line distance beyond that between two "in India" geocodes means one of them is
  // wrong, even though it individually passed the bounding-box check above.
  const INDIA_MAX_SPAN_KM=3800;
  if(directKm>INDIA_MAX_SPAN_KM)throw Error(`"${start}" and "${end}" resolved to locations ${directKm.toFixed(0)} km apart, which is farther than India's own span. One of the two names likely matched the wrong place — try selecting a specific suggestion from the dropdown instead of the free-typed name.`);
  const u=`https://router.project-osrm.org/route/v1/driving/${encodeURIComponent(a.lng)},${encodeURIComponent(a.lat)};${encodeURIComponent(b.lng)},${encodeURIComponent(b.lat)}?overview=full&geometries=geojson&alternatives=false&steps=true&annotations=false`;
  const r=await fetch(u,{signal:AbortSignal.timeout(8000)}); if(!r.ok)throw Error('Routing service unavailable');
  const data=await r.json(); if(data.code!=='Ok'||!Array.isArray(data.routes)||!data.routes.length)throw Error('No road route found between the selected places');
  const rawRoutes=data.routes.slice(0,1).filter(rr=>rr?.geometry?.type==='LineString'&&Array.isArray(rr.geometry.coordinates)&&rr.geometry.coordinates.length>=2&&Number.isFinite(Number(rr.distance))&&Number.isFinite(Number(rr.duration)));
  if(!rawRoutes.length)throw Error('Routing service returned an invalid road geometry');
  const routes=rawRoutes.filter(rr=>{
    const c=rr.geometry.coordinates;
    const first={lat:Number(c[0][1]),lng:Number(c[0][0])};
    const last={lat:Number(c[c.length-1][1]),lng:Number(c[c.length-1][0])};
    const endpointError=Math.max(hav(a,first),hav(b,last));
    // A valid driving route should be reasonably close to the requested endpoints and
    // should not be orders of magnitude longer than the straight-line distance. The ratio
    // check alone isn't enough (it's self-consistent even if a/b are both wrong), so it's
    // combined with the absolute INDIA_MAX_SPAN_KM check above and an absolute road-distance
    // ceiling here — no real India driving route exceeds ~6,000 km on the actual road network.
    const maxRouteKm=Math.min(6000, Math.max(250, directKm*8+100));
    return endpointError<=25 && rr.distance/1000<=maxRouteKm;
  });
  if(!routes.length)throw Error(`Routing service returned an implausible route for the selected locations (straight-line distance ${directKm.toFixed(1)} km). Please retry.`);
  const registry=projectRouteRecords(); const options={};
  for(let i=0;i<routes.length;i++){
    const rr=routes[i],key=String.fromCharCode(65+i),coords=rr.geometry.coordinates.map(([lng,lat])=>[lat,lng]);
    // Fast path: return the road route and locally indexed verified geometry first.
    // External GIS/OSM/PAIMANA scans are performed by /route-live-projects in the
    // background so a slow public source can never delay the route itself.
    const stateGis={projects:[],available:true,error:null};
    const routeWorkRecords=fetchNationalGovernmentWorkRecords(coords,radiusKm);
    const verified=registry.map(p=>{
      let distance=Infinity; const geometry=p.geometry;
      if(geometry?.type==='Point'&&Array.isArray(geometry.coordinates))distance=routeDistance({lat:Number(geometry.coordinates[1]),lng:Number(geometry.coordinates[0])},coords);
      else if(geometry?.type==='LineString'&&Array.isArray(geometry.coordinates))distance=lineGeometryDistanceKm(geometry.coordinates.map(([lng,lat])=>[Number(lat),Number(lng)]),coords);
      else if(geometry?.type==='MultiLineString'&&Array.isArray(geometry.coordinates))for(const line of geometry.coordinates)distance=Math.min(distance,lineGeometryDistanceKm(line.map(([lng,lat])=>[Number(lat),Number(lng)]),coords));
      return {...p,distance};
    }).filter(p=>p.routeEligible===true&&p.distance<=radiusKm)
      .map(p=>({...p,overlap:p.distance<=0.5?'On / overlapping route':'Near route',progress:Number.isFinite(Number(p.progress))?Number(p.progress):null,costImpactVerified:p.costImpactVerified===true}));
    // Fast PAIMANA text candidates are attached immediately so the first response already
    // contains the full set of route-locality/road-reference candidates. Their exact map
    // position is not claimed until the background geographic verification completes.
    const stepNames=(rr.legs||[]).flatMap(leg=>(leg.steps||[]).map(st=>st.name).filter(Boolean));
    const roadNames=[...new Set(stepNames)].filter(Boolean).slice(0,80);
    const monitoringCandidates=fastPaimanaRouteCandidates(coords,radiusKm,start,end,roadNames).map(p=>enrichRouteProject({...p,verificationStatus:'PAIMANA Candidate – Geographic verification pending'}));
    let projects=[...verified,...routeWorkRecords].map(enrichRouteProject);
    projects=projects.sort((x,y)=>(x.distance??999)-(y.distance??999)).slice(0,50);
    const impact=routeImpact(projects,rr.distance/1000,rr.duration);
    options[key]={key,coords,distance:rr.distance/1000,duration:rr.duration,from:a,to:b,fromName:start,toName:end,projects,monitoringCandidates,constructionSource:{available:true,error:null,pending:true,message:'Live project-source scan continues in the background.'},stateGisSource:stateGis,impact,roadNames,
      nationalHighways:[],
      source:'OSRM driving route + verified government GIS + state GIS adapters + national government work registry + PAIMANA monitoring candidates + OpenStreetMap mapped construction',
      evidence:{matchedProjectRecords:verified.length,verifiedGIS:verified.filter(p=>p.sourceClass==='verified-government-gis').length,databaseRecords:verified.filter(p=>p.sourceClass==='project-database').length,governmentWorkRecords:projects.filter(p=>p.sourceClass==='government-work-record').length,osmMappedConstruction:projects.filter(p=>p.sourceClass==='mapped').length,stateGisProjects:projects.filter(p=>p.sourceClass==='official-state-gis').length,paimanaCandidates:monitoringCandidates.length},
      routing:{profile:'driving',alternativesRequested:0,routeRank:i+1,geometry:'GeoJSON full road geometry',steps:rr.legs?.flatMap(l=>l.steps||[]).length||0}};
  }
  const result={start:a,end:b,options,generatedAt:new Date().toISOString(),radiusKm,
    coverage:{country:'India',route:'OSRM driving route with India-only geocoding',verifiedRegistry:'Imported records with explicit Point/LineString/MultiLineString geometry are eligible; source class is retained so user-entered records are not presented as official government facts',osm:'Mapped construction evidence from OpenStreetMap; not treated as official government progress; searched across the route-wide supplementary envelope',distanceRules:{onRouteKm:0.5,routeSearchEnvelopeKm:radiusKm,corridorKm:ROUTE_CORRIDOR_KM,noFixedTwoKmLimit:false},
      exactness:'Verified GIS/state GIS/project-registry geometry is used for exact corridor matching. PAIMANA route candidates are shown separately as approximate monitoring matches when project GIS geometry is not published.',
      traffic:'This version calculates route impact from infrastructure evidence. It does not claim live Google traffic speeds without a licensed live-traffic provider.',
      paimana:'PAIMANA/OCMS is the official MoSPI/IPMD monitoring source for Central Sector infrastructure projects in scope. Public portfolio rows do not provide universal project GIS geometry, so route/locality matches are explicitly labelled as monitoring candidates rather than exact footprints.'},
    dataSources:{verifiedProjectCount:registry.length,routeProjectRecords:registry.length,osmMappedConstruction:true,nationalGovernmentWorkRegistry:loadGovernmentWorkRegistry().length,paimanaPublicDashboard:PAIMANA_URL,projectRegisterCount:db.projects.length,demoMode:false,minimumRouteProjects:0,routeCandidateFallback:'none — no synthetic route projects'}};
  return result;
}


function decodeHtml(s){return String(s||'').replace(/&nbsp;/g,' ').replace(/&amp;/g,'&').replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&#x2F;/g,'/');}
function cleanHtml(s){return decodeHtml(String(s||'').replace(/<[^>]*>/g,' ').replace(/\s+/g,' ').trim());}
function parseNumber(s){const n=Number(String(s||'').replace(/[,₹]/g,'').trim());return Number.isFinite(n)?n:null;}
function parsePaimanaRows(html){
  const rows=[]; const trRe=/<tr[^>]*>([\s\S]*?)<\/tr>/gi; let m;
  while((m=trRe.exec(html))){
    const cells=[]; const tdRe=/<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/gi; let c;
    while((c=tdRe.exec(m[1]))) cells.push(cleanHtml(c[1]));
    if(cells.length<10) continue;
    const joined=cells.join(' | ');
    if(!/Project Code|Project Name|Original Cost/i.test(joined) && /^\d+\s*\|/.test(joined)){
      const id=cells[3], name=cells[4];
      if(!id || !name || !/^\d+$/.test(id)) continue;
      rows.push({
        id:`PAIMANA-${id}`, projectCode:id, name,
        sector:cells[1]||null, ministry:cells[2]||null,
        originalCost:parseNumber(cells[5]), cost:parseNumber(cells[6]), expenditure:parseNumber(cells[7]),
        start:null, completion:cells[8]||null, revisedCompletion:cells[9]||null,
        sourceType:'PAIMANA public dashboard', sourceClass:'official-government', sourceVerified:true,
        routeEligible:false, locationPrecision:'not-provided-by-source', sourceUrl:PAIMANA_URL,
        lastUpdated:new Date().toISOString(), status:'Official portfolio record', progress:null,
        note:'Official PAIMANA portfolio metadata. Exact route matching requires separately verified GIS geometry.'
      });
    }
  }
  const seen=new Set(); return rows.filter(x=>!seen.has(x.id)&&seen.add(x.id));
}
async function syncPaimana(){
  const r=await fetch(PAIMANA_URL,{headers:{'User-Agent':USER_AGENT},signal:AbortSignal.timeout(30000)});
  if(!r.ok) throw new Error(`PAIMANA public dashboard returned HTTP ${r.status}`);
  const html=await r.text(); const rows=parsePaimanaRows(html);
  if(!rows.length) throw new Error('PAIMANA page was reachable but no project rows could be parsed. The public page structure may have changed. No existing data was overwritten.');
  const existingById=new Map(db.projects.map(p=>[p.id,p]));
  for(const row of rows) existingById.set(row.id,{...(existingById.get(row.id)||{}),...row});
  db.projects=[...existingById.values()]; save(); return {imported:rows.length,totalProjects:db.projects.length,source:PAIMANA_URL,syncedAt:new Date().toISOString(),note:'PAIMANA metadata imported. Geometry/progress fields are only shown when supplied by the authoritative source or a verified GIS import.'};
}
let paimanaLastSync=Date.now();
async function refreshPaimanaCacheIfStale(maxAgeMs=6*60*60*1000){
  if(db.projects.length && Date.now()-paimanaLastSync<maxAgeMs)return;
  try{
    const result=await Promise.race([
      syncPaimana(),
      new Promise((_,reject)=>setTimeout(()=>reject(new Error('PAIMANA refresh timeout')),10000))
    ]);
    paimanaLastSync=Date.now();
    return result;
  }catch(e){
    // Keep route analysis usable when the public dashboard is slow/unavailable.
    paimanaLastSync=Date.now();
    return {imported:0,error:e.message||'PAIMANA refresh unavailable'};
  }
}
function routeLocalityTokens(routeCoords){
  const samples=routeSamplePoints(routeCoords,20);
  if(samples.length<=40)return samples;
  return Array.from({length:40},(_,i)=>samples[Math.round(i*(samples.length-1)/39)]);
}
async function reverseRouteLocalities(routeCoords){
  const samples=routeSamplePoints(routeCoords,8);
  const maxSamples=16;
  const selected=samples.length>maxSamples?Array.from({length:maxSamples},(_,i)=>samples[Math.round(i*(samples.length-1)/(maxSamples-1))]):samples;
  const results=await Promise.all(selected.map(([lat,lon])=>fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&zoom=10&addressdetails=1&countrycodes=in`,{headers:{'User-Agent':USER_AGENT},signal:AbortSignal.timeout(1800)}).then(r=>r.ok?r.json():null).catch(()=>null)));
  const tokens=new Set();
  for(const x of results){
    const a=x?.address||{};
    for(const v of [a.village,a.town,a.city,a.municipality,a.county,a.district,a.state_district,a.state]){
      const t=String(v||'').toLowerCase().replace(/[^a-z0-9]+/g,' ').trim();
      if(t.length>=4) tokens.add(t);
    }
  }
  return [...tokens];
}
function routeMatchTokens(start,end,roadNames=[]){
  const roads=Array.isArray(roadNames)?roadNames:(roadNames==null?[]:[roadNames]);
  const raw=[start,end,...roads].filter(v=>v!==null&&v!==undefined).map(v=>String(v)).join(' ');
  const tokens=new Set();
  const cleaned=String(raw).toLowerCase().replace(/[^a-z0-9\- ]+/g,' ');
  for(const t of cleaned.split(/\s+/)){
    const x=t.trim();
    if(x.length>=5)tokens.add(x);
  }
  // Highway identifiers are particularly useful because many PAIMANA project names
  // contain the exact NH reference while the locality name is absent.
  const nh=cleaned.match(/\b(?:nh|sh)[\s-]*\d+[a-z]?\b/g)||[];
  nh.forEach(x=>tokens.add(x.replace(/\s+/g,'-')));
  const genericRouteWords=new Set(['india','telangana','andhra','pradesh','district','city','town','village','national','highway','road','roads','route','main','street','state','expressway','bypass','junction','crossing','unknown','unnamed']);
  return [...tokens].filter(x=>!genericRouteWords.has(x));
}
function fastPaimanaRouteCandidates(routeCoords,radiusKm,start='',end='',roadNames=[]){
  const tokens=routeMatchTokens(start,end,roadNames);
  if(!tokens.length||!db.projects.length)return [];
  const candidates=[];
  for(const p of db.projects){
    const source=String(p.sourceType||p.source||'').toLowerCase();
    if(!source.includes('paimana') && !String(p.id||'').startsWith('PAIMANA-'))continue;
    const text=String([p.name,p.state,p.ministry,p.sector,p.projectCode].filter(Boolean).join(' ')).toLowerCase();
    const hits=tokens.filter(t=>text.includes(t));
    if(!hits.length)continue;
    // Keep real April-2026 PAIMANA records, but score stronger route references first.
    const endpointHits=tokens.filter(t=>[String(start||''),String(end||'')].join(' ').toLowerCase().includes(t)&&text.includes(t));
    const roadText=(Array.isArray(roadNames)?roadNames:[roadNames]).filter(v=>v!==null&&v!==undefined).map(v=>String(v)).join(' ').toLowerCase();
    const roadHits=tokens.filter(t=>roadText.includes(t)&&text.includes(t));
    const score=hits.length*10+endpointHits.length*6+roadHits.length*4+(String(p.status||'').toLowerCase()==='ongoing'?5:0);
    candidates.push({...p,matchTokens:hits.slice(0,6),matchStrength:Math.min(1,0.55+hits.length*0.08),routeMatchScore:score,
      sourceClass:'paimana-location-candidate',sourceVerified:false,routeEligible:false,
      status:p.status||'Ongoing',statusEvidence:'PAIMANA April 2026 project record matched to a selected route locality/road reference. This is monitoring evidence, not project GIS geometry.',
      sourceType:'PAIMANA April 2026 + route road/locality text match',locationPrecision:'route text match (project GIS geometry not published in PAIMANA snapshot)',
      dataConfidence:Number.isFinite(Number(p.dataConfidence))?Number(p.dataConfidence):0.99});
  }
  return candidates.sort((a,b)=>Number(b.routeMatchScore||0)-Number(a.routeMatchScore||0));
}
async function fetchNationalPaimanaRouteCandidates(routeCoords,radiusKm,start='',end='',roadNames=[]){
  await refreshPaimanaCacheIfStale();
  if(!db.projects.length)return [];
  // Fast path: match PAIMANA project text against the selected endpoints and OSRM road
  // names (e.g. NH-63 / NH-765D). This avoids dozens of reverse-geocoding calls on every route.
  let candidates=fastPaimanaRouteCandidates(routeCoords,radiusKm,start,end,roadNames);
  // Fast local-place path: if the matched PAIMANA records contain a known locality,
  // return those approximate candidates immediately. Do not wait for public geocoding.
  const localCandidates=candidates.map(p=>{
    const g=localProjectPlaceAnchor(p.name); if(!g)return null;
    const distance=routeDistance(g,routeCoords); if(distance>radiusKm)return null;
    const title=String(p.name||''),lower=title.toLowerCase();
    const type=lower.includes('flyover')||lower.includes('elevated corridor')?'Flyover / Elevated Road':lower.includes('bridge')||lower.includes('rob')?'Bridge':lower.includes('pipeline')?'Water / Pipeline':lower.includes('rail')||lower.includes('metro')?'Rail / Metro':lower.includes('highway')||lower.includes('road')||lower.includes('lane')?'Road / Highway':'Infrastructure';
    const kmMatch=title.match(/(?:length|km|chainage)[^0-9]{0,12}(\d+(?:\.\d+)?)\s*(?:km)?/i);
    return {...p,lat:g.lat,lng:g.lng,distance,overlap:distance<=0.5?'On / overlapping route':'Near route',location:g.label,type,lengthKm:kmMatch?Number(kmMatch[1]):null,agency:p.agency||p.ministry||null,sourceClass:'paimana-location-candidate',sourceVerified:false,locationPrecision:'approximate offline place-name anchor',verificationStatus:'PAIMANA Candidate – approximate location; GIS verification required',recommendation:'Review schedule, cost and route-interface coordination before the next milestone.'};
  }).filter(Boolean);
  if(localCandidates.length>=6)return localCandidates.slice(0,8);
  if(!candidates.length){
    const localityTokens=await withTimeout(reverseRouteLocalities(routeCoords),2500,[]);
    if(localityTokens.length){
      candidates=db.projects.filter(p=>{
        const isPaimana=String(p.sourceType||'').toLowerCase().includes('paimana') || String(p.sourceClass||'').toLowerCase().includes('paimana');
        if(!isPaimana)return false;
        const text=String([p.name,p.state,p.ministry,p.sector].filter(Boolean).join(' ')).toLowerCase();
        return localityTokens.some(t=>text.includes(t));
      }).slice(0,30);
    }
  }
  if(!candidates.length)return [];
  // Geocode only the strongest April-2026 PAIMANA candidates, and keep the result explicitly approximate.
  // This runs in the live-source/background stage so route rendering remains fast.
  const resolved=await withTimeout(geocodePaimanaCandidates(candidates.slice(0,16),start,end,routeCoords,radiusKm),6000,[]);
  if(Array.isArray(resolved)&&resolved.length){
    const byId=new Map();
    [...localCandidates,...resolved].forEach(p=>byId.set(String(p.id),p));
    return [...byId.values()].sort((a,b)=>(Number(b.routeMatchScore||0)-Number(a.routeMatchScore||0)) || ((a.distance??999)-(b.distance??999))).slice(0,8);
  }
  // Offline/text fallback: preserve the real PAIMANA records as cards even if the
  // external geocoder is unavailable. Local place-name anchors may provide an
  // approximate marker; records with no anchor remain card-only rather than invented.
  return candidates.map(p=>{const g=localProjectPlaceAnchor(p.name); return g?{...p,lat:g.lat,lng:g.lng,distance:routeDistance(g,routeCoords),overlap:routeDistance(g,routeCoords)<=0.5?'On / overlapping route':'Near route',location:g.label,locationPrecision:'approximate offline place-name anchor',verificationStatus:'PAIMANA Candidate – approximate location; GIS verification required'}:{...p,lat:null,lng:null,distance:null,overlap:'Route/locality match',locationPrecision:'route text match; no project GIS coordinate'};});
}

function projectRouteRecords(){
  return loadVerifiedGeoJSON().filter(p=>p.routeEligible===true&&p.sourceVerified===true);
}
function loadGovernmentWorkRegistry(){
  const file=path.join(STORAGE_DIR,'government-work-records.geojson');
  try{
    const raw=JSON.parse(fs.readFileSync(file,'utf8'));
    return (raw.features||[]).map(f=>({...(f.properties||{}),geometry:f.geometry,sourceClass:f.properties?.sourceClass||'government-work-record',sourceVerified:false,routeEligible:true}));
  }catch{return []}
}
function geometryDistanceForProject(p,routeCoords){
  const g=p.geometry;
  if(g?.type==='Point')return routeDistance({lat:Number(g.coordinates[1]),lng:Number(g.coordinates[0])},routeCoords);
  if(g?.type==='LineString')return lineGeometryDistanceKm(g.coordinates.map(([lng,lat])=>[Number(lat),Number(lng)]),routeCoords);
  if(g?.type==='MultiLineString')return Math.min(...g.coordinates.map(line=>lineGeometryDistanceKm(line.map(([lng,lat])=>[Number(lat),Number(lng)]),routeCoords)));
  if(Number.isFinite(Number(p.lat))&&Number.isFinite(Number(p.lng)))return routeDistance({lat:Number(p.lat),lng:Number(p.lng)},routeCoords);
  return Infinity;
}
function fetchNationalGovernmentWorkRecords(routeCoords,radiusKm=2){
  return loadGovernmentWorkRegistry().map(p=>({...p,distance:geometryDistanceForProject(p,routeCoords)}))
    .filter(p=>p.distance<=radiusKm)
    .map(p=>({...p,overlap:p.distance<=0.5?'On / overlapping route':'Near route',costImpactVerified:false}));
}

// No synthetic route fallback is used. National PAIMANA records without verified
// project geometry remain portfolio/monitoring candidates and are not exact GIS matches.
// Route results must be geographically supported by a verified geometry, configured work
// record, official state GIS feature, or clearly-labelled OSM mapped construction.

const server=http.createServer(async(req,res)=>{try{if(req.method==='OPTIONS'){res.writeHead(204,{'access-control-allow-origin':'*','access-control-allow-methods':'GET,POST,PATCH,DELETE,OPTIONS','access-control-allow-headers':'Content-Type, Authorization'});return res.end()}const u=new URL(req.url,`http://${req.headers.host}`);if(req.method==='GET'&&u.pathname==='/api/version')return send(res,200,{version:'india-wide-routing-final-v2',backend:'Infra Risk Radar',geocoder:'India-scoped multi-variant geocoder'});if(req.method==='GET'&&u.pathname==='/api/health')return send(res,200,{ok:true,service:'Infra Risk Radar',version:'7.0',coverage:'India-wide route analysis',demoMode:false,routeDemoFallback:false,minimumRouteProjects:0,projectRegistryCount:db.projects.length,verifiedProjectCount:loadVerifiedGeoJSON().length,externalServices:['Nominatim','OSRM','Overpass','PAIMANA public dashboard','state GIS adapters','national government work registry'],time:new Date().toISOString()});if(req.method==='GET'&&u.pathname==='/api/auth/status')return send(res,200,{keyExists:Boolean(auth.adminKeyHash)});
if(req.method==='POST'&&u.pathname==='/api/auth/key/generate'){
  const user=currentUser(req);
  if(auth.adminKeyHash && (!user||user.role!=='Administrator'))return send(res,403,{error:'Administrator authentication required to rotate the administrator key.'});
  const key=makeAdminKey(); auth.adminKeyHash=hashSecret(key); saveAuth();
  return send(res,200,{ok:true,key,firstSetup:!user});
}
if(req.method==='POST'&&u.pathname==='/api/auth/register'){
  let body='';for await(const ch of req)body+=ch;const b=JSON.parse(body||'{}');
  const role=b.role==='Administrator'?'Administrator':'General User';
  if(!b.name||!b.email||!b.password||String(b.password).length<6)return send(res,400,{error:'Name, email and a password of at least 6 characters are required.'});
  if(auth.users.some(x=>x.email.toLowerCase()===String(b.email).toLowerCase()))return send(res,409,{error:'An account with this email already exists.'});
  if(role==='Administrator'){
    if(!auth.adminKeyHash)return send(res,400,{error:'Generate the administrator key first.'});
    if(!b.adminKey||!verifySecret(b.adminKey,auth.adminKeyHash))return send(res,403,{error:'Invalid administrator key. Authentication failed.'});
    if(auth.users.some(x=>x.role==='Administrator'))return send(res,403,{error:'An administrator already exists. Administrator accounts can only be added by an authenticated administrator.'});
  }
  if(role==='Administrator' && currentUser(req)?.role!=='Administrator' && auth.users.some(x=>x.role==='Administrator'))return send(res,403,{error:'Administrator authentication required.'});
  const user={id:crypto.randomUUID(),name:String(b.name).trim(),email:String(b.email).trim().toLowerCase(),passwordHash:hashSecret(b.password),role,createdAt:new Date().toISOString()};
  auth.users.push(user);saveAuth();const token=makeSession(user);return send(res,201,{user:{id:user.id,name:user.name,email:user.email,role:user.role},token});
}
if(req.method==='POST'&&u.pathname==='/api/auth/google'){
  try{
    const b=await readBody(req);
    const profile=await verifyGoogleCredential(b.credential);
    const requestedRole=b.role==='Administrator'?'Administrator':'General User';
    if(requestedRole==='Administrator'){
      if(!GOOGLE_ADMIN_EMAILS.has(profile.email))return send(res,403,{error:'This Google account is not authorized for Administrator access.'});
      if(!auth.adminKeyHash||!b.adminKey||!verifySecret(b.adminKey,auth.adminKeyHash))return send(res,403,{error:'Valid Administrator Key is required for Google Administrator sign-in.'});
    }
    let user=auth.users.find(x=>x.email===profile.email);
    if(user){
      if(requestedRole==='Administrator' && user.role!=='Administrator')return send(res,403,{error:'This Google account is verified, but its portal account is not provisioned as Administrator.'});
      if(requestedRole==='General User' && user.role==='Administrator'){
        user={...user,role:'General User'};
      }
      user.name=profile.name||user.name;
    }else{
      if(requestedRole==='Administrator' && auth.users.some(x=>x.role==='Administrator'))return send(res,403,{error:'Administrator account already exists. Ask an authenticated Administrator to provision this Google account.'});
      user={id:crypto.randomUUID(),name:profile.name,email:profile.email,passwordHash:null,role:requestedRole,googleSub:profile.sub,googlePicture:profile.picture,createdAt:new Date().toISOString()};
      auth.users.push(user);
    }
    if(user.googleSub!==profile.sub){user.googleSub=profile.sub;}
    if(profile.picture)user.googlePicture=profile.picture;
    saveAuth();
    const token=makeSession(user);
    return send(res,200,{user:{id:user.id,name:user.name,email:user.email,role:user.role,google:true},token});
  }catch(e){return send(res,400,{error:e.message||'Google sign-in failed.'})}
}

if(req.method==='POST'&&u.pathname==='/api/auth/login'){
  let body='';for await(const ch of req)body+=ch;const b=JSON.parse(body||'{}');
  const role=b.role==='Administrator'?'Administrator':'General User';const user=auth.users.find(x=>x.email===String(b.email||'').trim().toLowerCase()&&x.role===role);
  if(!user||!verifySecret(b.password, user.passwordHash))return send(res,401,{error:'Invalid login credentials.'});
  if(role==='Administrator' && (!auth.adminKeyHash||!b.adminKey||!verifySecret(b.adminKey,auth.adminKeyHash)))return send(res,403,{error:'Invalid administrator key. Authentication failed.'});
  const token=makeSession(user);return send(res,200,{user:{id:user.id,name:user.name,email:user.email,role:user.role},token});
}
if(req.method==='POST'&&u.pathname==='/api/auth/verify-key'){
  const user=currentUser(req);if(!user||user.role!=='Administrator')return send(res,403,{error:'Administrator authentication required.'});
  let body='';for await(const ch of req)body+=ch;const b=JSON.parse(body||'{}');
  if(!auth.adminKeyHash||!b.adminKey||!verifySecret(b.adminKey,auth.adminKeyHash))return send(res,403,{error:'Invalid administrator key. Authentication failed.'});
  return send(res,200,{ok:true});
}
if(req.method==='POST'&&u.pathname==='/api/auth/logout'){
  const h=String(req.headers.authorization||''); if(h.startsWith('Bearer ')){auth.sessions=auth.sessions.filter(x=>x.token!==h.slice(7));saveAuth()} return send(res,200,{ok:true});
}
if(req.method==='GET'&&u.pathname==='/api/auth/me'){
  const user=currentUser(req);if(!user)return send(res,401,{error:'Authentication required'});return send(res,200,{user:{id:user.id,name:user.name,email:user.email,role:user.role}});
}
if(req.method==='GET'&&u.pathname==='/api/projects')return send(res,200,db.projects.map(p=>({...p,plannedValue:approvedPlannedValue(p)})));
if(req.method==='GET'&&u.pathname.startsWith('/api/projects/')&&!u.pathname.endsWith('/planned-value')){
  const id=decodeURIComponent(u.pathname.slice('/api/projects/'.length));
  const project=db.projects.find(x=>String(x.id)===id);
  if(!project)return send(res,404,{error:'Project not found'});
  const plannedValue=approvedPlannedValue(project);
  return send(res,200,{id:project.id,name:project.name,plannedValue,earnedValue:Number(project.cost||project.revisedCost||0)*Number(project.progress||0)/100,actualCost:Number(project.expenditure||0),plannedValueAvailable:plannedValue!==null});
}
if(req.method==='GET'&&u.pathname.startsWith('/api/projects/')&&u.pathname.endsWith('/planned-value')){
  const id=decodeURIComponent(u.pathname.slice('/api/projects/'.length,-'/planned-value'.length));
  const project=db.projects.find(x=>String(x.id)===id);
  if(!project)return send(res,404,{error:'Project not found'});
  const plannedValue=approvedPlannedValue(project);
  return send(res,200,{projectId:project.id,plannedValue,available:plannedValue!==null,currency:'INR',unit:'Cr'});
}
if(req.method==='GET'&&u.pathname==='/api/alerts')return send(res,200,deriveAlerts());
if(req.method==='GET'&&u.pathname==='/api/audit-log'){const user=currentUser(req);if(!user)return send(res,401,{error:'Authentication required'});return send(res,200,{entries:db.auditLog||[]})};if(req.method==='GET'&&u.pathname==='/api/portfolio-insights'){const metrics=db.projects.map(p=>({project:p,metrics:riskModel(p)}));return send(res,200,{generatedAt:new Date().toISOString(),projects:metrics})}
if(req.method==='GET'&&u.pathname==='/api/benchmark'){const rows=db.projects.map(p=>({project:p,metrics:riskModel(p)}));const avg=rows.length?Math.round(rows.reduce((a,x)=>a+x.metrics.riskScore,0)/rows.length):0;return send(res,200,{portfolioAverageRisk:avg,projects:rows})}
if(req.method==='GET'&&u.pathname==='/api/drivers'){const rows=db.projects.map(p=>{const m=riskModel(p);return {projectId:p.id,project:p.name,drivers:[{name:'Material price escalation',score:Math.min(30,Math.round((m.observedCostOverrunPct||0)*.9))},{name:'Contractor / execution delay',score:Math.min(25,Math.round(m.scheduleRisk*.25))},{name:'Land acquisition / ROW',score:p.progress<60?18:9},{name:'Approvals & clearances',score:p.status==='Delayed'?15:7},{name:'Design / scope changes',score:(m.observedCostOverrunPct||0)>10?12:6}]}});return send(res,200,{generatedAt:new Date().toISOString(),projects:rows})}
if(req.method==='GET'&&u.pathname==='/api/paimana-overview'){const overrunLakhCr=Math.round((paimanaOverview.revisedCostLakhCr-paimanaOverview.originalCostLakhCr)*100)/100;const overrunPct=Math.round((overrunLakhCr/paimanaOverview.originalCostLakhCr)*1000)/10;const expenditurePct=Math.round((paimanaOverview.expenditureLakhCr/paimanaOverview.revisedCostLakhCr)*1000)/10;return send(res,200,{...paimanaOverview,overrunLakhCr,overrunPct,expenditurePct})}
if(req.method==='GET'&&u.pathname==='/api/cuf-fields'){return send(res,200,{cufFields,additionalVariables,note:'Core fields mirror the Common Upload Form (CUF) items described in the PAIMANA/OCMS framework. Additional variables are proposed, not presently captured, and are used to test predictive-performance attribution per technical dimension (c).'})}
if(req.method==='GET'&&u.pathname==='/api/model-metrics'){
  const resultFile=path.join(__dirname,'data','ml-validation-results.json');
  const result=readJson(resultFile,null);
  if(result && result.validated===true) return send(res,200,result);
  return send(res,200,{model:'Historical outcome validation pipeline',version:'1.0',status:'not-validated',validated:false,features:['approved/original cost','revised cost','cumulative expenditure','physical progress','implementation timeline','project status'],validation:{note:'No validated historical outcome model is connected. Accuracy metrics are intentionally suppressed until a documented historical dataset with target labels is trained and evaluated on an independent time-aware test set.',recommendedMetrics:['MAE','RMSE','F1','ROC-AUC'],resultFile:'backend/data/ml-validation-results.json'}});
}
if(req.method==='GET'&&u.pathname==='/api/work-sources'){let registry=[];try{registry=JSON.parse(fs.readFileSync(OFFICIAL_SOURCE_REGISTRY,'utf8'))}catch{} return send(res,200,{sources:registry,generatedAt:new Date().toISOString()});}
if(req.method==='GET'&&u.pathname==='/api/analytics-readiness'){
  const outcomeTemplate=path.join(__dirname,'data','historical-outcome-training-template.csv');
  const resultFile=path.join(__dirname,'data','ml-validation-results.json');
  const result=readJson(resultFile,null);
  return send(res,200,{validated:Boolean(result?.validated===true),historicalOutcomeDatasetConnected:false,trainTestValidated:Boolean(result?.validated===true),baselineComparison:Boolean(result?.baselineComparison===true),cuFields:cufFields.length,additionalVariables:additionalVariables.length,template:outcomeTemplate.replace(__dirname,'backend'),validationResult:result||null});
}
if(req.method==='GET'&&u.pathname==='/api/data-sources')return send(res,200,{nationalCoverage:true,demoMode:false,sources:[{name:'PAIMANA / OCMS',type:'official-government',scope:'Central Sector infrastructure projects monitored by MoSPI/IPMD',url:PAIMANA_URL,routeGeometryRequired:true,routeEligible:false,progress:'Official portfolio metadata when synchronized. The public dashboard does not provide universal route geometry.'},{name:'Verified Government GIS Registry',type:'verified-gis',scope:'Any Indian state/UT/departmental project with verified point or line geometry',url:null,routeGeometryRequired:true,routeEligible:true,progress:'Shown only when supplied by the imported authoritative GIS source'},{name:'OpenStreetMap',type:'mapped-construction',scope:'National mapped construction features',url:'https://www.openstreetmap.org/',routeGeometryRequired:true,routeEligible:true,progress:'Only when explicitly tagged; not treated as official government progress'},{name:'Telangana TGRAC / R&B GIS',type:'official-state-gis',scope:'Telangana R&B/Panchayat Raj road geometry including ongoing and proposed road layers',url:TELANGANA_RNB_SERVICE,routeGeometryRequired:true,routeEligible:true,progress:'Official geometry/status layer; project financial and physical progress is shown only when the source supplies it'},{name:'Telangana State eProcurement',type:'official-tender-source',scope:'Tender/work notices for Telangana government departments; tender status is procurement evidence, not proof of physical construction',url:'https://tender.telangana.gov.in/',routeGeometryRequired:false,routeEligible:false,progress:'Tender metadata can be imported only after the work location is independently verified through GIS'},{name:'Telangana Roads & Buildings',type:'official-department-source',scope:'Department tender/works information and R&B project documents',url:'https://roadbuild.telangana.gov.in/',routeGeometryRequired:true,routeEligible:false,progress:'Documents/tender records are not treated as route geometry without an authoritative GIS location'},{name:'National Government Work Registry',type:'government-work-record',scope:'Configurable Indian state/department work records with coordinates or geometry',url:null,routeGeometryRequired:true,routeEligible:true,progress:'Only shown with source evidence; tender/work records are not automatically labelled physical construction'}],distanceRules:{onRouteKm:0.5,nearRouteKm:ROUTE_CORRIDOR_KM,corridorKm:ROUTE_CORRIDOR_KM},registry:{count:loadVerifiedGeoJSON().length,geometryTypes:['Point','LineString','MultiLineString']},projectRegisterCount:db.projects.length,note:'Exact route matches require project geometry. PAIMANA monitoring candidates are separated when only place-name evidence is available. Government work records are matched only from configured coordinates/geometry and retain their evidence/status labels.'});
if(req.method==='POST'&&u.pathname==='/api/paimana/sync'){try{return send(res,200,await syncPaimana())}catch(err){return send(res,503,{error:err.message,source:PAIMANA_URL})}}
if(req.method==='GET'&&u.pathname==='/api/project-register')return send(res,200,{count:db.projects.length,projects:db.projects,source:PAIMANA_URL});
if(req.method==='GET'&&u.pathname==='/api/verified-projects'){const real=loadVerifiedGeoJSON();return send(res,200,{count:real.length,projects:real,demoCount:0,demoProjects:[]});}
if(req.method==='POST'&&u.pathname==='/api/projects/import'){
  const user=requireAdmin(req,res);if(!user)return;
  let body='';for await(const ch of req)body+=ch;const payload=JSON.parse(body||'{}');
  const incoming=payload.type==='FeatureCollection'?payload.features:(Array.isArray(payload)?payload:payload.projects||[]);
  if(!Array.isArray(incoming))return send(res,400,{error:'Expected a GeoJSON FeatureCollection, array of projects, or {projects:[...]}' });
  const existing=loadVerifiedGeoJSON();
  const normalized=incoming.map((item,i)=>{
    const p=item.type==='Feature'?{...(item.properties||{}),geometry:item.geometry}:item;
    if(!p.geometry && Number.isFinite(Number(p.lat)) && Number.isFinite(Number(p.lng))) p.geometry={type:'Point',coordinates:[Number(p.lng),Number(p.lat)]};
    if(!p.geometry || !['Point','LineString','MultiLineString'].includes(p.geometry.type)) throw new Error(`Project ${p.id||i+1} needs verified Point, LineString or MultiLineString geometry`);
    if(p.sourceVerified!==true) throw new Error(`Project ${p.id||i+1} must include sourceVerified=true after authoritative GIS validation`); if(!p.sourceUrl) throw new Error(`Project ${p.id||i+1} must include sourceUrl for provenance`); return {...p,id:p.id||`GIS-${Date.now()}-${i}`,routeEligible:true,sourceVerified:true,sourceClass:p.sourceClass||'verified-government-gis',importedAt:new Date().toISOString(),locationPrecision:p.locationPrecision||((p.geometry.type==='Point')?'point':'line/geometry')};
  });
  const merged=[...existing];for(const p of normalized){const idx=merged.findIndex(x=>x.id===p.id);if(idx>=0)merged[idx]=p;else merged.push(p);}saveVerifiedGeoJSON(merged); normalized.forEach(p=>audit(user,'Imported verified project','project',p.id,p.name));
  return send(res,201,{ok:true,imported:normalized.length,totalVerifiedProjects:merged.length,message:'Imported into the national verified GIS registry. These records can now be matched against any Indian route.'});
}
if(req.method==='GET'&&u.pathname==='/api/verified-projects/export')return send(res,200,{type:'FeatureCollection',features:loadVerifiedGeoJSON().map(p=>({type:'Feature',geometry:p.geometry,properties:{...p,geometry:undefined}}))});
if(req.method==='DELETE'&&u.pathname.startsWith('/api/verified-projects/')){
  const user=requireAdmin(req,res);if(!user)return;
  const id=decodeURIComponent(u.pathname.split('/').pop()); const items=loadVerifiedGeoJSON(); const next=items.filter(p=>p.id!==id);
  if(next.length===items.length)return send(res,404,{error:'Verified project not found'}); saveVerifiedGeoJSON(next); return send(res,200,{ok:true,deleted:id,count:next.length});
}
if(req.method==='POST'&&u.pathname==='/api/route-live-projects'){
  let body='';for await(const ch of req)body+=ch;
  try{
    const b=JSON.parse(body||'{}');
    const coords=Array.isArray(b.coords)?b.coords:[];
    const officialRadiusKm=ROUTE_CORRIDOR_KM;
    const supplementaryRadiusKm=ROUTE_CORRIDOR_KM;
    if(coords.length<2)return send(res,400,{error:'coords are required'});
    // Fresh lookup on every request. Every source is measured against the complete
    // selected route geometry within the same 2 km corridor on each side.
    const results=await Promise.allSettled([
      withTimeout(fetchTelanganaOfficialProjects(coords,officialRadiusKm),3500,{projects:[],available:false,error:'Telangana GIS timed out'}),
      withTimeout(Promise.resolve(fetchNationalGovernmentWorkRecords(coords,officialRadiusKm)),2000,[]),
      withTimeout(fetchOsmConstructionProjects(coords,supplementaryRadiusKm),3500,[]),
      withTimeout(fetchNationalPaimanaRouteCandidates(coords,officialRadiusKm,b.start||'',b.end||'',b.roadNames||[]),2500,[])
    ]);
    const tg=results[0].status==='fulfilled'?results[0].value:{projects:[],available:false,error:'Telangana GIS unavailable'};
    const work=results[1].status==='fulfilled'?results[1].value:[];
    const osm=results[2].status==='fulfilled'?results[2].value:[];
    const paimana=results[3].status==='fulfilled'?results[3].value:[];
    // Preserve approximate coordinates returned by the PAIMANA resolver. A null
    // coordinate remains null; a resolved point is explicitly approximate and never
    // promoted to authoritative GIS geometry.
    const paimanaRouteProjects=(paimana||[]).map(p=>enrichRouteProject({...p,sourceClass:'paimana-location-candidate',sourceVerified:false,routeEligible:false,status:p.status||'Ongoing',verificationStatus:p.verificationStatus||'PAIMANA Candidate – Geographic verification required',locationPrecision:p.locationPrecision||'approximate place-name match (no project GIS geometry)',geometry:null}));
    const combined=[...(tg.projects||[]),...(work||[]),...(osm||[]),...paimanaRouteProjects];
    const seen=new Map();
    for(const p of combined){
      const key=String(p.id||'').trim()||`${String(p.name||'').trim().toLowerCase()}|${Number(p.lat).toFixed(5)}|${Number(p.lng).toFixed(5)}`;
      if(!seen.has(key))seen.set(key,p);
    }
    let projects=[...seen.values()].sort((a,b)=>(a.distance??999)-(b.distance??999));
    // Real-world mode: NEVER promote unrelated national portfolio records or generated
    // placeholders into route projects. Every displayed project must have route-supporting
    // geometry from an authoritative registry/state GIS, a configured government work record,
    // or an explicitly-labelled OSM mapped construction feature.
    const routeEligibleProjects=projects.filter(p=>
      p.sourceClass!=='national-portfolio-candidate' &&
      p.sourceClass!=='route-analysis-candidate' &&
      p.sourceClass!=='paimana-location-candidate'
    );
    const matchedProjects=routeEligibleProjects.filter(p=>p.isDemo!==true&&p.sourceClass!=='route-demo'&&Number.isFinite(Number(p.distance))&&Number(p.distance)<=officialRadiusKm);
    const geographicMatches=projects.filter(p=>p.sourceClass==='paimana-location-candidate'&&p.isDemo!==true&&(!Number.isFinite(Number(p.distance))||Number(p.distance)>officialRadiusKm));
    const hasLocation=p=>Boolean(p?.geometry||(Number.isFinite(Number(p?.lat))&&Number.isFinite(Number(p?.lng))));
    const exactRouteMatches=matchedProjects.filter(p=>p.sourceClass!=='paimana-location-candidate'&&(p.overlap==='On / overlapping route'||Number.isFinite(Number(p.distance))&&Number(p.distance)<=1)).length;
    const verifiedOngoing=matchedProjects.filter(p=>p.sourceClass!=='mapped'&&p.sourceClass!=='paimana-location-candidate'&&/ongoing|in progress|active|under construction|construction started/i.test(String(p.status||''))).length;
    const mappedConstruction=matchedProjects.filter(p=>p.sourceClass==='mapped'&&hasLocation(p)).length;
    const proximityFallback=matchedProjects.filter(p=>p.sourceClass==='paimana-location-candidate'&&Number.isFinite(Number(p.distance))&&Number(p.distance)<=supplementaryRadiusKm);
    const exactRouteMatchesFallback=proximityFallback.filter(p=>Number(p.distance)<=1).length;
    const verifiedOngoingFallback=proximityFallback.filter(p=>/ongoing|in progress|active|under construction|construction started/i.test(String(p.status||''))).length;
    const mappedConstructionFallback=proximityFallback.filter(p=>/road|highway|bridge|flyover|construction/i.test(String(p.type||p.name||''))).length;
    const paimanaCandidates=projects.filter(p=>p.sourceClass==='paimana-location-candidate'&&p.isDemo!==true&&Number.isFinite(Number(p.distance))&&Number(p.distance)<=officialRadiusKm).length;
    const projectsDisplayed=matchedProjects.length;
    projects=matchedProjects.sort((a,b)=>{
      const rank=p=>p.sourceClass==='paimana-location-candidate'?0:p.sourceClass==='verified-government-gis'||p.sourceClass==='official-state-gis'||p.sourceClass==='government-work-record'?1:p.sourceClass==='mapped'?2:3;
      return rank(a)-rank(b) || Number(b.routeMatchScore||0)-Number(a.routeMatchScore||0) || (a.distance??999)-(b.distance??999);
    }).slice(0,ROUTE_MAX_PROJECTS);
    const demoProjects=projects.filter(p=>p.isDemo===true||p.sourceClass==='route-demo').length;
    const realSourceBacked=projects.filter(p=>p.isDemo!==true&&p.sourceClass!=='mapped'&&p.sourceClass!=='paimana-location-candidate').length;
    return send(res,200,{projects,geographicMatches,available:true,counts:{found:projects.length,projectsDisplayed,exactRouteMatches,verifiedOngoing,mappedConstruction,exactRouteMatchesFallback,verifiedOngoingFallback,mappedConstructionFallback,paimanaCandidates,geographicMatches:geographicMatches.length,requiringVerification:geographicMatches.length,realSourceBacked,demoProjects,realProjects:projects.filter(p=>p.isDemo!==true).length},corridor:{officialRadiusKm,supplementaryRadiusKm,samplingKm:4,routeVertices:coords.length,corridorKm:ROUTE_CORRIDOR_KM,corridorEachSideKm:ROUTE_CORRIDOR_KM},sources:{telanganaGIS:tg.available!==false,governmentWorkRegistry:(work||[]).length>0,paimanaCandidates,geographicMatches:geographicMatches.length,openStreetMap:osm.length>0,openStreetMapStatus:osm.length>0?'available':'no-matches-or-temporarily-unavailable',telanganaError:tg.error||null},note:'Fresh route-wide lookup with April 2026 PAIMANA-first project priority and real-project evidence only. The selected road route is checked within a 2 km corridor on each side. Verified GIS geometry is measured against the full selected route; PAIMANA records without project GIS geometry remain separate geographic matches requiring verification and are never fabricated as exact project footprints.'});
  }catch(e){
    // Keep the map populated even when one or more public data services are temporarily
    // unavailable. These are explicitly simulated route examples, never real projects.
    return send(res,200,{projects:[],available:false,error:e.message||'Live project lookup unavailable',counts:{found:0,verifiedOngoing:0,mappedConstruction:0,paimanaCandidates:0,realSourceBacked:0,demoProjects:0,realProjects:0},corridor:{officialRadiusKm:ROUTE_CORRIDOR_KM,supplementaryRadiusKm:ROUTE_CORRIDOR_KM,samplingKm:4,routeVertices:coords.length,corridorKm:ROUTE_CORRIDOR_KM},sources:{telanganaGIS:false,governmentWorkRegistry:false,paimanaCandidates:0,openStreetMap:false},note:'Public source lookup failed or timed out. No project is fabricated; retry the live lookup or use an authoritative GIS import.'});
  }
}
if(req.method==='POST'&&u.pathname==='/api/route-osm'){
let body='';for await(const ch of req)body+=ch;
try{
  const b=JSON.parse(body||'{}');
  const coords=Array.isArray(b.coords)?b.coords:[];
  const radiusKm=Math.max(1,Math.min(50,Number(b.radiusKm)||25));
  if(!coords.length)return send(res,400,{error:'coords are required'});
  const projects=await fetchOsmConstructionProjects(coords,radiusKm);
  return send(res,200,{projects,available:true});
}catch(e){return send(res,200,{projects:[],available:false,error:e.message||'OpenStreetMap supplementary construction data unavailable'});}
}
if(req.method==='GET'&&u.pathname==='/api/geocode'){const q=u.searchParams.get('q');if(!q)return send(res,400,{error:'q is required'});try{return send(res,200,{query:q,results:await geocodePlace(q)})}catch(err){return send(res,503,{error:err.message})}}if(req.method==='GET'&&u.pathname==='/api/route-analysis'){const s=u.searchParams.get('start'),e=u.searchParams.get('end'),r=Number(u.searchParams.get('radiusKm')||2);if(!s||!e)return send(res,400,{error:'start and end are required'});const startLatRaw=u.searchParams.get('startLat'),startLngRaw=u.searchParams.get('startLng'),endLatRaw=u.searchParams.get('endLat'),endLngRaw=u.searchParams.get('endLng');const slat=Number(startLatRaw),slng=Number(startLngRaw),elat=Number(endLatRaw),elng=Number(endLngRaw);const sp=startLatRaw!==null&&startLngRaw!==null&&startLatRaw!==''&&startLngRaw!==''&&Number.isFinite(slat)&&Number.isFinite(slng)?{lat:slat,lng:slng,label:s,locality:s}:null;const ep=endLatRaw!==null&&endLngRaw!==null&&endLatRaw!==''&&endLngRaw!==''&&Number.isFinite(elat)&&Number.isFinite(elng)?{lat:elat,lng:elng,label:e,locality:e}:null;try{return send(res,200,await routeAnalysis(s,e,r,sp,ep))}catch(err){return send(res,503,{error:err.message})}}if(req.method==='POST'&&u.pathname==='/api/projects'){
  const user=requireAdmin(req,res); if(!user)return;
  let body='';for await(const ch of req)body+=ch;const p=JSON.parse(body||'{}');
  const item={...p,id:p.id||`P-${String(Date.now()).slice(-6)}`,sourceType:p.sourceType||'Administrator-entered project',lastUpdated:new Date().toISOString()};
  delete item.sourceVerified; db.projects.push(item); save(); audit(user,'Added project','project',item.id,item.name); return send(res,201,item);
}
if(req.method==='PATCH'&&u.pathname.startsWith('/api/projects/')){
  const user=requireAdmin(req,res); if(!user)return;
  const id=decodeURIComponent(u.pathname.split('/').pop());const idx=db.projects.findIndex(x=>String(x.id)===String(id));if(idx<0)return send(res,404,{error:'Project not found'});
  let body='';for await(const ch of req)body+=ch;const patch=JSON.parse(body||'{}');delete patch.id;delete patch.sourceVerified;
  db.projects[idx]={...db.projects[idx],...patch,lastUpdated:new Date().toISOString()};save();audit(user,'Edited project','project',id,db.projects[idx].name);return send(res,200,db.projects[idx]);
}
if(req.method==='DELETE'&&u.pathname.startsWith('/api/projects/')){
  const user=requireAdmin(req,res); if(!user)return;
  const id=decodeURIComponent(u.pathname.split('/').pop());const idx=db.projects.findIndex(x=>String(x.id)===String(id));if(idx<0)return send(res,404,{error:'Project not found'});
  const [removed]=db.projects.splice(idx,1);save();audit(user,'Deleted project','project',id,removed.name);return send(res,200,{ok:true,deleted:id});
}
if(req.method==='PATCH'&&u.pathname.startsWith('/api/alerts/')){
  const user=requireAdmin(req,res);if(!user)return;
  const id=decodeURIComponent(u.pathname.split('/').pop());const alert=deriveAlerts().find(x=>String(x.id)===String(id));if(!alert)return send(res,404,{error:'Alert not found'});
  let body='';for await(const ch of req)body+=ch;const b=JSON.parse(body||'{}');db.alertAcknowledgements=db.alertAcknowledgements||{};
  if(b.ack){db.alertAcknowledgements[id]={ack:true,acknowledgedAt:new Date().toISOString(),acknowledgedBy:user.name};audit(user,'Acknowledged alert','alert',id,alert.project)}
  else delete db.alertAcknowledgements[id];
  save();return send(res,200,deriveAlerts().find(x=>x.id===id));
}
return send(res,404,{error:'Not found'})}catch(e){return send(res,500,{error:e.message})}});
server.listen(PORT,()=>console.log(`Infra Risk Radar API running on http://localhost:${PORT}`));
