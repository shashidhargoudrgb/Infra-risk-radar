import {spawn} from 'node:child_process';
import {setTimeout as sleep} from 'node:timers/promises';
import process from 'node:process';
const port=5199;
const child=spawn(process.execPath,['backend/server.js'],{env:{...process.env,PORT:String(port)},stdio:['ignore','pipe','pipe']});
let stderr=''; child.stderr.on('data',d=>stderr+=d);
try{
  for(let i=0;i<20;i++){
    try{const r=await fetch(`http://127.0.0.1:${port}/api/health`); if(r.ok)break;}catch{}
    await sleep(150);
  }
  const checks=['/api/health','/api/paimana-overview','/api/model-metrics','/api/analytics-readiness','/api/cuf-fields','/api/projects'];
  for(const endpoint of checks){
    const r=await fetch(`http://127.0.0.1:${port}${endpoint}`);
    if(!r.ok)throw new Error(`${endpoint} returned HTTP ${r.status}`);
    const data=await r.json();
    if(data===null||typeof data!=='object')throw new Error(`${endpoint} returned invalid JSON`);
  }
  const health=await (await fetch(`http://127.0.0.1:${port}/api/health`)).json();
  if(health.demoMode!==false||health.projectRegistryCount!==1981)throw new Error('Health/data integrity check failed');
  const metrics=await (await fetch(`http://127.0.0.1:${port}/api/model-metrics`)).json();
  if(metrics.validated!==false)throw new Error('Unvalidated ML metrics must remain suppressed');
  console.log('SMOKE TEST PASSED');
} finally {child.kill('SIGTERM'); await sleep(100); if(stderr) process.stderr.write(stderr);}
