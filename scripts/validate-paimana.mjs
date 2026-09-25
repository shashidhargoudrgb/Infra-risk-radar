import fs from 'node:fs';
const d=JSON.parse(fs.readFileSync(new URL('../backend/infra_risk_data.json', import.meta.url),'utf8'));
const p=d.projects;
const sum=k=>p.reduce((s,x)=>s+(Number(x[k])||0),0);
const checks={count:p.length,original:sum('originalCost'),revised:sum('revisedCost'),expenditure:sum('expenditure')};
console.log(JSON.stringify(checks,null,2));
if(checks.count!==1981) throw new Error('Expected 1981 projects');
for(const [k,v] of [['original',3712662.01],['revised',4278402.37],['expenditure',2036107.49]]) if(Math.abs(checks[k]-v)>0.01) throw new Error(`${k} total mismatch`);
console.log('PAIMANA validation: PASS');
