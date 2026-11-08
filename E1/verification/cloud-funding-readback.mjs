import fs from 'node:fs';
import {createPsqlSession} from '../coordinator/index.mjs';
if(process.argv[2]!=='--e1-only')throw Error('EXPLICIT_E1_READBACK_REQUIRED');
const db=await createPsqlSession(JSON.parse(fs.readFileSync('.private/e1-resource.json')),{role:'admin'});
try{
 const v=JSON.parse(await db.query("SELECT json_build_object('authenticated_funding_rows',count(*) FILTER(WHERE grant_document->>'evidence_mode'='AUTHENTICATED_HOST'),'synthetic_funding_rows',count(*) FILTER(WHERE grant_document->>'evidence_mode'='EXPLICIT_SYNTHETIC'),'authenticated_reserved',COALESCE(sum(reserved) FILTER(WHERE grant_document->>'evidence_mode'='AUTHENTICATED_HOST'),0),'authenticated_spent',COALESCE(sum(spent) FILTER(WHERE grant_document->>'evidence_mode'='AUTHENTICATED_HOST'),0)) FROM awe_e1_runtime.cloud_budget;"));
 if(v.authenticated_funding_rows!==0||v.authenticated_spent!==0||v.authenticated_reserved!==0)throw Error('UNEXPECTED_REAL_FUNDING');
 const r={schema:'awe.e1.cloud-funding-readback/1',at:new Date().toISOString(),...v,paid_generation_requests:0,real_limits:[0,0,0],resource:'ISOLATED_E1_5433',query:'READ_ONLY_COUNTERS_NO_KEYS'};
 fs.mkdirSync('E1/evidence3',{recursive:true});fs.writeFileSync('E1/evidence3/REAL-FUNDING-DISABLED.json',JSON.stringify(r,null,2)+'\n');console.log(JSON.stringify(r));
}finally{await db.close();}
