import {writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {world,request,success} from '../budget/fixtures.mjs';
import {createModelGateway} from '../../awe/model_gateway/gateway.mjs';
import {syntheticProfile} from '../../awe/model_gateway/profiles.mjs';
import {benchmarkCases,materializeCorpus} from '../../awe/model_gateway/bench.mjs';
const results=[];
for(const [scenario,reply] of [['success',success()],['timeout',{status:'TIMEOUT'}]]) {
  const w=world({scripts:[[reply]]}),g=createModelGateway({...w,profiles:w.routes.map(x=>syntheticProfile(x)),readAuthority:()=>w.ledger.authority()});
  const r=request(),p=g.prepare(r);if(p.decision!=='READY_OFFLINE')throw Error(p.code);
  w.ledger.approve({id:'ap1',operationId:r.operationId,logicalRequestId:r.logicalRequestId,correlationId:r.correlationId,scopeId:r.scopeId,
    effectSlot:r.effectSlot,planHash:p.d06.planHash,authority:r.authority,maxMicros:p.d06.totalBoundMicros,maxAttempts:r.maxAttempts,expiresAt:7000,allowUnknownCost:false});
  const outcome=await g.run(p.handle,'ap1'),replay=await g.run(p.handle,'ap1');
  results.push({scenario,plan:p.plan,outcome,replay,calls:w.controls.r1.calls().length,physicalDispatches:0});
}
const cases=benchmarkCases();
writeFileSync('LLM-01/evidence/synthetic-demo.json',JSON.stringify({mode:'SYNTHETIC_ONLY',liveBench:'LIVE_BENCH_NOT_RUN',results},null,2)+'\n');
writeFileSync('LLM-01/bench-cases.json',JSON.stringify(cases,null,2)+'\n');
writeFileSync('LLM-01/evidence/corpus-manifest.json',JSON.stringify(cases.filter(x=>x.oracle.kind==='corpus').map(c=>{
  const x=materializeCorpus(c);return {id:c.id,offset:x.offset,bytes:Buffer.byteLength(x.text),sha256:createHash('sha256').update(x.text).digest('hex')};}),null,2)+'\n');
console.log(JSON.stringify({scenarios:results.map(x=>({name:x.scenario,status:x.outcome.status,calls:x.calls})),cases:cases.length,physicalDispatches:0,liveBench:'LIVE_BENCH_NOT_RUN'}));
