import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {createFuseCandidate} from '../host.mjs';
import {createInt04OfflineHost} from '../../INTEGRATION-01/adapters/int04-host.mjs';
import {createMockModel,createMockExecutors} from '../../AUTO-01/mock.mjs';
import {planMockDraft} from '../../AUTO-01/mock-extraction.mjs';
import {createArtifactStore} from '../../awe/context/store.mjs';
import {harness} from '../../tests/state/harness.mjs';
import {MemoryStorage} from '../../awe/state/memory-storage.mjs';
import {digest} from '../../contracts/canonical.mjs';
import {evaluateExact} from '../../awe/qa/evaluator.mjs';
import {setup} from '../../tests/qa02/fixtures.mjs';
import {buildFeedback} from '../../awe/qa_profiles/auto02.mjs';
const evidence=path.resolve(import.meta.dirname,'../../../runs/fuse-tests');fs.mkdirSync(evidence,{recursive:true});
const save=(name,data)=>fs.writeFileSync(path.join(evidence,name+'.json'),JSON.stringify(data,null,2)+'\n');
const noComplete=s=>assert.ok(Object.values(s.tasks).every(t=>t.state!=='COMPLETE'));

test('two runtime-generated goals form different DAGs; real SEC rejects executable bindings before any effect',async()=>{
 const nonce=randomBytes(4).toString('hex'),goals=[
  `Вычисли сумму чисел ${Date.now()%1000} 13 21. Без сети. Готово, когда: локальная таблица ${nonce}`,
  `Подготовь анализ текста ${nonce}; сравни количество строк; составь отчёт. Без сети и не публиковать. Готово, когда: доступны три результата ${nonce}`];
 const signatures=[];
 for(let i=0;i<goals.length;i++){
  const f=await createFuseCandidate({sessionId:'goal'+i});await f.converse(goals[i]);const s=f.snapshot();
  assert.equal(s.phase,'BLOCKED_OWNER_CHANGE_REQUEST');assert.equal(s.effects,0);noComplete(s);
  assert.equal(f.preflights.length,1);assert.equal(f.preflights[0].sec_registry,'TOOL_IMPLEMENTATION_DENIED');
  assert.equal(f.attempts[0].decision,'READY_OFFLINE');assert.equal(f.attempts[0].outputReleased,false);
  assert.equal(s.authoritative_qa,'NOT_SUBMITTED');assert.equal(s.accepted,false);
  assert.equal(s.spec.content.original_request.text,goals[i]);
  assert.ok(s.plan.content.nodes.length>=2);assert.ok(f.archive.every(a=>a.receipt.status==='PERSISTED_CANDIDATE'&&!a.receipt.authoritative_complete));
  const view=f.restoreView();assert.equal(view.ok,true,JSON.stringify(view));assert.equal(view.value.status,'HOLD_FOR_OWNER_RECONCILIATION');assert.equal(view.value.resume,false);
  assert.equal(f.foreignRead().ok,false);assert.equal(f.foreignRead().code,'SCOPE_DENIED');
  const id=Object.keys(s.results)[0],ref=s.results[id].artifacts[0].artifact_ref;
  assert.ok(f.host.readArtifact(id,ref).length);assert.throws(()=>f.host.readArtifact('task_foreign',ref),/AUTO01_ARTIFACT_SCOPE/);
  signatures.push(digest(s.plan.content));save('goal'+i,{goal:goals[i],snapshot:s,archive:f.archive,view,foreign:f.foreignRead()});
 }
 assert.notEqual(signatures[0],signatures[1]);
});

async function profile({executors,model=createMockModel(),maxReplans=2,sessionId='profile',h=harness()}={}){
 try{h.service.getProject(h.owner,'prj_alpha');}catch{await h.project();}
 const host=await createInt04OfflineHost({profile:'FUSE01',h,projectId:'prj_alpha',sessionId,model,
  executors:executors??createMockExecutors(),artifacts:createArtifactStore(),maxReplans});return {h,host};
}
test('candidate QA PASS stops at D03 QA_PENDING and never completes dependencies',async()=>{
 const executors=createMockExecutors({verify:({handoff,result})=>({verdict:'CANDIDATE_PASS',handoff_hash:digest(handoff),result_hash:digest(result)})});
 const f=await profile({executors});await f.host.converse({text:'Подготовь отчёт. Готово, когда: сохранён результат',idempotencyKey:'goal',expectedRevision:f.host.snapshot().revision});
 const s=f.host.snapshot();assert.equal(s.phase,'BLOCKED_D08_OWNER_ACCEPTANCE');noComplete(s);
 assert.equal(Object.values(s.tasks).filter(t=>t.state==='QA_PENDING').length,1);assert.equal(executors.calls.length,1);save('candidate-pass-is-not-complete',s);
});
test('MOCK_PASS cannot satisfy the FUSE candidate gate',async()=>{
 const f=await profile();await f.host.converse({text:'Подготовь отчёт',idempotencyKey:'goal',expectedRevision:f.host.snapshot().revision});
 assert.equal(f.host.snapshot().phase,'HOLD');assert.ok(f.host.snapshot().blockers.includes('AUTO01_QA_FAILED'));noComplete(f.host.snapshot());
});
test('known executor failure is bounded to two replans and never reaches COMPLETE',async()=>{
 let version=0;
 const model=createMockModel({replan:c=>{const p=planMockDraft(c);for(const n of p.nodes)n.instructions+=' repair '+(++version);return p;}});
 const executors=createMockExecutors({execute:(_,h)=>({version:'auto01/1',handoff_hash:digest(h),status:'FAILED',summary:'Known synthetic executor failure',outputs:[],uncertainties:[]})});
 const f=await profile({model,executors,maxReplans:2});await f.host.converse({text:'Подготовь отчёт',idempotencyKey:'goal',expectedRevision:f.host.snapshot().revision});
 const s=f.host.snapshot();assert.equal(executors.calls.length,3);assert.equal(s.replans,2);assert.equal(s.phase,'HOLD');assert.ok(s.blockers.includes('AUTO01_REPLAN_EXHAUSTED'));noComplete(s);save('bounded-rework-fixture',s);
});
test('cancel fences an awaited preflight; no late effect or downstream dispatch',async()=>{
 let release,entered;const started=new Promise(r=>entered=r),pause=new Promise(r=>release=r);
 const f=await createFuseCandidate({sessionId:'cancel',beforePreflight:async()=>{entered();await pause;}});
 const running=f.converse('Подготовь отчёт');await started;await f.host.cancel();release();await running;
 const s=f.snapshot();assert.equal(s.phase,'CANCELLING');assert.equal(s.effects,0);assert.equal(f.preflights.length,0);noComplete(s);save('cancel',s);
});
test('D03 snapshot restart enters HOLD and refuses a fresh command key',async()=>{
 const f=await createFuseCandidate({sessionId:'restart'});await f.converse('Подготовь отчёт');
 const h=harness({storage:new MemoryStorage({snapshot:f.h.storage.snapshot()})});
 const restored=await createFuseCandidate({sessionId:'restart',h});assert.equal(restored.snapshot().phase,'HOLD');
 await assert.rejects(()=>restored.host.run({idempotencyKey:'new-key',expectedRevision:restored.host.snapshot().revision}),/AUTO01_HOLD/);
 assert.equal(restored.preflights.length,0);assert.equal(restored.snapshot().effects,0);save('restart-hold',restored.snapshot());
});
test('QA02 actual worker evidence is candidate-only; generic output has no D08 dialect',async()=>{
 const q=await setup('document'),r=await q.run(),gate=q.qa.gate(q.refs(r));
 assert.equal(gate.verdict,'PASS');assert.equal(gate.authority,'CANDIDATE_ONLY');assert.equal(gate.authoritative_qa,'NOT_SUBMITTED');assert.equal(gate.accepted,false);
 const bytes=Buffer.from('{"result":"arbitrary dynamic goal"}'),reference={...q.head,file_hash:'sha256:'+'0'.repeat(64),bytes:bytes.length};
 const official=evaluateExact({bytes,reference,requirements:{kind:'FUSE01_DYNAMIC_OUTPUT_V1',spec:q.profile.spec,project_id:q.head.project_id,task_id:q.head.task_id},evidence:{},operations:[],pin:q.f.statePort.read().pin});
 assert.notEqual(official.verdict,'QA_PASS');save('qa02-vs-authoritative-d08',{gate,official});
});
test('QA02 repair envelope preserves owner limits and unknown outcome escalation',async()=>{
 const f=await setup('document',{text:'TODO'}),r=await f.run(),gate=f.qa.gate(f.refs(r));assert.equal(gate.verdict,'FAIL');
 const first=buildFeedback(gate,f.retryContext()),again=buildFeedback(gate,f.retryContext()),last=buildFeedback(gate,f.retryContext({attempts_used:2})),unknown=buildFeedback(gate,f.retryContext({outcome_unknown:true}));
 assert.equal(first.action,'REWORK');assert.equal(first.idempotency_key,again.idempotency_key);assert.equal(last.action,'ESCALATE');assert.equal(unknown.code,'OUTCOME_UNKNOWN_RECONCILIATION_REQUIRED');
 save('repair-contract',{first,last,unknown});
});
