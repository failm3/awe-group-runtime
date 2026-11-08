import './evaluation-counter.mjs';
import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {start,stop,fixture,json} from './fixtures.mjs';
import {canonicalize,bytesHash,digest} from '../../awe/qa/common.mjs';
let cluster;before(()=>{cluster=start();});after(()=>stop());
const pg=(name,fn)=>test('INT03 AUD01 REAL_PG '+name,fn);
async function pendingFixture() {
 const f=await fixture();await f.execute();f.issue();
 const pending=f.call('start_qa',{grant_id:'qa1',key:'qa_key'},'d09_qa_login');
 const proof={mode:'E0_SYNTHETIC_ONLY',run_id:pending.run_id,verifier:pending.actor,bundle_hash:pending.bundle_hash,
  artifact:pending.bundle.reference,requirements_hash:digest(pending.bundle.requirements),
  result:{verdict:'QA_PASS',artifact_hash:pending.bundle.reference.file_hash,policy_version:'D08_E0_EXACT_ARTIFACT_V1'}};
 return {...f,pending,proof,request:{...f.scope,run_id:pending.run_id}};
}
const direct=(f,proof=f.proof,login='d09_qa_login')=>f.call('finish_qa',{grant_id:'qa1',run_id:f.pending.run_id,proof:JSON.stringify(proof)},login);

pg('correct-hash forged PASS by actual verifier login is rejected without evaluation or owner acceptance',async()=>{
 const f=await pendingFixture(),calls=globalThis.__aud01EvaluatorCalls;
 assert.throws(()=>direct(f),/permission denied for function finish_qa/);
 assert.equal(globalThis.__aud01EvaluatorCalls,calls);assert.equal(calls,0);
 const state=await f.host.worker.inspect();assert.equal(state.qa,'QA_PENDING');assert.notEqual(state.effective_qa,'QA_PASS');assert.equal(state.accepted,false);
 assert.throws(()=>f.issue('ACCEPT','own1','d09_owner_login'));
 assert.throws(()=>f.call('accept',{grant_id:'fake',proof_hash:bytesHash(Buffer.from(JSON.stringify(f.proof))),key:'forged'},'d09_owner_login'));
 assert.equal(f.sql('SELECT count(*) FROM awe_int03.proofs'),'0');
 writeFileSync(join(cluster.run,'AUD01-CORRECT-HASH-FORGERY-DENIED.json'),JSON.stringify({state,forged_proof:f.proof,
  actual_parent_evaluator_calls:calls,login:'d09_qa_login',database:f.name,denial:'SQL EXECUTE privilege denied',physical_decision:'DENY'},null,2)+'\n');
});
pg('extra authentic-looking findings, traces and execution claims do not grant finish capability',async()=>{
 const f=await pendingFixture();const proof={...f.proof,evaluator_ran:true,evaluator_login:'d09_evaluator_login',execution_calls:1,
  result:{...f.proof.result,findings:[],criteria:['ARTIFACT','REQUIREMENTS','FUNCTIONAL','RECEIPTS','CHAIN','CITATIONS','ISOLATION'].map(id=>({id,status:'PASS'})),trace:[{ok:true}]}};
 assert.throws(()=>direct(f,proof),/permission denied/);assert.equal((await f.host.worker.inspect()).accepted,false);
});
pg('verifier cannot SET ROLE to service, write proofs or register its own evaluator trust',async()=>{
 const f=await pendingFixture();
 assert.equal(f.sql("SELECT pg_has_role(session_user,'awe_int03_evaluator','MEMBER')",'d09_qa_login'),'f');
 assert.throws(()=>f.sql('SET ROLE awe_int03_evaluator','d09_qa_login'));
 assert.throws(()=>f.sql("UPDATE awe_int03.evaluator_trust SET login='d09_qa_login'",'d09_qa_login'));
 assert.throws(()=>f.sql("INSERT INTO awe_int03.proofs SELECT * FROM awe_int03.proofs",'d09_qa_login'));
 assert.throws(()=>f.sql('GRANT awe_int03_evaluator TO d09_qa_login','d09_qa_login'));
});
pg('real separate evaluator process runs fixed D08 then distinct owner accepts',async()=>{
 const f=await pendingFixture();const evaluated=await f.host.trusted.verify('qa1','qa_key');
 assert.equal(evaluated.qa,'QA_PASS');assert.equal(evaluated.evaluation_execution.calls,1);
 assert.notEqual(evaluated.evaluator_process_id,process.pid);assert.equal(globalThis.__aud01EvaluatorCalls,0);
 const provenance=JSON.parse(f.sql('SELECT to_jsonb(p) FROM awe_int03.proofs p'));
 assert.equal(provenance.login,'d09_qa_login');assert.equal(provenance.evaluator_login,'d09_evaluator_login');
 assert.equal(provenance.evaluator_sha256,evaluated.evaluation_execution.evaluator_sha256);
 const accepted=await f.accept(evaluated);assert.equal(accepted.accepted,true);assert.equal(accepted.physical_decision,'DENY');
 writeFileSync(join(cluster.run,'AUD01-REAL-EVALUATOR-POSITIVE.json'),JSON.stringify({evaluated,accepted,provenance,parent_process_id:process.pid},null,2)+'\n');
});
pg('broken committed artifact cannot become PASS through service or manual verifier proof',async()=>{
 const f=await fixture();await f.execute();const b=f.bundle(),out=JSON.parse(Buffer.from(b.bytes_base64,'base64'));
 out.model.output.text='INT03-AUD01 deliberately broken';const bytes=Buffer.from(canonicalize(out));
 b.bytes_base64=bytes.toString('base64');b.reference={...b.reference,version:2,file_hash:bytesHash(bytes),bytes:bytes.length};
 await f.host.trusted.revise(b,(await f.host.trusted.inspect()).revision);f.issue();
 const p=f.call('start_qa',{grant_id:'qa1',key:'qa_key'},'d09_qa_login');
 assert.throws(()=>f.call('finish_qa',{grant_id:'qa1',run_id:p.run_id,proof:JSON.stringify({mode:'E0_SYNTHETIC_ONLY',run_id:p.run_id,
  verifier:p.actor,bundle_hash:p.bundle_hash,artifact:p.bundle.reference,result:{verdict:'QA_PASS',artifact_hash:p.bundle.reference.file_hash,policy_version:'D08_E0_EXACT_ARTIFACT_V1'}})},'d09_qa_login'),/permission denied/);
 const result=await f.host.trusted.verify('qa1','qa_key');assert.equal(result.qa,'QA_FAIL');assert.equal(result.evaluation_execution.calls,1);
 assert(result.proof.result.findings.some(x=>x.code==='FUNCTIONAL_OUTPUT'));assert.throws(()=>f.issue('ACCEPT','own1','d09_owner_login'));
});
pg('service RPC refuses caller proof, verdict, code and source pin inputs',async()=>{
 const f=await pendingFixture();
 for(const extra of [{proof:f.proof},{verdict:'QA_PASS'},{evaluator:'skip'},{evaluator_sha256:'a'.repeat(64)}])
  await assert.rejects(()=>f.evaluator.evaluateRun({...f.request,...extra}),/EVALUATOR_REQUEST_INVALID/);
 await assert.rejects(()=>f.evaluator.evaluateRun({...f.request,project_id:'prj_beta'}));
 assert.equal((await f.host.worker.inspect()).qa,'QA_PENDING');assert.equal(f.sql('SELECT count(*) FROM awe_int03.proofs'),'0');
});
pg('service stopping before evaluator invocation leaves no PASS and a genuine retry remains live',async()=>{
 const f=await pendingFixture();f.evaluatorControl.failBeforeEvaluationOnce();
 await assert.rejects(()=>f.host.trusted.verify('qa1','qa_key'),/STOP_BEFORE_EVALUATION/);
 assert.equal(f.sql('SELECT count(*) FROM awe_int03.proofs'),'0');assert.notEqual((await f.host.worker.inspect()).effective_qa,'QA_PASS');
 assert.throws(()=>f.issue('ACCEPT','own1','d09_owner_login'));
 const result=await f.host.trusted.verify('qa1','qa_key');assert.equal(result.qa,'QA_PASS');assert.equal(result.evaluation_execution.calls,1);
});
pg('service rejects a mismatched pinned implementation before recording a proof',async()=>{
 const f=await pendingFixture();f.sql("UPDATE awe_int03.evaluator_trust SET evaluator_sha256=repeat('0',64)");
 await assert.rejects(()=>f.host.trusted.verify('qa1','qa_key'),/EVALUATOR_SOURCE_PIN_MISMATCH/);
 assert.equal(f.sql('SELECT count(*) FROM awe_int03.proofs'),'0');assert.equal((await f.host.worker.inspect()).accepted,false);
});
pg('revoked service identity and combined verifier-service role cannot authenticate evaluator completion',async()=>{
 const f=await pendingFixture();f.sql('UPDATE awe_int03.evaluator_trust SET revoked=true');
 await assert.rejects(()=>f.host.trusted.verify('qa1','qa_key'),/EVALUATOR_AUTHORITY_DENIED/);
 f.sql("GRANT awe_int03_evaluator TO d09_qa_login; INSERT INTO awe_int03.evaluator_trust SELECT project_id,'d09_qa_login',evaluator_sha256,service_sha256,policy_version,expires_at,false FROM awe_int03.evaluator_trust");
 try {assert.throws(()=>direct(f),/INT03_QA_PROOF_DENIED/);assert.equal(f.sql('SELECT count(*) FROM awe_int03.proofs'),'0');}
 finally {f.sql('REVOKE awe_int03_evaluator FROM d09_qa_login');}
});
pg('stale service run after artifact revision cannot reuse an earlier exact PASS',async()=>{
 const f=await pendingFixture();const old=await f.host.trusted.verify('qa1','qa_key');
 const b=f.bundle();b.reference.version=2;await f.host.trusted.revise(b,(await f.host.trusted.inspect()).revision);
 await assert.rejects(()=>f.evaluator.evaluateRun(f.request));assert.throws(()=>direct(f,old.proof),/permission denied/);
 assert.equal((await f.host.worker.inspect()).qa,'QA_NOT_RUN');assert.equal((await f.host.worker.inspect()).accepted,false);
});
pg('manual forged completion racing the real service cannot create a second or unauthenticated proof',async()=>{
 const f=await pendingFixture();
 const results=await Promise.allSettled([f.evaluator.evaluateRun(f.request),Promise.resolve().then(()=>direct(f))]);
 assert.equal(results[0].status,'fulfilled');assert.equal(results[1].status,'rejected');
 assert.equal(f.sql('SELECT count(*) FROM awe_int03.proofs'),'1');assert.equal(f.sql('SELECT evaluator_login FROM awe_int03.proofs'),'d09_evaluator_login');
});
pg('worker, verifier and owner cannot finish QA; evaluator cannot start, work or accept',async()=>{
 const f=await pendingFixture();
 for(const login of ['d09_worker','d09_qa_login','d09_owner_login','d09_issuer_login'])assert.throws(()=>direct(f,f.proof,login),/permission denied/);
 assert.throws(()=>f.call('start_qa',{grant_id:'qa1',key:'foreign'},'d09_evaluator_login'),/permission denied/);
 assert.throws(()=>f.call('accept',{grant_id:'fake',proof_hash:'fake',key:'fake'},'d09_evaluator_login'),/permission denied/);
 assert.throws(()=>f.call('admit',{command:f.command},'d09_evaluator_login'),/permission denied/);
 assert.equal((await f.host.worker.inspect()).accepted,false);assert.equal(f.host.worker.requestPhysicalEffect().decision,'DENY');
});
pg('lost service response after actual evaluator commit quarantines task and rejects acceptance',async()=>{
 const f=await pendingFixture();f.evaluatorControl.dropResponseOnce();
 await assert.rejects(()=>f.host.trusted.verify('qa1','qa_key'),/EVALUATOR_RESPONSE_OUTCOME_UNKNOWN/);
 assert.equal(f.sql('SELECT count(*) FROM awe_int03.proofs'),'1');
 const state=await f.make().trusted.inspect();assert.equal(state.state,'OUTCOME_UNKNOWN');assert.equal(state.accepted,false);
 assert.throws(()=>f.issue('ACCEPT','own1','d09_owner_login'));
});
