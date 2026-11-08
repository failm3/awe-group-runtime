import test from 'node:test';
import assert from 'node:assert/strict';
import {writeFileSync,mkdirSync} from 'node:fs';
import {fixture,evaluationFixture,text} from './fixtures.mjs';
import {prepareSyntheticJob} from '../integration_v3/synthetic-job.mjs';
import {canonicalize,digest,hashBytes} from '../../awe/execution_security/common.mjs';
import {createEvaluationBoundary,evaluationPins} from '../../awe/execution_security/evaluation.mjs';
async function ready(){
 const job=await prepareSyntheticJob();let bundle;
 const f=fixture({cost:job.plan.reserve_micros,grantCap:job.plan.reserve_micros,cap:job.plan.reserve_micros,complete:async()=>{bundle=await job.run();return {actual_micros:bundle.cost.actual_micros};}});f.request.plan_hash=digest(job.plan);
 const work=await f.execute();assert.equal(work.decision,'SIMULATED');assert.equal(bundle.physical_dispatches,0);
 const q=evaluationFixture(f,bundle);return {f,q,bundle,work};
}
test('Phase A positive: authorized action → actual D01-D07 synthetic workflow → fixed independent D08 QA → separate owner acceptance',async()=>{
 const {f,q,bundle,work}=await ready(),before=globalThis.__sec01EvaluatorCalls;
 assert.equal(work.accepted,false);assert.equal((await q.start()).qa,'QA_PENDING');const qa=await q.evaluate();
 assert.equal(qa.qa,'QA_PASS');assert.equal(qa.evaluator_calls,1);assert.equal(globalThis.__sec01EvaluatorCalls,before+1);
 const accepted=await q.accept(qa.proof);assert.equal(accepted.acceptance,'OWNER_ACCEPTED');assert.equal(accepted.physical_decision,'DENY');assert.equal(accepted.published,false);assert.equal(accepted.authoritative_complete,false);
 const proof=f.verifier.open(qa.proof,'evaluation','sec01.acceptance');assert.equal(proof.evaluator_id,'evaluator');assert.equal(proof.verifier_id,'verifier');assert.equal(proof.binding,work.binding);assert.equal(proof.plan_hash,digest(bundle.plan));assert.equal(proof.artifact_hash,bundle.reference.file_hash);assert.equal(String(f.world.spent),bundle.cost.actual_micros);
 const evidenceDir=new URL('../../MASTER-INTEGRATION-01/evidence/sec01/',import.meta.url);mkdirSync(evidenceDir,{recursive:true});
 writeFileSync(new URL('phase-a-positive-'+Date.now()+'.json',evidenceDir),JSON.stringify({mode:'E0_OFFLINE',work,qa:{qa:qa.qa,evaluator_calls:qa.evaluator_calls,source_pins:proof.source_pins,artifact_hash:proof.artifact_hash,criteria:proof.result.criteria,proof_hash:hashBytes(Buffer.from(qa.proof))},accepted,money:{spent_micros:String(f.world.spent),reserved_micros:String(f.world.reserved)},physical_dispatches:bundle.physical_dispatches,identity_assurance:'E0_LOCAL_PROVISIONED',store:'TEST_PROCESS_LOCAL_NOT_DURABLE'},null,2)+'\n',{flag:'wx'});
});
test('INT03-AUD-01 regression: correct-hash forged PASS from worker/verifier cannot finish or accept without actual evaluator',async()=>{
 const {f,q,bundle}=await ready();await q.start();const before=globalThis.__sec01EvaluatorCalls;
 const forged={run_id:'qa_one',artifact_hash:bundle.reference.file_hash,result:{verdict:'QA_PASS'},evaluator_id:'evaluator',evaluator_ran:true};
 assert.equal(q.boundary.submitProof(forged).decision,'DENY');
 assert.equal((await q.boundary.evaluateRun(f.token('verifier'),f.peer('verifier'),text(q.request))).decision,'DENY');
 assert.equal((await q.accept(text(forged))).decision,'DENY');assert.equal(q.pending.accepted,false);assert.equal(q.pending.qa,'QA_PENDING');assert.equal(globalThis.__sec01EvaluatorCalls,before);
 const genuine=await q.evaluate();assert.equal(genuine.qa,'QA_PASS');assert.equal(globalThis.__sec01EvaluatorCalls,before+1);
});
for(const role of ['worker','owner','provider'])test('QA forged service identity '+role+' cannot evaluate',async()=>{
 const {f,q}=await ready();await q.start();const n=globalThis.__sec01EvaluatorCalls;
 const out=await q.boundary.evaluateRun(f.token(role),f.peer(role),text(q.request));assert.equal(out.decision,'DENY');assert.equal(globalThis.__sec01EvaluatorCalls,n);assert.equal(q.pending.accepted,false);
});
test('QA requester cannot inject verdict/proof/callback/source hash or another project',async()=>{
 const {f,q}=await ready();await q.start();for(const extra of [{proof:'PASS'},{verdict:'QA_PASS'},{evaluator:'skip'},{evaluator_digest:digest('bad')},{project_id:'prj_beta'}]){
  const out=await q.boundary.evaluateRun(f.token('evaluator'),f.peer('evaluator'),text({...q.request,...extra}));assert.equal(out.decision,'DENY');
 }
});
test('QA actual evaluator rejects artifact whose bytes and hash were both recomputed by attacker',async()=>{
 const {q}=await ready();const b=q.pending.bundle,body=JSON.parse(Buffer.from(b.bytes_base64,'base64').toString());body.model.output.text='forged successful result';
 const bytes=Buffer.from(canonicalize(body));b.bytes_base64=bytes.toString('base64');b.reference.file_hash=hashBytes(bytes);b.reference.bytes=bytes.length;
 await q.start();const evaluated=await q.evaluate();assert.equal(evaluated.qa,'QA_FAIL');assert.equal((await q.accept(evaluated.proof)).decision,'DENY');
});
test('QA source changes, subject aliases and service revocation fail closed',async()=>{
 const {f,q}=await ready();const pins=evaluationPins();assert.throws(()=>createEvaluationBoundary({verifier:f.verifier,issuer:f.issuer,store:{},pins:{...pins,'../qa/evaluator.mjs':digest('wrong')}}),/EVALUATOR_SOURCE_PIN_MISMATCH/);
 await q.start();f.principals.evaluator.subject=f.principals.worker.subject;assert.equal((await q.evaluate()).decision,'DENY');
 f.principals.evaluator.subject='subject:evaluator';f.principals.evaluator.active=false;const token=f.issuer.issueIdentity;
 // Existing service credential cannot survive revocation. Do not mint a new one.
 assert.throws(()=>token('evaluator','prj_alpha'));
});
for(const [name,mutate] of [
 ['task cancellation',f=>f.state.cancelled=true],['restore fencing',f=>f.state.restore_pending=true],['owner epoch',f=>f.state.epochs.owner++],
 ['verifier generation',f=>f.principals.verifier.generation++],['evaluator generation',f=>f.principals.evaluator.generation++],['producer generation',f=>f.principals.worker.generation++]
])test('QA/acceptance current barrier '+name,async()=>{
 const {f,q}=await ready();await q.start();const evaluated=await q.evaluate();assert.equal(evaluated.qa,'QA_PASS');mutate(f);assert.equal((await q.accept(evaluated.proof)).decision,'DENY');assert.equal(q.pending.accepted,false);
});
test('QA worker cannot start or accept; owner cannot evaluate its own approval',async()=>{
 const {f,q}=await ready();assert.equal((await q.boundary.start(f.token('worker'),f.peer('worker'),text(q.request))).decision,'DENY');
 await q.start();const qa=await q.evaluate();assert.equal((await q.boundary.accept(f.token('worker'),f.peer('worker'),text(q.request),qa.proof)).decision,'DENY');
 assert.equal((await q.boundary.accept(f.token('verifier'),f.peer('verifier'),text(q.request),qa.proof)).decision,'DENY');assert.equal(q.pending.accepted,false);
});
for(const stage of ['finish','accept'])test('QA '+stage+' commit acknowledgement loss quarantines instead of exposing success',async()=>{
 const {q}=await ready();await q.start();if(stage==='finish')q.pending.fail='finish';const evaluated=await q.evaluate();
 if(stage==='finish')assert.equal(evaluated.code,'QA_OUTCOME_UNKNOWN');else {q.pending.fail='accept';assert.equal((await q.accept(evaluated.proof)).code,'ACCEPTANCE_OUTCOME_UNKNOWN');}
 assert.equal(q.pending.uncertain,true);assert.equal(q.pending.accepted,false);assert.equal((await q.accept(evaluated.proof??'forged')).decision,'DENY');
});
test('QA signed but uncommitted proof has no authority at acceptance',async()=>{
 const {f,q}=await ready();await q.start();const evaluated=await q.evaluate(),p=f.verifier.open(evaluated.proof,'evaluation','sec01.acceptance');
 const forged=f.issuer.seal('evaluation','sec01.acceptance',{...p,result:{...p.result,artifact_hash:digest('fake')}});assert.equal((await q.accept(forged)).decision,'DENY');assert.equal(q.pending.accepted,false);
});
