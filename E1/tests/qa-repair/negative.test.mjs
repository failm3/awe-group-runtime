import assert from 'node:assert/strict';
import test from 'node:test';
import {digest} from '../../contracts/index.mjs';
import {ORACLE_COMMITMENT} from '../../qa-coding/commitments.mjs';
import {priorRecord,checkAggregate,checkPriorNative} from '../../qa-repair/prior.mjs';
import {checkRepairTree,checkedProduct,inspectHead,reconcileVote} from '../../qa-repair/bindings.mjs';
import {treeFromFiles,gitOid,sha256} from '../../qa-coding/tree-proof.mjs';

const p=priorRecord(),oldAttempt=p.native_attempt;
const mission='mission_new_test', project='project_new_test';
function fresh(){
  const attempts=['head_plan','code_r02'].map((task_id,i)=>({project_id:project,mission_id:mission,task_id,attempt_id:'a'+i,logical_request_id:'r'+i,
    state:'CONFIRMED',route_id:oldAttempt.route,request_hash:digest('input'+i),usage:structuredClone(oldAttempt.usage),actual_cost:0,reserved:0}));
  return {project:{project_id:project,quota_cap:3,quota_used:2,reserved:0,spent:0},attempts,intents:[],cloud_attempts:[]};
}
test('combined count retains prior and allows exactly one Head and up to two repair codes',()=>{
 const s=fresh();assert.equal(checkAggregate(s,mission).total_wires,3);
 const a={...s.attempts[1],task_id:'code_r03',attempt_id:'a2',logical_request_id:'r2'};s.attempts.push(a);s.project.quota_used=3;
 assert.deepEqual(checkAggregate(s,mission),{prior_wires:1,head_wires:1,repair_wires:2,total_wires:4,total_cap:4,remaining:0});
});
for(const [label,edit] of [
 ['substituted prior project',s=>s.project.project_id=p.project_id],['foreign mission',s=>s.attempts[0].mission_id='other'],['raw project quota reset',s=>s.project.quota_used=0],
 ['UNKNOWN',s=>s.attempts[1].state='OUTCOME_UNKNOWN'],['duplicate Head',s=>s.attempts[1].task_id='head_plan'],['provider substitution',s=>s.attempts[1].route_id='other'],
 ['reused old logical request',s=>s.attempts[1].logical_request_id=oldAttempt.logical_request_id],['claimed free fourth wire',s=>s.project.quota_cap=4],['product model request',s=>s.attempts[1].task_id='product_gate']
])test('aggregate rejects '+label,()=>{const s=fresh();edit(s);assert.throws(()=>checkAggregate(s,mission));});

function records(label,cli){
  const files=[{path:'cli.py',mode:'100644',content_utf8:cli},{path:'normalizer.py',mode:'100644',content_utf8:'# harmless inert unchanged text'}]
    .map(f=>({...f,blob_sha:gitOid('blob',f.content_utf8)}));
  return {head_sha: label.repeat(40),tree_sha:treeFromFiles(files),files};
}
test('one-file repair preserves untouched Git blob; statement that both files changed is unnecessary',()=>{
 const base=records('a','# prior inert bytes'),final=records('b','# later inert bytes');
 const c={path:'cli.py',before_digest:sha256(base.files[0].content_utf8),after_text:final.files[0].content_utf8};
 const raw={base_sha:base.head_sha,changes:[c]},enriched={head_sha:final.head_sha,tree_sha:final.tree_sha,patch:{changes:[{...c,after_digest:sha256(c.after_text)}]}};
 checkRepairTree({base,final},raw,enriched);
 const forged=structuredClone(final);forged.files[1].content_utf8='# substituted';forged.files[1].blob_sha=gitOid('blob',forged.files[1].content_utf8);
 forged.tree_sha=treeFromFiles(forged.files);assert.throws(()=>checkRepairTree({base,final:forged},raw,{...enriched,tree_sha:forged.tree_sha}));
});
test('Head accepts a bounded real-diagnosis plan, rejects vague repair or permission changes',()=>{
 assert.equal(inspectHead({decision:'REPAIR',reason:'Prior CLI failed',focus:'Correct the CLI syntax.',max_code_attempts:2}),true);
 assert.equal(inspectHead({decision:'REPAIR',reason:'problem',focus:'do things',max_code_attempts:1}),false);
 assert.throws(()=>inspectHead({decision:'REPAIR',reason:'x',focus:'read .private',max_code_attempts:1}));
 assert.throws(()=>inspectHead({decision:'REPAIR',reason:'x',focus:'CLI syntax',max_code_attempts:3}));
});
test('held-out product gate cannot be satisfied by an accepted failed-test report or substituted code/result/QA',()=>{
 const ev={coding_artifact:{head_sha:'a'.repeat(40),tree_sha:'b'.repeat(40)},product_status:'PENDING_INDEPENDENT_QA'};
 const t={state:'ACCEPTED',task_id:'code_r02',mission_id:mission,producer_id:'worker',result:{evidence:ev}};t.result_hash=digest(t.result);
 const val={product_pass:true,head_sha:ev.coding_artifact.head_sha,tree_sha:ev.coding_artifact.tree_sha,code_result_hash:t.result_hash,oracle_digest:ORACLE_COMMITMENT,prior_result_hash:p.result_hash};
 const event={kind:'QA_PASS',mission_id:mission,task_id:'code_r02',body:{result_hash:t.result_hash,evaluator_id:'e1_qa'}};
 checkedProduct(val,t,[event],p);
 assert.throws(()=>checkedProduct({...val,product_pass:false},t,[event],p));
 assert.throws(()=>checkedProduct({...val,tree_sha:'d'.repeat(40)},t,[event],p));
 assert.throws(()=>checkedProduct(val,t,[],p));
 assert.throws(()=>checkedProduct(val,{...t,producer_id:'e1_qa'},[event],p));
 ev.product_status='PRODUCER_TEST_FAILED'; t.result_hash=digest(t.result);event.body.result_hash=t.result_hash;
 assert.throws(()=>checkedProduct({...val,code_result_hash:t.result_hash},t,[event],p));
});
test('native QA loss of acknowledgement reconciles once; mismatched or duplicate vote is not a success',()=>{
 const t={task_id:'code_r02',mission_id:mission,result_hash:digest('r'),state:'WAIT_QA'};
 const event={kind:'QA_PASS',task_id:t.task_id,mission_id:mission,body:{result_hash:t.result_hash,evaluator_id:'e1_qa'}};
 assert.equal(reconcileVote(t,[],'PASS'),'SUBMIT');assert.throws(()=>reconcileVote(t,[event],'PASS'));
 t.state='ACCEPTED';assert.equal(reconcileVote(t,[event],'PASS'),'RECONCILED');
 assert.throws(()=>reconcileVote(t,[event,event],'PASS'));assert.throws(()=>reconcileVote(t,[event],'FAIL'));
});
test('prior must be an actual native failure; an unrelated empty prior project is rejected',()=>{
 assert.throws(()=>checkPriorNative(fresh(),[]));
});
