import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../../contracts/index.mjs';
import {CODING_RUN_SCHEMA, validateCodingRunBinding, summarizeCodingAttempts, codingModelStepDisposition, validateCodingRunTransition, createCodingRunStore, EMPTY_CODING_RUN_ROLLBACK_SQL} from '../../coordinator/coding-run.mjs';

const h = label => digest({label});
function binding() {
  return {schema:CODING_RUN_SCHEMA,run_id:'repair_fixture',project_id:'project_repair',mission_id:'mission_repair',root_grant_digest:h('grant'),brief_digest:h('brief'),oracle_digest:h('oracle'),source_digest:h('source'),original_base_sha:'a'.repeat(40),deadline:'2099-11-08T00:00:00.000Z',head_task_id:'head_plan',code_task_ids:['code_r01','code_r02','code_r03'],head_capability_id:'e1.head.coding',code_capability_id:'e1.coding.patch',product_task_id:'product_gate',product_capability_id:'e1.coding.product',product_output_schema_digest:h('product_schema'),limits:{head:1,code:3,total:4},prior_attempt_refs:[]};
}
function attempt(task_id, state='CONFIRMED', extra={}) { return {project_id:'project_repair',mission_id:'mission_repair',task_id,attempt_id:'attempt_'+task_id,logical_request_id:'request_'+task_id,worker_id:'worker',fence:1,request_hash:h(task_id),route_id:'ollama.local.qwen3-4b-instruct',state,...extra}; }
function priorBinding() {
  const b=binding(),row=attempt('code_r01','CONFIRMED',{project_id:'project_original',mission_id:'mission_original'});
  b.prior_attempt_refs=[{project_id:row.project_id,mission_id:row.mission_id,task_id:row.task_id,attempt_id:row.attempt_id,logical_request_id:row.logical_request_id,worker_id:row.worker_id,fence:row.fence,request_hash:row.request_hash,plan_digest:h('oldplan'),result_hash:h('oldresult'),artifact_digest:h('oldartifact'),head_sha:b.original_base_sha,tree_sha:'b'.repeat(40)}];
  return {b,row};
}
test('run binding freezes exact scope, fixed combined limits and distinct product task',()=>{
  const b=binding();assert.equal(Object.isFrozen(validateCodingRunBinding(b)),true);
  for(const change of [x=>x.limits.total=5,x=>x.limits.code=4,x=>x.code_task_ids[1]=x.code_task_ids[0],x=>x.product_task_id=x.code_task_ids[0],x=>x.source_digest='unknown',x=>x.paid_cap=10]){const v=structuredClone(b);change(v);assert.throws(()=>validateCodingRunBinding(v));}
});
test('adopted native attempt is pinned once, including request/fence/result/source',()=>{
  const {b,row}=priorBinding();validateCodingRunBinding(b);const c=summarizeCodingAttempts(b,[row]);assert.equal(c.total,1);assert.equal(c.prior,1);assert.equal(c.remaining_code,2);assert.equal(c.remaining_total,3);
  assert.throws(()=>summarizeCodingAttempts(b,[]),/PRIOR_MISSING_OR_CHANGED/);
  assert.throws(()=>summarizeCodingAttempts(b,[{...row,request_hash:h('other')}]),/PRIOR_MISSING_OR_CHANGED/);
  b.prior_attempt_refs.push(b.prior_attempt_refs[0]);assert.throws(()=>validateCodingRunBinding(b),/PRIOR_SCOPE/);
});
test('all A2 states consume conservative attempt cap, including proven-no-send FAILED',()=>{
  const b=binding(),rows=[attempt('head_plan'),attempt('code_r01','FAILED'),attempt('code_r02'),attempt('code_r03')],c=summarizeCodingAttempts(b,rows);
  assert.equal(c.total,4);assert.equal(c.code,3);assert.equal(c.remaining_total,0);
  assert.throws(()=>codingModelStepDisposition(b,rows,{kind:'CODE',task_id:'code_r03',attempt_id:'another_attempt'}),/ATTEMPT_CAP/);
});
test('same-project foreign mission and unregistered routes force HOLD rather than hidden spend',()=>{
  for(const extra of [{mission_id:'other_mission'},{route_id:'router.cheap.unapproved'},{task_id:'unregistered'}]){const c=summarizeCodingAttempts(binding(),[attempt('code_r01','CONFIRMED',extra)]);assert.equal(c.total,1);assert.equal(c.hold,true);assert.equal(c.unregistered,1);}
});
test('UNKNOWN and SENDING remain HOLD and retain aggregate prior liabilities',()=>{
  const {b,row}=priorBinding();for(const state of ['SENDING','OUTCOME_UNKNOWN']){const rows=[row,attempt('head_plan',state)],d=codingModelStepDisposition(b,rows,{kind:'HEAD',task_id:'head_plan',attempt_id:'attempt_head_plan'});assert.equal(d.decision,'HOLD');assert.equal(d.counts.total,2);assert.equal(d.counts.prior,1);assert.equal(d.counts.remaining_total,2);}
});
test('confirmed model is recovered from frozen artifact, never invoked again',()=>{
  const b=binding(),row=attempt('head_plan');assert.equal(codingModelStepDisposition(b,[row],{kind:'HEAD',task_id:'head_plan',attempt_id:row.attempt_id}).decision,'RECOVER_CONFIRMED_ARTIFACT');
  row.state='RESERVED';assert.equal(codingModelStepDisposition(b,[row],{kind:'HEAD',task_id:'head_plan',attempt_id:row.attempt_id}).decision,'RECONCILE_EXISTING_ATTEMPT');
});
test('adopted round cannot be reset by a new task or revision',()=>{
  const {b,row}=priorBinding();assert.equal(codingModelStepDisposition(b,[row],{kind:'CODE',task_id:'code_r02',attempt_id:'new_attempt'}).decision,'NEW_NATIVE_ATTEMPT_ALLOWED');
  assert.throws(()=>codingModelStepDisposition(b,[row],{kind:'CODE',task_id:'code_r01',attempt_id:'new_attempt'}),/ROUND_SEQUENCE/);
  assert.throws(()=>codingModelStepDisposition(b,[row],{kind:'CODE',task_id:'code_r03',attempt_id:'new_attempt'}),/ROUND_SEQUENCE/);
});
test('product result cannot skip native coding QA or separate product phase',()=>{
  const t={phase:'RESULT_READY',decision:'CLAIM_SUCCESS',refs:{product_pass:true}};
  for(const phase of ['NEW','CODE_PENDING','TESTED','QA_PENDING'])assert.throws(()=>validateCodingRunTransition(phase,t),/PHASE_ORDER/);
  assert.equal(validateCodingRunTransition('PRODUCT_PENDING',t).phase,'RESULT_READY');
});
test('HOLD and other terminal states cannot resume under a fresh decision',()=>{
  for(const phase of ['HOLD','STOPPED','BLOCKED','RESULT_READY'])assert.throws(()=>validateCodingRunTransition(phase,{phase:'CODE_PENDING',decision:'RETRY',refs:{}}),/PHASE_ORDER/);
});
test('run references permit metadata only, reject code/tool requests and malformed pins',()=>{
  for(const refs of [{shell:'python arbitrary.py'},{model_receipt_digest:'not-a-hash'},{candidate_head_sha:'main'},{failure_ref:{raw_code:'not metadata'}},{cursor:-1}])assert.throws(()=>validateCodingRunTransition('CANDIDATE_READY',{phase:'TESTED',decision:'TEST_RESULT',refs}));
});
test('facade denies worker and QA mutations before querying SQL',()=>{
  const fakeDb=role=>({kind:'NATIVE_POSTGRESQL_PSQL_SESSION',role,query(){throw Error('UNEXPECTED_SQL');}});
  assert.throws(()=>createCodingRunStore({db:fakeDb('worker'),project_id:'project_repair'}),/NATIVE_HOST_REQUIRED/);
  const qa=createCodingRunStore({db:fakeDb('qa'),project_id:'project_repair'});
  assert.throws(()=>qa.open(binding()),/HOST_WRITE_REQUIRED/);assert.throws(()=>qa.advance({}),/HOST_WRITE_REQUIRED/);
});
test('facade binds own project and exact CAS/idempotency request hash',async()=>{
  // Labelled SQL transport double: validates encoding only, not PostgreSQL.
  let captured;const db={kind:'NATIVE_POSTGRESQL_PSQL_SESSION',role:'coordinator',async query(sql){captured=JSON.parse(Buffer.from(sql.match(/decode\('([a-f0-9]+)'/)[1],'hex').toString('utf8'));return '{"phase":"HEAD_PENDING","revision":1}';}};
  const store=createCodingRunStore({db,project_id:'project_repair'}),transition={phase:'HEAD_PENDING',decision:'START_HEAD',refs:{}};
  await store.advance({run_id:'repair_fixture',expected_revision:0,operation_id:'head.intent',transition});
  const {request_hash,...value}=captured;assert.equal(request_hash,digest(value));assert.equal(value.project_id,'project_repair');assert.equal(value.expected_revision,0);
  assert.throws(()=>store.open({...binding(),project_id:'another_project'}),/PROJECT_SCOPE/);
});
test('empty rollback is bounded to E1 and rejects all initialized lineage state',()=>{
  assert.match(EMPTY_CODING_RUN_ROLLBACK_SQL,/current_setting\('port'\)<>'5433'/);assert.match(EMPTY_CODING_RUN_ROLLBACK_SQL,/EXISTS\(SELECT 1 FROM awe_e1_runtime.coding_run\)/);assert.match(EMPTY_CODING_RUN_ROLLBACK_SQL,/ROLLBACK_NONEMPTY/);
  assert.match(EMPTY_CODING_RUN_ROLLBACK_SQL,/version>=8/);assert.match(EMPTY_CODING_RUN_ROLLBACK_SQL,/ROLLBACK_UPGRADED/);
  assert.doesNotMatch(EMPTY_CODING_RUN_ROLLBACK_SQL,/DROP\s+(?:DATABASE|SCHEMA)|DELETE\s+FROM\s+awe_e1_runtime\.(?:project|mission|task|model_attempt)\b/i);
});
