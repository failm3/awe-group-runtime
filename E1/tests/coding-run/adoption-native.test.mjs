import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {randomBytes,createHash} from 'node:crypto';
import {digest} from '../../contracts/index.mjs';
import {createPsqlSession,sqlJson} from '../../coordinator/psql-session.mjs';
import {validateResourceDescriptor} from '../../coordinator/resource.mjs';
import {createCodingRunStore} from '../../coordinator/coding-run.mjs';
import {createNativeE1Host} from '../../host/staging.mjs';
import {createRepairMission} from '../../host/coding/repair-mission.mjs';
import {REPAIR_PRODUCT_SCHEMA_DIGEST,REPAIR_HEAD_SCHEMA_DIGEST} from '../../host/coding/repair-contracts.mjs';
import {PATCH_PROPOSAL_SCHEMA_DIGEST} from '../../executors/coding/contracts.mjs';

const enabled=process.env.AWE_CODING_RUN_NATIVE==='1';
const results=[];
const hash=label=>digest({label});
const byteHash=text=>createHash('sha256').update(text).digest('hex');
const scalar=value=>sqlJson(value)+"#>>'{}'";
const RollbackFixture=class extends Error {};

/** These tests intentionally seed contract fixtures inside ROLLBACK. They
 * perform NO provider transport and produce NO claimed AWE implementation. */
test('native prior adoption and Head/product gates use real SQL and preserve original G1',{skip:!enabled,timeout:180000},async t=>{
  const resource=validateResourceDescriptor(JSON.parse(fs.readFileSync(process.env.AWE_E1_CODING_RUN_RESOURCE??new URL('../../../.private/e1-resource.json',import.meta.url),'utf8')));
  const report=JSON.parse(fs.readFileSync(new URL('../../coding/evidence/g1_normalize_01.json',import.meta.url),'utf8'));
  const a=report.native_attempts[0],artifact=report.outcome.artifact;
  const prior={project_id:a.project_id,mission_id:a.mission_id,task_id:a.task_id,attempt_id:a.attempt_id,logical_request_id:a.logical_request_id,worker_id:a.worker_id,fence:Number(a.fence),request_hash:a.request_hash,plan_digest:report.native_task.plan_digest,result_hash:report.native_task.result_hash,artifact_digest:artifact.artifact_digest,head_sha:artifact.head_sha,tree_sha:artifact.tree_sha};
  const hosts=[];let admin;
  t.after(async()=>{if(admin)await admin.close();for(const h of hosts){await h.host.coordinator.cancel({mission_id:h.f.spec.mission_id,reason:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST_COMPLETE'}).catch(()=>{});await h.host.close();}});
  async function fixture() {
    const run_id='adopt_'+randomBytes(5).toString('hex'),f=createRepairMission({run_id,issue:report.issue,prior,failedPublicTest:{origin:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST'}});
    const policy={budget_cap_micros:'0',quota_cap:3,max_parallel:1,resource_limits:{cpu:1,local_model:1},capabilities:Object.fromEntries(f.capabilities.map(c=>[c.ref.capability_id,{resource_keys:[c.executor_kind==='llm'?'local_model':'cpu'],max_claims:1,priority:0}]))};
    const host=await createNativeE1Host({resource,authority:f.authority,ingress:f.ingress,capabilities:f.capabilities,domainManifests:[f.domainManifest],ownerGrants:[f.grant],policy});
    await host.admitPublished(f.spec.mission_id,f.contexts.coordinator);
    const plan=f.codingPlan({draft:{decision:'REPAIR',reason:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST',focus:'No model or candidate implementation in this fixture.',max_code_attempts:2},revision:2,previous_digest:digest(f.plan),task_id:'code_r02',publicFailure:{origin:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST'}});
    f.publish(plan);await host.admitPublished(f.spec.mission_id,f.contexts.coordinator);
    const binding={schema:'awe.e1.coding-run-binding/1',run_id,project_id:f.spec.project_id,mission_id:f.spec.mission_id,root_grant_digest:digest(f.grant),brief_digest:report.issue.digest,oracle_digest:report.oracle_commitment,source_digest:hash('explicit native guard fixture'),original_base_sha:prior.head_sha,deadline:f.spec.deadline,head_task_id:'head_plan',code_task_ids:['code_r01','code_r02','code_r03'],head_capability_id:'e1.head.coding',code_capability_id:'e1.coding.patch',product_task_id:'product_gate',product_capability_id:'e1.coding.product',product_output_schema_digest:REPAIR_PRODUCT_SCHEMA_DIGEST,limits:{head:1,code:3,total:4},prior_attempt_refs:[prior]};
    const value={run_id,f,host,plan,binding};hosts.push(value);return value;
  }
  // Admission occurs before any prior row is read/locked in the test transaction.
  const one=await fixture(),two=await fixture();admin=await createPsqlSession(resource,{role:'admin'});
  const oldSnapshotSql="SELECT jsonb_build_object('project',(SELECT to_jsonb(x) FROM awe_e1_runtime.project x WHERE project_id="+scalar(prior.project_id)+"),'mission',(SELECT to_jsonb(x) FROM awe_e1_runtime.mission x WHERE mission_id="+scalar(prior.mission_id)+"),'task',(SELECT to_jsonb(x) FROM awe_e1_runtime.task x WHERE mission_id="+scalar(prior.mission_id)+" AND task_id="+scalar(prior.task_id)+"),'attempt',(SELECT to_jsonb(x) FROM awe_e1_runtime.model_attempt x WHERE attempt_id="+scalar(prior.attempt_id)+"),'qa',(SELECT jsonb_agg(to_jsonb(x) ORDER BY at) FROM awe_e1_runtime.qa_revision x WHERE mission_id="+scalar(prior.mission_id)+"));";
  const oldBefore=byteHash(await admin.query(oldSnapshotSql));
  const checks=[];
  try {
    await admin.transaction(async tx=>{
      const db={kind:admin.kind,role:admin.role,query:tx.query};
      const store=createCodingRunStore({db,project_id:one.f.spec.project_id}),other=createCodingRunStore({db,project_id:two.f.spec.project_id});
      const opened=await store.open(one.binding);assert.equal(opened.counters.total,1);assert.equal(opened.counters.prior,1);assert.equal(opened.counters.remaining_code,2);checks.push('PRIOR_REAL_CONFIRMED_FAILED_QA_JOIN');
      await assert.rejects(other.open({...two.binding,prior_attempt_refs:[{...prior,request_hash:hash('substitute request')}]}),/CODING_RUN_PRIOR_NATIVE_BINDING/);checks.push('PRIOR_REQUEST_SUBSTITUTION_DENIED');
      await assert.rejects(other.open(two.binding),/CODING_RUN_LINEAGE_ALREADY_ADOPTED/);checks.push('SECOND_PRIOR_ADOPTION_DENIED');
      const whereRun='project_id='+scalar(one.f.spec.project_id)+' AND run_id='+scalar(one.run_id),whereTask=id=>'project_id='+scalar(one.f.spec.project_id)+' AND mission_id='+scalar(one.f.spec.mission_id)+' AND task_id='+scalar(id);
      const headOutput={decision:'REPAIR',reason:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST',focus:'Контрактный SQL-тест; это не ответ AWE.',max_code_attempts:2};
      const headResult={output_schema_digest:REPAIR_HEAD_SCHEMA_DIGEST,output:headOutput,artifact_digest:digest(headOutput),evidence:{origin:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST'}};
      const headFence=Number(JSON.parse(await tx.query("SELECT to_jsonb(nextval('awe_e1_runtime.fence_sequence'));")));
      const headScope={task_id:'head_plan',worker_id:'e1_worker',fence:headFence,attempt_id:'head_'+one.run_id,logical_request_id:'head_request_'+one.run_id,plan_digest:digest(one.f.plan),head_output_digest:digest(headOutput)};
      await tx.query('UPDATE awe_e1_runtime.task SET state=\'ACCEPTED\',producer_id=\'e1_worker\',fence='+headFence+',result='+sqlJson(headResult)+',result_hash='+scalar(digest(headResult))+' WHERE '+whereTask('head_plan')+';');
      await tx.query('INSERT INTO awe_e1_runtime.model_attempt(attempt_id,project_id,mission_id,task_id,logical_request_id,worker_id,fence,route_id,request_hash,reserved,quota_units,state,actual_cost,usage,provider_ref) VALUES('+[scalar(headScope.attempt_id),scalar(one.f.spec.project_id),scalar(one.f.spec.mission_id),scalar('head_plan'),scalar(headScope.logical_request_id),scalar('e1_worker'),headFence,scalar('ollama.local.qwen3-4b-instruct'),scalar(hash('native no transport head')),0,1,scalar('CONFIRMED'),0,sqlJson({origin:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST',input_tokens:0,output_tokens:0}),scalar('explicit-synthetic-no-provider')].join(',')+');');
      await tx.query('UPDATE awe_e1_runtime.project SET quota_used=1 WHERE project_id='+scalar(one.f.spec.project_id)+';');
      const headChecks=one.f.plan.tasks.find(task=>task.task_id==='head_plan').qa.required_checks.map(check_id=>({check_id,passed:true,origin:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST'}));
      await tx.query('INSERT INTO awe_e1_runtime.qa_revision(mission_id,plan_digest,task_id,result_hash,evaluator_id,verdict,checks) VALUES('+[scalar(one.f.spec.mission_id),scalar(digest(one.f.plan)),scalar('head_plan'),scalar(digest(headResult)),scalar('e1_qa'),scalar('PASS'),sqlJson(headChecks)].join(',')+');');
      await tx.query('INSERT INTO awe_e1_runtime.event(project_id,mission_id,task_id,kind,body) VALUES('+[scalar(one.f.spec.project_id),scalar(one.f.spec.mission_id),scalar('head_plan'),scalar('CODING_RUN_HEAD_CONFIRMED'),sqlJson({run_id:one.run_id,refs:headScope,origin:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST'})].join(',')+');');
      const reset=async(phase,refs,revision=0)=>tx.query('UPDATE awe_e1_runtime.coding_run SET phase='+scalar(phase)+',revision='+revision+',state='+sqlJson({refs,decision:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST'})+' WHERE '+whereRun+';');
      const savepoint=async(name,fn)=>{await tx.query('SAVEPOINT '+name+';');try{await fn();}finally{await tx.query('ROLLBACK TO SAVEPOINT '+name+';');}};
      const headRefs={...headScope,plan_digest:digest(one.plan)};
      await reset('HEAD_CONFIRMED',headRefs);
      const admit={run_id:one.run_id,expected_revision:0,operation_id:'native.head.valid',transition:{phase:'PLAN_READY',decision:'ADMIT_NATIVE_FIXTURE',refs:{plan_digest:digest(one.plan)}}};
      const canonical=JSON.parse(await tx.query('SELECT to_jsonb(awe_e1_runtime.coding_head_output_digest('+sqlJson(headOutput)+'));'));assert.equal(canonical,digest(headOutput));checks.push('UNICODE_HEAD_DIGEST_MATCHES_JS');
      await savepoint('no_head_qa',async()=>{await tx.query('DELETE FROM awe_e1_runtime.qa_revision WHERE mission_id='+scalar(one.f.spec.mission_id)+' AND task_id=\'head_plan\';');await assert.rejects(store.advance(admit),/CODING_RUN_ACCEPTED_HEAD_REQUIRED/);});checks.push('HEAD_WITHOUT_QA_DENIED');
      await savepoint('head_same_evaluator',async()=>{await tx.query('UPDATE awe_e1_runtime.qa_revision SET evaluator_id=\'e1_worker\' WHERE mission_id='+scalar(one.f.spec.mission_id)+' AND task_id=\'head_plan\';');await assert.rejects(store.advance(admit),/CODING_RUN_ACCEPTED_HEAD_REQUIRED/);});checks.push('HEAD_PRODUCER_QA_DENIED');
      await savepoint('unrelated_head_fence',async()=>{await tx.query('UPDATE awe_e1_runtime.event SET body=jsonb_set(body,\'{refs,fence}\','+sqlJson(headFence+1)+') WHERE project_id='+scalar(one.f.spec.project_id)+' AND kind=\'CODING_RUN_HEAD_CONFIRMED\';');await assert.rejects(store.advance(admit),/CODING_RUN_ACCEPTED_HEAD_REQUIRED/);});checks.push('UNRELATED_HEAD_GENERATION_DENIED');
      await savepoint('wrong_head_digest',async()=>{await reset('HEAD_CONFIRMED',{...headRefs,head_output_digest:hash('substitute head')});await assert.rejects(store.advance(admit),/CODING_RUN_HEAD_NATIVE_PIN_REQUIRED/);});checks.push('HEAD_HASH_SUBSTITUTION_DENIED');
      await savepoint('head_blocked',async()=>{const blocked={...headOutput,decision:'BLOCK_SCOPE'},r={...headResult,output:blocked,artifact_digest:digest(blocked)};await tx.query('UPDATE awe_e1_runtime.task SET result='+sqlJson(r)+',result_hash='+scalar(digest(r))+' WHERE '+whereTask('head_plan')+';');await tx.query('UPDATE awe_e1_runtime.qa_revision SET result_hash='+scalar(digest(r))+' WHERE mission_id='+scalar(one.f.spec.mission_id)+' AND task_id=\'head_plan\';');await tx.query('UPDATE awe_e1_runtime.event SET body=jsonb_set(body,\'{refs,head_output_digest}\','+sqlJson(digest(blocked))+') WHERE project_id='+scalar(one.f.spec.project_id)+' AND kind=\'CODING_RUN_HEAD_CONFIRMED\';');await reset('HEAD_CONFIRMED',{...headRefs,head_output_digest:digest(blocked)});await assert.rejects(store.advance(admit),/CODING_RUN_HEAD_BLOCKED_SCOPE/);});checks.push('HEAD_BLOCK_SCOPE_DENIED');
      const admitted=await store.advance(admit);assert.equal(admitted.phase,'PLAN_READY');checks.push('ACCEPTED_PINNED_HEAD_ADMITS_PLAN');
      const v7Privileges=JSON.parse(await tx.query("SELECT jsonb_build_object('coord',has_function_privilege('awe_e1_coord','awe_e1_runtime.coding_run_command_v7(text,jsonb)','EXECUTE'),'qa',has_function_privilege('awe_e1_qa','awe_e1_runtime.coding_run_command_v7(text,jsonb)','EXECUTE'),'worker',has_function_privilege('awe_e1_worker','awe_e1_runtime.coding_run_command_v7(text,jsonb)','EXECUTE'));"));assert.deepEqual(v7Privileges,{coord:false,qa:false,worker:false});checks.push('V7_BYPASS_ROLES_DENIED');

      const claim=await tx.command('claim',{project_id:one.f.spec.project_id,mission_id:one.f.spec.mission_id,task_id:'code_r02',worker_id:'e1_worker',capabilities:['e1.coding.patch'],lease_ms:120000});assert.equal(claim.status,'CLAIMED');
      const codeScope={project_id:one.f.spec.project_id,mission_id:one.f.spec.mission_id,task_id:'code_r02',worker_id:claim.worker_id,fence:claim.fence,attempt_id:'code_'+one.run_id,logical_request_id:'code_request_'+one.run_id};
      await tx.command('reserve',{...codeScope,route_id:'ollama.local.qwen3-4b-instruct',request_hash:hash('explicit native no transport code'),reserve_micros:0,quota_units:1,capability_id:'e1.coding.patch',capability_version:'1.0.0'});
      await tx.command('mark_sending',codeScope);await tx.command('settle',{...codeScope,actual_cost_micros:0,usage:{origin:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST',input_tokens:0,output_tokens:0},provider_ref:'explicit-synthetic-no-provider'});
      const candidateHead='c'.repeat(40),candidateTree='d'.repeat(40),patch={base_sha:prior.head_sha,summary:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST_NOT_AWE_CODE',changes:[{path:'fixture.txt',before_digest:hash('not an executable baseline'),after_text:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST'}]};
      const codeResult={output_schema_digest:PATCH_PROPOSAL_SCHEMA_DIGEST,output:patch,artifact_digest:digest(patch),evidence:{origin:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST',product_status:'PENDING_INDEPENDENT_QA',coding_artifact:{contract_version:'awe.e1.coding-artifact/2',head_sha:candidateHead,tree_sha:candidateTree,tests:[{exit_code:0,origin:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST'}]}}};
      await tx.command('complete',{...codeScope,result:codeResult,result_hash:digest(codeResult)});
      const codeChecks=one.plan.tasks.find(task=>task.task_id==='code_r02').qa.required_checks.map(check_id=>({check_id,passed:true,origin:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST'}));
      await tx.command('qa_evaluate',{project_id:one.f.spec.project_id,mission_id:one.f.spec.mission_id,task_id:'code_r02',plan_digest:digest(one.plan),result_hash:digest(codeResult),evaluator_id:'e1_qa',verdict:'PASS',checks:codeChecks});
      await savepoint('head_limit_one',async()=>{
        const limited={...headOutput,max_code_attempts:1},r={...headResult,output:limited,artifact_digest:digest(limited)};
        await tx.query('UPDATE awe_e1_runtime.task SET result='+sqlJson(r)+',result_hash='+scalar(digest(r))+' WHERE '+whereTask('head_plan')+';');
        await tx.query('UPDATE awe_e1_runtime.qa_revision SET result_hash='+scalar(digest(r))+' WHERE mission_id='+scalar(one.f.spec.mission_id)+' AND task_id=\'head_plan\';');
        await tx.query('UPDATE awe_e1_runtime.event SET body=jsonb_set(body,\'{refs,head_output_digest}\','+sqlJson(digest(limited))+') WHERE project_id='+scalar(one.f.spec.project_id)+' AND kind=\'CODING_RUN_HEAD_CONFIRMED\';');
        await reset('PLAN_READY',{...headRefs,head_output_digest:digest(limited)},1);
        await assert.rejects(store.advance({run_id:one.run_id,expected_revision:1,operation_id:'native.head.max_one',transition:{phase:'CODE_PENDING',decision:'TRY_FORBIDDEN_SECOND_CODE',refs:{task_id:'code_r03',attempt_id:'never_sent_fixture',logical_request_id:'never_sent_request',worker_id:'e1_worker',fence:headFence+10,plan_digest:digest(one.plan),candidate_base_sha:candidateHead}}}),/CODING_RUN_HEAD_ATTEMPT_LIMIT/);
      });checks.push('HEAD_MAX_ONE_DENIES_SECOND_CODE');
      const refs={...headRefs,...codeScope,plan_digest:digest(one.plan),candidate_base_sha:prior.head_sha,candidate_head_sha:candidateHead,candidate_tree_sha:candidateTree,tests_passed:true,qa_result_hash:digest(codeResult),code_task_id:'code_r02',code_result_hash:digest(codeResult)};delete refs.project_id;delete refs.mission_id;
      await reset('QA_PENDING',refs,1);
      await assert.rejects(store.advance({run_id:one.run_id,expected_revision:1,operation_id:'native.code.false_finish',transition:{phase:'RESULT_READY',decision:'FALSE_CODE_ONLY_SUCCESS',refs:{product_pass:true}}}),/CODING_RUN_PHASE_ORDER/);checks.push('CODE_ONLY_RESULT_DENIED');
      const productPending=await store.advance({run_id:one.run_id,expected_revision:1,operation_id:'native.product.intent',transition:{phase:'PRODUCT_PENDING',decision:'START_PRODUCT_GUARD_FIXTURE',refs:{}}});assert.equal(productPending.phase,'PRODUCT_PENDING');
      const productOutput={product_pass:true,head_sha:candidateHead,tree_sha:candidateTree,code_result_hash:digest(codeResult),oracle_digest:one.binding.oracle_digest,prior_result_hash:prior.result_hash};
      const productResult={output_schema_digest:REPAIR_PRODUCT_SCHEMA_DIGEST,output:productOutput,artifact_digest:digest(productOutput),evidence:{origin:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST'}};
      const productClaim=await tx.command('claim',{project_id:one.f.spec.project_id,mission_id:one.f.spec.mission_id,task_id:'product_gate',worker_id:'e1_worker',capabilities:['e1.coding.product'],lease_ms:120000});assert.equal(productClaim.status,'CLAIMED');
      await tx.command('complete',{project_id:one.f.spec.project_id,mission_id:one.f.spec.mission_id,task_id:'product_gate',worker_id:productClaim.worker_id,fence:productClaim.fence,result:productResult,result_hash:digest(productResult)});
      const productChecks=one.plan.tasks.find(task=>task.task_id==='product_gate').qa.required_checks.map(check_id=>({check_id,passed:true,...(check_id==='product'?{oracle_digest:one.binding.oracle_digest,head_sha:candidateHead,tree_sha:candidateTree}:{}),origin:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST'}));
      await tx.command('qa_evaluate',{project_id:one.f.spec.project_id,mission_id:one.f.spec.mission_id,task_id:'product_gate',plan_digest:digest(one.plan),result_hash:digest(productResult),evaluator_id:'e1_qa',verdict:'PASS',checks:productChecks});
      const finish={run_id:one.run_id,expected_revision:2,operation_id:'native.product.finish',transition:{phase:'RESULT_READY',decision:'NATIVE_GUARD_FIXTURE_ONLY',refs:{product_pass:true,product_result_hash:digest(productResult)}}};
      async function rejectProduct(name,sql){await savepoint(name,async()=>{await tx.query(sql);await assert.rejects(store.advance(finish),/CODING_RUN_PRODUCT_GATE_REQUIRED/);assert.equal((await store.read(one.run_id)).stored_phase,'PRODUCT_PENDING');});checks.push(name.toUpperCase()+'_DENIED');}
      await rejectProduct('product_no_qa','DELETE FROM awe_e1_runtime.qa_revision WHERE mission_id='+scalar(one.f.spec.mission_id)+' AND task_id=\'product_gate\';');
      await rejectProduct('product_wrong_schema','UPDATE awe_e1_runtime.task SET result=jsonb_set(result,\'{output_schema_digest}\','+sqlJson(hash('wrong schema'))+') WHERE '+whereTask('product_gate')+';');
      await rejectProduct('product_wrong_head','UPDATE awe_e1_runtime.task SET result=jsonb_set(result,\'{output,head_sha}\','+sqlJson('e'.repeat(40))+') WHERE '+whereTask('product_gate')+';');
      await rejectProduct('product_wrong_prior','UPDATE awe_e1_runtime.task SET result=jsonb_set(result,\'{output,prior_result_hash}\','+sqlJson(hash('wrong prior'))+') WHERE '+whereTask('product_gate')+';');
      await rejectProduct('product_wrong_oracle','UPDATE awe_e1_runtime.task SET result=jsonb_set(result,\'{output,oracle_digest}\','+sqlJson(hash('wrong oracle'))+') WHERE '+whereTask('product_gate')+';');
      await rejectProduct('product_same_producer_qa','UPDATE awe_e1_runtime.qa_revision SET evaluator_id=\'e1_worker\' WHERE mission_id='+scalar(one.f.spec.mission_id)+' AND task_id=\'product_gate\';');
      await savepoint('unexpected_mission',async()=>{
        const foreignFence=Number(JSON.parse(await tx.query("SELECT to_jsonb(nextval('awe_e1_runtime.fence_sequence'));")));
        await tx.query('INSERT INTO awe_e1_runtime.model_attempt(attempt_id,project_id,mission_id,task_id,logical_request_id,worker_id,fence,route_id,request_hash,reserved,quota_units,state,actual_cost,usage,provider_ref) VALUES('+[scalar('foreign_'+one.run_id),scalar(one.f.spec.project_id),scalar(two.f.spec.mission_id),scalar('code_r02'),scalar('foreign_request_'+one.run_id),scalar('e1_worker'),foreignFence,scalar('ollama.local.qwen3-4b-instruct'),scalar(hash('synthetic cross-scope fixture')),0,1,scalar('CONFIRMED'),0,sqlJson({origin:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST'}),scalar('explicit-synthetic-no-provider')].join(',')+');');
        await tx.query('UPDATE awe_e1_runtime.project SET quota_used=3 WHERE project_id='+scalar(one.f.spec.project_id)+';');
        const held=await store.read(one.run_id);assert.equal(held.phase,'HOLD');assert.equal(held.counters.total,4);assert.equal(held.counters.unregistered,1);
        await assert.rejects(store.advance(finish),/CODING_RUN_NATIVE_HOLD/);
      });checks.push('ALL_PROJECT_FOREIGN_MISSION_COUNTED_AND_HELD');
      const final=await store.advance(finish);assert.equal(final.phase,'RESULT_READY');assert.equal(final.counters.total,3);assert.equal((await store.advance(finish)).repeated,true);checks.push('EXACT_PRODUCT_NATIVE_QA_GUARD_POSITIVE');
      throw new RollbackFixture('ROLLBACK_ALL_NEW_GUARD_STATE');
    });
    assert.fail('The native fixture must end in rollback.');
  } catch(error) {if(!(error instanceof RollbackFixture))throw error;}
  const oldAfter=byteHash(await admin.query(oldSnapshotSql));assert.equal(oldAfter,oldBefore,'Original G1 project/task/attempt/QA must remain unchanged.');
  const adopted=JSON.parse(await admin.query('SELECT jsonb_build_object(\'rows\',count(*)) FROM awe_e1_runtime.coding_run WHERE binding#>>\'{prior_attempt_refs,0,attempt_id}\'='+scalar(prior.attempt_id)+';'));assert.equal(adopted.rows,0,'Rollback must leave the real prior lineage free for the actual repair.');
  results.push({status:'PASS_NATIVE_GUARD_FIXTURES_ONLY',checks,guard_project_ids:hosts.map(h=>h.f.spec.project_id),prior_attempt_id:prior.attempt_id,old_native_digest_before:oldBefore,old_native_digest_after:oldAfter,prior_rows_after_rollback:0,all_seeded_results:'EXPLICIT_SYNTHETIC_NATIVE_GUARD_TEST_NOT_AWE_AUTHORSHIP',provider_calls:0,model_calls:0,paid_calls:0,old_rows_changed:0});
});

test.after(()=>{if(enabled&&process.env.AWE_CODING_RUN_ADOPTION_EVIDENCE)fs.writeFileSync(process.env.AWE_CODING_RUN_ADOPTION_EVIDENCE,JSON.stringify({schema:'awe.e1.coding-run-adoption-native-review/1',mode:'EXPLICIT_SYNTHETIC_NATIVE_FIXTURES_ROLLED_BACK',results},null,2)+'\n');});
