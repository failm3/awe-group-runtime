import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createPsqlSession,createAuthorityServer,createAuthorityClient} from '../../coordinator/index.mjs';
import {digest} from '../../contracts/index.mjs';
import {publicationFixture,runtime} from '../coordinator/helpers.mjs';
import {ledgerFixture,descriptor,resultFor,unique} from './fixtures.mjs';

const enabled=process.env.AWE_E1_CLOUD_NATIVE_TEST==='1',evidence=[];
test('native E1 shared cloud accounting — explicit synthetic funding/fake charges only',{skip:!enabled,timeout:120000},async t=>{
  // Root installs additive 0003 first. Tests never migrate/start/stop a cluster.
  await t.test('unfunded key is disabled with zero limits and cannot reserve',async()=>{
    const f=ledgerFixture();try{const rt=await f.open();await rt.admit();const scope=f.scope(await f.claim(rt));
      const budget=await rt.coordinator.cloudBudget(f.funding.grant.key_binding_id);assert.equal(budget.state,'DISABLED');assert.equal(budget.budget_cap,0);assert.equal(budget.per_attempt_cap,0);assert.equal(budget.attempts_cap,0);assert.equal(budget.booked_confirmed_micros,'0');assert.equal(budget.observed_held_charge_micros,'0');assert.equal(budget.observed_overrun_micros,'0');assert.equal(budget.unknown_charge_attempts,0);assert.equal(budget.accounting_semantics.unknown_charge_cost,'UNKNOWN_NOT_ZERO');
      await assert.rejects(()=>rt.coordinator.reserve(scope),{code:'A2_CLOUD_BUDGET_DISABLED'});assert.equal((await rt.coordinator.snapshot()).attempts.length,0);
      evidence.push({kind:'UNFUNDED_CLOUD_DISABLED',project_id:rt.source.spec.project_id,limits:[0,0,0]});
    }finally{await f.close();}
  });
  await t.test('one atomic A2/global reservation settles exact source/cache price and actual charged cost',async()=>{
    const f=ledgerFixture();try{const rt=await f.open();await rt.admit();await f.fund(rt);assert.equal((await f.fund(rt)).repeated,true);
      const claim=await f.claim(rt),scope=f.scope(claim);assert.equal(scope.reserve_micros,40);assert.equal((await rt.coordinator.reserve(scope)).status,'RESERVED');assert.equal((await rt.coordinator.reserve(scope)).repeated,true);
      await assert.rejects(()=>rt.coordinator.reserve({...scope,cloud:{...scope.cloud,quote_digest:digest({changed:true})}}),{code:'A2_CLOUD_ATTEMPT_CONFLICT'});
      await rt.coordinator.markSending(scope);const settle=f.settlement(scope);assert.equal((await rt.coordinator.settle(settle)).status,'CONFIRMED');assert.equal((await rt.coordinator.settle(settle)).repeated,true);
      const state=await rt.coordinator.snapshot(),budget=await rt.coordinator.cloudBudget(f.funding.grant.key_binding_id);assert.equal(budget.spent,16);assert.equal(budget.booked_confirmed_micros,'16');assert.equal(budget.observed_held_charge_micros,'0');assert.equal(budget.observed_overrun_micros,'0');assert.equal(budget.unknown_charge_attempts,0);assert.equal(budget.reserved,0);assert.equal(budget.attempts_used,1);assert.equal(state.project.spent,16);assert.equal(state.project.quota_used,1);assert.equal(state.cloud_attempts[0].actual_charged_micros,16);assert.equal(state.cloud_attempts[0].priced_usage_micros,16);assert.equal(state.cloud_attempts[0].settlement.charge_evidence_label,'EXPLICIT_SYNTHETIC_FAKE_PROVIDER_CHARGED_COST');
      const result=resultFor(claim);await rt.coordinator.complete({...scope,result,result_hash:digest(result)});assert.equal((await rt.coordinator.snapshot()).project.reserved,0);
      evidence.push({kind:'FAKE_CHARGE_EXACT_RATIONAL_SETTLEMENT',project_id:rt.source.spec.project_id,reserved:40,charged:16,source_coefficient:'5/3',input_tokens:12,cached_input_tokens:3,output_tokens:4,attempts_used:1});
    }finally{await f.close();}
  });
  await t.test('different projects and real backend sessions share one atomic spend gate',async()=>{
    const f=ledgerFixture({projects:2,budget_cap_micros:'60'});try{const left=await f.open(0),right=await f.open(1);await left.admit();await right.admit();await f.fund(left);const scopes=[f.scope(await f.claim(left)),f.scope(await f.claim(right))];
      const outcomes=await Promise.allSettled([left.coordinator.reserve(scopes[0]),right.coordinator.reserve(scopes[1])]);assert.equal(outcomes.filter(x=>x.status==='fulfilled').length,1);assert.equal(outcomes.find(x=>x.status==='rejected').reason.code,'A2_CLOUD_BUDGET_EXHAUSTED');
      const budget=await left.coordinator.cloudBudget(f.funding.grant.key_binding_id);assert.equal(budget.reserved,40);assert.equal(budget.attempts_used,1);const states=await Promise.all([left.coordinator.snapshot(),right.coordinator.snapshot()]);assert.equal(states.reduce((n,x)=>n+x.attempts.length,0),1);assert.equal(states.reduce((n,x)=>n+x.project.quota_used,0),1);
      for(const rt of [left,right])await rt.coordinator.cancel({mission_id:rt.source.spec.mission_id,owner_id:rt.source.spec.owner_id,reason:'EXPLICIT_SYNTHETIC_TEST_STOP'});const released=await left.coordinator.cloudBudget(f.funding.grant.key_binding_id);assert.equal(released.reserved,0);assert.equal(released.attempts_used,1);
      evidence.push({kind:'CROSS_PROJECT_NATIVE_BUDGET_RACE',projects:f.sources.map(x=>x.spec.project_id),statuses:outcomes.map(x=>x.status),cap:60,peak_reserved:40,after_cancel_reserved:0,attempts_used:1});
    }finally{await f.close();}
  });
  await t.test('cold authority after lost sending ACK keeps UNKNOWN money/quota and forbids blind retry/refund',async()=>{
    const f=ledgerFixture();try{const first=await f.open();await first.admit();await f.fund(first);const scope=f.scope(await f.claim(first,{lease_ms:100}));await first.coordinator.reserve(scope);await first.coordinator.markSending(scope);await first.db.close();await new Promise(resolve=>setTimeout(resolve,150));
      const cold=await f.open();await cold.coordinator.recover();const state=await cold.coordinator.snapshot(),budget=await cold.coordinator.cloudBudget(f.funding.grant.key_binding_id);assert.equal(state.attempts[0].state,'OUTCOME_UNKNOWN');assert.equal(state.missions[0].state,'HOLD');assert.equal(budget.reserved,40);assert.equal(budget.attempts_used,1);assert.equal(state.project.quota_used,1);assert.equal(budget.booked_confirmed_micros,'0');assert.equal(budget.observed_held_charge_micros,'0');assert.equal(budget.observed_overrun_micros,'0');assert.equal(budget.unknown_charge_attempts,1);assert.equal(budget.accounting_semantics.unknown_charge_cost,'UNKNOWN_NOT_ZERO');
      await assert.rejects(()=>cold.coordinator.failBeforeSend(scope),{code:'A2_NO_BLIND_RETRY'});await assert.rejects(()=>cold.coordinator.reserve({...scope,attempt_id:unique('fresh_attempt')}));assert.equal((await cold.coordinator.cloudBudget(f.funding.grant.key_binding_id)).reserved,40);
      evidence.push({kind:'COLD_LOST_ACK_RETAINS_UNKNOWN',project_id:cold.source.spec.project_id,reserved:40,attempts_used:1,quota_used:1,booked_confirmed_micros:budget.booked_confirmed_micros,observed_held_charge_micros:budget.observed_held_charge_micros,observed_overrun_micros:budget.observed_overrun_micros,unknown_charge_attempts:budget.unknown_charge_attempts,unknown_charge_cost:budget.accounting_semantics.unknown_charge_cost,provider_submits:'NO_PROVIDER_TRANSPORT_EXISTS',retried:false});
    }finally{await f.close();}
  });
  await t.test('proven no send releases funding but lifetime attempts cap cannot reset',async()=>{
    const f=ledgerFixture({attempts_cap:'1'});try{const rt=await f.open();await rt.admit();await f.fund(rt);const scope=f.scope(await f.claim(rt));await rt.coordinator.reserve(scope);await rt.coordinator.failBeforeSend(scope);await rt.coordinator.failBeforeSend(scope);const budget=await rt.coordinator.cloudBudget(f.funding.grant.key_binding_id);assert.equal(budget.reserved,0);assert.equal(budget.attempts_used,1);
      const fresh=f.scope(await f.claim(rt));await assert.rejects(()=>rt.coordinator.reserve(fresh),{code:'A2_CLOUD_ATTEMPTS_EXHAUSTED'});assert.equal((await rt.coordinator.snapshot()).attempts.length,1);
    }finally{await f.close();}
  });
  await t.test('observed provider charge above reserved becomes durable HOLD without negative accounting',async()=>{
    const f=ledgerFixture();try{const rt=await f.open();await rt.admit();await f.fund(rt);const scope=f.scope(await f.claim(rt));await rt.coordinator.reserve(scope);await rt.coordinator.markSending(scope);
      const result=await rt.coordinator.settle(f.settlement(scope,{actual_charged_micros:'41'}));assert.equal(result.status,'OUTCOME_UNKNOWN');assert.equal(result.reason,'CLOUD_CHARGE_EXCEEDS_RESERVATION');const state=await rt.coordinator.snapshot(),budget=await rt.coordinator.cloudBudget(f.funding.grant.key_binding_id);assert.equal(budget.state,'HOLD');assert.equal(budget.spent,0);assert.equal(budget.booked_confirmed_micros,'0');assert.equal(budget.observed_held_charge_micros,'41');assert.equal(budget.observed_overrun_micros,'1');assert.equal(budget.unknown_charge_attempts,0);assert.equal(budget.accounting_semantics.spent,'BOOKED_CONFIRMED_CHARGES_ONLY');assert.equal(budget.reserved,40);assert.equal(state.cloud_attempts[0].actual_charged_micros,41);assert.equal(state.cloud_attempts[0].funded_reserved,40);assert.equal(state.attempts[0].actual_cost,null);assert.equal(state.missions[0].state,'HOLD');
      evidence.push({kind:'EXPLICIT_SYNTHETIC_OVERCHARGE_HOLD',project_id:rt.source.spec.project_id,observed_charge:41,reserved:40,spent:0,booked_confirmed_micros:budget.booked_confirmed_micros,observed_held_charge_micros:budget.observed_held_charge_micros,observed_overrun_micros:budget.observed_overrun_micros,unknown_charge_attempts:budget.unknown_charge_attempts,state:'HOLD'});
    }finally{await f.close();}
  });
  await t.test('worker/QA cannot install funding; worker RPC cannot expose host installation or frozen bypass',async()=>{
    const f=ledgerFixture();let authority;try{const rt=await f.open();await rt.admit();authority=await createAuthorityServer({coordinator:rt.coordinator});const credential=authority.issueCredential({principal_id:'e1_worker1',project_id:rt.source.spec.project_id,role:'WORKER',capabilities:['common.research']});const client=createAuthorityClient({url:authority.url,token:credential.token});await assert.rejects(()=>client.call('provisionCloudBudget',f.funding),{code:'A2_RPC_METHOD_DENIED'});
      const admin=await createPsqlSession(descriptor(),{role:'admin'});try{const acl=JSON.parse(await admin.query("SELECT jsonb_build_object('coord_old',has_function_privilege('awe_e1_coord','awe_e1_runtime.command(text,jsonb)','EXECUTE'),'coord_wrapper',has_function_privilege('awe_e1_coord','awe_e1_runtime.cloud_command(text,jsonb)','EXECUTE'),'worker_fund',has_function_privilege('awe_e1_worker','awe_e1_runtime.provision_cloud_budget(jsonb)','EXECUTE'),'qa_fund',has_function_privilege('awe_e1_qa','awe_e1_runtime.provision_cloud_budget(jsonb)','EXECUTE'),'worker_table',has_table_privilege('awe_e1_worker','awe_e1_runtime.cloud_budget','SELECT'));"));assert.deepEqual(acl,{coord_old:false,coord_wrapper:true,worker_fund:false,qa_fund:false,worker_table:false});evidence.push({kind:'NATIVE_CLOUD_ACL',...acl});}finally{await admin.close();}
    }finally{if(authority)await authority.close();await f.close();}
  });
  await t.test('default local Ollama A2 accounting still passes with no cloud policy/funding',async()=>{
    const source=publicationFixture({project_id:unique('prj_cloud_local'),task_count:1,llm:true}),rt=await runtime([source]);try{await rt.admitAll();const claim=await rt.coordinator.claim({worker_id:'e1_worker1',capabilities:['common.research'],lease_ms:30000});const scope={mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,attempt_id:unique('local_attempt'),logical_request_id:unique('local_request'),capability_id:'common.research',capability_version:'1.0.0',route_id:'ollama.local.qwen3-4b-instruct',request_hash:digest({synthetic:true}),reserve_micros:0,quota_units:1};await rt.coordinator.reserve(scope);await rt.coordinator.markSending(scope);await rt.coordinator.settle({...scope,actual_cost_micros:0,usage:{wire_attempts:1},provider_ref:'synthetic-local-zero-charge'});const state=await rt.coordinator.snapshot();assert.equal(state.attempts[0].state,'CONFIRMED');assert.equal(state.cloud_attempts.length,0);assert.equal(state.cloud_policies.length,0);evidence.push({kind:'DEFAULT_LOCAL_REGRESSION',project_id:source.spec.project_id,spent:0,cloud_attempts:0});}finally{await rt.db.close();}
  });
});
test.after(()=>{if(enabled&&process.env.AWE_E1_CLOUD_EVIDENCE){const target=path.resolve(process.env.AWE_E1_CLOUD_EVIDENCE);fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,JSON.stringify({evidence_level:'NATIVE_E1_POSTGRESQL_EXPLICIT_SYNTHETIC_FUNDING_FAKE_PROVIDER_CHARGES',provider_requests:0,evidence},null,2)+'\n');}});
