import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {digest} from '../../contracts/index.mjs';
import {createPsqlSession,applyCoordinatorMigrations,createAuthorityServer,createAuthorityClient,createCoordinator} from '../../coordinator/index.mjs';
import {descriptor,publicationFixture,publishRevision,runtime,id,startLeaf,resultFor,independentAccept} from './helpers.mjs';

const enabled=process.env.AWE_E1_NATIVE_TEST==='1';
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const evidence=[];
test('A2 native PostgreSQL concurrency, D03/D09 and recovery', {skip:!enabled,timeout:60000},async t=>{
  const admin=await createPsqlSession(descriptor(),{role:'admin'});
  const migrations=await applyCoordinatorMigrations(admin);await admin.close();evidence.push({kind:'MIGRATIONS',migrations});

  await t.test('two real leaf processes overlap; dependencies wait for independent QA',async()=>{
    const source=publicationFixture(),rt=await runtime([source]),qa=await runtime([source],{role:'qa'});let authority;const leaves=[];
    try {
      await rt.admitAll();authority=await createAuthorityServer({coordinator:rt.coordinator,qaCoordinator:qa.coordinator});
      for(const principal_id of ['e1_worker1','e1_worker2']){const credential=authority.issueCredential({principal_id,project_id:source.spec.project_id,role:'WORKER',capabilities:['common.research','common.transform','common.build','common.qa']});leaves.push(startLeaf(authority,credential,{delay_ms:500}));}
      const claims=await Promise.all(leaves.map(leaf=>leaf.waitFor('CLAIMED'))),exits=await Promise.all(leaves.map(leaf=>leaf.exit));
      assert.ok(exits.every(exit=>exit.code===0),JSON.stringify(exits));assert.notEqual(claims[0].pid,claims[1].pid);assert.notEqual(claims[0].pid,process.pid);
      assert.ok(claims.every(claim=>!claim.received_keys.some(key=>/database|pgdata|descriptor|password/.test(key))));
      const state=await qa.coordinator.snapshot(),upstream=state.tasks.filter(task=>task.state==='WAIT_QA');assert.equal(upstream.length,2);assert.equal(state.tasks.find(task=>task.task_id==='dedupe').state,'READY');
      const intervals=upstream.map(task=>task.result.trace);assert.ok(Math.max(...intervals.map(x=>Date.parse(x.started_at)))<Math.min(...intervals.map(x=>Date.parse(x.finished_at))));
      const wait=await rt.coordinator.claim({worker_id:'e1_worker',capabilities:['common.transform'],lease_ms:1000});assert.equal(wait.status,'WAIT');
      for(const task of upstream){assert.equal(task.result.artifact_digest,digest(task.result.output));assert.match(task.result.output.text,/Computed: Inspect synthetic module/);await independentAccept(qa.coordinator,task);}
      const credential=authority.issueCredential({principal_id:'e1_worker',project_id:source.spec.project_id,role:'WORKER',capabilities:['common.research','common.transform','common.build','common.qa']});const dependent=startLeaf(authority,credential,{delay_ms:30});leaves.push(dependent);assert.equal((await dependent.exit).code,0);
      const complete=await qa.coordinator.snapshot();await independentAccept(qa.coordinator,complete.tasks.find(task=>task.task_id==='dedupe'));assert.equal((await rt.coordinator.snapshot()).missions[0].state,'COMPLETE');
      evidence.push({kind:'OVERLAPPING_PROCESS_READBACK',project_id:source.spec.project_id,pids:claims.map(c=>c.pid),intervals,dependency:'ACCEPTED_AFTER_UPSTREAM_QA'});
    }finally{for(const leaf of leaves)if(leaf.child.exitCode===null)leaf.child.kill();if(authority)await authority.close();await rt.db.close();await qa.db.close();}
  });

  await t.test('hard-killed read worker yields lease takeover; old fence is rejected',async()=>{
    const source=publicationFixture({task_count:1}),rt=await runtime([source]);let authority;const leaves=[];
    try{
      await rt.admitAll();authority=await createAuthorityServer({coordinator:rt.coordinator});
      const credential=principal_id=>authority.issueCredential({principal_id,project_id:source.spec.project_id,role:'WORKER',capabilities:['common.research','common.transform','common.build','common.qa']});
      const first=startLeaf(authority,credential('e1_worker1'),{delay_ms:3000,lease_ms:300});leaves.push(first);const old=await first.waitFor('CLAIMED');first.child.kill('SIGKILL');await first.exit;await pause(400);
      const second=startLeaf(authority,credential('e1_worker2'),{delay_ms:30,lease_ms:2000});leaves.push(second);const fresh=await second.waitFor('CLAIMED');assert.equal((await second.exit).code,0);assert.ok(fresh.scope.fence>old.scope.fence);
      const task=(await rt.coordinator.snapshot()).tasks[0],result={output_schema_digest:task.document.capability.output_schema.digest,output:{text:'late stale result'}};
      await assert.rejects(()=>rt.coordinator.complete({...old.scope,result,result_hash:digest(result)}),error=>['A2_STALE_FENCE','A2_RESULT_SCOPE'].includes(error.code));
      evidence.push({kind:'HARD_KILL_LEASE_TAKEOVER',project_id:source.spec.project_id,old_fence:old.scope.fence,new_fence:fresh.scope.fence,old_pid:old.pid,new_pid:fresh.pid,accepted_late_results:0});
    }finally{for(const leaf of leaves)if(leaf.child.exitCode===null)leaf.child.kill();if(authority)await authority.close();await rt.db.close();}
  });

  await t.test('real independent backend contenders respect shared money and source/GPU slots',async()=>{
    const source=publicationFixture({task_count:2,task_cost:'7'}),policy={budget_cap_micros:'7',quota_cap:8,max_parallel:2,resource_limits:{gpu:1},capabilities:{'common.research':{resource_keys:['gpu'],max_claims:2}}};
    const left=await runtime([source],{policy}),right=await runtime([source],{policy});
    try{
      await left.admitAll();const claims=await Promise.all([left.coordinator.claim({worker_id:'e1_worker1',capabilities:['common.research'],lease_ms:2000}),right.coordinator.claim({worker_id:'e1_worker2',capabilities:['common.research'],lease_ms:2000})]);assert.equal(claims.filter(c=>c.status==='CLAIMED').length,1);
      const state=await right.coordinator.snapshot();assert.equal(state.project.reserved,7);assert.equal(state.leases.length,1);assert.equal(state.project.spent,0);
      await left.coordinator.cancel({mission_id:source.spec.mission_id,owner_id:source.spec.owner_id,reason:'bounded-test-stop'});const stopped=await right.coordinator.snapshot();assert.equal(stopped.project.reserved,0);assert.equal(stopped.leases.length,0);
      evidence.push({kind:'ATOMIC_BUDGET_SLOT_RACE',project_id:source.spec.project_id,statuses:claims.map(c=>c.status),peak_reserved:7,capacity:1,after_cancel_reserved:0});
    }finally{await left.db.close();await right.db.close();}
  });

  await t.test('model reservation, one-shot sending, actual settlement and quota survive authority restart',async()=>{
    const source=publicationFixture({task_count:2,task_cost:'9',llm:true}),rt=await runtime([source]);let restarted;
    try{
      await rt.admitAll();const claim=await rt.coordinator.claim({worker_id:'e1_worker1',capabilities:['common.research'],lease_ms:3000});
      const scope={mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,logical_request_id:id('logical'),attempt_id:id('attempt'),route_id:'ollama.local.qwen3-4b-instruct',capability_id:'common.research',capability_version:'1.0.0',reserve_micros:9,request_hash:digest({synthetic:true}),quota_units:1};
      assert.equal((await rt.coordinator.reserve(scope)).status,'RESERVED');assert.equal((await rt.coordinator.reserve(scope)).repeated,true);await assert.rejects(()=>rt.coordinator.reserve({...scope,attempt_id:id('attempt'),reserve_micros:1}),{code:'A2_NO_BLIND_RETRY'});
      assert.equal((await rt.coordinator.markSending(scope)).status,'SENDING');await assert.rejects(()=>rt.coordinator.markSending(scope),{code:'A2_NO_BLIND_RETRY'});
      assert.equal((await rt.coordinator.settle({...scope,actual_cost_micros:4,usage:{input_tokens:1,output_tokens:2,wire_attempts:1},provider_ref:'fake-model:1'})).status,'CONFIRMED');
      const result=resultFor(claim);await rt.coordinator.complete({...scope,result,result_hash:digest(result)});const settled=await rt.coordinator.snapshot();assert.equal(settled.project.spent,4);assert.equal(settled.project.reserved,0);assert.equal(settled.project.quota_used,1);
      const events=await rt.coordinator.events(),last=events.at(-1).sequence;await rt.coordinator.ackCursor({consumer_id:'test_monitor',sequence:last,expected_sequence:0});await rt.db.close();
      restarted=await runtime([source]);assert.equal((await restarted.coordinator.getCursor('test_monitor')).sequence,last);const readback=await restarted.coordinator.snapshot();assert.equal(readback.project.spent,4);assert.equal(readback.project.quota_used,1);assert.equal(readback.attempts[0].state,'CONFIRMED');
      await assert.rejects(()=>restarted.coordinator.ackCursor({consumer_id:'test_monitor',sequence:last,expected_sequence:0}),{code:'A2_CURSOR_CAS'});
      evidence.push({kind:'MODEL_LEDGER_AUTHORITY_RESTART',project_id:source.spec.project_id,reserved:readback.project.reserved,spent:4,quota_used:1,cursor:last,provider:'CLEARLY_LABELED_FAKE_MODEL'});
    }finally{await rt.db.close();if(restarted)await restarted.db.close();}
  });

  await t.test('UNKNOWN before and after fake-provider effect never triggers a second submit',async()=>{
    for(const after of [false,true]){
      const project_id=id('effect_project'),business_key=id('canonical_effect'),source=publicationFixture({project_id,task_count:1,effect:true,business_key}),next=publicationFixture({project_id,task_count:1,effect:true,business_key}),rt=await runtime([source,next]);
      const directory=path.resolve('E1/tests/coordinator/.local/'+project_id);fs.mkdirSync(directory,{recursive:true});const providerFile=path.join(directory,'clearly-fake-provider.json');fs.writeFileSync(providerFile,JSON.stringify({provider:'CLEARLY_LABELED_FAKE_PROVIDER',effects:[],submits:0}));
      try{
        await rt.admitAll();const claim=await rt.coordinator.claim({mission_id:source.spec.mission_id,worker_id:'e1_worker1',capabilities:['common.research'],lease_ms:250});assert.equal(claim.status,'CLAIMED');const scope={mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence};
        await rt.coordinator.markEffectSending(scope);
        if(after){const provider=JSON.parse(fs.readFileSync(providerFile));provider.submits++;provider.effects.push({business_key,provider_ref:'fake:'+business_key,payload_digest:claim.task.effect.payload_digest});fs.writeFileSync(providerFile,JSON.stringify(provider));}
        // Lost caller ACK/authority restart is simulated after the durable SENDING
        // commit. Recovery has no provider-submit path.
        await rt.db.close();await pause(350);const recovered=await runtime([source,next]);
        try{await recovered.coordinator.recover();const hold=await recovered.coordinator.snapshot();assert.equal(hold.intents.length,1);assert.equal(hold.intents[0].state,'OUTCOME_UNKNOWN');assert.equal(hold.missions.find(m=>m.mission_id===source.spec.mission_id).state,'HOLD');
          await assert.rejects(()=>recovered.coordinator.markEffectSending(scope),error=>['A2_MISSION_NOT_ACTIVE','A2_NO_BLIND_RETRY'].includes(error.code));
          const duplicate=await recovered.coordinator.claim({mission_id:next.spec.mission_id,worker_id:'e1_worker2',capabilities:['common.research'],lease_ms:1000});assert.equal(duplicate.status,'WAIT');
          const provider=JSON.parse(fs.readFileSync(providerFile));assert.equal(provider.submits,after?1:0);assert.equal(provider.effects.length,after?1:0);
          if(after){const receipt=provider.effects[0];await recovered.coordinator.confirmEffect({...scope,provider_ref:receipt.provider_ref,receipt});assert.equal((await recovered.coordinator.snapshot()).intents[0].state,'CONFIRMED');}
          evidence.push({kind:'FAKE_PROVIDER_PERSISTED_READBACK',project_id,business_key,crash:after?'AFTER_EFFECT_LOST_ACK':'BEFORE_EFFECT',provider_effect_count:provider.effects.length,provider_submit_count:provider.submits,intents:1,unknown_retried:false});
        }finally{await recovered.db.close();}
      }finally{await rt.db.close();}
    }
  });

  await t.test('bounded drained replan preserves ledger/history and rejects late fence/QA',async()=>{
    const source=publicationFixture({task_count:1,llm:true,task_cost:'9'}),rt=await runtime([source]),qa=await runtime([source],{role:'qa'});
    try{
      await rt.admitAll();const oldPlanDigest=source.publication.plan_digest,claim=await rt.coordinator.claim({worker_id:'e1_worker',capabilities:['common.research'],lease_ms:4000});
      const scope={mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,logical_request_id:id('logical'),attempt_id:id('attempt'),route_id:'ollama.local.qwen3-4b-instruct',capability_id:'common.research',capability_version:'1.0.0',reserve_micros:9,request_hash:digest({revision:1}),quota_units:1};
      await rt.coordinator.reserve(scope);
      publishRevision(source,plan=>{plan.tasks[0].input={instruction:'Inspect revised synthetic module'};plan.tasks[0].effect.payload_digest=digest(plan.tasks[0].input);});
      await assert.rejects(()=>rt.coordinator.admit({mission_id:source.spec.mission_id},rt.context),{code:'A2_REVISION_REQUIRES_DRAIN'});
      await rt.coordinator.markSending(scope);await rt.coordinator.settle({...scope,actual_cost_micros:4,usage:{wire_attempts:1},provider_ref:'fake-model:revision1'});
      const result=resultFor(claim);await rt.coordinator.complete({...scope,result,result_hash:digest(result)});
      await assert.rejects(()=>rt.coordinator.admit({mission_id:source.spec.mission_id},rt.context),{code:'A2_REVISION_REQUIRES_DRAIN'});
      const originalTask=(await qa.coordinator.snapshot()).tasks[0];await independentAccept(qa.coordinator,originalTask);
      assert.equal((await rt.coordinator.admit({mission_id:source.spec.mission_id},rt.context)).status,'ADMITTED');
      const revised=await rt.coordinator.snapshot();assert.equal(revised.plans.length,2);assert.equal(revised.task_history.length,1);assert.equal(revised.task_history[0].body.result_hash,originalTask.result_hash);assert.equal(revised.project.spent,4);assert.equal(revised.project.quota_used,1);assert.equal(revised.project.reserved,0);assert.equal(revised.missions[0].revision,2);
      const fresh=await rt.coordinator.claim({worker_id:'e1_worker',capabilities:['common.research'],lease_ms:4000});assert.ok(fresh.fence>claim.fence);
      await assert.rejects(()=>rt.coordinator.complete({...scope,result,result_hash:digest(result)}),{code:'A2_STALE_FENCE'});
      const freshResult=resultFor(fresh);await rt.coordinator.complete({...scope,fence:fresh.fence,result:freshResult,result_hash:digest(freshResult)});
      await assert.rejects(()=>qa.coordinator.qaEvaluate({mission_id:claim.mission_id,task_id:claim.task_id,plan_digest:oldPlanDigest,result_hash:originalTask.result_hash,evaluator_id:'id_e1_qa',verdict:'PASS',checks:originalTask.document.qa.required_checks.map(check_id=>({check_id,passed:true}))}),{code:'A2_QA_BINDING'});
      const current=(await qa.coordinator.snapshot()).tasks.find(task=>task.is_current);await independentAccept(qa.coordinator,current);
      const changedSpec={...structuredClone(source.spec),revision:2},changedGrant={...structuredClone(source.grant),grant_version:2,spec_digest:digest(changedSpec),issued_at:new Date().toISOString()};
      source.ingress.mission.revise({spec:changedSpec,grant:changedGrant,expected_spec_digest:digest(source.spec),expected_grant_digest:digest(source.grant),reason:'Normal A1 owner revision must not refresh durable scope.'},source.contexts.owner);
      source.spec=changedSpec;source.grant=changedGrant;publishRevision(source,plan=>{plan.spec_digest=digest(changedSpec);plan.grant_digest=digest(changedGrant);plan.grant_version=2;});
      await assert.rejects(()=>rt.coordinator.admit({mission_id:source.spec.mission_id},rt.context),{code:'A2_REVISION_SCOPE'});
      await rt.coordinator.revoke({mission_id:source.spec.mission_id,owner_id:source.spec.owner_id,reason:'test-stop'});await assert.rejects(()=>rt.coordinator.admit({mission_id:source.spec.mission_id},rt.context),{code:'A2_MISSION_NOT_ACTIVE'});
      evidence.push({kind:'BOUNDED_REPLAN',project_id:source.spec.project_id,plan_revisions:2,archived_task_results:1,old_fence:claim.fence,new_fence:fresh.fence,spent_preserved:4,quota_preserved:1,old_qa:'DENIED',changed_grant_revision:'DENIED',re_admit_revoked:'DENIED'});
    }finally{await rt.db.close();await qa.db.close();}
  });

  await t.test('model UNKNOWN retains zero-cost quota and resource hold across restart; inbox dedupes',async()=>{
    const source=publicationFixture({task_count:1,llm:true}),policy={budget_cap_micros:'0',quota_cap:1,max_parallel:1,resource_limits:{gpu:1},capabilities:{'common.research':{resource_keys:['gpu'],max_claims:2}}},rt=await runtime([source],{policy});let recovered;
    try{
      await rt.admitAll();const claim=await rt.coordinator.claim({worker_id:'e1_worker',capabilities:['common.research'],lease_ms:500}),scope={mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,logical_request_id:id('logical'),attempt_id:id('attempt'),route_id:'ollama.local.qwen3-4b-instruct',capability_id:'common.research',capability_version:'1.0.0',reserve_micros:0,request_hash:digest({cost:0}),quota_units:1};
      await rt.coordinator.reserve(scope);await rt.coordinator.markSending(scope);await rt.db.close();await pause(600);recovered=await runtime([source],{policy});await recovered.coordinator.recover();
      const state=await recovered.coordinator.snapshot();assert.equal(state.project.quota_used,1);assert.equal(state.project.reserved,0);assert.equal(state.attempts[0].state,'OUTCOME_UNKNOWN');assert.equal(state.leases[0].held,true);
      assert.equal((await recovered.coordinator.claim({worker_id:'e1_worker2',capabilities:['common.research']})).status,'WAIT');await assert.rejects(()=>recovered.coordinator.markSending(scope),{code:'A2_MISSION_NOT_ACTIVE'});
      const event={source_id:'synthetic_monitor',event_id:'event1',body:{outcome:'unknown-observed'},payload_hash:digest({outcome:'unknown-observed'})};const first=await recovered.coordinator.inbox(event),second=await recovered.coordinator.inbox(event);assert.equal(second.sequence,first.sequence);assert.equal(second.repeated,true);
      await assert.rejects(()=>recovered.coordinator.inbox({...event,body:{outcome:'different'},payload_hash:digest({outcome:'different'})}),{code:'A2_INBOX_CONFLICT'});
      evidence.push({kind:'ZERO_COST_QUOTA_UNKNOWN',project_id:source.spec.project_id,quota_used:1,reserved_micros:0,attempt_state:'OUTCOME_UNKNOWN',gpu_slot:'HELD',inbox_idempotent:true});
    }finally{await rt.db.close();if(recovered)await recovered.db.close();}
  });

  await t.test('independent budget, slot and model-quota races have one winner',async()=>{
    for(const limiting of ['budget','slot','quota']){
      const cost=limiting==='budget'?'7':'0',source=publicationFixture({task_count:2,task_cost:cost,llm:limiting==='quota'}),policy={budget_cap_micros:cost,quota_cap:limiting==='quota'?1:8,max_parallel:2,resource_limits:{source_account:limiting==='slot'?1:2},capabilities:{'common.research':{resource_keys:['source_account'],max_claims:2}}};
      const left=await runtime([source],{policy}),right=await runtime([source],{policy});try{
        await left.admitAll();const claims=await Promise.all([left.coordinator.claim({worker_id:'e1_worker1',capabilities:['common.research'],lease_ms:3000}),right.coordinator.claim({worker_id:'e1_worker2',capabilities:['common.research'],lease_ms:3000})]);
        if(limiting==='quota'){
          assert.equal(claims.filter(c=>c.status==='CLAIMED').length,2);
          const attempts=await Promise.allSettled(claims.map((claim,index)=>[left,right][index].coordinator.reserve({mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,logical_request_id:id('logical'),attempt_id:id('attempt'),route_id:'ollama.local.qwen3-4b-instruct',capability_id:'common.research',capability_version:'1.0.0',reserve_micros:0,request_hash:digest({index}),quota_units:1})));
          assert.equal(attempts.filter(a=>a.status==='fulfilled').length,1);assert.equal(attempts.find(a=>a.status==='rejected').reason.code,'A2_QUOTA_EXHAUSTED');assert.equal((await left.coordinator.snapshot()).project.quota_used,1);
        }else assert.equal(claims.filter(c=>c.status==='CLAIMED').length,1);
        await left.coordinator.cancel({mission_id:source.spec.mission_id,owner_id:source.spec.owner_id,reason:'test-stop'});
        evidence.push({kind:'INDEPENDENT_LIMIT_RACE',limit:limiting,project_id:source.spec.project_id,winners:1});
      }finally{await left.db.close();await right.db.close();}
    }
  });

  await t.test('proven prewire failure releases quota/reserve/lease exactly once after grant expiry',async()=>{
    const source=publicationFixture({task_count:1,task_cost:'5',llm:true,lifetime_ms:1400}),rt=await runtime([source]);try{
      await rt.admitAll();const claim=await rt.coordinator.claim({worker_id:'e1_worker',capabilities:['common.research'],lease_ms:1000}),scope={mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,logical_request_id:id('logical'),attempt_id:id('attempt'),route_id:'ollama.local.qwen3-4b-instruct',capability_id:'common.research',capability_version:'1.0.0',reserve_micros:5,request_hash:digest({prewire:true}),quota_units:1};
      await rt.coordinator.reserve(scope);assert.equal((await rt.coordinator.snapshot()).project.quota_used,1);await pause(1500);
      await assert.rejects(()=>rt.coordinator.markSending(scope),{code:'A2_GRANT_EXPIRED'});assert.equal((await rt.coordinator.failBeforeSend(scope)).status,'FAILED');assert.equal((await rt.coordinator.failBeforeSend(scope)).repeated,true);
      const state=await rt.coordinator.snapshot();assert.equal(state.project.quota_used,0);assert.equal(state.project.reserved,0);assert.equal(state.leases.length,0);assert.equal(state.attempts[0].state,'FAILED');assert.equal(state.attempts[0].reason,'PROVEN_NO_SEND');
      evidence.push({kind:'PROVEN_PREWIRE_RELEASE',project_id:source.spec.project_id,provider_wire_calls:0,quota_used:0,reserved:0,lease_count:0,idempotent_release:true});
    }finally{await rt.db.close();}
  });

  await t.test('real transaction session rollback, wrong output schema and RPC impersonation fail closed',async()=>{
    const source=publicationFixture({task_count:1}),rt=await runtime([source]);let authority;try{
      await rt.admitAll();let firstPid,secondPid;
      await assert.rejects(()=>rt.db.transaction(async tx=>{firstPid=await tx.query('SELECT pg_backend_pid();');await tx.command('inbox',{project_id:source.spec.project_id,source_id:'transaction_probe',event_id:'rollback',payload_hash:digest({rollback:true}),body:{rollback:true}});secondPid=await tx.query('SELECT pg_backend_pid();');throw new Error('EXPECTED_ROLLBACK');}),/EXPECTED_ROLLBACK/);
      assert.equal(firstPid,secondPid);assert.equal((await rt.coordinator.events()).some(e=>e.kind==='INBOX'),false);
      authority=await createAuthorityServer({coordinator:rt.coordinator});const credential=authority.issueCredential({principal_id:'e1_worker',project_id:source.spec.project_id,role:'WORKER',capabilities:['common.research']});const client=createAuthorityClient({url:authority.url,token:credential.token});
      await assert.rejects(()=>client.claim({worker_id:'id_e1_owner',capabilities:['common.research']}),{code:'A2_WORKER_IMPERSONATION'});await assert.rejects(()=>client.snapshot({}),{code:'A2_READ_SCOPE'});await assert.rejects(()=>client.claim({project_id:'foreign_project',capabilities:['common.research']}),{code:'A2_PROJECT_SCOPE'});await assert.rejects(()=>client.call('query',{sql:'SELECT 1'}),{code:'A2_RPC_METHOD_DENIED'});
      const claim=await client.claim({capabilities:['common.research'],lease_ms:2000}),result={output_schema_digest:claim.task.capability.output_schema.digest,output:{forged:'wrong'}};
      await assert.rejects(()=>client.complete({mission_id:claim.mission_id,task_id:claim.task_id,fence:claim.fence,result,result_hash:digest(result)}),{code:'A2_RPC_REJECT'});
      const state=await rt.coordinator.snapshot();assert.equal(state.tasks[0].state,'RUNNING');assert.equal(state.tasks[0].result,null);
      evidence.push({kind:'TRANSACTION_AND_RPC_BOUNDARIES',project_id:source.spec.project_id,same_backend_transaction:true,rollback_readback:'ABSENT',wrong_output:'DENIED',impersonation:'DENIED',foreign_project:'DENIED',worker_sql_rpc:'DENIED'});
    }finally{if(authority)await authority.close();await rt.db.close();}
  });

  await t.test('cancel/revoke/expiry/current capability and project ACL prevent dispatch',async()=>{
    for(const action of ['cancel','revoke','revokeCapability']){
      const source=publicationFixture({task_count:1,llm:true}),rt=await runtime([source]);try{await rt.admitAll();const claim=await rt.coordinator.claim({worker_id:'e1_worker',capabilities:['common.research'],lease_ms:2000}),scope={mission_id:claim.mission_id,task_id:claim.task_id,worker_id:claim.worker_id,fence:claim.fence,logical_request_id:id('logical'),attempt_id:id('attempt'),route_id:'ollama.local.qwen3-4b-instruct',capability_id:'common.research',capability_version:'1.0.0',reserve_micros:0,request_hash:digest({action}),quota_units:1};await rt.coordinator.reserve(scope);await rt.coordinator[action]({mission_id:claim.mission_id,owner_id:source.spec.owner_id,capability_id:'common.research',reason:'bounded-stop'});await assert.rejects(()=>rt.coordinator.markSending(scope),error=>['A2_MISSION_NOT_ACTIVE','A2_CAPABILITY_REVOKED','A2_GRANT_REVOKED'].includes(error.code));}finally{await rt.db.close();}
    }
    const source=publicationFixture({task_count:1,lifetime_ms:1200}),rt=await runtime([source]);try{await rt.admitAll();await pause(1300);assert.equal((await rt.coordinator.claim({worker_id:'e1_worker',capabilities:['common.research']})).status,'WAIT');assert.throws(()=>rt.coordinator.claim({project_id:'foreign_project',worker_id:'e1_worker',capabilities:['common.research']}),{code:'A2_PROJECT_SCOPE'});await assert.rejects(()=>rt.coordinator.qaEvaluate({mission_id:source.spec.mission_id}),{code:'A2_INDEPENDENT_QA_REQUIRED'});}finally{await rt.db.close();}
    // A worker Unix/PG identity has no schema usage, table read or function access.
    const worker=await createPsqlSession(descriptor(),{role:'worker',verify_marker:false});try{await assert.rejects(()=>worker.query('SELECT * FROM awe_e1_runtime.project;'),{code:'A2_DB_TRANSPORT_UNKNOWN'});}finally{await worker.close();}
    const other=await createPsqlSession(descriptor(),{role:'worker',verify_marker:false});try{await assert.rejects(()=>other.query("SELECT awe_e1_runtime.command('snapshot','{\"project_id\":\"foreign_project\"}');"),{code:'A2_DB_TRANSPORT_UNKNOWN'});}finally{await other.close();}
    evidence.push({kind:'NEGATIVE_BOUNDARIES',cancel:'DENY',revoke:'DENY',expiry:'DENY',capability_revoke:'DENY',foreign_project:'DENY',worker_table:'DENY',worker_function:'DENY',coordinator_qa:'DENY'});
  });
  fs.writeFileSync(new URL('./native-evidence.json',import.meta.url),JSON.stringify({status:'VERIFIED_LIVE_LOCAL_POSTGRESQL',provider:'FAKE_PROVIDER_ONLY',e0_connections:0,authority_uptime_24h:'NOT_RUN',evidence},null,2)+'\n');
});
