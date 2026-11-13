import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {digest} from '../../contracts/index.mjs';
import {MODEL_POLICY} from '../../broker/schemas.mjs';
import {LOCAL_MODEL_QUIESCENCE,validateLocalModelQuiescence,createPsqlSession,createAuthorityServer,createAuthorityClient} from '../../coordinator/index.mjs';
import {sqlJson} from '../../coordinator/psql-session.mjs';
import {publicationFixture,runtime,descriptor,id} from './helpers.mjs';
const evidence=[];
import {syntheticProof,unknownFixture} from './quiescence-fixtures.mjs';
test('native execution-only quiescence leaves UNKNOWN, accounting and grant untouched',{timeout:30000},async t=>{
  const admin=await createPsqlSession(descriptor(),{role:'admin'});
  const migration=fs.readFileSync(new URL('../../coordinator/migrations/0002-local-model-quiescence.sql',import.meta.url));
  // Apply only the new additive migration; frozen0001 and root live mission are untouched.
  await admin.query(migration.toString('utf8'));evidence.push({kind:'MIGRATION_0002',sha256:createHash('sha256').update(migration).digest('hex')});
  try{
    await t.test('release original execution hold once, preserve full attempt and task/mission HOLD',async()=>{
      const {rt,scope,source,request}=await unknownFixture();try{
        const before=await rt.coordinator.snapshot(),taskBefore=structuredClone(before.tasks[0]),claimCount=taskBefore.claims;
        const receipt=await rt.coordinator.quiesceLocalModel(request);assert.equal(receipt.status,'QUIESCED_EXECUTION_ONLY');assert.equal(receipt.quota_released,false);assert.equal(receipt.attempt_state,'OUTCOME_UNKNOWN');assert.ok(receipt.new_fence>scope.fence);
        const after=await rt.coordinator.snapshot();assert.deepEqual(after.project,before.project);assert.deepEqual(after.missions,before.missions);assert.deepEqual(after.attempts,before.attempts);assert.equal(after.leases.length,0);assert.equal(after.tasks[0].state,'HOLD');assert.equal(after.tasks[0].claims,claimCount);
        const taskAfter=structuredClone(after.tasks[0]);delete taskBefore.fence;delete taskAfter.fence;assert.deepEqual(taskAfter,taskBefore);
        const repeat=await rt.coordinator.quiesceLocalModel(request);assert.equal(repeat.repeated,true);assert.equal(repeat.new_fence,receipt.new_fence);assert.deepEqual((await rt.coordinator.snapshot()).attempts,before.attempts);
        const changed=structuredClone(request);changed.proof.proof_ref='artifact:synthetic-quiescence/changed';changed.proof_digest=digest(changed.proof);await assert.rejects(()=>rt.coordinator.quiesceLocalModel(changed),{code:'A2_QUIESCENCE_PROOF_CONFLICT'});
        await assert.rejects(()=>rt.coordinator.markSending(scope),{code:'A2_MISSION_NOT_ACTIVE'});await assert.rejects(()=>rt.coordinator.failBeforeSend(scope),{code:'A2_NO_BLIND_RETRY'});
        const rows=JSON.parse(await admin.query('SELECT jsonb_agg(to_jsonb(q)) FROM awe_e1_runtime.local_model_quiescence q WHERE attempt_id='+sqlJson({attempt_id:scope.attempt_id})+"->>'attempt_id';"));assert.equal(rows.length,1);assert.equal(rows[0].proof_digest,request.proof_digest);assert.deepEqual(rows[0].accounting_before.attempt,before.attempts[0]);
        const events=await rt.coordinator.events();assert.equal(events.filter(e=>e.kind==='LOCAL_MODEL_EXECUTION_QUIESCED').length,1);
        evidence.push({kind:'RESOURCE_ONLY_QUIESCENCE',project_id:source.spec.project_id,attempt_id:scope.attempt_id,old_fence:scope.fence,new_fence:receipt.new_fence,quota_used:after.project.quota_used,outcome:'OUTCOME_UNKNOWN',task:'HOLD',mission:'HOLD',usage:after.attempts[0].usage,proof_digest:request.proof_digest,original_attempt_unchanged:true,repeat_idempotent:true,provider_calls:0,proof:'EXPLICIT_SYNTHETIC_TEST_ATTESTATION'});
      }finally{await rt.db.close();}
    });
    await t.test('stale/future proof, false scope, effect, nonlocal route, money and linkage reject',async()=>{
      for(const kind of ['stale','future','scope','effect','nonlocal','money','linkage']){
        const fixture=await unknownFixture(kind==='effect'?{effect:true,business_key:id('quiesce_effect')}:kind==='money'?{task_cost:'1'}:{}),{rt,scope,source}=fixture;try{
          let request=fixture.request;
          if(kind==='stale')request=syntheticProof(scope,source.spec.project_id,{age_ms:400000});
          if(kind==='future')request=syntheticProof(scope,source.spec.project_id,{age_ms:-15000});
          if(kind==='scope'){request=structuredClone(request);request.worker_id='e1_worker2';request.proof.worker_id='e1_worker2';request.proof_digest=digest(request.proof);}
          if(kind==='nonlocal')await admin.query("UPDATE awe_e1_runtime.model_attempt SET route_id='nonlocal.test.denied' WHERE attempt_id=("+sqlJson({id:scope.attempt_id})+"->>'id');");
          if(kind==='linkage')await admin.query("UPDATE awe_e1_runtime.lease SET worker_id='e1_worker2' WHERE mission_id=("+sqlJson({id:scope.mission_id})+"->>'id');");
          const before=await rt.coordinator.snapshot();await assert.rejects(()=>rt.coordinator.quiesceLocalModel(request),error=>/^A2_(QUIESCENCE_|ATTEMPT_SCOPE)/.test(error.code));const after=await rt.coordinator.snapshot();assert.deepEqual(after,before);
          evidence.push({kind:'QUIESCENCE_NEGATIVE',case:kind,project_id:source.spec.project_id,result:'DENIED_UNCHANGED'});
        }finally{await rt.db.close();}
      }
    });
    await t.test('worker/BROKER/QA RPC and native QA/worker access have no quiescence capability',async()=>{
      const {rt,source,request}=await unknownFixture(),qa=await runtime([source],{role:'qa'});let authority;try{
        authority=await createAuthorityServer({coordinator:rt.coordinator,qaCoordinator:qa.coordinator});
        for(const role of ['WORKER','BROKER','QA']){const credential=authority.issueCredential({principal_id:role==='QA'?'id_e1_qa':'e1_worker',project_id:source.spec.project_id,role,capabilities:['common.research']}),client=createAuthorityClient({url:authority.url,token:credential.token});await assert.rejects(()=>client.call('quiesceLocalModel',request),{code:'A2_RPC_METHOD_DENIED'});}
        assert.throws(()=>qa.coordinator.quiesceLocalModel(request),{code:'A2_QUIESCENCE_ROLE_DENIED'});
        for(const role of ['qa','worker']){const db=await createPsqlSession(descriptor(),{role,verify_marker:role!=='worker'});try{await assert.rejects(()=>db.query('SELECT awe_e1_runtime.quiesce_local_model('+sqlJson({...request,project_id:source.spec.project_id})+');'),{code:'A2_DB_TRANSPORT_UNKNOWN'});}finally{await db.close();}}
        assert.equal((await rt.coordinator.snapshot()).leases.length,1);evidence.push({kind:'QUIESCENCE_ACL',project_id:source.spec.project_id,worker_rpc:'DENIED',broker_rpc:'DENIED',qa_rpc:'DENIED',qa_native:'DENIED',worker_native:'DENIED'});
      }finally{if(authority)await authority.close();await rt.db.close();await qa.db.close();}
    });
    fs.writeFileSync(new URL('./quiescence-evidence.json',import.meta.url),JSON.stringify({status:'VERIFIED_NATIVE_SYNTHETIC_BOUNDARY',actual_model_calls:0,root_live_mission_writes:0,evidence},null,2)+'\n');
  }finally{await admin.close();}
});
