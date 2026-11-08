import test from 'node:test';import assert from 'node:assert/strict';
import {digest} from '../contracts/index.mjs';import {TEXT_SCHEMA} from '../broker/schemas.mjs';
import {verifyPersistedTaskArtifact,modelRequestIds} from '../host/artifact-binding.mjs';
import {createNativeE1Host} from '../host/staging.mjs';
import {makeFixture,resource} from './native-fixture.mjs';
function row(output={text:'Clean source observation'}){const task={document:{capability:{output_schema:{digest:digest(TEXT_SCHEMA)}}},output_schema:structuredClone(TEXT_SCHEMA),result:{output,output_schema_digest:digest(TEXT_SCHEMA),artifact_digest:digest(output)}};task.result_hash=digest(task.result);return task;}
test('QA2 host commitment rejects frozen digest substitution, correctly rehashed wrong type and permissive stored schema',()=>{
 const good=row();assert.equal(verifyPersistedTaskArtifact(good),good.result.artifact_digest);
 const changed=structuredClone(good);changed.result.output.text='Changed after freeze';assert.throws(()=>verifyPersistedTaskArtifact(changed));
 const wrongArtifact=structuredClone(good);wrongArtifact.result.artifact_digest='sha256:'+'0'.repeat(64);wrongArtifact.result_hash=digest(wrongArtifact.result);assert.throws(()=>verifyPersistedTaskArtifact(wrongArtifact));
 assert.throws(()=>verifyPersistedTaskArtifact(row({text:7})));
 const schema=structuredClone(good);schema.output_schema={type:'object',properties:{text:{type:'number'}},required:['text'],additionalProperties:false};assert.throws(()=>verifyPersistedTaskArtifact(schema));
});
test('QA2 host model request IDs are deterministic within a task and distinct across missions',()=>{assert.deepEqual(modelRequestIds('mission_a','head'),modelRequestIds('mission_a','head'));assert.notEqual(modelRequestIds('mission_a','head').attempt_id,modelRequestIds('mission_b','head').attempt_id);assert.notEqual(modelRequestIds('mission_a','head').logical_request_id,modelRequestIds('mission_a','review').logical_request_id);});
test('QA2 native host admits only authenticated published owner scope and counts RUNNING correctly',async()=>{
 const f=makeFixture();const host=await createNativeE1Host({resource,authority:f.authority,ingress:f.ingress,capabilities:f.registry.descriptors,domainManifests:[f.domainManifest],ownerGrants:[f.grant],policy:f.policy});
 try{
  await assert.rejects(()=>host.admitPublished(f.spec.mission_id,structuredClone(f.contexts.e1_owner)),{code:'E1_AUTH_CONTEXT'});
  await assert.rejects(()=>host.admitPublished(f.spec.mission_id,f.contexts.e1_worker),{code:'E1_NATIVE_ADMITTER'});
  await assert.rejects(()=>host.coordinator.admit({mission_id:f.spec.mission_id,auth_context:f.contexts.e1_owner},f.contexts.e1_owner),{code:'E1_AUTH_CONTEXT'});
  assert.equal((await host.admitPublished(f.spec.mission_id,f.contexts.e1_owner)).status,'ADMITTED');assert.equal((await host.health()).active_tasks,0);
  const claim=await host.coordinator.claim({mission_id:f.spec.mission_id,task_id:'parse_source',worker_id:'e1_worker_a',capabilities:['e1.code.parse'],lease_ms:30000});assert.equal(claim.status,'CLAIMED');assert.equal((await host.health()).active_tasks,1);
  await host.coordinator.cancel({mission_id:f.spec.mission_id,owner_id:'e1_owner',reason:'QA2 host seam completed'});assert.equal((await host.health()).active_tasks,0);
 }finally{await host.close();}
});
