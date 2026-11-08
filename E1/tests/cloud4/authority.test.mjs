import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../../contracts/index.mjs';
import {LIMITS,issueCloud4Authorization,cloud4AuthorizationReceipt,cloud4AuthorizationAdmission,verifyCloud4Receipt,validateAuthorizationDocument,issueCloud4CanaryGate,cloud4CanaryAdmission,cloud4PaidReadiness} from '../../cloud4/authority.mjs';
import {createCloud4Accounting} from '../../cloud4/accounting.mjs';
import {createCloud4LiveBinding} from '../../cloud4/provider-contract.mjs';
import {authorityFixture} from './fixtures.mjs';

test('actual asymmetric receipt binds bounded mandate; JSON and wrong context cannot mint authority',async()=>{
  const f=authorityFixture(),token=await f.issue(),receipt=cloud4AuthorizationReceipt(token);assert.equal(receipt.document.owner_consent,'ISSUED');assert.deepEqual(receipt.document.limits,LIMITS);verifyCloud4Receipt(receipt,{trusted_public_key_digest:f.trusted_public_key_digest});
  await assert.rejects(()=>issueCloud4Authorization({kind:'CLOUD4_HOST_AUTHORIZATION_AUTHORITY'},f.request,{}));await assert.rejects(()=>issueCloud4Authorization(f.authority,f.request,{}));await assert.rejects(()=>issueCloud4Authorization(f.authority,f.request,f.contexts.worker));
  await assert.rejects(()=>cloud4AuthorizationAdmission(f.authority,{kind:'CLOUD4_AUTHENTICATED_OWNER_AUTHORIZATION'},f.contexts.coordinator));await assert.rejects(()=>cloud4AuthorizationAdmission(f.authority,token,{}));
});
test('signature substitution, cap enlargement, scope and stale documents are rejected',async()=>{
  const f=authorityFixture(),receipt=cloud4AuthorizationReceipt(await f.issue());
  for(const mutate of [r=>r.document.limits.total_actual_micros='10000001',r=>r.document.project_ids=['foreign_project'],r=>r.signature='A'.repeat(86)+'==',r=>r.document_digest=digest({forged:true}),r=>r.algorithm='RSA']){const value=structuredClone(receipt);mutate(value);assert.throws(()=>verifyCloud4Receipt(value,{trusted_public_key_digest:f.trusted_public_key_digest}));}
  assert.throws(()=>verifyCloud4Receipt(receipt,{trusted_public_key_digest:digest({untrusted:true})}));
  const wide=structuredClone(receipt.document);wide.limits.followup.attempts=21;assert.throws(()=>validateAuthorizationDocument(wide));
  await assert.rejects(()=>authorityFixture({verifyMandate:()=>false}).issue());const stale=authorityFixture();stale.request.expires_at=new Date(Date.now()-1000).toISOString();await assert.rejects(()=>stale.issue());
});
test('independent canary gate cannot be self-issued by coordinator/worker or failed reviewer',async()=>{
  const f=authorityFixture(),owner=await f.issue(),ids=['attempt_a','attempt_b'];
  await assert.rejects(()=>issueCloud4CanaryGate(f.authority,owner,{attempt_ids:ids},f.contexts.coordinator));await assert.rejects(()=>issueCloud4CanaryGate(f.authority,owner,{attempt_ids:ids},f.contexts.worker));
  const bad=authorityFixture({verifyIndependentCanary:()=>false}),badOwner=await bad.issue();await assert.rejects(()=>issueCloud4CanaryGate(bad.authority,badOwner,{attempt_ids:ids},bad.contexts.qa));
  const gate=await issueCloud4CanaryGate(f.authority,owner,{attempt_ids:ids},f.contexts.qa),receipt=await cloud4CanaryAdmission(f.authority,gate,f.contexts.qa);assert.equal(receipt.document.evaluator_id,'synthetic_qa');await assert.rejects(()=>cloud4CanaryAdmission(f.authority,gate,f.contexts.coordinator));
});
test('same native accounting boundary receives phase binding; UNKNOWN uses its existing port',async()=>{
  const f=authorityFixture(),authorization=await f.issue(),receipt=cloud4AuthorizationReceipt(authorization),calls=[];let phase='PREPARED_PROVIDER_BLOCKED';
  const coordinator={kind:'AWE_E1_DURABLE_COORDINATOR',project_id:'prj_cloud_authority4',async cloud4Authorization(){return{state:phase,authorization_digest:receipt.document_digest};},...Object.fromEntries(['reserve','markSending','settle','unknown','failBeforeSend'].map(method=>[method,async value=>{calls.push({method,value});return{status:'TEST_DOUBLE'};}]))};
  const port=createCloud4Accounting({coordinator,authorization});await assert.rejects(()=>port.reserve({cloud:{}}));assert.equal(calls.length,0);phase='CANARY';await port.reserve({cloud:{quote_digest:digest({test:true})}});assert.equal(calls[0].value.cloud.cloud4_phase,'CANARY');assert.equal(calls[0].value.cloud.cloud4_authorization_digest,receipt.document_digest);phase='HOLD';await assert.rejects(()=>port.markSending({}));await port.unknown({reason:'LOST_ACK'});assert.equal(calls.at(-1).method,'unknown');
});
test('issued financial authorization and caller-supplied proof never override objective provider blocker',async()=>{
  const f=authorityFixture(),authorization=await f.issue(),readiness=cloud4PaidReadiness({authorization,provider_contract:{verified:true}});assert.equal(readiness.owner_consent,'ISSUED_AUTHENTICATED_HOST_ATTESTATION');assert.equal(readiness.spending_enabled,false);
  let wires=0;const binding=createCloud4LiveBinding({authorization,provider_contract:{verified:true},accounting:{kind:'CLOUD4_BOUND_NATIVE_ACCOUNTING',send(){wires++;}}}),result=await binding.invoke({});assert.equal(result.reason,'PROVIDER_ACTUAL_CHARGE_CAP_AND_ACK_NOT_PROVEN');assert.equal(result.actual_paid_calls,0);assert.equal(wires,0);
});
