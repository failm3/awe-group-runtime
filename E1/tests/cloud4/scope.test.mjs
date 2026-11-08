import test from 'node:test';
import assert from 'node:assert/strict';
import {amendCloud4Authorization,cloud4AuthorizationReceipt,restoreCloud4Authorization} from '../../cloud4/authority.mjs';
import {authorityFixture} from './fixtures.mjs';
test('scope expansion is same-key signed CAS, exact limits and nonincreasing expiry',async()=>{
 const f=authorityFixture(),prior=await f.issue(),old=cloud4AuthorizationReceipt(prior),next=await amendCloud4Authorization(f.authority,prior,{project_ids:[...old.document.project_ids,'prj_cloud_planned_canary']},f.contexts.coordinator),value=cloud4AuthorizationReceipt(next);
 assert.equal(value.document.key_binding_id,old.document.key_binding_id);assert.equal(value.document.owner_id,old.document.owner_id);assert.equal(value.document.prior_authorization_digest,old.document_digest);assert.equal(value.document.scope_revision,2);assert.deepEqual(value.document.limits,old.document.limits);assert.equal(value.document.expires_at,old.document.expires_at);assert.equal(value.public_key_digest,old.public_key_digest);
 await assert.rejects(()=>amendCloud4Authorization(f.authority,prior,{project_ids:['prj_cloud_different']},f.contexts.coordinator));await assert.rejects(()=>amendCloud4Authorization(f.authority,prior,{project_ids:[...old.document.project_ids,'prj_cloud_next'],expires_at:new Date(Date.parse(old.document.expires_at)+1000).toISOString()},f.contexts.coordinator));
});
test('cold restore still requires trusted public anchor and live host mandate/context',async()=>{
 const f=authorityFixture(),receipt=cloud4AuthorizationReceipt(await f.issue());await restoreCloud4Authorization(f.authority,receipt,f.contexts.coordinator);await assert.rejects(()=>restoreCloud4Authorization(f.authority,receipt,{}));const other=authorityFixture();await assert.rejects(()=>restoreCloud4Authorization(other.authority,receipt,other.contexts.coordinator));
});
