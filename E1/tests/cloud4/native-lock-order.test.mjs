import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {digest} from '../../contracts/index.mjs';
import {createPsqlSession,createCoordinator,createAuthorityServer} from '../../coordinator/index.mjs';
import {sqlJson} from '../../coordinator/psql-session.mjs';
import {ledgerFixture,descriptor,unique} from '../cloud-ledger/fixtures.mjs';
import {authorityFixture} from './fixtures.mjs';
import {createCloud4AuthorizationAuthority,issueCloud4Authorization,amendCloud4Authorization,cloud4AuthorizationReceipt} from '../../cloud4/authority.mjs';
const enabled=process.env.AWE_E1_CLOUD6_NATIVE_TEST==='1',evidence=[];
test('native funded amendment rejects before auth-row wait and preserves a real concurrent reserve',{skip:!enabled,timeout:30000},async()=>{
 const f=ledgerFixture({budget_cap_micros:'10000000',per_attempt_cap_micros:'1000000',attempts_cap:'22'});let server,contenderDb,releaseHolder,holder,amendment;
 try{
  const base=await f.open(),project_id=f.sources[0].spec.project_id;server=await createAuthorityServer({coordinator:base.coordinator});const host=server.issueCredential({principal_id:'lock_host_delegate',project_id,role:'COORDINATOR'}),signing=authorityFixture();
  const cloud4Authority=createCloud4AuthorizationAuthority({authenticateContext:server.authenticateContext,mandate_digest:digest({label:'EXPLICIT_SYNTHETIC_LOCK_ORACLE'}),verifyMandate:({context})=>context===host.context,signer:signing.signer,trusted_public_key_digest:signing.trusted_public_key_digest});
  const owner=await issueCloud4Authorization(cloud4Authority,{key_binding_id:f.funding.grant.key_binding_id,owner_id:f.sources[0].spec.owner_id,project_ids:[project_id],evidence_mode:'EXPLICIT_SYNTHETIC',expires_at:f.funding.grant.expires_at},host.context),receipt=cloud4AuthorizationReceipt(owner);
  f.funding.grant.cloud4_authorization_digest=receipt.document_digest;f.funding.grant.owner_grant_digest=receipt.document_digest;f.funding.grant_digest=digest(f.funding.grant);
  const rt=await f.open();await rt.admit();const coordinator=createCoordinator({db:rt.db,project_id,cloud4Authority});await coordinator.prepareCloud4Authorization(owner,host.context);await f.fund(rt);await coordinator.activateCloud4Canary(owner,f.funding.grant_digest,host.context);
  const scope=f.scope(await f.claim(rt));scope.cloud.cloud4_authorization_digest=receipt.document_digest;scope.cloud.cloud4_phase='CANARY';
  const next=await amendCloud4Authorization(cloud4Authority,owner,{project_ids:[project_id,unique('prj_cloud_lock_planned')]},host.context);contenderDb=await createPsqlSession(descriptor());const contender=createCoordinator({db:contenderDb,project_id,cloud4Authority});
  let ready;const locked=new Promise(resolve=>ready=resolve),go=new Promise(resolve=>releaseHolder=resolve);
  holder=rt.db.transaction(async tx=>{
   // Idempotent native activation acquires the same budget-row/auth-row lock
   // prefix as the funded reserve path, held by this actual backend transaction.
   const activation=JSON.parse(await tx.query('SELECT awe_e1_runtime.cloud4_activate_canary('+sqlJson({key_binding_id:f.funding.grant.key_binding_id,authorization_digest:receipt.document_digest,funding_grant_digest:f.funding.grant_digest})+');'));assert.equal(activation.state,'CANARY');ready();await go;
   return tx.command('reserve',{...scope,project_id});
  });
  await locked;const started=Date.now();amendment=contender.amendCloud4Authorization(next,host.context).then(value=>({value}),error=>({error:error.code}));
  let timer;const early=await Promise.race([amendment,new Promise(resolve=>timer=setTimeout(()=>resolve({timeout:true}),1500))]);clearTimeout(timer);releaseHolder();
  const reserve=await holder,finalAmend=await amendment;
  assert.equal(early.timeout,undefined,'A funded amendment must not wait for the holder auth-row lock.');assert.equal(finalAmend.error,'A2_CLOUD_AUTHZ_AMEND_FUNDED_OR_ATTEMPTED');assert.equal(reserve.status,'RESERVED');
  const budget=await coordinator.cloudBudget(f.funding.grant.key_binding_id),state=await rt.coordinator.snapshot();assert.equal(budget.reserved,40);assert.equal(budget.attempts_used,1);assert.equal(state.attempts[0].state,'RESERVED');assert.equal(state.project.quota_used,1);
  await rt.coordinator.failBeforeSend(scope);assert.equal((await coordinator.cloudBudget(f.funding.grant.key_binding_id)).reserved,0);assert.equal((await coordinator.cloudBudget(f.funding.grant.key_binding_id)).attempts_used,1);
  evidence.push({case:'FUNDED_AMEND_RESERVE_LOCK_ORDER',native_backends:2,holder:'NATIVE_BUDGET_AND_AUTH_ROW_LOCKS_WITH_REAL_RESERVE',amend_reject:finalAmend.error,amend_completed_while_auth_held:true,reserve:'RESERVED',reserved:40,attempts_used:1,no_send_release_reserved:0,counters_reset:false,provider_calls:0,elapsed_ms:Date.now()-started});
 }finally{releaseHolder?.();await Promise.allSettled([holder,amendment].filter(Boolean));if(contenderDb)await contenderDb.close();if(server)await server.close();await f.close();}
});
test.after(()=>{if(enabled&&process.env.AWE_E1_CLOUD6_EVIDENCE)fs.writeFileSync(process.env.AWE_E1_CLOUD6_EVIDENCE,JSON.stringify({schema:'awe.e1.cloud6.lock-order-review/1',mode:'NATIVE_POSTGRESQL_EXPLICIT_SYNTHETIC_FUNDING',provider_calls:0,ddl:false,evidence},null,2)+'\n');});
