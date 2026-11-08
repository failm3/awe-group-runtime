import fs from 'node:fs';
import {digest,need} from '../contracts/index.mjs';
import {createPsqlSession,createCoordinator,createAuthorityServer} from '../coordinator/index.mjs';
import {createCloud4HostSigner} from '../host/router-cheap/authority4.mjs';
import {createCloud4AuthorizationAuthority,restoreCloud4Authorization,amendCloud4Authorization,cloud4AuthorizationReceipt} from './authority.mjs';

// Host-only same-key prepared scope expansion. No funded/attempted key may change.
need(process.argv.length===4&&process.argv[2]==='--projects','CLOUD4_CLI_ARGUMENTS');
const project_ids=process.argv[3].split(',').sort();need(project_ids.length<=32&&new Set(project_ids).size===project_ids.length&&project_ids.every(p=>/^[a-z][a-z0-9_.-]{0,79}$/.test(p)),'CLOUD4_CLI_ARGUMENTS');
const receipt=JSON.parse(fs.readFileSync(new URL('./evidence/owner-authorization.json',import.meta.url),'utf8')),prior=receipt.document,read=name=>JSON.parse(fs.readFileSync(new URL('../../.private/'+name,import.meta.url),'utf8')),publicSigner=read('cloud4-public-signer.json'),control=read('run-control.json');
need(control.owner_authorization==='ISSUED_GITHUB3_4_RATIFIED_IN_CHAT'&&Date.now()<Date.parse(control.stop_at),'CLOUD4_HOST_MANDATE_REQUIRED');
const snapshots=[read('owner-issue3.json'),read('owner-issue4.json')];for(const [i,row]of snapshots.entries())need(row.transport==='AUTHENTICATED_GITHUB_CONNECTOR'&&row.chat_ratified===true&&row.source==='https://github.com/failm3/awe-group-runtime/issues/'+(i+3),'CLOUD4_HOST_MANDATE_REQUIRED');
const mandate=JSON.parse(fs.readFileSync(new URL('./evidence/owner-mandate.json',import.meta.url),'utf8'));need(digest(mandate)===prior.mandate_digest&&mandate.sources.every((s,i)=>s.body_digest===digest({body:snapshots[i].body})&&s.updated_at===snapshots[i].updated_at),'CLOUD4_HOST_MANDATE_REQUIRED');
const trusted_public_key_digest=digest({spki_der:publicSigner.public_key_spki_der}),project_id=prior.project_ids[0],db=await createPsqlSession(read('e1-resource.json'));let server;
try{
 const base=createCoordinator({db,project_id});server=await createAuthorityServer({coordinator:base});const credential=server.issueCredential({principal_id:prior.issuer_id,project_id,role:'COORDINATOR'});
 const cloud4Authority=createCloud4AuthorizationAuthority({authenticateContext:server.authenticateContext,mandate_digest:prior.mandate_digest,signer:createCloud4HostSigner({trusted_public_key_digest}),trusted_public_key_digest,verifyMandate:({context,request})=>context===credential.context&&request.owner_id===prior.owner_id&&request.key_binding_id===prior.key_binding_id&&request.project_ids.every(p=>project_ids.includes(p))});
 const current=await restoreCloud4Authorization(cloud4Authority,receipt,credential.context),next=await amendCloud4Authorization(cloud4Authority,current,{project_ids},credential.context),coordinator=createCoordinator({db,project_id,cloud4Authority}),result=await coordinator.amendCloud4Authorization(next,credential.context),nextReceipt=cloud4AuthorizationReceipt(next),readback=await coordinator.cloud4Authorization(prior.key_binding_id),history=await coordinator.cloud4AuthorizationHistory(prior.key_binding_id);
 need(result.state==='PREPARED_PROVIDER_BLOCKED'&&readback.funding.state==='DISABLED'&&history.history.some(h=>h.authorization_digest===receipt.document_digest),'CLOUD4_SCOPE_READBACK_REQUIRED');
 const target=new URL('./evidence/',import.meta.url);fs.writeFileSync(new URL('owner-authorization-revision-'+(prior.scope_revision??1)+'.json',target),JSON.stringify(receipt,null,2)+'\n');fs.writeFileSync(new URL('owner-authorization.json',target),JSON.stringify(nextReceipt,null,2)+'\n');fs.writeFileSync(new URL('scope-amendment-readback.json',target),JSON.stringify({schema:'awe.e1.cloud4.scope-amendment-readback/1',result,readback,history,provider_calls:0,router_key_read:false,accounting_reset:false},null,2)+'\n');
 process.stdout.write(JSON.stringify({state:result.state,key_binding_id:prior.key_binding_id,prior_authorization_digest:receipt.document_digest,authorization_digest:nextReceipt.document_digest,project_ids,spending_enabled:false,provider_calls:0,router_key_read:false})+'\n');
}finally{if(server)await server.close();await db.close();}
