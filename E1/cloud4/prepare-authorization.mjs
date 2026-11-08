import fs from 'node:fs';
import {digest,need} from '../contracts/index.mjs';
import {createPsqlSession,createCoordinator,createAuthorityServer} from '../coordinator/index.mjs';
import {createCloud4HostSigner} from '../host/router-cheap/authority4.mjs';
import {LIMITS,createCloud4AuthorizationAuthority,issueCloud4Authorization,cloud4AuthorizationReceipt,cloud4PaidReadiness} from './authority.mjs';

// Root/host command only, after guarded 0004 application. No provider key read,
// provider call, fabricated provider evidence, or spending activation exists.
const opts={};for(let i=2;i<process.argv.length;i+=2){need(['--project','--owner','--key-binding'].includes(process.argv[i])&&process.argv[i+1]&&!Object.hasOwn(opts,process.argv[i]),'CLOUD4_CLI_ARGUMENTS');opts[process.argv[i]]=process.argv[i+1];}
for(const flag of ['--project','--owner','--key-binding'])need(typeof opts[flag]==='string'&&/^[a-z][a-z0-9_.-]{0,79}$/.test(opts[flag]),'CLOUD4_CLI_ARGUMENTS');
const read=name=>JSON.parse(fs.readFileSync(new URL('../../.private/'+name,import.meta.url),'utf8'));
const snapshots=[read('owner-issue3.json'),read('owner-issue4.json')],control=read('run-control.json'),publicSigner=read('cloud4-public-signer.json');
need(control.owner_authorization==='ISSUED_GITHUB3_4_RATIFIED_IN_CHAT'&&control.max_paid_actual_micros===LIMITS.total_actual_micros&&Date.now()<Date.parse(control.stop_at),'CLOUD4_HOST_MANDATE_REQUIRED');
for(const [i,row] of snapshots.entries())need(row.schema==='awe.owner.verified-github-directive/1'&&row.transport==='AUTHENTICATED_GITHUB_CONNECTOR'&&row.chat_ratified===true&&row.source==='https://github.com/failm3/awe-group-runtime/issues/'+(i+3)&&row.updated_at===(i===0?'2026-11-08T03:57:57Z':'2026-11-08T03:58:00Z')&&row.body.startsWith('> 2026-11-08 OWNER-DELEGATED CONSOLIDATED AUTONOMY AUTHORIZATION'),'CLOUD4_HOST_MANDATE_REQUIRED');
const mandate={schema:'awe.e1.cloud4.verified-owner-mandate/1',provenance:'HOST_ATTESTED_CHAT_AND_GITHUB_DELEGATION',chat_ratified:true,sources:snapshots.map(row=>({url:row.source,updated_at:row.updated_at,body_digest:digest({body:row.body})})),limits:LIMITS};
const mandate_digest=digest(mandate),trusted_public_key_digest=digest({spki_der:publicSigner.public_key_spki_der}),project_id=opts['--project'],owner_id=opts['--owner'],key_binding_id=opts['--key-binding'];
const db=await createPsqlSession(read('e1-resource.json'),{role:'coordinator'});let server;
try{
  const base=createCoordinator({db,project_id});server=await createAuthorityServer({coordinator:base});
  const credential=server.issueCredential({principal_id:'e1_cloud4_host_delegate',project_id,role:'COORDINATOR'});
  const cloud4Authority=createCloud4AuthorizationAuthority({authenticateContext:server.authenticateContext,mandate_digest,trusted_public_key_digest,signer:createCloud4HostSigner({trusted_public_key_digest}),verifyMandate:({mandate_digest:actual,principal,request,context})=>actual===mandate_digest&&context===credential.context&&principal.role==='COORDINATOR'&&principal.project_id===project_id&&request.owner_id===owner_id&&request.key_binding_id===key_binding_id&&request.project_ids.length===1&&request.project_ids[0]===project_id});
  const token=await issueCloud4Authorization(cloud4Authority,{key_binding_id,owner_id,project_ids:[project_id],expires_at:control.stop_at},credential.context),coordinator=createCoordinator({db,project_id,cloud4Authority});
  const prepared=await coordinator.prepareCloud4Authorization(token,credential.context),readback=await coordinator.cloud4Authorization(key_binding_id),receipt=cloud4AuthorizationReceipt(token);
  need(prepared.state==='PREPARED_PROVIDER_BLOCKED'&&readback.state==='PREPARED_PROVIDER_BLOCKED'&&readback.funding.state==='DISABLED','CLOUD4_PREPARED_READBACK_REQUIRED');
  const target=new URL('./evidence/',import.meta.url);fs.mkdirSync(target,{recursive:true});
  for(const [name,value] of [['owner-authorization.json',receipt],['owner-mandate.json',mandate],['authorization-readback.json',{schema:'awe.e1.cloud4.authorization-readback/1',prepared,readback,readiness:cloud4PaidReadiness({authorization:token}),router_key_read:false,provider_calls:0,private_signing_key_exposed:false}]])fs.writeFileSync(new URL(name,target),JSON.stringify(value,null,2)+'\n');
  process.stdout.write(JSON.stringify({owner_consent:'ISSUED',authorization_digest:receipt.document_digest,trusted_public_key_digest,state:readback.state,spending_enabled:false,provider_calls:0,router_key_read:false})+'\n');
}finally{if(server)await server.close();await db.close();}
