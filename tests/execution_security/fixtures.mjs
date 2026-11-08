// All stores below are deterministic process-local TEST ports. They do not
// implement production D09, durable approvals or native D03/D06 storage.
import {generateKeyPairSync} from 'node:crypto';
import {createIdentityVerifier,createLocalIssuer} from '../../awe/execution_security/identity.mjs';
import {createPermissionAuthority,intentBinding} from '../../awe/execution_security/authority.mjs';
import {createPinnedToolRegistry,INPUT_SCHEMA} from '../../awe/execution_security/registry.mjs';
import {createExecutionGate} from '../../awe/execution_security/gate.mjs';
import {createEvaluationBoundary,evaluationPins} from '../../awe/execution_security/evaluation.mjs';
import {FIXED_CODE_DIGEST} from '../../awe/execution_security/synthetic-executor.mjs';
import {SecurityError,digest,copy,need} from '../../awe/execution_security/common.mjs';
export const text=JSON.stringify;
export function fixture(options={}){
 let time=1000000,healthy=true,keyActive=true;const proofs=new Map();
 const roles={user:['USER','HUMAN'],owner:['OWNER','HUMAN'],supervisor:['SUPERVISOR','SERVICE'],worker:['WORKER','AGENT'],child:['WORKER','SUBAGENT'],child2:['WORKER','SUBAGENT'],verifier:['VERIFIER','SERVICE'],evaluator:['EVALUATOR','SERVICE'],registry:['REGISTRY','SERVICE'],executor:['EXECUTOR','SERVICE'],provider:['PROVIDER','SERVICE']};
 const principals=Object.fromEntries(Object.entries(roles).map(([principal_id,[role,kind]])=>[principal_id,{principal_id,role,kind,subject:'subject:'+principal_id,active:true,projects:['prj_alpha'],generation:1,valid_until:2000000,channel_binding:'channel:'+principal_id,database_login:'sec01_'+principal_id}]));
 principals.foreign={...copy(principals.worker),principal_id:'foreign',subject:'subject:foreign',channel_binding:'channel:foreign',database_login:'sec01_foreign',projects:['prj_beta']};
 const state={project_id:'prj_alpha',task_id:'task_one',status:'RUNNING',epochs:{auth:1,policy:1,owner:1,stop:1},revision:1,fence:1,cancelled:false,restore_pending:false,uncertain:false,lease_until:1300000};
 const directory={health:()=>healthy,principal:p=>principals[p]??null,principals:()=>Object.values(principals),snapshot:(project,task)=>project===state.project_id&&task===state.task_id?state:null,
  identityTask:()=>state.task_id,keyActive:()=>keyActive,proofActive:jti=>proofs.get(jti)===true,registerProof:jti=>{need(!proofs.has(jti),'PROOF_ID_COLLISION');proofs.set(jti,true);},incarnation:()=>options.incarnation??'fixture-1'};
 const keys=generateKeyPairSync('ed25519'),config={keys:[{kid:'local-key-1',issuer:'sec01-local',publicKey:keys.publicKey}],directory,clock:()=>time};
 const verifier=createIdentityVerifier(config),issuer=createLocalIssuer({issuer:'sec01-local',kid:'local-key-1',privateKey:keys.privateKey,verifier,directory});
 const auth=createPermissionAuthority({verifier,issuer}),registry=createPinnedToolRegistry({verifier});
 const token=id=>issuer.issueIdentity(id,principals[id].projects[0]);
 const peer=id=>({binding:principals[id].channel_binding,database_login:principals[id].database_login});
 const manifest={v:'sec01.tool.v1',project_id:'prj_alpha',tool_id:'fixture.digest',version:'1.0.0',code_digest:FIXED_CODE_DIGEST,schema_hash:digest(INPUT_SCHEMA),risk:options.risk??'READ',resources:['resource:one'],paths:['inputs/data.txt'],domains:options.risk==='NETWORK'?['api.example.test']:[],cost_micros:options.cost??'10',max_input_bytes:8192,max_output_bytes:1024,implementation:'FIXED_SYNTHETIC_DIGEST'};
 registry.control.register(token('registry'),peer('registry'),text(manifest));
 const grantRequest={subject_id:'worker',project_id:'prj_alpha',task_id:'task_one',tools:[digest(manifest)],resources:manifest.resources,risks:[manifest.risk],domains:manifest.domains,max_cost_micros:options.grantCap??'100',max_attempts:4,max_children:2,ttl_ms:60000};
 const rootGrant=auth.control.issueGrant(token('supervisor'),peer('supervisor'),text(grantRequest));
 const request={v:'sec01.execution.v1',project_id:'prj_alpha',task_id:'task_one',operation_id:'op_one',attempt_id:'attempt_one',effect_slot:'slot_one',idempotency_key:'key_one',grant_token:rootGrant,
  tool_id:manifest.tool_id,tool_version:manifest.version,tool_digest:manifest.code_digest,schema_hash:manifest.schema_hash,manifest_hash:digest(manifest),resource_id:'resource:one',payload:{text:'safe synthetic content'},payload_hash:digest({text:'safe synthetic content'}),plan_hash:digest({plan:'fixed'}),epochs:copy(state.epochs),revision:1,fence:1,reserve_micros:manifest.cost_micros,expires_at:time+60000,approval_token:null};
 const world={balance:BigInt(options.cap??'100'),reserved:0n,spent:0n,attempts:new Map(),operations:new Set(),slots:new Set(),idempotency:new Set(),approvals:new Set(),lineage:new Map(),quarantined:false,healthy:true,sent:0,simulations:0,calls:[],audit:[],hook:null,fail:null};
 let portTail=Promise.resolve();const serial=fn=>{const p=portTail.then(fn);portTail=p.catch(()=>{});return p;};
 const ack=(r,binding,status)=>({physical_decision:'DENY',status,attempt_id:r.attempt_id,binding,committed:true});
 const assertAvailable=()=>need(world.healthy,'DATABASE_UNAVAILABLE');
 const rejection=code=>{const e=new SecurityError(code);e.knownNotAdmitted=true;throw e;};
 async function at(stage){world.calls.push(stage);if(world.hook)await world.hook(stage);if(world.fail===stage)throw Error('SENSITIVE_INTERNAL_CAUSE');}
 const admission={profile:'SEC01_SYNTHETIC_ADMISSION_V1',
  recoveryBarrier:async()=>{await at('barrier');assertAvailable();const unresolved=[...world.attempts.values()].some(a=>['ADMITTED','SENT','OUTCOME_UNKNOWN'].includes(a.status));return {status:world.quarantined||unresolved?'QUARANTINED':'READY',physical_decision:'DENY'};},
  admit:input=>serial(async()=>{
   await at('admit:before');assertAvailable();const {request:r,authorization:a,binding}=input;
   if(world.quarantined)rejection('D09_QUARANTINED');
   if(world.attempts.has(r.attempt_id)||world.operations.has(r.operation_id)||world.slots.has(r.effect_slot)||world.idempotency.has(r.idempotency_key))rejection('D09_OPERATION_REPLAY');
   if(a.approval_id&&world.approvals.has(a.approval_id))rejection('D09_APPROVAL_REPLAY');
   const cost=BigInt(r.reserve_micros);if(cost>world.balance)rejection('D09_BUDGET_EXCEEDED');
   for(const g of a.lineage){const used=world.lineage.get(g.grant_id)??{attempts:0,cost:0n};if(used.attempts>=g.max_attempts||used.cost+cost>BigInt(g.max_cost_micros))rejection('D09_TREE_LIMIT');}
   world.balance-=cost;world.reserved+=cost;
   for(const g of a.lineage){const u=world.lineage.get(g.grant_id)??{attempts:0,cost:0n};world.lineage.set(g.grant_id,{attempts:u.attempts+1,cost:u.cost+cost});}
   if(a.approval_id)world.approvals.add(a.approval_id);
   world.attempts.set(r.attempt_id,{binding,cost,status:'ADMITTED',request:copy(r)});world.operations.add(r.operation_id);world.slots.add(r.effect_slot);world.idempotency.add(r.idempotency_key);
   await at('admit:after');return ack(r,binding,'ADMITTED');
  }),
  markSent:async r=>{await at('sent:before');assertAvailable();const a=world.attempts.get(r.attempt_id);need(a&&a.status==='ADMITTED'&&a.binding===r.binding,'D09_STALE_ATTEMPT');a.status='SENT';world.sent++;await at('sent:after');return ack(r,r.binding,'SENT');},
  complete:async r=>{await at('complete:before');assertAvailable();const a=world.attempts.get(r.attempt_id);need(a&&a.status==='SENT'&&!state.cancelled,'D09_LATE_CALLBACK');
   const usage=options.complete?await options.complete(r):null;const actual=usage?.actual_micros!==undefined?BigInt(usage.actual_micros):a.cost;need(actual>=0n&&actual<=a.cost&&!state.cancelled,'D09_ENVELOPE_OR_CANCEL');
   a.status='WORK_COMPLETED';a.output=copy(r.output);world.reserved-=a.cost;world.balance+=a.cost-actual;world.spent+=actual;world.simulations++;await at('complete:after');return ack(r,r.binding,'WORK_COMPLETED');},
  cancelKnownPreSend:async r=>{await at('cancel');assertAvailable();const a=world.attempts.get(r.attempt_id);need(a&&a.status==='ADMITTED','D09_NOT_SENT_UNPROVEN');a.status='NOT_SENT';world.reserved-=a.cost;world.balance+=a.cost;return {status:'NOT_SENT',committed:true};},
  flagUnknown:async r=>{await at('unknown');assertAvailable();world.quarantined=true;const a=world.attempts.get(r.attempt_id);if(a)a.status='OUTCOME_UNKNOWN';return {status:'OUTCOME_UNKNOWN'};}
 };
 const audit={append:async row=>{await at('audit');world.audit.push(copy(row));}};
 const makeGate=()=>createExecutionGate({authority:auth,verifier,registry,admission,audit});const gate=makeGate();
 const signApproval=(r=request)=>{r.approval_token=auth.control.issueApproval(token('owner'),peer('owner'),r,'worker');return r;};
 if(['NETWORK','PAYMENT','DESTRUCTIVE','CREDENTIAL_TRANSFER'].includes(manifest.risk))signApproval();
 const execute=(r=request,who='worker',g=gate)=>g.execute(token(who),peer(who),text(r));
 const review=(r=request,who='worker')=>gate.review(token(who),peer(who),text(r));
 const changePayload=(r,payload)=>({...copy(r),payload,payload_hash:digest(payload)});
 return {state,principals,world,directory,config,keys,verifier,issuer,auth,registry,manifest,grantRequest,rootGrant,request,admission,audit,gate,makeGate,token,peer,signApproval,execute,review,changePayload,
  setTime:n=>{time=n;},setHealthy:b=>{healthy=b;},revokeKey:()=>{keyActive=false;},revokeProof:jti=>proofs.set(jti,false),time:()=>time};
}

export function evaluationFixture(f,bundle){
 const pending={pin:copy(f.state),binding:intentBinding(f.request),plan_hash:f.request.plan_hash,producer_id:'worker',producer_generation:f.principals.worker.generation,producer_subject:f.principals.worker.subject,bundle:structuredClone(bundle),verifier_id:null,verifier_generation:null,verifier_subject:null,proof:null,qa:'QA_NOT_RUN',accepted:false,uncertain:false,fail:null};
 const check=r=>{need(r.project_id===f.state.project_id&&r.task_id===f.state.task_id&&r.run_id==='qa_one','QA_RUN_DENIED');need(!pending.uncertain&&!f.state.cancelled&&!f.state.restore_pending&&!f.state.uncertain,'QA_STATE_DENIED');need(digest(pending.pin)===digest(f.state),'QA_STATE_STALE');};
 const store={
  start:async(r,a)=>{check(r);need(f.world.simulations===1,'WORK_NOT_COMPLETED');need(pending.qa==='QA_NOT_RUN','QA_ALREADY_STARTED');pending.verifier_id=a.principal_id;pending.verifier_generation=a.generation;pending.verifier_subject=a.subject;pending.qa='QA_PENDING';return {qa:pending.qa,committed:true,physical_decision:'DENY'};},
  readPending:async(r)=>{check(r);need(pending.qa==='QA_PENDING','QA_NOT_PENDING');return {...structuredClone(pending),physical_decision:'DENY'};},
  finish:async(r,a,proof,result)=>{check(r);need(pending.qa==='QA_PENDING','QA_NOT_PENDING');pending.proof=proof;pending.qa=result.verdict;if(pending.fail==='finish')throw Error('COMMIT_ACK_LOST');return {qa:pending.qa,committed:true,physical_decision:'DENY'};},
  accept:async(r,owner,proof,p)=>{check(r);need(pending.proof===proof&&pending.qa==='QA_PASS'&&p.binding===pending.binding&&p.plan_hash===pending.plan_hash&&p.artifact_hash===pending.bundle.reference.file_hash&&p.artifact_version===pending.bundle.reference.version,'QA_PROOF_NOT_COMMITTED');pending.accepted=true;if(pending.fail==='accept')throw Error('ACCEPT_COMMIT_ACK_LOST');return {accepted:true,committed:true,acceptance:'OWNER_ACCEPTED',qa:'QA_PASS',published:false,authoritative_complete:false,physical_decision:'DENY'};},
  flagUnknown:async()=>{pending.uncertain=true;pending.accepted=false;}
 };
 const boundary=createEvaluationBoundary({verifier:f.verifier,issuer:f.issuer,store,pins:evaluationPins()});
 const r={project_id:'prj_alpha',task_id:'task_one',run_id:'qa_one'};
 return {pending,boundary,request:r,start:()=>boundary.start(f.token('verifier'),f.peer('verifier'),text(r)),evaluate:()=>boundary.evaluateRun(f.token('evaluator'),f.peer('evaluator'),text(r)),accept:proof=>boundary.accept(f.token('owner'),f.peer('owner'),text(r),proof)};
}
