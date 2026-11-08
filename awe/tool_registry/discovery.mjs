import {verify} from 'node:crypto';
import {VERSION,bounded,copy,digest,canonical,ensure,exactKeys,hash,id} from './common.mjs';
import {CAPABILITIES,parseCapabilityRequest} from './taxonomy.mjs';
export function normalizeRequest(value){
 const r=bounded(value,8192);exactKeys(r,['project_id','need','capabilities','limit','mode','platform','max_cost_micros','currency','text_filter']);
 ensure(id(r.project_id),'TR_PROJECT');ensure(typeof r.need==='string'&&r.need.length<=1000,'TR_NEED');
 const capabilities=r.capabilities??parseCapabilityRequest(r.need);
 ensure(Array.isArray(capabilities)&&capabilities.length>0&&capabilities.length<=8&&capabilities.every(c=>CAPABILITIES.includes(c)),'TR_CAPABILITY');
 ensure(r.limit===undefined||(Number.isSafeInteger(r.limit)&&r.limit>=1&&r.limit<=20),'TR_LIMIT');
 ensure(r.mode===undefined||['CANDIDATES','VERIFIED'].includes(r.mode),'TR_MODE');
 ensure(r.platform===undefined||(typeof r.platform==='string'&&r.platform.length<=40),'TR_PLATFORM');
 ensure(r.text_filter===undefined||(typeof r.text_filter==='string'&&r.text_filter.length>0&&r.text_filter.length<=160),'TR_TEXT_FILTER');
 ensure(r.max_cost_micros===undefined||(typeof r.max_cost_micros==='string'&&/^\d{1,18}$/.test(r.max_cost_micros)&&/^[A-Z]{3}$/.test(r.currency)),'TR_COST');
 return {...r,capabilities:[...new Set(capabilities)],limit:r.limit??5,mode:r.mode??'VERIFIED'};
}
export function rankRecords(rows,request,now){
 const r=normalizeRequest(request);
 return rows.filter(t=>!t.disabled&&!t.compromised&&!t.hazards?.length&&t.capabilities?.some(c=>r.capabilities.includes(c)))
  .filter(t=>r.mode==='CANDIDATES'||(t.verified==='TESTED'&&t.available==='AVAILABLE'&&Date.parse(t.valid_until)>now))
  .filter(t=>!r.platform||t.platform?.includes(r.platform))
  .filter(t=>r.max_cost_micros===undefined||(t.cost?.amount_micros!==null&&t.cost?.amount_micros!==undefined&&t.cost.currency===r.currency&&/^\d+$/.test(String(t.cost.amount_micros))&&BigInt(t.cost.amount_micros)<=BigInt(r.max_cost_micros)))
  .map(t=>({tool_id:t.tool_id,title:String(t.title).replace(/[\x00-\x1f\x7f<>]/g,'').slice(0,160),capabilities:t.capabilities.filter(c=>r.capabilities.includes(c)),
   version:t.version,input_schema_digest:t.input_schema_digest??null,manifest_digest:t.manifest_digest??null,revision:t.revision,
   verified_state:t.verified,availability:t.available,cost:copy(t.cost),risk:t.risk??'UNKNOWN',permitted:false,
   score:r.capabilities.filter(c=>t.capabilities.includes(c)).length*100+(t.verified==='TESTED'?20:0)+(t.available==='AVAILABLE'?10:0),
   requires_review:t.verified!=='TESTED',physical_decision:'DENY'}))
  .sort((a,b)=>b.score-a.score||a.tool_id.localeCompare(b.tool_id,'en')).slice(0,r.limit);
}
// Host provides principal and repository, never supplied by an LLM request.
export function createDiscovery({repository,principal,clock=()=>Date.now(),issuerKeys={},pep=null}){
 ensure(repository&&typeof repository.search==='function'&&typeof repository.get==='function','TR_REPOSITORY');
 ensure(principal&&id(principal.tenant_id)&&id(principal.actor_id),'TR_PRINCIPAL');
 const actor=copy(principal),reviews=[];
 const trail=(action,request,decision,reason)=>{const e={sequence:reviews.length+1,at:new Date(clock()).toISOString(),actor,action,request_digest:digest(request),decision,reason};reviews.push(e);return e;};
 return Object.freeze({
  async searchCapabilities(request){const r=normalizeRequest(request);try{
   const rows=await repository.search(r,actor);const results=rankRecords(rows,r,clock());trail('SEARCH',r,'METADATA_ONLY','NO_EXECUTION_AUTHORITY');
   return {contract:VERSION,project_id:r.project_id,results,physical_decision:'DENY'};
  }catch(e){trail('SEARCH',r,'DENY','STORE_OR_ACL_FAILURE');throw Error('TR_SEARCH_DENIED');}},
  async bindTool(value){
   const r=bounded(value,16384);try{
    exactKeys(r,['project_id','tool_id','capability','version','revision','manifest_digest','input_schema_digest','epochs','task_id','operation_id','idempotency_key','artifact_digest','plan_digest','max_cost_micros','currency']);
    for(const k of ['project_id','tool_id','task_id','operation_id','idempotency_key'])ensure(id(r[k]),'TR_BIND_FIELDS');
    for(const k of ['manifest_digest','input_schema_digest','artifact_digest','plan_digest'])ensure(hash(r[k]),'TR_BIND_DIGEST');
    ensure(CAPABILITIES.includes(r.capability)&&Number.isSafeInteger(r.revision),'TR_BIND_CAPABILITY');
    exactKeys(r.epochs,['auth','policy','tool','project']);ensure(['auth','policy','tool','project'].every(k=>Number.isSafeInteger(r.epochs[k])&&r.epochs[k]>0),'TR_EPOCHS');
    ensure(typeof r.max_cost_micros==='string'&&/^\d{1,18}$/.test(r.max_cost_micros)&&/^[A-Z]{3}$/.test(r.currency),'TR_BIND_FUNDS');
    const t=await repository.get(r.project_id,r.tool_id,actor);
    ensure(t&&!t.disabled&&!t.compromised&&!t.hazards?.length&&t.verified==='TESTED'&&t.available==='AVAILABLE'&&Date.parse(t.valid_until)>clock(),'TR_TOOL_DENIED');
    ensure(t.version===r.version&&t.revision===r.revision&&t.input_schema_digest===r.input_schema_digest&&t.manifest_digest===r.manifest_digest&&t.capabilities.includes(r.capability),'TR_STALE_BINDING');
    const m=t.signed_manifest;ensure(m&&issuerKeys[m.key_id]&&typeof m.signature==='string','TR_MANIFEST_REQUIRED');
    const p=m.payload;ensure(digest(p)===r.manifest_digest&&verify(null,Buffer.from(canonical(p)),issuerKeys[m.key_id],Buffer.from(m.signature,'base64')),'TR_SIGNATURE');
    ensure(p.tenant_id===actor.tenant_id&&p.actor_id===actor.actor_id&&p.project_id===r.project_id&&p.tool_id===r.tool_id&&p.version===r.version&&p.revision===r.revision&&p.input_schema_digest===r.input_schema_digest&&p.capabilities.includes(r.capability),'TR_MANIFEST_SCOPE');
    ensure(Date.parse(p.valid_until)>clock()&&Date.parse(p.issued_at)<=clock()&&canonical(p.epochs)===canonical(r.epochs),'TR_STALE_MANIFEST');
    ensure(pep&&typeof pep.review==='function','TR_PEP_REQUIRED');
    const decision=await pep.review(copy({actor,request:r,manifest_digest:r.manifest_digest}));
    ensure(decision?.decision==='ALLOW_E0_PROPOSAL'&&hash(decision.approval_digest)&&decision.request_digest===digest(r),'TR_PEP_DENIED');
    trail('BIND',r,'BOUND_E0_ONLY','D04_SEC_GATES_PENDING');
    return {contract:VERSION,status:'BOUND_E0_ONLY',proposal:{...r,actor,approval_digest:decision.approval_digest},physical_decision:'DENY',retry_owner:'D04_D09',runtime_dispatch:false};
   }catch(e){trail('BIND',r,'DENY',e.message);return {contract:VERSION,status:'DENIED',reason:e.message,physical_decision:'DENY'};}
  },
  reviewTrail:()=>copy(reviews)
 });
}
