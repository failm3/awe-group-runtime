// CR-01 candidate: validation is not authentication or a dispatch capability.
import {parseIntent,copy,freeze,requireKeys} from '../policy/json.mjs';
import {digest,canonicalize} from '../../contracts/canonical.mjs';
import {safePath} from '../artifacts/paths.mjs';
export const NATIVE_SCHEMA='sec02.native.binding.cr01.v1';
export const COMMAND_SCHEMA='sec02.native.admit.cr01.v1';
export const RECEIPT_SCHEMA='sec02.native.receipt.cr01.v1';
export const NATIVE_PROFILE='SEC02_NATIVE_BINDING_ONLY_CR01';
export class NativeBindingError extends Error {constructor(code,{outcomeUnknown=false}={}){super(code);this.code=code;this.outcomeUnknown=outcomeUnknown;}}
const need=(ok,code='NATIVE_COMMAND_INVALID')=>{if(!ok)throw new NativeBindingError(code);};
const exact=(v,keys)=>{try{requireKeys(v,keys);}catch{throw new NativeBindingError('NATIVE_FIELDS_INVALID');}};
const id=v=>need(typeof v==='string'&&/^[A-Za-z0-9_.:-]{1,128}$/.test(v));
const hash=v=>need(typeof v==='string'&&/^sha256:[a-f0-9]{64}$/.test(v));
const integer=(v,min=0)=>need(Number.isSafeInteger(v)&&v>=min);
const money=v=>need(typeof v==='string'&&/^(0|[1-9][0-9]{0,29})$/.test(v));
const text=v=>need(typeof v==='string'&&v.length>0&&Buffer.byteLength(v)<=128&&!/[\x00-\x1f\x7f]/.test(v));
function artifact(r,s){exact(r,['project_id','task_id','artifact_id','version','path','bytes','file_hash','provenance_hash']);for(const k of ['project_id','task_id','artifact_id'])id(r[k]);integer(r.version,1);integer(r.bytes);hash(r.file_hash);hash(r.provenance_hash);need(r.project_id===s.project_id&&r.task_id===s.task_id);try{safePath(r.path);}catch{throw new NativeBindingError('NATIVE_ARTIFACT_PATH');}}
function model(p){exact(p,['model_id','model_revision','profile_hash','route_id','route_hash','price_hash','policy_hash','protocol','endpoint_ref','account_ref']);for(const k of ['model_id','route_id','protocol','endpoint_ref','account_ref'])id(p[k]);text(p.model_revision);for(const k of ['profile_hash','route_hash','price_hash','policy_hash'])hash(p[k]);}
function runtime(p){exact(p,['build_hash','image_hash','config_hash','sandbox_profile_hash','toolset_hash']);Object.values(p).forEach(hash);}
function tool(p){exact(p,['tool_id','version','code_digest','schema_hash','manifest_hash']);id(p.tool_id);text(p.version);for(const k of ['code_digest','schema_hash','manifest_hash'])hash(p[k]);}
function body(b){
 exact(b,['schema','kind','command_id','scope','run','state_pin','data_pins','execution_pins','authority','budget','expires_at']);need(b.schema===NATIVE_SCHEMA&&['MODEL_REQUEST','RUNTIME_CONTROL','TOOL_EXECUTION'].includes(b.kind));id(b.command_id);
 exact(b.scope,['project_id','task_id','origin_id','operation_id','attempt_id','effect_slot','idempotency_key','logical_request_id','correlation_id']);Object.values(b.scope).forEach(id);
 exact(b.run,['run_id','parent_run_id','child_id']);id(b.run.run_id);if(b.run.parent_run_id!==null)id(b.run.parent_run_id);if(b.run.child_id!==null)id(b.run.child_id);need(b.run.parent_run_id!==b.run.run_id&&(b.run.parent_run_id===null)===(b.run.child_id===null));
 const s=b.state_pin;exact(s,['spec','epochs','task_revision','task_fence','lease_epoch','config_revision','lease_expires_at']);exact(s.spec,['spec_id','revision','content_hash']);id(s.spec.spec_id);integer(s.spec.revision,1);hash(s.spec.content_hash);exact(s.epochs,['auth','policy','owner','stop']);for(const [k,v] of Object.entries(s.epochs))integer(v,k==='stop'?0:1);for(const k of ['task_revision','task_fence','lease_epoch','config_revision','lease_expires_at'])integer(s[k],1);
 const d=b.data_pins;exact(d,['payload_ref','payload_hash','payload_serializer_hash','context_ref','context_hash','context_protocol_hash']);artifact(d.payload_ref,b.scope);artifact(d.context_ref,b.scope);for(const k of ['payload_hash','payload_serializer_hash','context_hash','context_protocol_hash'])hash(d[k]);
 const e=b.execution_pins;exact(e,['runtime','tool','model']);if(b.kind==='MODEL_REQUEST'){need(e.runtime===null&&e.tool===null);model(e.model);}else if(b.kind==='RUNTIME_CONTROL'){need(e.tool===null);runtime(e.runtime);model(e.model);}else{need(e.model===null);runtime(e.runtime);tool(e.tool);}
 exact(b.authority,['grant_ref','grant_lineage_digest','subject_binding_hash','policy_hash']);id(b.authority.grant_ref);for(const k of ['grant_lineage_digest','subject_binding_hash','policy_hash'])hash(b.authority[k]);
 exact(b.budget,['currency','reserve_micros','quote_hash','max_attempts']);need(b.budget.currency==='RUB'&&b.budget.max_attempts===1);money(b.budget.reserve_micros);hash(b.budget.quote_hash);integer(b.expires_at,1);need(b.expires_at<=s.lease_expires_at);
}
export function parseNativeAdmission(text,scope){
 try{
  const q=parseIntent(text);exact(q,['schema','body','binding','approval_ref','command','expected_revision','plan_hash']);need(q.schema===COMMAND_SCHEMA);body(q.body);hash(q.binding);need(digest(q.body)===q.binding,'NATIVE_BINDING_MISMATCH');id(q.approval_ref);integer(q.expected_revision,1);hash(q.plan_hash);
  const b=q.body,c=q.command;exact(c,['project_id','task_id','operation_id','attempt_id','effect_slot','approval_id','grant_id','idempotency_key','plan_hash','payload_hash','reserve_micros']);for(const k of ['project_id','task_id','operation_id','attempt_id','effect_slot','approval_id','grant_id','idempotency_key'])id(c[k]);hash(c.plan_hash);hash(c.payload_hash);money(c.reserve_micros);
  need(b.scope.project_id===scope.project_id&&b.scope.task_id===scope.task_id,'NATIVE_SCOPE_MISMATCH');for(const k of ['project_id','task_id','operation_id','attempt_id','effect_slot','idempotency_key'])need(c[k]===b.scope[k],'NATIVE_COMMAND_BINDING');need(c.approval_id===q.approval_ref&&c.grant_id===b.authority.grant_ref&&c.reserve_micros===b.budget.reserve_micros&&c.plan_hash===b.budget.quote_hash,'NATIVE_COMMAND_BINDING');
  return freeze({schema:COMMAND_SCHEMA,body_text:canonicalize(b),binding:q.binding,approval_ref:q.approval_ref,command_text:canonicalize(c),expected_revision:q.expected_revision,plan_hash:q.plan_hash});
 }catch(e){if(e instanceof NativeBindingError)throw e;throw new NativeBindingError('NATIVE_COMMAND_INVALID');}
}
export function checkNativeReceipt(v,q,scope){
 try{
  exact(v,['schema','execution_profile','project_id','task_id','status','body_text','binding','command_text','approval_ref','plan_hash','pre_revision','revision','task_pin','attempt','recorded_in_transaction','physical_decision','dispatch_authorized','accepted','qa']);
  need(v&&v.schema===RECEIPT_SCHEMA&&v.execution_profile===NATIVE_PROFILE&&v.physical_decision==='DENY'&&v.dispatch_authorized===false&&v.accepted===false&&v.recorded_in_transaction===true);
  need(['ADMITTED','READBACK','HOLD'].includes(v.status)&&['QA_NOT_RUN','QA_INCONCLUSIVE'].includes(v.qa));
  need(v.project_id===scope.project_id&&v.task_id===scope.task_id&&typeof v.revision==='string'&&/^[1-9][0-9]*$/.test(v.revision));
  if(q){for(const k of ['body_text','binding','approval_ref','command_text','plan_hash'])need(v[k]===q[k]);need(digest(v.task_pin)===digest(JSON.parse(q.body_text).state_pin));need(v.pre_revision===String(q.expected_revision)&&BigInt(v.revision)>=BigInt(q.expected_revision)+1n);if(v.status!=='HOLD')need(BigInt(v.revision)===BigInt(q.expected_revision)+1n);const c=JSON.parse(q.command_text),a=v.attempt;need(a&&digest(a.request)===digest(c)&&a.physical_decision==='DENY'&&a.dispatch_authorized===false);for(const k of ['project_id','attempt_id','operation_id','idempotency_key','grant_id','reserve_micros'])need(a[k]===c[k]);need(a.status==='ADMITTED'&&a.accounting_status==='RESERVED'&&a.delivery_fence==='0'&&a.actual_micros===null);}
  return freeze(copy(v));
 }catch{throw new NativeBindingError('NATIVE_RECEIPT_INVALID');}
}
export const nativeDenial=()=>freeze({decision:'DENY',physical_decision:'DENY',code:'NATIVE_DISPATCH_NOT_IMPLEMENTED_CR01'});
