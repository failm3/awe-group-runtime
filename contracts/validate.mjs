import {validateShape} from './schema-validator.mjs';
import {digest} from './canonical.mjs';
const contexts=new WeakSet();
const terminal=new Set(['COMPLETE','CANCELLED','FAILED']);
const boundBody=(value,field)=>{const body={...value};delete body[field];return digest(body);};
const transitions={
 DRAFT:['READY'],READY:['RUNNING'],RUNNING:['QA_PENDING'],QA_PENDING:['REWORK','PERSISTING'],
 REWORK:['READY'],PERSISTING:['COMPLETE'],RECONCILING:[],WAITING_FOR_EVENT:[],WAITING_FOR_OWNER:[],BLOCKED:[],CANCELLING:['CANCELLED','RECONCILING']
};
// This is an offline trust-boundary seam, not authentication or an authorization server.
// Only future trusted D-02/D-03 adapters may construct it from authenticated durable state.
export function createValidationContext(input) {
  const ctx=JSON.parse(JSON.stringify(input));
  if(!Number.isFinite(Date.parse(ctx.now))) throw new TypeError('CLOCK_REQUIRED');
  function freeze(v) {if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;}
  freeze(ctx);contexts.add(ctx);return ctx;
}
export function validate(name,value,ctx) {
  const errors=validateShape(name,value);
  if(errors.length) return {ok:false,errors};
  if(!contexts.has(ctx)) return {ok:false,errors:['TRUSTED_CONTEXT_REQUIRED']};
  const reject=reason=>errors.push(reason);
  const actor=(a,authenticated=false)=>{
    const trusted=ctx.principals?.[a.identity_id];
    if(!trusted||trusted.role!==a.role) reject('UNKNOWN_OR_FORGED_ACTOR');
    if(authenticated&&a.identity_id!==ctx.authenticated_identity_id) reject('ACTOR_CONTEXT_MISMATCH');
    if(trusted&&value.scope&&!trusted.projects.includes(value.scope.project_id)) reject('ACTOR_SCOPE_DENIED');
  };
  if(value.actor) actor(value.actor,true);
  if(value.scope&&value.scope.project_id!==ctx.project_id) reject('PROJECT_SCOPE_MISMATCH');
  if(value.scope&&(value.scope.task_id!==ctx.task_id||value.scope.operation_id!==ctx.operation?.id)) reject('TASK_OPERATION_SCOPE_MISMATCH');
  if(value.project_id&&value.project_id!==ctx.project_id) reject('PROJECT_SCOPE_MISMATCH');
  if(value.epochs&&Object.keys(value.epochs).some(k=>value.epochs[k]!==ctx.epochs?.[k])) reject('STALE_EPOCH');
  if(value.spec&&digest(value.spec)!==digest(ctx.spec)) reject('SPEC_REVISION_MISMATCH');
  if(value.expected_revision!==undefined&&value.expected_revision!==ctx.revision) reject('STALE_REVISION');
  if(value.created_at&&value.created_at>ctx.now) reject('FUTURE_RECORD');
  const unexpired=time=>{if(time<=ctx.now) reject('EXPIRED');};
  if(value.expires_at) unexpired(value.expires_at);
  const scopedArtifact=a=>{if(a.project_id!==ctx.project_id) reject('ARTIFACT_SCOPE_MISMATCH');};
  if(value.artifact) scopedArtifact(value.artifact);
  if(value.payload_ref) scopedArtifact(value.payload_ref);
  if(value.output) scopedArtifact(value.output);
  if(name==='spec-revision') {
    if(value.actor.role!=='OWNER') reject('SPEC_OWNER_REQUIRED');
    if(value.supersedes&&(value.supersedes.spec_id!==value.spec.spec_id||value.supersedes.revision>=value.spec.revision||value.supersedes.content_hash===value.spec.content_hash)) reject('INVALID_SUPERSESSION');
  }
  if(name==='event-envelope') {
    if(value.received_at<value.created_at||value.received_at>ctx.now||value.expires_at<=value.received_at) reject('EVENT_TIME_ORDER');
    const receipt=ctx.event_receipts?.[value.event_id];
    if(receipt?.receipt_hash!==value.producer_receipt_hash||receipt?.body_hash!==boundBody(value,'producer_receipt_hash')) reject('EVENT_PRODUCER_UNVERIFIED');
  }
  if(name==='state-transition') {
    if(value.actor.role!=='SUPERVISOR') reject('SUPERVISOR_REQUIRED');
    if(terminal.has(value.from_state)) reject('TERMINAL_IMMUTABLE');
    if(value.lease_epoch!==ctx.lease_epoch||value.fence!==ctx.fence) reject('STALE_FENCE');
    if(value.from_state!==ctx.state) reject('STATE_MISMATCH');
    if(ctx.cancel_requested&&!['CANCELLING','CANCELLED','RECONCILING'].includes(value.to_state)) reject('CANCEL_PENDING');
    const exceptional=['RECONCILING','WAITING_FOR_OWNER','WAITING_FOR_EVENT','BLOCKED','CANCELLING','FAILED'];
    let valid=(transitions[value.from_state]??[]).includes(value.to_state);
    if(!terminal.has(value.from_state)&&value.from_state!=='CANCELLING'&&exceptional.includes(value.to_state)&&value.to_state!==value.from_state) valid=true;
    if(['WAITING_FOR_OWNER','WAITING_FOR_EVENT','BLOCKED','RECONCILING'].includes(value.from_state))
      valid=valid||(value.resume_state===value.to_state&&value.resume_state===ctx.resume_state);
    if(!valid) reject('ILLEGAL_TRANSITION');
    if(value.to_state==='WAITING_FOR_OWNER'&&!value.owner_action_id) reject('OWNER_ACTION_REQUIRED');
    if(value.to_state==='WAITING_FOR_EVENT'&&!value.subscription_id) reject('SUBSCRIPTION_REQUIRED');
    const guards={RUNNING:['deps_complete','project_ready','quota'],PERSISTING:['local_qa','examiner_qa','auditor_qa','integration_qa'],COMPLETE:['persisted','independent_readback','checkpoint','outbox'],CANCELLED:['effects_reconciled']};
    const required=guards[value.to_state]??[];
    if(['WAITING_FOR_OWNER','WAITING_FOR_EVENT','BLOCKED','RECONCILING'].includes(value.from_state)) required.push('resume_verified');
    if(required.some(key=>!ctx.guards?.[key]||!value.guard_refs.includes(ctx.guards[key]))) reject('GUARD_EVIDENCE_MISSING');
  }
  if(name==='owner-action') {
    if(value.revoked_at&&value.status!=='REVOKED') reject('REVOKED_ACTION');
    if(value.status==='VERIFIED'&&(!value.verification_receipt||value.actor.role==='EXECUTOR')) reject('VERIFICATION_REQUIRED');
    if(value.status!=='VERIFIED'&&value.verification_receipt) reject('PREMATURE_VERIFICATION');
  }
  if(name==='approval') {
    actor(value.approver);
    if(value.approver.role!=='OWNER'||value.actor.identity_id!==value.approver.identity_id) reject('OWNER_APPROVER_REQUIRED');
    if(value.revoked_at||value.uses>=value.max_uses||value.policy_revision!==ctx.epochs.policy) reject('APPROVAL_UNUSABLE');
  }
  if(name==='tool-capability'&&value.effect_class==='NON_IDEMPOTENT'&&value.retry_eligible) reject('UNSAFE_RETRY');
  if(name==='tool-receipt') {
    if(!['EXECUTOR','STATE_SERVICE'].includes(value.actor.role)) reject('TOOL_RECEIPT_PRODUCER_INVALID');
    const op=ctx.operation;
    if(!op||value.scope.operation_id!==op.id||value.payload_hash!==op.payload_hash||value.tool_id!==op.tool_id||value.tool_digest!==op.tool_digest) reject('OPERATION_BINDING_MISMATCH');
    if(value.effect_class==='NON_IDEMPOTENT'&&value.retry_allowed) reject('UNSAFE_RETRY');
    if(value.outcome==='OUTCOME_UNKNOWN'&&(value.retry_allowed||value.output)) reject('UNKNOWN_EFFECT_REPLAY');
    if(value.outcome==='CONFIRMED'&&!value.external_receipt) reject('RECEIPT_REQUIRED');
    if(value.output&&value.output.bytes>value.full_output_bytes) reject('OUTPUT_LENGTH_MISMATCH');
    if(!value.truncated&&value.output&&value.output.bytes!==value.full_output_bytes) reject('OUTPUT_LENGTH_MISMATCH');
  }
  if(name==='provider-price') {
    const fields=['currency','input_micros_per_million','output_micros_per_million','quote_ref','checked_at','expires_at'];
    if(value.status==='UNKNOWN'&&(fields.some(k=>value[k]!==null)||!value.reason)) reject('UNKNOWN_PRICE_NOT_ZERO');
    if(value.status==='QUOTED'&&(fields.some(k=>value[k]===null)||value.reason!==null)) reject('INCOMPLETE_QUOTE');
    if(value.status==='QUOTED'&&(value.checked_at>ctx.now||value.expires_at<=value.checked_at)) reject('INVALID_QUOTE_TIME');
  }
  if(name==='attempt-receipt') {
    if(value.actor.role!=='ROUTE_BROKER') reject('BROKER_RECEIPT_REQUIRED');
    const priceResult=validate('provider-price',value.price,ctx);
    errors.push(...priceResult.errors);
    const op=ctx.operation;
    if(!op||value.scope.operation_id!==op.id||value.payload_hash!==op.payload_hash) reject('OPERATION_BINDING_MISMATCH');
    if(value.status!=='NOT_SENT'&&value.price.status==='UNKNOWN') reject('PRICE_UNKNOWN_DISPATCH_DENIED');
    if(value.status==='OUTCOME_UNKNOWN'&&(!value.uncertain||value.settled_micros!==null||BigInt(value.reservation_micros)===0n)) reject('UNCERTAIN_RESERVATION_REQUIRED');
    if(value.status==='RECEIVED'&&(value.uncertain||value.settled_micros===null||value.usage_tokens===null)) reject('SETTLEMENT_REQUIRED');
    if(value.status==='NOT_SENT'&&(value.uncertain||value.settled_micros!==null||value.usage_tokens!==null)) reject('NOT_SENT_NOT_SETTLED');
    if(value.settled_micros!==null&&BigInt(value.settled_micros)>BigInt(value.reservation_micros)) reject('RESERVATION_EXCEEDED');
  }
  if(name==='event-cursor') {
    actor(value.recipient,true);
    const trusted=ctx.principals[value.recipient.identity_id];
    if(trusted&&!trusted.projects.includes(value.project_id)) reject('CURSOR_SCOPE_DENIED');
    if(value.stream_id!==ctx.stream_id||value.last_sequence>ctx.last_sequence) reject('CURSOR_STREAM_MISMATCH');
  }
  if(name==='qa-evidence') {
    actor(value.runner);
    if(!['EXAMINER','AUDITOR'].includes(value.runner.role)||value.runner.identity_id!==value.actor.identity_id) reject('INDEPENDENT_RUNNER_REQUIRED');
    if(value.execution_status==='EXECUTED'&&(value.exit_code===null||value.verdict===null||!value.stdout_ref||!value.stderr_ref||!value.producer_attestation)) reject('RUN_EVIDENCE_REQUIRED');
    if(value.execution_status!=='EXECUTED'&&value.verdict==='PASS') reject('NOT_RUN_NOT_PASS');
    if(value.verdict==='PASS'&&value.exit_code!==0) reject('EXIT_NOT_PASS');
    if(value.execution_status!=='EXECUTED'&&!value.reason) reject('NOT_RUN_REASON_REQUIRED');
    if(value.artifact.aggregate_hash!==ctx.aggregate_hash||value.artifact.content_hash!==ctx.artifact_hash) reject('STALE_QA');
    if(!value.criterion_ids.every(c=>ctx.required_criteria?.includes(c))) reject('UNKNOWN_CRITERION');
    const attestation=ctx.attestations?.[value.run_id];
    if(value.execution_status==='EXECUTED'&&(value.producer_attestation!==attestation?.attestation||attestation?.body_hash!==boundBody(value,'producer_attestation'))) reject('UNTRUSTED_ATTESTATION');
    for(const a of [value.stdout_ref,value.stderr_ref]) if(a) scopedArtifact(a);
  }
  if(name==='run-grant') {
    if(value.actor.role!=='SUPERVISOR') reject('SUPERVISOR_REQUIRED');
    unexpired(value.deadline);
    if((value.parent_run_id===null)!==(value.depth===0)) reject('CHILD_DEPTH_MISMATCH');
    if(value.depth===1&&(value.max_children!==0||!ctx.parent_grant||value.capabilities.some(c=>!ctx.parent_grant.capabilities.includes(c))||value.max_physical_attempts>ctx.parent_grant.max_physical_attempts||value.deadline>ctx.parent_grant.deadline||value.budget_ref!==ctx.parent_grant.budget_ref)) reject('CHILD_GRANT_WIDENED');
  }
  if(name==='wait-subscription') {
    unexpired(value.deadline);
    errors.push(...validate('event-cursor',value.cursor,ctx).errors);
  }
  return {ok:errors.length===0,errors};
}
// Policy is deliberately non-executable. No valid DTO is an effect grant.
export function evaluateOfflinePolicy() {return {decision:'DENY',reason:'D01_OFFLINE_ONLY_POLICY_UNRATIFIED'};}
export function qaBindingMatches(evidence,{spec,aggregate_hash,artifact_hash}) {
  return digest(evidence.spec)===digest(spec)&&evidence.artifact.aggregate_hash===aggregate_hash&&evidence.artifact.content_hash===artifact_hash;
}
