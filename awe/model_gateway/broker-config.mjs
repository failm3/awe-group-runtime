import {copy} from './profiles.mjs';
import {requireThat as need,integer,money} from '../budget/money.mjs';
export function exact(value,keys,code='FIELDS_INVALID') {
  need(value && Object.getPrototypeOf(value)===Object.prototype && Object.keys(value).sort().join()===keys.slice().sort().join(),code);
}
export function brokerId(x) {need(typeof x==='string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(x) && !['constructor','prototype','__proto__'].includes(x),'ID_INVALID');return x;}
const strings=(v)=>need(Array.isArray(v)&&v.length>0&&v.every(x=>typeof x==='string'&&x.length>0)&&new Set(v).size===v.length,'ALLOWLIST_INVALID');
export function validateBrokerConfig(raw) {
  const c=copy(raw);exact(c,['version','mode','physicalDecision','policies']);
  need(c.version==='LLM01_BROKER_CONFIG_V1'&&c.mode==='MOCK_ONLY'&&c.physicalDecision==='DENY','LIVE_CONFIGURATION_DISABLED');
  need(Array.isArray(c.policies)&&c.policies.length>0&&new Set(c.policies.map(x=>x.taskClass)).size===c.policies.length,'POLICIES_INVALID');
  for(const p of c.policies) {
    exact(p,['taskClass','routeIds','agentRoles','maxInputTokens','maxOutputTokens','maxToolCalls','maxAttempts','maxReserveMicros','timeoutMs','allowFallback','qualityFloorBps','allowedRegions','allowedPrivacy']);
    brokerId(p.taskClass);strings(p.routeIds);p.routeIds.forEach(brokerId);strings(p.agentRoles);need(p.agentRoles.every(x=>['MAIN','CHILD'].includes(x)),'AGENT_ROLE_INVALID');
    for(const k of ['maxInputTokens','maxOutputTokens','maxToolCalls','maxAttempts','timeoutMs','qualityFloorBps'])integer(p[k]);
    need(p.maxInputTokens>0&&p.maxOutputTokens>0&&p.maxAttempts>0&&p.maxAttempts<=2&&p.timeoutMs>0&&p.timeoutMs<=1000&&p.qualityFloorBps<=10000,'POLICY_LIMIT_INVALID');
    money(p.maxReserveMicros);need(money(p.maxReserveMicros)>0n&&typeof p.allowFallback==='boolean','POLICY_LIMIT_INVALID');
    strings(p.allowedRegions);strings(p.allowedPrivacy);
  }
  return c;
}
export function validateTaskBinding(raw,ledger) {
  const b=copy(raw);exact(b,['id','scopeId','projectId','taskId','runId','parentRunId','agentId','agentRole','context']);
  for(const k of ['id','scopeId','projectId','taskId','runId','agentId'])brokerId(b[k]);
  need(['MAIN','CHILD'].includes(b.agentRole),'AGENT_ROLE_INVALID');
  if(b.agentRole==='MAIN')need(b.parentRunId===null,'MAIN_PARENT_INVALID');else {brokerId(b.parentRunId);need(b.parentRunId!==b.runId,'CHILD_PARENT_INVALID');}
  const s=ledger.scope(b.scopeId);need(s.projectId===b.projectId&&s.taskId===b.taskId,'TASK_SCOPE_MISMATCH');
  exact(b.context,['project_id','task_id','revision','readonly','artifact_ref','snapshot','hash']);
  integer(b.context.revision);need(b.context.revision>0&&b.context.project_id===b.projectId&&b.context.task_id===b.taskId&&b.context.readonly===true,'CONTEXT_SCOPE_INVALID');
  need(typeof b.context.snapshot==='string'&&Buffer.byteLength(b.context.snapshot)<=16000&&/^sha256:[a-f0-9]{64}$/.test(b.context.artifact_ref),'CONTEXT_INVALID');
  return b;
}
