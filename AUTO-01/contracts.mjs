import {digest,canonicalize} from '../contracts/canonical.mjs';
import {validateDag} from '../awe/project_factory/factory.mjs';
import {readFileSync} from 'node:fs';
const draftSchema=JSON.parse(readFileSync(new URL('./draft.schema.json',import.meta.url)));

// Strict local JSON Schema subset used by the draft contract; no remote $refs.
function schemaCheck(s,v){
 if(s.oneOf){need(s.oneOf.filter(branch=>{try{schemaCheck(branch,v);return true;}catch{return false;}}).length===1,'AUTO01_DRAFT_SCHEMA');return;}
 const matches=s.type==='object'?v&&Object.getPrototypeOf(v)===Object.prototype:s.type==='array'?Array.isArray(v):s.type==='integer'?Number.isSafeInteger(v):typeof v===s.type;
 need(matches,'AUTO01_DRAFT_SCHEMA');
 if(s.enum)need(s.enum.includes(v),'AUTO01_DRAFT_SCHEMA');
 if(s.type==='object'){need(s.required.every(k=>Object.hasOwn(v,k))&&Object.keys(v).every(k=>Object.hasOwn(s.properties,k)),'AUTO01_DRAFT_SCHEMA');for(const [k,child] of Object.entries(s.properties))schemaCheck(child,v[k]);}
 if(s.type==='array'){need(v.length>=(s.minItems??0)&&v.length<=(s.maxItems??Infinity),'AUTO01_DRAFT_SCHEMA');v.forEach(x=>schemaCheck(s.items,x));}
 if(s.type==='string')need(v.length>=(s.minLength??0)&&v.length<=(s.maxLength??Infinity)&&(!s.pattern||new RegExp(s.pattern).test(v)),'AUTO01_DRAFT_SCHEMA');
}

export const VERSION='auto01/1';
export function need(ok,code){if(!ok)throw Object.assign(new Error(code),{code});}
export function exact(value,keys,code='AUTO01_SHAPE'){
 need(value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k)),code);
 canonicalize(value);return value;
}
export function text(value,max=2048){need(typeof value==='string'&&value.trim().length>0&&value.length<=max,'AUTO01_TEXT');return value;}
export function list(value,max=32){need(Array.isArray(value)&&value.length<=max,'AUTO01_LIST');return value;}
export function unique(value){need(new Set(value).size===value.length,'AUTO01_DUPLICATE');return value;}
export function identifier(value){need(typeof value==='string'&&/^[a-z][a-z0-9_]{0,39}$/.test(value),'AUTO01_ID');return value;}

export function validateDraft(draft,history){
 canonicalize(draft);schemaCheck(draftSchema,draft);
 exact(draft,['goal','requirements','constraints','resources','completion_criteria','assumptions','questions','contradictions']);text(draft.goal,4096);
 need(list(draft.requirements).length>0,'AUTO01_REQUIREMENTS');
 const sources=new Set(history.filter(m=>m.kind==='user').map(m=>m.id));
 function source(r){need(['USER','PROJECT','INFERRED','UNKNOWN'].includes(r.origin),'AUTO01_ORIGIN');need(unique(list(r.source_ids,16)).length>0&&r.source_ids.every(id=>sources.has(id)||(r.origin==='PROJECT'&&id==='policy_e0')),'AUTO01_PROVENANCE');}
 for(const r of draft.requirements){identifier(r.id);text(r.text);need(list(r.acceptance,8).length>0,'AUTO01_ACCEPTANCE');r.acceptance.forEach(x=>text(x));source(r);}
 const requirementIds=new Set(unique(draft.requirements.map(r=>r.id))),covered=new Set();
 for(const group of [draft.constraints,draft.resources,draft.completion_criteria]){unique(group.map(r=>r.id));group.forEach(source);}
 for(const c of draft.completion_criteria){need(c.requirement_ids.every(id=>requirementIds.has(id)),'AUTO01_CRITERION_REQUIREMENT');c.requirement_ids.forEach(id=>covered.add(id));}
 need(covered.size===requirementIds.size,'AUTO01_CRITERIA_COVERAGE');
 for(const c of draft.contradictions)need(c.source_ids.every(id=>sources.has(id)),'AUTO01_PROVENANCE');
 for(const a of list(draft.assumptions,16)){exact(a,['text','material']);text(a.text);need(typeof a.material==='boolean','AUTO01_ASSUMPTION');}
 for(const q of list(draft.questions,8)){exact(q,['id','text','reason']);identifier(q.id);text(q.text);need(['MISSING_DATA','CONFLICT','RISK'].includes(q.reason),'AUTO01_QUESTION');}
 unique(draft.questions.map(q=>q.id));
 return structuredClone(draft);
}

export function validatePlan(plan,spec){
 exact(plan,['nodes']);need(list(plan.nodes).length>0,'AUTO01_EMPTY_PLAN');
 const requirements=new Set(spec.requirements.map(r=>r.id)),covered=new Set(),tasks={};
 for(const n of plan.nodes){
  exact(n,['id','title','capability','instructions','requirement_ids','depends_on','deliverable']);identifier(n.id);text(n.title,128);text(n.capability,128);text(n.instructions,4096);text(n.deliverable,128);
  need(unique(list(n.requirement_ids)).length>0&&n.requirement_ids.every(id=>requirements.has(id)),'AUTO01_PLAN_REQUIREMENT');n.requirement_ids.forEach(id=>covered.add(id));
  unique(list(n.depends_on));n.depends_on.forEach(identifier);need(!Object.hasOwn(tasks,n.id),'AUTO01_DUPLICATE');tasks[n.id]={dependencies:n.depends_on};
 }
 need(covered.size===requirements.size,'AUTO01_PLAN_COVERAGE');validateDag(tasks);
 return structuredClone(plan);
}

export function validateResult(result,handoff){
 exact(result,['version','handoff_hash','status','summary','outputs','uncertainties']);
 need(Buffer.byteLength(canonicalize(result))<=handoff.limits.max_output_bytes,'AUTO01_RESULT_SIZE');
 need(result.version===VERSION&&result.handoff_hash===digest(handoff),'AUTO01_RESULT_BINDING');
 need(['SUCCEEDED','FAILED','NEEDS_INPUT','OUTCOME_UNKNOWN'].includes(result.status),'AUTO01_RESULT_STATUS');text(result.summary,1024);
 for(const o of list(result.outputs,8)){exact(o,['name','media_type','text']);text(o.name,128);text(o.media_type,128);text(o.text,8192);}
 for(const u of list(result.uncertainties,8)){exact(u,['text','material']);text(u.text);need(typeof u.material==='boolean','AUTO01_UNCERTAINTY');}
 if(result.status==='SUCCEEDED')need(result.outputs.length>0,'AUTO01_EMPTY_RESULT');
 return structuredClone(result);
}

export function readyNodes(plan,tasks){
 return plan.nodes.filter(n=>tasks[n.id]?.state==='DRAFT'&&n.depends_on.every(id=>tasks[id]?.state==='COMPLETE'&&!tasks[id].acceptance_stale));
}

export function validateDecision(decision){
 need(['EXECUTE','REPLAN','ASK_USER'].includes(decision?.action),'AUTO01_HEAD_ACTION');
 if(decision.action==='EXECUTE'){exact(decision,['action','node_id','executor_id']);identifier(decision.node_id);text(decision.executor_id,128);}
 if(decision.action==='REPLAN'){exact(decision,['action','reason']);text(decision.reason);}
 if(decision.action==='ASK_USER'){exact(decision,['action','question','reason']);text(decision.question);need(['MISSING_DATA','CONFLICT','RISK'].includes(decision.reason),'AUTO01_QUESTION');}
 return structuredClone(decision);
}

export function topological(plan){
 const ordered=[],pending=new Map(plan.nodes.map(n=>[n.id,n]));
 while(pending.size){const batch=[...pending.values()].filter(n=>n.depends_on.every(id=>ordered.some(x=>x.id===id)));need(batch.length,'AUTO01_CYCLE');for(const n of batch){ordered.push(n);pending.delete(n.id);}}
 return ordered;
}
