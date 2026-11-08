import {id} from '../../awe/memory/boundary.mjs';
import {copy,digest,exact,integer,hash,need,result,sync,DataError} from './common.mjs';

// Proposed trusted-host seam for AUTO-01 / INT04. No task/ledger writer,
// callback executor, resume, reserve, retry or approval method is accepted.
export function createCoordinatorPorts({memory,readerSession,writerSession,childSession,readBindings}){
  function bindings(){
    const b=sync(readBindings,'BINDINGS_UNAVAILABLE');
    exact(b,['schema','project_id','task_id','revision','spec_ref','required_refs','child_record_ids','purpose','context_bytes']);
    need(b.schema==='DATA02_BINDINGS_V1'&&b.project_id===memory.project_id,'SCOPE_DENIED');
    id(b.task_id,'task');integer(b.revision,1);hash(b.spec_ref);
    need(Array.isArray(b.required_refs)&&b.required_refs.length<=64&&new Set(b.required_refs).size===b.required_refs.length);b.required_refs.forEach(hash);
    need(Array.isArray(b.child_record_ids)&&b.child_record_ids.length<=32&&new Set(b.child_record_ids).size===b.child_record_ids.length);b.child_record_ids.forEach(x=>id(x,'mem'));
    need(typeof b.purpose==='string'&&b.purpose.length>0);integer(b.context_bytes,256,16384);return b;
  }
  function unwrap(r){if(!r.ok)throw new DataError(r.code);return r.value;}
  function finish(b){need(digest(bindings())===digest(b),'BINDINGS_CHANGED');}
  const restoreView=()=>result(()=>{
    const b=bindings(),recovery=unwrap(memory.recover(readerSession,JSON.stringify({refs:b.required_refs})));need(recovery.spec_ref===b.spec_ref,'BINDINGS_STALE');finish(b);
    return {schema:'DATA02_RECOVERY_VIEW_V1',project_id:b.project_id,task_id:b.task_id,spec_ref:b.spec_ref,binding_revision:b.revision,
      recovery,status:'HOLD_FOR_OWNER_RECONCILIATION',resume:false,physical_decision:'DENY'};
  });
  const persistCandidate=text=>result(()=>{const b=bindings();const receipt=unwrap(memory.persist(writerSession,text));need(receipt.spec_ref===b.spec_ref,'BINDINGS_STALE');finish(b);return receipt;});
  const child=Object.freeze({pack:()=>result(()=>{
    const b=bindings();const pack=unwrap(memory.workerPort(childSession,{record_ids:copy(b.child_record_ids),purpose:b.purpose,max_bytes:b.context_bytes}).pack());
    need(pack.spec_ref===b.spec_ref&&pack.records.every(r=>b.required_refs.includes(r.ref)),'BINDINGS_STALE');finish(b);return pack;
  })});
  return Object.freeze({host:Object.freeze({restoreView,persistCandidate}),child});
}
