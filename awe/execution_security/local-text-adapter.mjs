import {randomUUID} from 'node:crypto';
import {createScope,scopeInfo,writeScoped,readScoped} from '../executable_tools/scope.mjs';
import {verifyWritePins,validateLocalInput} from './local-reviewed.mjs';
import {digest,hashBytes,need,freeze} from './common.mjs';
import {intentBinding} from './authority.mjs';
const staged=new Map();
// Existing TOOLS02 CREATE_EXCLUSIVE implementation, called only AFTER the gate
// has committed real D09 admission and SENT. This module owns bytes, not rights.
export function executeReviewedText({request:r,current}){
 verifyWritePins();validateLocalInput(r.payload,{tool_id:'tool_fs_write'});current();
 const scope={project_id:r.project_id,task_id:r.task_id,operation_id:r.operation_id};
 const handle=createScope(scope);let mayHaveWritten=false;
 try{
  current();mayHaveWritten=true;const ack=writeScoped(handle,r.payload.path,r.payload.text);
  const bytes=readScoped(handle,r.payload.path);need(bytes.equals(Buffer.from(r.payload.text))&&ack.digest===hashBytes(bytes)&&ack.bytes===bytes.length,'LOCAL_TEXT_READBACK');current();
  const id='stage_'+randomUUID().replaceAll('-',''),output={path:r.payload.path,bytes:bytes.length,sha256:hashBytes(bytes)};
  staged.set(id,{handle,binding:intentBinding(r),output:structuredClone(output)});
  return freeze({profile:r.local.profile,output,output_hash:digest(output),payload_hash:r.payload_hash,attempt_id:r.attempt_id,staging_id:id,evidence:{adapter:'TOOLS02_SCOPED_FS',write_semantics:'CREATE_EXCLUSIVE',external_requests:0,readback_hash:hashBytes(bytes)},physical_decision:'DENY',authoritative_complete:false});
 }catch(e){if(mayHaveWritten)e.potentialEffect=true;throw e;}
}
// Host-only read projection. Never accepts a caller path. Retain the exact file
// until authoritative D07 persistence/reconciliation; no automatic retry/cleanup.
export function readReviewedText(request,execution,current){
 current();const s=staged.get(execution.staging_id);need(s&&s.binding===intentBinding(request)&&digest(s.output)===digest(execution.output),'LOCAL_TEXT_STAGE_UNKNOWN');
 const bytes=readScoped(s.handle,s.output.path);need(hashBytes(bytes)===s.output.sha256&&bytes.length===s.output.bytes,'LOCAL_TEXT_STAGE_CHANGED');current();return Buffer.from(bytes);
}
export function reviewedTextLocation(request,execution){const s=staged.get(execution.staging_id);need(s&&s.binding===intentBinding(request),'LOCAL_TEXT_STAGE_UNKNOWN');return scopeInfo(s.handle).root+'/'+s.output.path;}
