import {openSync,closeSync,writeFileSync,fsyncSync,renameSync,readFileSync,existsSync,lstatSync,realpathSync,mkdirSync} from 'node:fs';
import {resolve,relative,join,isAbsolute,dirname} from 'node:path';
import {sourceRoot} from './profile.mjs';
import {digest,need,parseIntent,freeze,exact} from './protocol.mjs';
function owned(file){
 const base=realpathSync(join(sourceRoot,'RT-01')),target=resolve(file),rel=relative(base,target);
 need(rel&&!rel.startsWith('..')&&!isAbsolute(rel),'RT_CHECKPOINT_PATH');
 let cursor=base;for(const part of rel.split(/[\\/]/)){cursor=join(cursor,part);if(existsSync(cursor))need(!lstatSync(cursor).isSymbolicLink(),'RT_CHECKPOINT_LINK');}
 return target;
}
// Dependent process metadata, never task/attempt/authority state or a resume permit.
export function writeProcessCheckpoint(file,data){
 const target=owned(file);mkdirSync(dirname(target),{recursive:true});const tmp=target+'.tmp';
 const body={contract:'int04.rt01.process.checkpoint/1',data,physical_decision:'DENY',resumable:false};
 const text=JSON.stringify({...body,hash:digest(body)})+'\n';parseIntent(text);const fd=openSync(tmp,'wx',0o600);
 try{writeFileSync(fd,text);fsyncSync(fd);}finally{closeSync(fd);}renameSync(tmp,target);return readProcessCheckpoint(target);
}
export function readProcessCheckpoint(file){
 const value=parseIntent(readFileSync(owned(file),'utf8'));exact(value,['contract','data','physical_decision','resumable','hash']);
 const {hash,...body}=value;need(value.contract==='int04.rt01.process.checkpoint/1'&&body.physical_decision==='DENY'&&body.resumable===false&&digest(body)===hash,'RT_CHECKPOINT_CORRUPT');
 exact(body.data,['runtime','process']);need(body.data.runtime.run_id===body.data.process.run_id&&body.data.process.contract==='rt01.process/1','RT_CHECKPOINT_BINDING');
 const runtime=body.data.runtime;exact(runtime,['run_id','request_hash','cursor','hash','resumable','physical_decision']);
 need(runtime.resumable===false&&runtime.physical_decision==='DENY'&&runtime.request_hash===body.data.process.request_hash
  &&runtime.hash===digest({run_id:runtime.run_id,request_hash:runtime.request_hash,cursor:runtime.cursor}),'RT_CHECKPOINT_BINDING');
 return freeze({...value,startup:'HOLD',recovery:'RECONCILE_REQUIRED',accepted:false});
}
