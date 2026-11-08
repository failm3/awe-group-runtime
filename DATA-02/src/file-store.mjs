import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {hashBytes,hash,need,DataError} from './common.mjs';
const workspace=path.resolve(import.meta.dirname,'..');

// Trusted host adapter. D07's putIfAbsent/read shape, confined to DATA-02.
// No catalogue, task state, ledger, authentication or automatic lock removal.
export function createFileStore(directory,storage_id,{max_objects=2048,max_bytes=16*1024*1024,fault=()=>{}}={}){
  const root=path.resolve(directory);
  need(root.startsWith(workspace+path.sep),'STORAGE_ROOT_DENIED');
  need(Number.isSafeInteger(max_objects)&&max_objects>0&&Number.isSafeInteger(max_bytes)&&max_bytes>0);
  function checkParents(target){
    let cursor=path.parse(target).root;
    for(const part of target.slice(cursor.length).split(path.sep).filter(Boolean)){
      cursor=path.join(cursor,part);
      if(fs.existsSync(cursor)){const s=fs.lstatSync(cursor);need(!s.isSymbolicLink(),'UNSAFE_STORAGE');}
    }
  }
  checkParents(root);fs.mkdirSync(root,{recursive:true});checkParents(root);
  const real=fs.realpathSync(root);
  const location=key=>{hash(key);return path.join(real,key.slice(7)+'.json');};
  function safe(file){
    checkParents(real);need(fs.realpathSync(root)===real,'UNSAFE_STORAGE');
    const s=fs.lstatSync(file);need(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1,'UNSAFE_STORAGE');return s;
  }
  function read(key){
    const file=location(key);checkParents(real);let b=null;
    try{const s=safe(file);need(s.size<=65536,'INTEGRITY_FAILURE');b=fs.readFileSync(file);}
    catch(e){if(e.code!=='ENOENT')throw e;}
    return {kind:'file',reparse:false,link_count:1,canonical_key:key,bytes:b};
  }
  function write(key,bytes){
    const file=location(key),b=Buffer.from(bytes);need(b.length<=65536&&hashBytes(b)===key,'INTEGRITY_FAILURE');
    checkParents(real);const lock=path.join(real,'.writer.lock');let fd;
    try{fd=fs.openSync(lock,'wx',0o600);}catch{throw new DataError('WRITER_HOLD');}
    let tmp=null;
    try{
      if(fs.existsSync(file)){const old=read(key).bytes;need(old?.equals(b),'INTEGRITY_FAILURE');return 'EXISTS';}
      const files=fs.readdirSync(real).filter(n=>/^[a-f0-9]{64}\.json$/.test(n));
      const total=files.reduce((n,f)=>n+safe(path.join(real,f)).size,0);
      need(files.length<max_objects&&total+b.length<=max_bytes,'STORAGE_CAPACITY');
      tmp=path.join(real,'.stage-'+randomUUID());const w=fs.openSync(tmp,'wx',0o600);
      try{fs.writeFileSync(w,b);fs.fsyncSync(w);}finally{fs.closeSync(w);}
      fault('after_stage');fs.renameSync(tmp,file);tmp=null;fault('after_publish');
      need(read(key).bytes?.equals(b),'READBACK_FAILED');return 'CREATED';
    }finally{if(tmp&&fs.existsSync(tmp))fs.unlinkSync(tmp);fs.closeSync(fd);fs.unlinkSync(lock);}
  }
  function remove(key){const file=location(key);try{safe(file);fs.unlinkSync(file);return true;}catch(e){if(e.code==='ENOENT')return false;throw e;}}
  return Object.freeze({storage_id,root_identity:hashBytes(Buffer.from(process.platform==='win32'?real.toLowerCase():real)),putIfAbsent:write,read,remove});
}
