import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
const root=path.resolve(import.meta.dirname,'../..');
// Existing D07 storage port: putIfAbsent(key,bytes) and read(key). No D07
// lifecycle, provenance, ACL or QA implementation is replaced by this adapter.
export function createFileStore(directory,storageId){
 const target=path.resolve(directory);if(!target.startsWith(root+path.sep))throw Error('D07_FILE_ROOT_DENIED');
 let cursor=root;for(const part of path.relative(root,target).split(path.sep)){cursor=path.join(cursor,part);if(fs.existsSync(cursor)&&fs.lstatSync(cursor).isSymbolicLink())throw Error('D07_FILE_LINK_DENIED');}
 fs.mkdirSync(target,{recursive:true});const real=fs.realpathSync(target);if(!real.startsWith(fs.realpathSync(root)+path.sep))throw Error('D07_FILE_ROOT_DENIED');
 const reads=[],writes=[],locations=new Map();
 const location=key=>{if(typeof key!=='string'||key.length>4096)throw Error('D07_FILE_KEY_INVALID');return path.join(real,createHash('sha256').update(key).digest('hex')+'.bin');};
 const port=Object.freeze({storage_id:storageId,
  putIfAbsent(key,bytes){const file=location(key);writes.push(key);locations.set(key,file);let fd;
   try{fd=fs.openSync(file,'wx',0o600);}catch(e){if(e.code!=='EEXIST')throw e;const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1)throw Error('D07_FILE_UNSAFE_EXISTING');return 'EXISTS';}
   try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}return 'CREATED';
  },
  read(key){const file=location(key);reads.push(key);if(!fs.existsSync(file))return {kind:'file',reparse:false,link_count:1,canonical_key:key,bytes:null};const s=fs.lstatSync(file);return {kind:s.isFile()?'file':'directory',reparse:s.isSymbolicLink(),link_count:s.nlink,canonical_key:key,bytes:s.isFile()&&!s.isSymbolicLink()&&s.nlink===1?fs.readFileSync(file):null};}
 });
 return {port,reads,writes,locations,keys:()=>[...locations.keys()].sort(),bytes:key=>fs.readFileSync(location(key)),corrupt(key,bytes){if(!locations.has(key))throw Error('D07_TEST_KEY_UNKNOWN');fs.writeFileSync(location(key),bytes);},directory:real};
}
