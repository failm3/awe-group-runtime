import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {ensure,text,bytesDigest,freeze,scopeShape,copy,fileName} from './protocol.mjs';
const base=fileURLToPath(new URL('../../TOOLS-02/sandbox/',import.meta.url));
const handles=new WeakMap();
const MAX_FILES=32,MAX_TOTAL=65536;
const clean=fileName;
function state(handle){const s=handles.get(handle);ensure(s&&!s.closed,'TOOLS_SCOPE_CLOSED');
 const st=fs.lstatSync(s.root);ensure(st.isDirectory()&&!st.isSymbolicLink()&&st.dev===s.dev&&st.ino===s.ino,'TOOLS_SCOPE_REPLACED');
 ensure(fs.realpathSync(s.root)===s.root,'TOOLS_SCOPE_REPLACED');return s;
}
function inspect(s,file){const p=path.join(s.root,clean(file));if(fs.existsSync(p)){
 const st=fs.lstatSync(p);ensure(st.isFile()&&!st.isSymbolicLink()&&st.nlink===1&&st.size<=16384,'TOOLS_FILE_TYPE');
 }return p;}
export function createScope(scope){
 scopeShape(scope);fs.mkdirSync(base,{recursive:true});ensure(!fs.lstatSync(base).isSymbolicLink()&&fs.realpathSync(base)===path.resolve(base),'TOOLS_SCOPE_BASE');
 const root=fs.realpathSync(fs.mkdtempSync(path.join(base,'tools02-'))),st=fs.lstatSync(root),handle=Object.freeze({});
 handles.set(handle,{root,scope:freeze(copy(scope)),dev:st.dev,ino:st.ino,closed:false});return handle;
}
export function scopeInfo(handle){const s=state(handle);return {root:s.root,scope:s.scope};}
export function readScoped(handle,file){const s=state(handle),p=inspect(s,file);
 const fd=fs.openSync(p,fs.constants.O_RDONLY| (fs.constants.O_NOFOLLOW??0));try{
 const st=fs.fstatSync(fd);ensure(st.isFile()&&st.nlink===1&&st.size<=16384,'TOOLS_FILE_TYPE');
 const data=fs.readFileSync(fd);ensure(data.length<=16384,'TOOLS_FILE_SIZE');return data;
 }finally{fs.closeSync(fd);}}
export function writeScoped(handle,file,value){
 text(value,16384);const s=state(handle),p=inspect(s,file),names=fs.readdirSync(s.root);
 ensure(names.includes(file)||names.length<MAX_FILES,'TOOLS_FILE_QUOTA');
 const total=names.reduce((n,f)=>{const st=fs.lstatSync(inspect(s,f));return n+st.size;},0);
 const old=fs.existsSync(p)?fs.statSync(p).size:0;ensure(total-old+Buffer.byteLength(value)<=MAX_TOTAL,'TOOLS_BYTE_QUOTA');
 // Refuse overwrite: a caller must use a new name. No truncate/race with existing links.
 const fd=fs.openSync(p,'wx',0o600);try{fs.writeFileSync(fd,value);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 return {bytes:Buffer.byteLength(value),digest:bytesDigest(Buffer.from(value))};
}
export function listScoped(handle){const s=state(handle);return fs.readdirSync(s.root).sort().map(f=>({name:clean(f),bytes:fs.lstatSync(inspect(s,f)).size}));}
export function closeScope(handle){const s=handles.get(handle);if(!s||s.closed)return;
 state(handle);const target=path.resolve(s.root);ensure(path.dirname(target)===path.resolve(base)&&path.basename(target).startsWith('tools02-'),'TOOLS_CLEANUP_PATH');
 // All recursive cleanup targets are verified absolute direct children of the fixed base.
 fs.rmSync(target,{recursive:true,force:false});s.closed=true;
}
