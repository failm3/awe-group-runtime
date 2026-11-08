import {openSync,closeSync,writeSync,fsyncSync,readFileSync,existsSync,unlinkSync,lstatSync,realpathSync,mkdirSync} from 'node:fs';
import {resolve,dirname,relative,isAbsolute,join} from 'node:path';
import {sourceRoot} from './profile.mjs';
import {digest,copy,freeze,need,parseIntent} from './protocol.mjs';
// E0 lifecycle projection ONLY. D09 remains the authority for execution attempts.
// One writer, fsync per record, hash chaining, fail closed on torn/corrupt data.
// No stale-lock guessing, process killing, truncation, or automatic replay.
export function openJournal(path) {
 const base=realpathSync(join(sourceRoot,'RT-01')),file=resolve(path),rel=relative(base,file);
 need(rel&&!rel.startsWith('..')&&!isAbsolute(rel),'JOURNAL_PATH_DENIED');
 let cursor=base;for(const part of rel.split(/[\\/]/)){cursor=join(cursor,part);if(existsSync(cursor))need(!lstatSync(cursor).isSymbolicLink(),'JOURNAL_LINK_DENIED');}
 mkdirSync(dirname(file),{recursive:true});const lock=file+'.lock';
 const lockFd=openSync(lock,'wx',0o600);let fd,closed=false,broken=false,rows=[];
 try {
  if(existsSync(file)) {
   const text=readFileSync(file,'utf8');need(text===''||text.endsWith('\n'),'JOURNAL_TORN');
   for(const line of text.split('\n').filter(Boolean)) {
    const r=parseIntent(line),{hash,...body}=r;
    need(Object.keys(r).sort().join(',')==='entry,hash,prev,seq'&&r.seq===rows.length+1&&r.prev===(rows.at(-1)?.hash??null)&&hash===digest(body),'JOURNAL_CORRUPT');rows.push(freeze(r));
   }
  }
  fd=openSync(file,'a',0o600);
 }catch(e){closeSync(lockFd);unlinkSync(lock);throw e;}
 return Object.freeze({
  read:()=>freeze(copy(rows)),
  append(entry) {
   need(!closed&&!broken,'JOURNAL_UNAVAILABLE');
   const body={seq:rows.length+1,prev:rows.at(-1)?.hash??null,entry:copy(entry)},row={...body,hash:digest(body)};
   const text=JSON.stringify(row);parseIntent(text);
   try{const bytes=Buffer.from(text+'\n');need(writeSync(fd,bytes)===bytes.length,'JOURNAL_SHORT_WRITE');fsyncSync(fd);rows.push(freeze(row));}
   catch(e){broken=true;throw e;}
   return row.hash;
  },
  close(){if(!closed){closed=true;closeSync(fd);closeSync(lockFd);unlinkSync(lock);}}
 });
}
