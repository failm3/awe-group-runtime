import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {deflateSync} from 'node:zlib';
import {gitOid,PATHS} from '../../qa-coding/tree-proof.mjs';
import {inspectCommittedTrees} from '../../qa-coding/git-readback.mjs';

test('cold reader reconstructs loose objects and refs, catches changed worktree bytes/main/parent',t=>{
  const root=mkdtempSync(join(tmpdir(),'qa-g1-objects-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  const repository_root=join(root,'base'),worktree_root=join(root,'candidate'),git=join(repository_root,'.git');
  mkdirSync(worktree_root,{recursive:true});
  function write(name,bytes){mkdirSync(dirname(name),{recursive:true});writeFileSync(name,bytes);}
  function object(type,bytes){
    const data=Buffer.from(bytes),oid=gitOid(type,data);
    write(join(git,'objects',oid.slice(0,2),oid.slice(2)),deflateSync(Buffer.concat([Buffer.from(type+' '+data.length+'\0'),data])));
    return oid;
  }
  function revision(label,parent){
    const entries=PATHS.map(path=>{
      const bytes=Buffer.from('# inert '+label+' '+path+'\n');
      if(label==='candidate')write(join(worktree_root,path),bytes);
      const blob=object('blob',bytes);
      return Buffer.concat([Buffer.from('100644 '+path+'\0'),Buffer.from(blob,'hex')]);
    });
    const tree=object('tree',Buffer.concat(entries));
    return object('commit','tree '+tree+'\n'+(parent?'parent '+parent+'\n':'')+'\nSynthetic fixture\n');
  }
  const branch='codex/g1_test',base_sha=revision('base'),head_sha=revision('candidate',base_sha);
  const baseRef=join(git,'refs','heads','main'),finalRef=join(git,'refs','heads',branch);
  write(baseRef,base_sha+'\n'); write(finalRef,head_sha+'\n');
  const args={repository_root,worktree_root,branch,base_sha,head_sha};
  assert.equal(inspectCommittedTrees(args).final.files.length,2);
  write(baseRef,head_sha+'\n');
  assert.throws(()=>inspectCommittedTrees(args));write(baseRef,base_sha+'\n');
  const wrongParent=revision('other','f'.repeat(40));
  write(finalRef,wrongParent+'\n');assert.throws(()=>inspectCommittedTrees({...args,head_sha:wrongParent}));write(finalRef,head_sha+'\n');
  write(join(worktree_root,'cli.py'),'# mutated after commit');
  assert.throws(()=>inspectCommittedTrees(args));
});
