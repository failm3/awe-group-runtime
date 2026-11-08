import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fixture} from './fixtures.mjs';
import {digest} from '../../awe/executable_tools/protocol.mjs';
const using=async(options,fn)=>{const f=fixture(options);try{await fn(f);}finally{await f.tools.close();}};
test('operation replay belongs to the existing-owner port and never executes twice',()=>using({},async f=>{
 const q=f.request('fs.write',{path:'once.txt',text:'synthetic'});assert.equal((await f.tools.execute(JSON.stringify(q))).decision,'EXECUTED_LOCAL');
 assert.equal((await f.tools.execute(JSON.stringify(q))).decision,'DENY');assert.equal(f.calls.length,1);
}));
test('host denial never calls the adapter',()=>using({admission:{current:()=>true,execute:async()=>{throw Error('TOOLS_DENIED');}}},async f=>{
 assert.equal((await f.execute('fs.write',{path:'no.txt',text:'x'})).decision,'DENY');assert(!fs.existsSync(path.join(f.tools.inspect().scope.root,'no.txt')));
}));
test('an acknowledgement without invoking admitted work is not execution',()=>using({admission:{current:()=>true,execute:async b=>({status:'COMMITTED',request_digest:digest(b)})}},async f=>{assert.equal((await f.execute('fs.list')).decision,'DENY');}));
test('revocation after await is checked at the immediate effect barrier',()=>{
 let current=true;return using({admission:{current:()=>current,execute:async(b,effect)=>{await Promise.resolve();current=false;await effect();return {status:'COMMITTED',request_digest:digest(b)};}}},async f=>{
  assert.equal((await f.execute('fs.write',{path:'revoked.txt',text:'x'})).decision,'DENY');assert(!fs.existsSync(path.join(f.tools.inspect().scope.root,'revoked.txt')));
 });
});
test('asynchronous current check is never treated as truthy authorization',()=>using({admission:{current:async()=>true,execute:async(b,effect)=>{await effect();return {status:'COMMITTED',request_digest:digest(b)};}}},async f=>{assert.equal((await f.execute('fs.list')).code,'TOOLS_CURRENT_ASYNC');}));
test('a retained admission callback cannot execute after host port returns',async()=>{
 let retained;await using({admission:{current:()=>true,execute:async(b,effect)=>{retained=effect;return {status:'COMMITTED',request_digest:digest(b)};}}},async f=>{
  assert.equal((await f.execute('fs.write',{path:'late.txt',text:'x'})).decision,'DENY');await assert.rejects(()=>retained(),/TOOLS_EFFECT_REPLAY/);assert(!fs.existsSync(path.join(f.tools.inspect().scope.root,'late.txt')));
 });
});
test('double callback is blocked; ambiguous completion stays unknown',()=>using({admission:{current:()=>true,execute:async(b,effect)=>{await effect();await effect();return {status:'COMMITTED',request_digest:digest(b)};}}},async f=>{
 const r=await f.execute('fs.write',{path:'double.txt',text:'x'});assert.equal(r.decision,'OUTCOME_UNKNOWN');assert.equal(r.retry_allowed,false);
 assert.equal(fs.readFileSync(path.join(f.tools.inspect().scope.root,'double.txt'),'utf8'),'x');
}));
test('commit failure after effect discards output and never implies safe retry',()=>using({admission:{current:()=>true,execute:async(b,effect)=>{await effect();throw Error('database secret not for output');}}},async f=>{
 const r=await f.execute('fs.write',{path:'unknown.txt',text:'fixture'});assert.equal(r.decision,'OUTCOME_UNKNOWN');assert.equal(r.output,null);assert.equal(r.code,'TOOLS_HOST_FAILURE');assert.equal(r.retry_allowed,false);
}));
test('wrong completion digest cannot certify a performed effect',()=>using({admission:{current:()=>true,execute:async(b,effect)=>{await effect();return {status:'COMMITTED',request_digest:digest('wrong')};}}},async f=>{assert.equal((await f.execute('fs.list')).decision,'OUTCOME_UNKNOWN');}));
test('early acknowledgement cancels and joins an unawaited child without publishing output',()=>using({admission:{current:()=>true,execute:async(b,effect)=>{effect();return {status:'COMMITTED',request_digest:digest(b)};}}},async f=>{const r=await f.execute('js.text.stats',{text:'fixture'});assert.equal(r.decision,'OUTCOME_UNKNOWN');assert.equal(r.output,null);}));
test('post-effect revocation discards successful work output',()=>{
 let active=true;return using({admission:{current:()=>active,execute:async(b,effect)=>{await effect();active=false;return {status:'COMMITTED',request_digest:digest(b)};}}},async f=>{const r=await f.execute('fs.list');assert.equal(r.decision,'OUTCOME_UNKNOWN');assert.equal(r.output,null);});
});
test('port timeout closes the retained callback with no effect and no automatic retry',async()=>{
 let effect;await using({admission:{current:()=>true,execute:async(b,e)=>{effect=e;return new Promise(()=>{});}}},async f=>{
  const r=await f.execute('fs.list');assert.equal(r.decision,'DENY');assert.equal(r.code,'TOOLS_PORT_TIMEOUT');await assert.rejects(()=>effect(),/TOOLS_EFFECT_REPLAY/);
 });
});
test('quarantined pin fails the barrier even after it passed initial validation',async()=>{
 let f;f=fixture({admission:{current:()=>true,execute:async(b,effect)=>{f.tools.quarantine(b.pin.id);await effect();return {status:'COMMITTED',request_digest:digest(b)};}}});
 try{assert.equal((await f.execute('fs.list')).decision,'DENY');assert.equal(f.tools.check([{id:'tool_fs_list',digest:digest('wrong')}]),false);}finally{await f.tools.close();}
});
