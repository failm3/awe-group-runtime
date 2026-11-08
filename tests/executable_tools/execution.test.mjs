import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fixture,scope} from './fixtures.mjs';
import {digest,parse,fileName} from '../../awe/executable_tools/protocol.mjs';
import {createScope,scopeInfo,writeScoped,readScoped,listScoped,closeScope} from '../../awe/executable_tools/scope.mjs';
import {createExecutableTools} from '../../awe/executable_tools/host.mjs';
import {loadPins,verifyPins} from '../../awe/executable_tools/pins.mjs';
import {runProgram,inspectProcesses} from '../../awe/executable_tools/process.mjs';
import {expectedStats} from '../../awe/executable_tools/verification.mjs';
const withFixture=async fn=>{const f=fixture();try{await fn(f);}finally{await f.tools.close();}};
test('scoped write/read/list execute actual bytes, with no task acceptance',()=>withFixture(async f=>{
 const data='Synthetic 🧪\n';const w=await f.execute('fs.write',{path:'fixture.txt',text:data});assert.equal(w.decision,'EXECUTED_LOCAL');
 const r=await f.execute('fs.read',{path:'fixture.txt'});assert.equal(r.output.text,data);assert.equal(r.output.bytes,Buffer.byteLength(data));assert.equal(r.authoritative_complete,false);assert.equal(r.retry_allowed,false);
 assert.deepEqual((await f.execute('fs.list')).output.files,[{name:'fixture.txt',bytes:Buffer.byteLength(data)}]);
 assert.equal((await f.execute('fs.write',{path:'fixture.txt',text:'replacement'})).decision,'OUTCOME_UNKNOWN');assert.equal((await f.execute('fs.read',{path:'fixture.txt'})).output.text,data);
}));
for(const cap of ['js.text.stats','python.text.stats'])test(cap+' runs a real pinned child and Unicode readback',()=>withFixture(async f=>{
 const text='Hello Привет 🧪\n';const r=await f.execute(cap,{text});assert.equal(r.decision,'EXECUTED_LOCAL');assert.deepEqual(r.output,expectedStats(text));assert.equal(inspectProcesses().active,0);
}));
for(const cap of ['cli.node_version','cli.git_version'])test(cap+' executes a fixed local CLI without caller arguments',()=>withFixture(async f=>{const r=await f.execute(cap);assert.equal(r.decision,'EXECUTED_LOCAL');assert.match(r.output.version,cap.includes('node')?/^v24\.21\.0$/:/^git version /);}));
for(const [cap,input] of [['browser.snapshot',{fixture_id:'welcome',credential:'TEST_BROWSER_ONLY'}],['api.get',{fixture_id:'inventory',credential:'TEST_API_ONLY'}]])test(cap+' is fixture-only with zero external requests',()=>withFixture(async f=>{const r=await f.execute(cap,input);assert.equal(r.decision,'EXECUTED_LOCAL');assert.equal(r.output.network_requests,0);assert.equal(r.external_requests,0);assert(!JSON.stringify(r.output).includes(input.credential));}));
for(const bad of ['../outside','/etc/passwd','C:\\Windows\\win.ini','file.txt:secret','\\\\server\\share','a/b','a\\b','NUL','COM1.txt','name.','x..y','x\n',''])test('filesystem rejects path '+JSON.stringify(bad)+' before admission',()=>withFixture(async f=>{const r=await f.execute('fs.read',{path:bad});assert.equal(r.decision,'DENY');assert.equal(f.calls.length,0);}));
for(const [cap,input] of [['cli.git_version',{args:['status']}],['cli.node_version',{command:'echo secret'}],['js.text.stats',{text:'x',source:'process.exit()'}],['python.text.stats',{code:'import os'}],['browser.snapshot',{url:'https://example.org',credential:'TEST_BROWSER_ONLY'}],['api.get',{fixture_id:'inventory',credential:'REAL_TOKEN'}],['api.get',{fixture_id:'inventory',credential:'TEST_API_ONLY',headers:{}}]])test('input injection denied '+cap+' '+JSON.stringify(input),()=>withFixture(async f=>{assert.equal((await f.execute(cap,input)).decision,'DENY');assert.equal(f.calls.length,0);}));
for(const [name,patch] of [['foreign project',{scope:{...scope,project_id:'prj_other',operation_id:'op_x'}}],['control operation',{scope}],['foreign actor',{actor_id:'act_other'}],['foreign run',{run_id:'run_other'}],['unbound pin',{pin:{id:'tool_fs_read',digest:digest('wrong')}}],['input substitution',{input_hash:digest('wrong')}],['worker permission',{approved:true}],['foreign version',{contract:'tools02/2'}]])test('execution denies '+name,()=>withFixture(async f=>{assert.equal((await f.execute('fs.list',{},patch)).decision,'DENY');}));
test('duplicate JSON keys, poison keys, huge payloads and lone surrogates fail closed',()=>withFixture(async f=>{
 const q=JSON.stringify(f.request('fs.list'));assert.equal((await f.tools.execute(q.replace('"contract":','"contract":"tools02/1","contract":'))).decision,'DENY');
 for(const text of ['{"__proto__":{}}','{bad',' '.repeat(17000),JSON.stringify(f.request('js.text.stats',{text:'\uD800'}))])assert.equal((await f.tools.execute(text)).decision,'DENY');
 assert.equal((await f.execute('js.text.stats',{text:'я'.repeat(2049)})).decision,'DENY');
}));
test('symlink/junction and hardlink entries never become scoped file access',t=>withFixture(async f=>{
 const root=f.tools.inspect().scope.root,other=createScope({...scope,operation_id:'op_other'}),otherRoot=scopeInfo(other).root;
 try{writeScoped(other,'private.txt','synthetic private');try{fs.linkSync(path.join(otherRoot,'private.txt'),path.join(root,'hard.txt'));}catch(e){if(e.code==='EPERM'){t.skip('HOST_SANDBOX_LINK_CREATION_DENIED');return;}throw e;}
  assert.equal((await f.execute('fs.read',{path:'hard.txt'})).decision,'OUTCOME_UNKNOWN');
  fs.symlinkSync(otherRoot,path.join(root,'junction'),'junction');assert.equal((await f.execute('fs.list')).decision,'OUTCOME_UNKNOWN');
  assert.equal(fs.readFileSync(path.join(otherRoot,'private.txt'),'utf8'),'synthetic private');
 }finally{if(fs.existsSync(path.join(root,'hard.txt')))fs.unlinkSync(path.join(root,'hard.txt'));if(fs.existsSync(path.join(root,'junction')))fs.rmdirSync(path.join(root,'junction'));closeScope(other);}
}));
test('file count/byte quotas and forged scope handle are rejected',()=>{
 const s=createScope(scope);try{for(let i=0;i<32;i++)writeScoped(s,'f'+i,'x');assert.throws(()=>writeScoped(s,'over','x'),/TOOLS_FILE_QUOTA/);assert.throws(()=>readScoped({},'f1'),/TOOLS_SCOPE_CLOSED/);}finally{closeScope(s);}
 const b=createScope(scope);try{for(let i=0;i<4;i++)writeScoped(b,'f'+i,'x'.repeat(16384));assert.throws(()=>writeScoped(b,'over','x'),/TOOLS_BYTE_QUOTA/);}finally{closeScope(b);}
});
test('timeout and output overflow stop owned child and keep outcome unknown',async()=>{
 for(const limits of [{timeout_ms:1,max_output_bytes:8192},{timeout_ms:1500,max_output_bytes:16}]){const f=fixture({limits});try{
  const r=await f.execute('js.text.stats',{text:'x'});assert.equal(r.decision,'OUTCOME_UNKNOWN');assert.equal(r.output,null);assert.equal(r.retry_allowed,false);assert.equal(inspectProcesses().active,0);
 }finally{await f.tools.close();}}
});
test('unreviewed source is rejected before an interpreter is launched',async()=>{await assert.rejects(()=>runProgram({lock:loadPins(),scope,language:'JS',source:"process.exit(0)",input:{text:'x'}}),/TOOLS_UNREVIEWED_SOURCE/);assert.equal(inspectProcesses().active,0);});
test('binary and implementation digest drift fail closed',()=>{
 const binary=structuredClone(loadPins());binary.binaries.node.digest=digest('forged');assert.throws(()=>verifyPins(binary,'node'),/TOOLS_BINARY_DRIFT/);
 const source=structuredClone(loadPins());source.files[0].digest=digest('forged');assert.throws(()=>verifyPins(source,'node'),/TOOLS_SOURCE_DRIFT/);
});
test('unknown host options and absent existing-owner admission cannot enable execution',()=>{
 assert.throws(()=>createExecutableTools({scope,admission:null,reviewer:null,generator_id:'act_generator',limits:{timeout_ms:1500,max_output_bytes:8192}}),/TOOLS_ADMISSION_REQUIRED/);
 assert.throws(()=>createExecutableTools({scope,command:'anything'}),/TOOLS_FIELDS/);
});
test('close removes temporary directory, rejects calls and preserves unrelated siblings',async()=>{
 const f=fixture(),root=f.tools.inspect().scope.root,sibling=createScope({...scope,operation_id:'op_sibling'}),p=scopeInfo(sibling).root;
 try{writeScoped(sibling,'keep.txt','fixture');await f.tools.close();assert(!fs.existsSync(root));assert(fs.existsSync(path.join(p,'keep.txt')));assert.equal((await f.tools.execute('{}')).decision,'DENY');assert.equal(f.tools.check([]),false);}finally{closeScope(sibling);}
});
test('host shutdown cancels an owned running child and joins it before cleanup',async()=>{
 const f=fixture(),root=f.tools.inspect().scope.root,work=f.execute('js.text.stats',{text:'fixture'});await Promise.resolve();await f.tools.close();
 const r=await work;assert.equal(r.decision,'OUTCOME_UNKNOWN');assert.equal(r.output,null);assert.equal(inspectProcesses().active,0);assert(!fs.existsSync(root));
});
