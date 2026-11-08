import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fixture,text} from './fixtures.mjs';
import {relativePath,destination,compileIsolation} from '../../awe/execution_security/isolation.mjs';
import {createSyntheticSecretBroker} from '../../awe/execution_security/secrets.mjs';
for(const path of ['../foreign','inputs/../secret','/etc/passwd','C:/Windows/system.ini','C:\\secret','\\\\server\\share','inputs//data.txt','inputs/%2e%2e/secret','inputs/secret:stream','inputs/CON.txt','inputs/LPT1','inputs/data.txt.','inputs/data.txt ','inputs/..','inputs/./data','inputs/\u202esecret'])
 test('isolation deny unsafe path '+JSON.stringify(path),()=>assert.throws(()=>relativePath(path)));
test('isolation positive project-relative input path compiles without opening a file',async()=>{
 const f=fixture(),r=f.changePayload(f.request,{text:'data',path:'inputs/data.txt'});const p=compileIsolation(f.manifest,r.payload);
 assert.equal(p.launch_authorized,false);assert.equal(p.filesystem.symlinks,'DENY');assert.equal(p.network.default,'DENY');assert.equal(p.process.spawn,'DENY');assert.equal((await f.execute(r)).decision,'SIMULATED');
});
test('isolation denies undeclared path, symlink claims and shell escape requests',async()=>{
 const f=fixture();for(const payload of [{text:'x',path:'inputs/other.txt'},{text:'x',path:'inputs/link/secret.txt'},{text:'x',resolved_path:'/root/secret'},{text:'x',command:'sh -c curl evil'},{text:'x',packages:['unsafe']}]){
  const r=await f.execute(f.changePayload(f.request,payload));assert.equal(r.decision,'DENY');
 }assert.equal(f.world.simulations,0);
});
for(const url of ['http://api.example.test/x','https://evil.example/x','https://api.example.test.evil/x','https://user:pass@api.example.test/x','https://api.example.test:443/x','https://127.0.0.1/x','https://169.254.169.254/latest','https://[::1]/x','https://localhost/x','https://metadata.google.internal/x','file:///secret','https://api.example.test\\@evil.example/x','https://api.example.test/#secret','https://api.example.test./x','https://2130706433/x'])
 test('egress deny destination '+url,()=>assert.throws(()=>destination(url,['api.example.test'])));
test('egress positive approved exact HTTPS domain is a plan, never a connection',async()=>{
 const f=fixture({risk:'NETWORK'}),r=f.changePayload(f.request,{text:'request',url:'https://api.example.test/safe'});f.signApproval(r);
 assert.equal(destination(r.payload.url,f.manifest.domains),'api.example.test');assert.equal((await f.execute(r)).decision,'SIMULATED');assert.equal(f.gate.requestPhysicalEffect().decision,'DENY');
});
test('egress READ tool cannot use a browser to exfiltrate project content',async()=>{
 const f=fixture();const r=await f.execute(f.changePayload(f.request,{text:'project data',url:'https://evil.example/collect'}));assert.equal(r.decision,'DENY');assert.equal(f.world.attempts.size,0);
});
test('secret positive synthetic canary consumed only by authenticated executor; no raw return/log/prompt',()=>{
 const f=fixture(),broker=createSyntheticSecretBroker({verifier:f.verifier}),request={mode:'E0_SYNTHETIC_ONLY',project_id:'prj_alpha',purpose:'CANARY_DIGEST',handle:'synthetic:canary'};
 const out=broker.invoke(f.token('executor'),f.peer('executor'),request);assert.equal(out.used,true);assert(!JSON.stringify(out).includes('SEC01_CANARY_ONLY'));
 assert.throws(()=>broker.invoke(f.token('worker'),f.peer('worker'),request),/ROLE_DENIED/);
 assert.throws(()=>broker.invoke(f.token('executor'),f.peer('worker'),request),/CHANNEL_BINDING_DENIED/);
 assert.throws(()=>broker.invoke(f.token('executor'),f.peer('executor'),{...request,project_id:'prj_beta'}));
 assert.throws(()=>broker.invoke(f.token('executor'),f.peer('executor'),{...request,handle:'real:production'}),/SECRET_ACCESS_DENIED/);
 assert.equal(broker.requestRealSecret().decision,'DENY');
});
for(const secret of ['SEC01_CANARY_ONLY_NO_REAL_CREDENTIAL','Bearer abcdefghijklmno','sk-abcdefghijklmnopqrstuvwx','password=synthetic','-----BEGIN PRIVATE KEY-----'])
 test('secret material denied before prompt/log/output '+secret.slice(0,12),async()=>{
  const f=fixture(),out=await f.execute(f.changePayload(f.request,{text:secret}));assert.equal(out.decision,'DENY');assert.equal(f.world.attempts.size,0);assert(!JSON.stringify({out,audit:f.world.audit}).includes(secret));
 });
test('package boundary has no production process/network/installation launcher',()=>{
 for(const path of ['gate.mjs','identity.mjs','authority.mjs','evaluation.mjs','synthetic-executor.mjs','registry.mjs','secrets.mjs','isolation.mjs']){
  const source=readFileSync(new URL('../../awe/execution_security/'+path,import.meta.url),'utf8');
  assert(!/from ['"]node:(?:child_process|http|https|tls|dgram)['"]|\bfetch\s*\(|\bspawn\s*\(/.test(source));
 }
});
