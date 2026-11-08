import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {fixture} from './fixtures.mjs';
import {evaluationPins} from '../../awe/execution_security/evaluation.mjs';
import {digest,canonicalize} from '../../contracts/canonical.mjs';
const env={};for(const k of ['SystemRoot','WINDIR','PATH','TEMP','TMP','COMSPEC'])if(process.env[k])env[k]=process.env[k];env.TZ='UTC';
const fixed=(worker,args=[],input='')=>spawnSync(process.execPath,['--require','./baseline/offline-guard.cjs','tests/integration_v4/'+worker,...args],{env,input,encoding:'utf8',windowsHide:true,timeout:10000,maxBuffer:1024*1024});
test('separate guarded fixed D08 process reads actual complete bundle and rejects forged digest',async t=>{
 const f=await fixture(t);await f.host.start();await f.host.finish();
 const b=f.host.bundle,run=b=>fixed('qa-worker.mjs',[],JSON.stringify({bundle:b,source_pins:evaluationPins()}));
 const r=run(b);assert.equal(r.status,0,r.stderr);assert.equal(JSON.parse(r.stdout).result.verdict,'QA_PASS');
 const o=JSON.parse(Buffer.from(b.bytes_base64,'base64'));o.execution.output.text_bytes++;const bytes=Buffer.from(canonicalize(o));
 const forged=run({...b,bytes_base64:bytes.toString('base64'),reference:{...b.reference,file_hash:digest(o),bytes:bytes.length}});
 assert.equal(forged.status,0,forged.stderr);assert.equal(JSON.parse(forged.stdout).result.verdict,'QA_FAIL');
 fs.mkdirSync('INT-04/evidence/scenarios',{recursive:true});fs.writeFileSync('INT-04/evidence/scenarios/independent-process-qa.json',JSON.stringify({pass:JSON.parse(r.stdout),forged:JSON.parse(forged.stdout)},null,2)+'\n');
});
test('real new Node process reloads checkpoint and denies automatic resume/acceptance',async t=>{
 const f=await fixture(t);await f.host.start();await f.host.finish();const qa=await f.host.verify();await f.host.accept(qa.proof);f.host.save();
 const r=fixed('restart-worker.mjs',[path.resolve(f.directory)]);assert.equal(r.status,0,r.stderr);const body=JSON.parse(r.stdout);
 assert.equal(body.restore_pending,true);assert.equal(body.ledger_recovery,true);assert.equal(body.accepted,false);assert.equal(body.resumable,false);assert.equal(body.bundle_hash,f.host.bundle.reference.file_hash);assert.equal(body.operation.attempts.length,1);
 fs.writeFileSync('INT-04/evidence/scenarios/process-restart.json',JSON.stringify(body,null,2)+'\n');
});
test('new process refuses missing checkpoint with no state recreation',async t=>{
 const f=await fixture(t);fs.renameSync(path.join(f.directory,'checkpoint.json'),path.join(f.directory,'checkpoint.saved'));
 const r=fixed('restart-worker.mjs',[path.resolve(f.directory)]);assert.notEqual(r.status,0);assert.match(r.stderr,/ENOENT/);assert.equal(fs.existsSync(path.join(f.directory,'checkpoint.json')),false);
});
