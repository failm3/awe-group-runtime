import test from 'node:test';
import assert from 'node:assert/strict';
import {join} from 'node:path';
import {writeFileSync,appendFileSync,readFileSync,mkdirSync,mkdtempSync} from 'node:fs';
import {fixture} from './fixtures.mjs';
import {openJournal} from '../../awe/hermes_runtime/journal.mjs';
import {bootstrap,sourceRoot,cleanEnvironment,requireOffline,profile} from '../../awe/hermes_runtime/profile.mjs';
test('journal excludes second writer',async t=>{const f=await fixture(t);assert.throws(()=>openJournal(f.path),/EEXIST/);});
test('journal torn trailing record rejected; never truncates',async t=>{const f=await fixture(t);await f.launch();f.journal.close();appendFileSync(f.path,'{');assert.throws(()=>openJournal(f.path),/JOURNAL_TORN/);assert(readFileSync(f.path,'utf8').endsWith('{'));});
test('journal tampered hash rejected',async t=>{const f=await fixture(t);await f.launch();f.journal.close();const bytes=readFileSync(f.path,'utf8');writeFileSync(f.path,bytes.replace('RUNNING','FAILED'));assert.throws(()=>openJournal(f.path),/JOURNAL_CORRUPT/);});
test('journal outside RT01 denied before write',()=>{assert.throws(()=>openJournal(join(sourceRoot,'awe/hermes_runtime/escape.jsonl')),/JOURNAL_PATH_DENIED/);});
test('failed journal append quarantines adapter before admission',async t=>{const f=await fixture(t);f.journal.close();assert.equal((await f.launch()).decision,'DENY');assert.equal(f.counts.begin,0);});
test('bootstrap creates deterministic clean profile and refuses existing target',()=>{
 const parent=join(sourceRoot,'RT-01/sandbox');mkdirSync(parent,{recursive:true});const dir=mkdtempSync(join(parent,'bootstrap-'));
 const a=bootstrap(join(dir,'one')),b=bootstrap(join(dir,'two'));assert.equal(a.configHash,b.configHash);assert.equal(a.real_hermes,'REAL_HERMES_NOT_RUN');
 assert.equal(readFileSync(join(a.target,'config.yaml'),'utf8'),readFileSync(join(b.target,'config.yaml'),'utf8'));assert.throws(()=>bootstrap(a.target),/CLEAN_PROFILE_REQUIRED/);
});
test('bootstrap outside RT01 rejected',()=>assert.throws(()=>bootstrap(join(sourceRoot,'unowned')),/PROFILE_PATH_DENIED/));
test('mutable policy cannot arm physical dispatch',()=>{assert.throws(()=>requireOffline({...profile,physical_decision:'ALLOW'}),/PROFILE_NOT_ADMITTED/);});
test('environment allowlist does not inherit secrets, endpoints, options or caches',()=>{
 const env=cleanEnvironment(join(sourceRoot,'RT-01/sandbox/environment'));
 for(const k of ['PATH','OPENAI_API_KEY','ANTHROPIC_API_KEY','HTTP_PROXY','NODE_OPTIONS','PYTHONPATH'])assert.equal(Object.hasOwn(env,k),false);
 assert.equal(env.HOME,env.HERMES_HOME);assert(env.UV_CACHE_DIR.startsWith(env.HERMES_HOME));assert.equal(env.UV_OFFLINE,'1');
});
