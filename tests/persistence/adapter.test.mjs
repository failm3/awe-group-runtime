import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createPostgresPersistence, micros, PHYSICAL_DECISION} from '../../awe/persistence/postgres.mjs';
const hash='sha256:'+'a'.repeat(64);
export const admission=()=>({project_id:'p1',task_id:'t1',operation_id:'o1',attempt_id:'a1',effect_slot:'slot1',approval_id:'ap1',grant_id:'g1',idempotency_key:'key1',plan_hash:hash,payload_hash:hash,reserve_micros:'100'});
function scripted({failAt, badResult, rollbackFails=false}={}) {
  const calls=[], releases=[];
  const client={query:async(text,values)=>{
    calls.push({text,values});
    if(text===failAt || (text==='ROLLBACK' && rollbackFails)) throw Error('synthetic failure');
    return {rows:[{result:badResult ?? {physical_decision:'DENY',status:'ADMITTED'}}]};
  },release:bad=>releases.push(bad)};
  return {port:createPostgresPersistence({connect:async()=>client}),calls,releases};
}
test('D09 adapter is a SQL port, never an in-memory durability ledger',()=>{
  assert.throws(()=>createPostgresPersistence(),/POOL_REQUIRED/);assert.equal(PHYSICAL_DECISION,'DENY');
});
test('D09 admission parameterized and committed exactly once',async()=>{
  const s=scripted(), j=admission(),r=await s.port.admit(j);
  assert.deepEqual(s.calls.map(x=>x.text),['BEGIN ISOLATION LEVEL SERIALIZABLE','SET LOCAL synchronous_commit = on',"SET LOCAL statement_timeout = '10s'","SET LOCAL lock_timeout = '5s'",'SELECT awe_d09.admit($1::jsonb) AS result','COMMIT']);
  assert.deepEqual(JSON.parse(s.calls[4].values[0]),j); assert.deepEqual(s.releases,[false]);
  assert(Object.isFrozen(r));assert.equal(r.physical_decision,'DENY');
});
test('D09 pre-commit SQL failure rolls back and destroys session',async()=>{
  const s=scripted({failAt:'SELECT awe_d09.admit($1::jsonb) AS result'});
  await assert.rejects(s.port.admit(admission()),e=>e.code==='TRANSACTION_REJECTED'&&!e.outcomeUnknown);
  assert.equal(s.calls.at(-1).text,'ROLLBACK');assert.deepEqual(s.releases,[true]);
});
for(const rollbackFails of [false,true]) test(`D09 lost commit ACK quarantines client; rollbackFails=${rollbackFails}`,async()=>{
  const s=scripted({failAt:'COMMIT',rollbackFails});
  await assert.rejects(s.port.admit(admission()),e=>e.code==='COMMIT_OUTCOME_UNKNOWN'&&e.outcomeUnknown);
  assert.equal(s.calls.filter(x=>x.text==='COMMIT').length,1);
  assert.equal(s.calls.filter(x=>x.text.includes('awe_d09.admit')).length,1);assert.deepEqual(s.releases,[true]);
});
test('D09 BEGIN failure does not issue unrelated rollback',async()=>{
  const s=scripted({failAt:'BEGIN ISOLATION LEVEL SERIALIZABLE'});
  await assert.rejects(s.port.admit(admission()),/TRANSACTION_REJECTED/);
  assert.equal(s.calls.length,1);assert.deepEqual(s.releases,[true]);
});
test('D09 connection acquisition failure is distinct from an ambiguous commit',async()=>{
  const port=createPostgresPersistence({connect:async()=>{throw Error('private connection detail');}});
  await assert.rejects(port.admit(admission()),e=>e.code==='CONNECTION_UNAVAILABLE'&&!e.outcomeUnknown&&!e.message.includes('private'));
});
test('D09 rejects invalid pool client without starting a transaction',async()=>{
  const port=createPostgresPersistence({connect:async()=>({})});await assert.rejects(port.admit(admission()),/CLIENT_CONTRACT_INVALID/);
});
for(const lostAck of [false,true]) test('D09 client release failure preserves commit certainty '+lostAck,async()=>{
  const client={query:async text=>{if(lostAck&&text==='COMMIT')throw Error('ack lost');return {rows:[{result:{physical_decision:'DENY',status:'ADMITTED'}}]};},release:()=>{throw Error('pool bookkeeping failure');}};
  const port=createPostgresPersistence({connect:async()=>client});
  if(lostAck)await assert.rejects(port.admit(admission()),e=>e.code==='COMMIT_OUTCOME_UNKNOWN'&&e.outcomeUnknown);
  else assert.equal((await port.admit(admission())).status,'ADMITTED');
});
for(const badResult of [{physical_decision:'ALLOW'},{status:'SENT'},[]]) test('D09 denies invalid database result '+JSON.stringify(badResult),async()=>{
  const s=scripted({badResult}); await assert.rejects(s.port.admit(admission()),/DATABASE_CONTRACT_INVALID/);
  assert.equal(s.calls.at(-1).text,'ROLLBACK');
});
test('D09 rejects numeric money in a database JSON response',async()=>{
  const s=scripted({badResult:{physical_decision:'DENY',reserve_micros:9007199254740992}});
  await assert.rejects(s.port.admit(admission()),/MICROS_INVALID/);assert.equal(s.calls.at(-1).text,'ROLLBACK');
});
test('D09 preserves exact large monetary outputs across the SQL port',async()=>{
  const r={physical_decision:'DENY',reserve_micros:'90071992547409929999',actual_micros:null};
  const s=scripted({badResult:r});assert.equal((await s.port.admit(admission())).reserve_micros,r.reserve_micros);
});
for(const value of [0,0.1,-1,100n,'-1','1.0','01','1e6','','9'.repeat(31),null,undefined]) test('D09 rejects monetary input '+String(value),()=>assert.throws(()=>micros(value),/MICROS_INVALID/));
for(const value of ['0','1','9007199254740993','9'.repeat(30)]) test('D09 preserves micros string '+value,()=>assert.equal(micros(value),value));
for(const [key,value] of [['actor_id','forged'],['tenant_id','p2'],['physical_decision','ALLOW'],['input_tokens',10],['sql','DROP SCHEMA awe_d09'],['project_id',"p1'; DROP SCHEMA awe_d09;--"],['plan_hash','x'],['attempt_id',''],['reserve_micros',1]]) {
  test('D09 rejects caller supplied authority/invalid field '+key,async()=>{
    const s=scripted();await assert.rejects(s.port.admit({...admission(),[key]:value})); assert.equal(s.calls.length,0);
  });
}
test('D09 snapshots payload before awaiting database',async()=>{
  const s=scripted(),j=admission(),promise=s.port.admit(j);j.reserve_micros='999';await promise;
  assert.equal(JSON.parse(s.calls[4].values[0]).reserve_micros,'100');
});
const commands={inspect:{project_id:'p1',attempt_id:'a1'},claim:{project_id:'p1',attempt_id:'a1'},markSent:{project_id:'p1',attempt_id:'a1',fence:1},cancel:{project_id:'p1',attempt_id:'a1'},recordResult:{project_id:'p1',attempt_id:'a1',result:'FAILED',evidence_hash:hash},reconcile:{project_id:'p1',attempt_id:'a1',provider:'synthetic',invoice_id:'i1',actual_micros:'30',input_tokens:10,output_tokens:2,evidence_hash:hash},proveNotSent:{project_id:'p1',attempt_id:'a1',evidence_hash:hash},recover:{project_id:'p1'},advanceEpoch:{project_id:'p1',epoch:'auth'}};
for(const [method,j] of Object.entries(commands)) test('D09 fixed parameterized SQL entry '+method,async()=>{
  const s=scripted();await s.port[method](j);assert.equal(s.calls[4].values.length,1);
  assert(s.calls[4].text.endsWith('($1::jsonb) AS result'));assert.equal(s.calls.at(-1).text,'COMMIT');
});
for(const [method,key,val] of [['markSent','fence',-1],['markSent','fence',1.1],['reconcile','input_tokens','10'],['reconcile','output_tokens',Number.MAX_SAFE_INTEGER+1],['advanceEpoch','epoch','auth;DROP'],['recordResult','result','ACCEPTED']]) test('D09 method invalid scalar '+method+'/'+key,async()=>{
  const s=scripted();await assert.rejects(s.port[method]({...commands[method],[key]:val}));assert.equal(s.calls.length,0);
});
test('D09 source owns no transport and imports no frozen module',()=>{
  const text=readFileSync(new URL('../../awe/persistence/postgres.mjs',import.meta.url),'utf8');
  assert(!/^import /m.test(text));assert(!/\b(fetch|spawn|connect\()/.test(text.replace('pool.connect()','pool.acquire()')));
});
// These checks inspect the delivered SQL, not PostgreSQL execution or RLS proof.
const sql=readFileSync(new URL('../../awe/persistence/migrations/001-up.sql',import.meta.url),'utf8');
test('D09 schema review: transaction and owner role separation',()=>{
  assert(sql.includes('BEGIN;'));assert(sql.endsWith('COMMIT;\n'));assert(sql.includes('NOLOGIN NOSUPERUSER NOBYPASSRLS'));
  assert(sql.includes('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA awe_d09 FROM PUBLIC'));
});
test('D09 schema review: session_user authority, not spoofable GUC',()=>{
  assert(sql.includes('a.login=session_user'));assert(!sql.includes('current_setting('));
  assert(sql.includes('FORCE ROW LEVEL SECURITY'));assert(sql.includes('SET search_path=pg_catalog,awe_d09'));
});
test('D09 schema review: durable dedup and tenant-qualified references',()=>{
  assert(sql.includes('UNIQUE(project_id,idempotency_key)'));assert(sql.includes('UNIQUE(project_id,origin_id,effect_slot)'));
  assert(sql.includes('FOREIGN KEY(project_id,attempt_id) REFERENCES awe_d09.attempts'));
  assert(sql.includes('PRIMARY KEY(provider,invoice_id)'));
});
test('D09 schema review: unknown stays sticky across charge reconciliation',()=>{
  assert(sql.includes("status=CASE WHEN status='SENT' THEN 'SETTLED' ELSE status END"));
  assert(sql.includes('D09_STICKY_QUARANTINE'));assert(sql.includes('D09_STICKY_OR_INVALID_TRANSITION'));
});
