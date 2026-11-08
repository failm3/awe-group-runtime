import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {available,reason,createCluster,admission,invoice,json,quote,hash} from './local-postgres.mjs';
let db;
before(()=>{if(available)db=createCluster();});
after(()=>db?.close());
const pg=(name,fn)=>test('D09 REAL_PG '+name,{skip:available?false:reason},fn);
const call=(fn,j,login)=>db.call(fn,j,login);
const admit=(p,i=1,reserve='60')=>call('admit',admission(p,i,reserve));
const send=p=>{admit(p);const t=call('claim_attempt',{project_id:p,attempt_id:'a1'});return call('mark_sent',{project_id:p,attempt_id:'a1',fence:Number(t.delivery_fence)});};
const count=p=>Number(db.sql(`SELECT count(*) FROM awe_d09.attempts WHERE project_id=${quote(p)}`));
const budget=p=>JSON.parse(db.sql(`SELECT to_jsonb(b) FROM awe_d09.budgets b WHERE project_id=${quote(p)} AND kind='PROJECT'`));
const inspect=p=>call('inspect_attempt',{project_id:p,attempt_id:'a1'});
const deny=fn=>assert.throws(fn);
pg('migration version, durability settings and FORCE RLS',()=>{
  const settings={};
  for(const key of ['server_version','server_version_num','data_directory','listen_addresses','port','unix_socket_directories','fsync','synchronous_commit','full_page_writes'])settings[key]=db.sql('SHOW '+key);
  assert(Number(settings.server_version_num)>=160000);assert.equal(settings.listen_addresses,'127.0.0.1');assert.equal(settings.port,'55491');
  if(process.platform==='linux')assert(settings.data_directory.startsWith('/tmp/awe-d09-'));
  writeFileSync(join(db.run,'server-settings.json'),JSON.stringify(settings,null,2)+'\n');
  assert.equal(db.sql('SELECT version FROM awe_d09.schema_version'),'1');
  for(const key of ['fsync','synchronous_commit','full_page_writes'])assert.equal(db.sql('SHOW '+key),'on');
  assert.equal(db.sql("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='awe_d09' AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity"),'14');
  assert.equal(db.sql('SET ROLE awe_d09_owner; SELECT count(*) FROM awe_d09.projects'),'0');
});
pg('atomic reserve, approval, attempt, events and outbox',()=>{
  const p='atomic';db.seed(p);const r=admit(p);assert.equal(r.status,'ADMITTED');assert.equal(r.physical_decision,'DENY');
  assert.equal(count(p),1);assert.equal(budget(p).reserved_micros,60);
  assert.equal(db.sql(`SELECT used_by FROM awe_d09.approvals WHERE project_id=${quote(p)} AND approval_id='ap1'`),'a1');
  assert.equal(db.sql(`SELECT count(*) FROM awe_d09.allocations WHERE project_id=${quote(p)}`),'6');
  assert.equal(db.sql(`SELECT count(*) FROM awe_d09.events WHERE project_id=${quote(p)}`),'2');
  assert.equal(db.sql(`SELECT state FROM awe_d09.outbox WHERE project_id=${quote(p)}`),'READY');
});
pg('duplicate admission returns same record, no second reservation',()=>{
  const p='dedup';db.seed(p);admit(p);admit(p);assert.equal(count(p),1);assert.equal(budget(p).reserved_micros,60);assert.equal(budget(p).attempts_used,1);
  deny(()=>call('admit',{...admission(p),reserve_micros:'59'}));
});
pg('large monetary micros remain exact decimal strings, distinct from token counts',()=>{
  const p='exact_money',reserve='90071992547409929999',actual='90071992547409929998';
  db.seed(p,{cap:'90071992547409930000'});assert.equal(admit(p,1,reserve).reserve_micros,reserve);
  const lease=call('claim_attempt',{project_id:p,attempt_id:'a1'});call('mark_sent',{project_id:p,attempt_id:'a1',fence:Number(lease.delivery_fence)});
  assert.equal(call('reconcile_charge',invoice(p,1,actual),'d09_reconciler_login').actual_micros,actual);
  assert.equal(db.sql(`SELECT spent_micros::text FROM awe_d09.budgets WHERE project_id=${quote(p)} AND kind='PROJECT'`),actual);
});
pg('effect slot and consumed approval cannot be rearmed under new IDs',()=>{
  const p='rearm';db.seed(p,{cap:'500'});admit(p);
  deny(()=>call('admit',{...admission(p),attempt_id:'changed',idempotency_key:'changed'}));
  db.sql(`UPDATE awe_d09.approvals SET effect_slot='s1' WHERE project_id=${quote(p)} AND approval_id='ap2'`);
  deny(()=>call('admit',{...admission(p,2),effect_slot:'s1'}));assert.equal(count(p),1);
});
for(const field of ['plan_hash','payload_hash','task_id','operation_id','approval_id']) pg('approval immutable binding '+field,()=>{
  const p='bind_'+field;db.seed(p);const j=admission(p);j[field]=field.endsWith('hash')?'sha256:'+'b'.repeat(64):'wrong';deny(()=>call('admit',j));assert.equal(count(p),0);assert.equal(budget(p).reserved_micros,0);
});
pg('JSON actor spoof and SQL injection rejected in database, not only adapter',()=>{
  const p='injection';db.seed(p);
  deny(()=>call('admit',{...admission(p),actor_id:'d09_worker'}));
  deny(()=>call('admit',{...admission(p),project_id:"injection';DROP SCHEMA awe_d09 CASCADE;--"}));
  assert.equal(db.sql('SELECT version FROM awe_d09.schema_version'),'1');assert.equal(count(p),0);
});
pg('tenant GUC spoof and RLS cross-project select/write denial',()=>{
  const p='rls';db.seed(p);admit(p);
  const text=`SET awe.project_id=${quote(p)}; SET awe.actor_id='d09_worker'; SELECT count(*) FROM awe_d09.attempts WHERE project_id=${quote(p)}`;
  assert.equal(db.sql(text,{login:'d09_intruder'}),'0');
  deny(()=>db.sql(`UPDATE awe_d09.attempts SET status='SETTLED' WHERE project_id=${quote(p)}`,{login:'d09_worker'}));
  deny(()=>call('inspect_attempt',{project_id:p,attempt_id:'a1'},'d09_intruder'));
  deny(()=>call('admit',admission(p),'d09_other'));
});
pg('role separation, no SET ROLE/SESSION AUTHORIZATION escalation',()=>{
  const p='roles';db.seed(p);
  deny(()=>call('admit',admission(p),'d09_reader_login'));
  for(const statement of ['SET ROLE awe_d09_owner','SET ROLE awe_d09_issuer','SET SESSION AUTHORIZATION d09_issuer_login'])deny(()=>db.worker(statement));
  deny(()=>call('reconcile_charge',invoice(p)));
  deny(()=>db.worker('SELECT * FROM awe_d09.principals'));
});
pg('revoked principal and removed membership deny without partial writes',()=>{
  const p='revoked';db.seed(p);
  db.sql("UPDATE awe_d09.principals SET revoked=true WHERE login='d09_worker'");
  try {deny(()=>admit(p));assert.equal(count(p),0);} finally {db.sql("UPDATE awe_d09.principals SET revoked=false WHERE login='d09_worker'");}
  db.sql(`DELETE FROM awe_d09.memberships WHERE project_id=${quote(p)} AND login='d09_worker'`);deny(()=>admit(p));assert.equal(count(p),0);
});
pg('expired issuer principal fails closed even with valid project grant',()=>{
  const p='principal_expiry';db.seed(p);db.sql("UPDATE awe_d09.principals SET valid_until=clock_timestamp()-interval '1 second' WHERE login='d09_worker'");
  try {deny(()=>admit(p));assert.equal(count(p),0);} finally {db.sql("UPDATE awe_d09.principals SET valid_until=clock_timestamp()+interval '1 day' WHERE login='d09_worker'");}
});
for(const epoch of ['auth','policy','owner','stop']) pg('stale grant after issuer '+epoch+' epoch advance',()=>{
  const p='epoch_'+epoch;db.seed(p);call('advance_epoch',{project_id:p,epoch},'d09_issuer_login');deny(()=>admit(p));assert.equal(count(p),0);
});
pg('expiry/revocation/task CAS/cancellation checked on admission',()=>{
  for(const [label,statement] of [
    ['expiry',"UPDATE awe_d09.grants SET expires_at=clock_timestamp()-interval '1 second'"],
    ['revocation','UPDATE awe_d09.approvals SET revoked=true'],
    ['revision','UPDATE awe_d09.tasks SET revision=revision+1'],
    ['fence','UPDATE awe_d09.tasks SET fence=fence+1'],
    ['cancel','UPDATE awe_d09.tasks SET cancelled=true']]){
    const p='authority_'+label;db.seed(p);db.sql(statement+' WHERE project_id='+quote(p));deny(()=>admit(p));assert.equal(count(p),0);
  }
});
pg('orphan constraints and missing required pool rollback',()=>{
  const p='orphan';db.seed(p);db.sql(`DELETE FROM awe_d09.task_budgets WHERE project_id=${quote(p)} AND budget_id='account'`);
  deny(()=>admit(p));assert.equal(count(p),0);
  deny(()=>db.sql(`INSERT INTO awe_d09.outbox VALUES(${quote(p)},'missing','READY')`));
});
pg('explicit transaction rollback undoes all admission writes',()=>{
  const p='rollback';db.seed(p);deny(()=>db.worker(`BEGIN; SELECT awe_d09.admit(${json(admission(p))}); SELECT 1/0; COMMIT`));
  assert.equal(count(p),0);assert.equal(budget(p).reserved_micros,0);assert.equal(db.sql(`SELECT count(*) FROM awe_d09.operations WHERE project_id=${quote(p)}`),'0');
});
pg('two processes cannot overspend a shared cap',async()=>{
  const p='spend_race';db.seed(p);
  const r=await Promise.all([1,2].map(i=>db.asyncSql(`BEGIN ISOLATION LEVEL SERIALIZABLE; SELECT awe_d09.admit(${json(admission(p,i))}); SELECT pg_sleep(0.1); COMMIT`)));
  assert.equal(r.filter(x=>x.code===0).length,1);assert.equal(count(p),1);assert.equal(budget(p).reserved_micros,60);
});
pg('two-process duplicate idempotency key creates one allocation set',async()=>{
  const p='dup_race';db.seed(p);
  const r=await Promise.all([1,2].map(()=>db.asyncSql(`BEGIN ISOLATION LEVEL SERIALIZABLE; SELECT awe_d09.admit(${json(admission(p))}); COMMIT`)));
  assert(r.some(x=>x.code===0));admit(p);assert.equal(count(p),1);assert.equal(budget(p).attempts_used,1);
});
pg('CAS delivery lease race has one winner',async()=>{
  const p='lease_race';db.seed(p);admit(p);
  const r=await Promise.all([1,2].map(()=>db.asyncSql(`SELECT awe_d09.claim_attempt(${json({project_id:p,attempt_id:'a1'})})`)));
  assert.equal(r.filter(x=>x.code===0).length,1);assert.equal(Number(inspect(p).delivery_fence),1);
});
pg('stale delivery fence and post-claim epoch revoke deny send intent',()=>{
  const p='stale_fence';db.seed(p);admit(p);call('claim_attempt',{project_id:p,attempt_id:'a1'});
  db.sql(`UPDATE awe_d09.attempts SET delivery_until=clock_timestamp()-interval '1 second' WHERE project_id=${quote(p)}`);
  const t=call('claim_attempt',{project_id:p,attempt_id:'a1'});assert.equal(Number(t.delivery_fence),2);
  deny(()=>call('mark_sent',{project_id:p,attempt_id:'a1',fence:1}));
  call('advance_epoch',{project_id:p,epoch:'stop'},'d09_issuer_login');deny(()=>call('mark_sent',{project_id:p,attempt_id:'a1',fence:2}));
});
pg('pre-send cancellation releases once and never consumes another attempt',()=>{
  const p='cancel_early';db.seed(p);admit(p);const j={project_id:p,attempt_id:'a1'};
  assert.equal(call('cancel_attempt',j).status,'NOT_SENT');call('cancel_attempt',j);
  assert.equal(budget(p).reserved_micros,0);assert.equal(budget(p).spent_micros,0);assert.equal(budget(p).attempts_used,1);deny(()=>call('claim_attempt',j));
});
pg('late cancel retains liability and sticky origin quarantine blocks new IDs',()=>{
  const p='cancel_late';db.seed(p,{cap:'500'});send(p);
  assert.equal(call('cancel_attempt',{project_id:p,attempt_id:'a1'}).status,'OUTCOME_UNKNOWN');
  assert.equal(budget(p).reserved_micros,60);deny(()=>admit(p,2));deny(()=>call('claim_attempt',{project_id:p,attempt_id:'a1'}));
  deny(()=>call('prove_not_sent',{project_id:p,attempt_id:'a1',evidence_hash:hash},'d09_reconciler_login'));
});
pg('duplicate invoice callback settles money exactly once',async()=>{
  const p='invoice_dup';db.seed(p);send(p);const j=invoice(p);
  const r=await Promise.all([1,2].map(()=>db.asyncSql(`SELECT awe_d09.reconcile_charge(${json(j)})`,{login:'d09_reconciler_login'})));
  assert(r.every(x=>x.code===0));assert.equal(inspect(p).status,'SETTLED');assert.equal(budget(p).spent_micros,30);assert.equal(budget(p).reserved_micros,0);
  deny(()=>call('reconcile_charge',{...j,actual_micros:'31'},'d09_reconciler_login'));
  call('cancel_attempt',{project_id:p,attempt_id:'a1'});assert.equal(budget(p).spent_micros,30);
});
pg('provider invoice identity cannot be reused by another attempt or project',()=>{
  const p='invoice_scope';db.seed(p,{cap:'500'});send(p);call('reconcile_charge',invoice(p),'d09_reconciler_login');
  const q='invoice_foreign';db.seed(q);send(q);
  deny(()=>call('reconcile_charge',{...invoice(q),invoice_id:invoice(p).invoice_id},'d09_reconciler_login'));assert.equal(budget(q).reserved_micros,60);
});
pg('task failure does not refund charge and task result cannot settle money',()=>{
  const p='result';db.seed(p);send(p);
  call('record_result',{project_id:p,attempt_id:'a1',result:'FAILED',evidence_hash:hash});assert.equal(budget(p).reserved_micros,60);
  call('reconcile_charge',invoice(p),'d09_reconciler_login');assert.equal(budget(p).spent_micros,30);
  deny(()=>call('record_result',{project_id:p,attempt_id:'a1',result:'SUCCEEDED',evidence_hash:hash}));
});
pg('unknown can reconcile charge while effect quarantine stays sticky',()=>{
  const p='unknown_charge';db.seed(p,{cap:'500'});send(p);call('cancel_attempt',{project_id:p,attempt_id:'a1'});
  const r=call('reconcile_charge',invoice(p),'d09_reconciler_login');assert.equal(r.status,'OUTCOME_UNKNOWN');assert.equal(r.accounting_status,'SETTLED');
  assert.equal(budget(p).spent_micros,30);deny(()=>admit(p,2));
});
pg('over-envelope invoice retained as dispute, project halted, no fabricated settlement',()=>{
  const p='overbilling';db.seed(p);send(p);const r=call('reconcile_charge',invoice(p,1,'120'),'d09_reconciler_login');
  assert.equal(r.status,'OUTCOME_UNKNOWN');assert.equal(r.accounting_status,'DISPUTED');assert.equal(budget(p).reserved_micros,60);assert.equal(budget(p).spent_micros,0);
  assert.equal(db.sql(`SELECT halted FROM awe_d09.projects WHERE project_id=${quote(p)}`),'t');
  assert.equal(db.sql(`SELECT actual_micros FROM awe_d09.invoices WHERE project_id=${quote(p)}`),'120');
});
pg('trusted known-not-sent proof releases without rearming operation',()=>{
  const p='not_sent';db.seed(p);send(p);const r=call('prove_not_sent',{project_id:p,attempt_id:'a1',evidence_hash:hash},'d09_reconciler_login');
  assert.equal(r.status,'NOT_SENT');assert.equal(budget(p).reserved_micros,0);assert.equal(admit(p).status,'NOT_SENT');
});
pg('restart recovery distinguishes pre-send orphan from committed send intent',()=>{
  const p='recover_pre';db.seed(p);admit(p);db.expire(p,'a1');
  const q='recover_sent';db.seed(q);send(q);db.expire(q,'a1');db.crashRestart();
  call('recover_project',{project_id:p},'d09_reconciler_login');call('recover_project',{project_id:q},'d09_reconciler_login');
  assert.equal(inspect(p).status,'NOT_SENT');assert.equal(budget(p).reserved_micros,0);
  assert.equal(inspect(q).status,'OUTCOME_UNKNOWN');assert.equal(budget(q).reserved_micros,60);
  assert.equal(call('recover_project',{project_id:q},'d09_reconciler_login').recovered,0);
});
pg('uncommitted admission rolls back after immediate server crash',async()=>{
  const p='crash_tx';db.seed(p);
  const pending=db.asyncSql(`BEGIN; SELECT awe_d09.admit(${json(admission(p))}); SELECT pg_sleep(12); COMMIT`,{app:'d09-crash-victim'});
  let ready=false;
  for(let i=0;i<50;i++){
    if(db.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='d09-crash-victim' AND wait_event='PgSleep'")==='1'){ready=true;break;}
    await new Promise(r=>setTimeout(r,50));
  }
  assert(ready,'victim must be inside uncommitted transaction');db.crashRestart();assert.notEqual((await pending).code,0);
  assert.equal(count(p),0);assert.equal(budget(p).reserved_micros,0);assert.equal(budget(p).attempts_used,0);
});
pg('post-commit client failure uses stable-key readback without another reserve',async()=>{
  const p='ack_failure';db.seed(p);
  const pending=db.asyncSql(`BEGIN; SELECT awe_d09.admit(${json(admission(p))}); COMMIT; SELECT pg_sleep(12)`,{app:'d09-ack-victim'});
  let ready=false;
  for(let i=0;i<50;i++){
    if(db.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='d09-ack-victim' AND wait_event='PgSleep'")==='1'){ready=true;break;}
    await new Promise(r=>setTimeout(r,50));
  }
  assert(ready);db.sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='d09-ack-victim'");
  assert.notEqual((await pending).code,0);assert.equal(admit(p).status,'ADMITTED');assert.equal(count(p),1);assert.equal(budget(p).reserved_micros,60);
});
pg('backup restore preserves every schema table byte representation and fences dispatch',()=>{
  db.seed('restore_fence');
  const r=db.backupRestore(admission('restore_fence'));assert.equal(r.source,r.restored);assert.equal(r.fenced,'t');assert.equal(r.dispatch_denied,true);assert.equal(r.restored_attempt_count,'0');assert.match(r.backup_sha256,/^[a-f0-9]{64}$/);
});
pg('down/up migration only on owned disposable cluster',()=>{
  db.migration('down');assert.equal(db.sql("SELECT count(*) FROM pg_namespace WHERE nspname='awe_d09'"),'0');db.migration('up');assert.equal(db.sql('SELECT version FROM awe_d09.schema_version'),'1');
});
