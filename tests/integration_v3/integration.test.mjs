import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {start,stop,fixture,json,quote} from './fixtures.mjs';
import {canonicalize,bytesHash,digest,copy} from '../../awe/qa/common.mjs';
import {storageEnvelope} from '../../awe/integration_v3/storage.mjs';
let cluster;
before(()=>{cluster=start();});after(()=>stop());
const pg=(name,fn)=>test('INT03 REAL_PG '+name,fn);
const rejected=async fn=>assert.rejects(fn);

pg('real INT02 task, PostgreSQL accounting, D08 evaluation and controlled independent owner acceptance',async()=>{
 const f=await fixture();assert.equal((await f.host.worker.inspect()).state,'CREATED');
 const work=await f.execute();assert.equal(work.state,'WORK_COMPLETED');assert.equal(work.qa,'QA_NOT_RUN');assert.equal(work.accepted,false);
 const qa=await f.verify();assert.equal(qa.qa,'QA_PASS');assert.equal(qa.proof.verifier,'d09_qa_login');assert.equal(qa.accepted,false);
 const accepted=await f.accept(qa);assert.equal(accepted.acceptance,'OWNER_ACCEPTED');assert.equal(accepted.accepted,true);
 assert.equal(accepted.published,false);assert.equal(accepted.physical_decision,'DENY');
 const restored=await f.make().trusted.inspect();assert.equal(restored.accepted,true);
 const b=f.bundle();assert.equal(b.evidence.chain.rows.length,6);assert.equal(b.physical_dispatches,0);
 assert.equal(b.checkpoint.d03.data.projects.prj_alpha.tasks.task_one.state,'QA_PENDING');
 assert.equal(f.counts().spent,b.cost.actual_micros);assert.equal(f.counts().reserved,'0');assert.equal(f.counts().attempts,1);
 writeFileSync(join(cluster.run,'full-cycle.json'),JSON.stringify({work,qa,accepted,restarted:restored,accounting:f.counts(),bundle:b},null,2)+'\n');
});
pg('physical calls and worker self-acceptance denied',async()=>{
 const f=await fixture();assert.equal(f.host.worker.requestPhysicalEffect().decision,'DENY');assert.equal(f.host.worker.publish().decision,'DENY');
 assert.throws(()=>f.host.worker.submitQa());assert.throws(()=>f.host.worker.accept());
 assert.throws(()=>f.call('finish_qa',{grant_id:'fake',run_id:'fake',proof:'{}'}));
 assert.throws(()=>f.call('accept',{grant_id:'fake',proof_hash:'fake',key:'fake'}));
});
pg('agent cannot supply project, actor, approvals or forged QA as authority',async()=>{
 const f=await fixture();await rejected(()=>f.host.trusted.admit({...f.command,project_id:'prj_beta'}));
 await rejected(()=>f.host.trusted.admit({...f.command,qa:'QA_PASS'}));assert.equal(f.counts().attempts,0);
 assert.throws(()=>f.call('issue',{action:'VERIFY',grant_id:'fake',login:'d09_worker'}));
});
pg('session spoof and foreign-project read rejected by actual RLS',async()=>{
 const f=await fixture();assert.equal(f.sql("SELECT count(*) FROM awe_int03.runtime",'d09_intruder'),'0');
 assert.equal(f.sql("SET app.project_id='prj_beta'; SET app.actor='d09_worker'; SELECT count(*) FROM awe_d09.tasks WHERE project_id='prj_beta'",'d09_other'),'0');
 assert.throws(()=>f.call('inspect',{project_id:'prj_beta'}));
 assert.throws(()=>f.sql("SELECT awe_int03.inspect('{\"project_id\":\"prj_alpha\",\"task_id\":\"task_one\"}')",'d09_intruder'));
});
pg('stale grant rejects before reserve and task admission',async()=>{
 const f=await fixture();f.sql("UPDATE awe_d09.projects SET auth_epoch=2 WHERE project_id='prj_alpha'");
 await rejected(()=>f.host.trusted.admit(f.command));assert.equal(f.counts().attempts,0);assert.equal(f.counts().reserved,'0');
 assert.equal((await f.host.trusted.inspect()).state,'CREATED');
});
pg('over-budget admission rolls back durable task, counters, outbox and reserve',async()=>{
 const f=await fixture();f.sql("UPDATE awe_d09.budgets SET cap_micros=1,balance_micros=1");
 await rejected(()=>f.host.trusted.admit(f.command));assert.equal(f.counts().attempts,0);assert.equal(f.counts().attempts_used,0);
 assert.equal((await f.host.trusted.inspect()).state,'CREATED');
});
pg('duplicate and concurrent admission creates exactly one durable liability',async()=>{
 const f=await fixture();const results=await Promise.allSettled([f.host.trusted.admit(f.command),f.make().trusted.admit(f.command)]);
 assert(results.some(x=>x.status==='fulfilled'));await f.make().trusted.admit(f.command);
 assert.equal(f.counts().attempts,1);assert.equal(f.counts().attempts_used,1);assert.equal(f.counts().reserved,f.plan.reserve_micros);
});
pg('idempotency collision and changed plan rejected without second reserve',async()=>{
 const f=await fixture();await f.host.trusted.admit(f.command);
 await rejected(()=>f.host.trusted.admit({...f.command,reserve_micros:'1'}));
 assert.equal(f.counts().attempts_used,1);
});
pg('DAG child blocked until exact current parent owner acceptance',async()=>{
 const f=await fixture();const child=f.make({taskId:'task_followup'});
 const cmd={...f.command,operation_id:'o2',attempt_id:'a2',effect_slot:'s2',approval_id:'ap2',grant_id:'g2',idempotency_key:'key2'};
 await rejected(()=>child.trusted.admit(cmd));await f.execute();const qa=await f.verify();await rejected(()=>child.trusted.admit(cmd));
 await f.accept(qa);assert.equal((await child.trusted.admit(cmd)).state,'ADMITTED');
});
pg('uncommitted admission and state checkpoint roll back together',async()=>{
 const f=await fixture();const c={...f.command,...f.scope};
 f.sql(`BEGIN; SELECT awe_int03.admit(${json({...f.scope,command:f.command})}); ROLLBACK;`,'d09_worker');
 assert.equal(f.counts().attempts,0);assert.equal((await f.host.trusted.inspect()).state,'CREATED');
});
pg('unknown admission COMMIT ACK is latched durably and cannot retry',async()=>{
 const f=await fixture();f.pools.workerPool.faultNextCommit('after','admit');
 await assert.rejects(()=>f.host.trusted.admit(f.command),/COMMIT_OUTCOME_UNKNOWN/);
 const state=await f.make().trusted.inspect();assert.equal(state.state,'OUTCOME_UNKNOWN');assert.equal(state.accepted,false);
 await rejected(()=>f.make().trusted.admit(f.command));assert.equal(f.counts().attempts,1);
});
pg('unknown COMMIT before send also fails closed without phantom admission',async()=>{
 const f=await fixture();f.pools.workerPool.faultNextCommit('before','admit');
 await assert.rejects(()=>f.host.trusted.admit(f.command),/COMMIT_OUTCOME_UNKNOWN/);
 assert.equal(f.counts().attempts,0);assert.equal((await f.make().trusted.inspect()).state,'OUTCOME_UNKNOWN');
});
pg('concurrent execution barrier invokes synthetic job at most once',async()=>{
 const f=await fixture();await f.host.trusted.admit(f.command);let calls=0;
 const job={plan:f.job.plan,run:async()=>{calls++;return f.job.run();}};
 const result=await Promise.allSettled([f.host.trusted.execute(job),f.make().trusted.execute(job)]);
 assert.equal(calls,1);assert(result.some(x=>x.status==='fulfilled'));assert.equal(f.counts().invoices,1);
});
pg('lost execution callback is sticky in task, D09 attempt, chain and QA gates',async()=>{
 const f=await fixture();await f.host.trusted.admit(f.command);
 await rejected(()=>f.host.trusted.execute({plan:f.job.plan,run:async()=>{throw Error('LOST_CALLBACK');}}));
 const s=await f.make().trusted.inspect();assert.equal(s.state,'OUTCOME_UNKNOWN');assert.equal(s.qa,'QA_INCONCLUSIVE');
 assert.equal(f.sql("SELECT status FROM awe_d09.attempts WHERE attempt_id='a1'"),'OUTCOME_UNKNOWN');
 assert.equal(f.counts().reserved,f.plan.reserve_micros);await rejected(()=>f.make().trusted.execute(f.job));
 assert.throws(()=>f.issue());
});
pg('actual postmaster crash after intent recovers unknown without re-execution',async()=>{
 const f=await fixture();await f.host.trusted.admit(f.command);f.call('begin_execution');cluster.crashRestart();
 const s=await f.make().trusted.recover();assert.equal(s.state,'OUTCOME_UNKNOWN');
 assert.equal(f.sql("SELECT status FROM awe_d09.attempts WHERE attempt_id='a1'"),'OUTCOME_UNKNOWN');
 await rejected(()=>f.make().trusted.execute(f.job));
});
pg('actual crash after committed artifact retains immutable checkpoint and exact accounting',async()=>{
 const f=await fixture();await f.execute();const old=storageEnvelope(f.bundle());cluster.crashRestart();
 assert.equal(storageEnvelope(f.bundle()),old);assert.equal((await f.make().trusted.recover()).state,'WORK_COMPLETED');
 const qa=await f.verify();assert.equal(qa.qa,'QA_PASS');assert.equal(f.counts().attempts,1);
});
pg('completion COMMIT loss persists receipt and accounting once but quarantines acceptance',async()=>{
 const f=await fixture();await f.host.trusted.admit(f.command);f.pools.workerPool.faultNextCommit('after','complete');
 await assert.rejects(()=>f.host.trusted.execute(f.job),/COMMIT_OUTCOME_UNKNOWN/);
 assert.equal(f.counts().bundles,1);assert.equal(f.counts().invoices,1);assert.equal((await f.make().trusted.inspect()).state,'OUTCOME_UNKNOWN');
 assert.throws(()=>f.issue());
});
pg('cancel before execution releases reserve and rejects late execution',async()=>{
 const f=await fixture();await f.host.trusted.admit(f.command);assert.equal((await f.host.worker.cancel()).state,'CANCELLED');
 assert.equal(f.counts().reserved,'0');await rejected(()=>f.make().trusted.execute(f.job));
});
pg('cancel racing execution callback cannot commit a false completed artifact',async()=>{
 const f=await fixture();await f.host.trusted.admit(f.command);let ready,release;
 const started=new Promise(r=>ready=r),wait=new Promise(r=>release=r);
 const execution=f.host.trusted.execute({plan:f.job.plan,run:async()=>{ready();await wait;return f.job.run();}});
 await started;await f.make().trusted.cancel();release();await rejected(()=>execution);
 assert.equal((await f.make().trusted.inspect()).state,'OUTCOME_UNKNOWN');assert.equal(f.counts().bundles,0);
});
pg('late result and invoice settle money once without clearing unknown or QA',async()=>{
 const f=await fixture();await f.host.trusted.admit(f.command);f.call('begin_execution');f.call('flag_uncertain',{reason:'lost'});
 await f.host.trusted.persistence.recordResult({project_id:'prj_alpha',attempt_id:'a1',result:'SUCCEEDED',evidence_hash:f.plan.payload_hash});
 const invoice={project_id:'prj_alpha',attempt_id:'a1',provider:'synthetic',invoice_id:'late1',actual_micros:'1',input_tokens:9,output_tokens:1,evidence_hash:f.plan.payload_hash};
 await f.host.trusted.persistence.reconcile(invoice);await f.host.trusted.persistence.reconcile(invoice);
 assert.equal(f.counts().spent,'1');assert.equal(f.counts().invoices,1);assert.equal((await f.make().trusted.inspect()).state,'OUTCOME_UNKNOWN');
});
pg('forged untrusted D09 SUCCEEDED receipt cannot produce artifact or QA pass',async()=>{
 const f=await fixture();await f.host.trusted.admit(f.command);f.call('begin_execution');
 await f.host.trusted.persistence.recordResult({project_id:'prj_alpha',attempt_id:'a1',result:'SUCCEEDED',evidence_hash:f.plan.payload_hash});
 assert.equal(f.counts().bundles,0);assert.throws(()=>f.issue());assert.equal((await f.host.worker.inspect()).accepted,false);
});
pg('deliberately incorrect real D07 artifact MUST FAIL D08 evaluator',async()=>{
 const f=await fixture();await f.execute();const b=f.bundle(),out=JSON.parse(Buffer.from(b.bytes_base64,'base64'));
 out.model.output.text='deliberately incorrect canary';const bytes=Buffer.from(canonicalize(out));
 b.bytes_base64=bytes.toString('base64');b.reference={...b.reference,version:2,bytes:bytes.length,file_hash:bytesHash(bytes)};
 await f.host.trusted.revise(b,(await f.host.trusted.inspect()).revision);
 const qa=await f.verify();assert.equal(qa.qa,'QA_FAIL');assert(qa.proof.result.findings.some(x=>x.code==='FUNCTIONAL_OUTPUT'));
 assert.throws(()=>f.issue('ACCEPT','own1','d09_owner_login'));
 writeFileSync(join(cluster.run,'canary-must-fail.json'),JSON.stringify(qa,null,2)+'\n');
});
pg('post-QA new artifact version invalidates exact proof and owner grant',async()=>{
 const f=await fixture();await f.execute();const qa=await f.verify();f.issue('ACCEPT','own1','d09_owner_login');
 const b=f.bundle();b.reference.version=2;await f.host.trusted.revise(b,(await f.host.trusted.inspect()).revision);
 await rejected(()=>f.host.trusted.accept('own1',qa.proof_hash,'owner_key'));assert.equal((await f.host.trusted.inspect()).qa,'QA_NOT_RUN');
});
pg('artifact revision cannot rewrite settled cost or authenticated execution checkpoint',async()=>{
 const f=await fixture();await f.execute();const b=f.bundle();b.reference.version=2;
 for(const changed of [{...copy(b),cost:{...b.cost,actual_micros:'0'}},{...copy(b),operations:[]}])
  await rejected(async()=>f.host.trusted.revise(changed,(await f.host.trusted.inspect()).revision));
 assert.equal(f.counts().bundles,1);assert.equal(f.counts().spent,b.cost.actual_micros);
});
pg('artifact bytes and proof rows are immutable through worker and QA SQL roles',async()=>{
 const f=await fixture();await f.execute();await f.verify();
 assert.throws(()=>f.sql("UPDATE awe_int03.bundles SET body='{}'",'d09_worker'));
 assert.throws(()=>f.sql("DELETE FROM awe_int03.proofs",'d09_qa_login'));
 assert.throws(()=>f.sql("UPDATE awe_int03.bundles SET body='{}'"));
});
pg('post-QA simulated privileged bit rot is detected at owner acceptance',async()=>{
 const f=await fixture();await f.execute();const qa=await f.verify();f.issue('ACCEPT','own1','d09_owner_login');
 f.sql("ALTER TABLE awe_int03.bundles DISABLE TRIGGER bundle_immutable; UPDATE awe_int03.bundles SET body=body||' '; ALTER TABLE awe_int03.bundles ENABLE TRIGGER bundle_immutable;");
 assert.equal((await f.host.trusted.inspect()).effective_qa,'QA_INCONCLUSIVE');await rejected(()=>f.host.trusted.accept('own1',qa.proof_hash,'owner_key'));
});
pg('cross-project artifact scope and changed requirements rejected before durable completion',async()=>{
 const f=await fixture();await f.host.trusted.admit(f.command);
 await rejected(()=>f.host.trusted.execute({plan:f.job.plan,run:async()=>{const b=await f.job.run();b.reference.project_id='prj_beta';return b;}}));
 assert.equal(f.counts().bundles,0);assert.equal(f.counts().spent,'0');assert.equal((await f.host.trusted.inspect()).accepted,false);
});
pg('QA cannot issue own authority, be worker, or act as owner',async()=>{
 const f=await fixture();await f.execute();assert.throws(()=>f.call('issue',{grant_id:'fake',login:'d09_qa_login',action:'VERIFY'},'d09_qa_login'));
 assert.throws(()=>f.issue('VERIFY','fake','d09_worker'));const qa=await f.verify();
 assert.throws(()=>f.issue('ACCEPT','fake','d09_qa_login'));assert.equal(qa.accepted,false);
});
pg('revoked or expired verifier grant fails even after successful evaluation',async()=>{
 const f=await fixture();await f.execute();const qa=await f.verify();f.issue('ACCEPT','own1','d09_owner_login');
 f.sql("UPDATE awe_int03.authorities SET revoked=true WHERE grant_id='qa1'");
 assert.equal((await f.host.trusted.inspect()).effective_qa,'QA_INCONCLUSIVE');await rejected(()=>f.host.trusted.accept('own1',qa.proof_hash,'owner_key'));
});
pg('epoch, restore and task fence invalidate previously accepted exact proof',async()=>{
 const f=await fixture();await f.execute();const qa=await f.verify();await f.accept(qa);
 f.sql("UPDATE awe_d09.projects SET restore_pending=true,auth_epoch=auth_epoch+1 WHERE project_id='prj_alpha'");
 assert.equal((await f.make().trusted.inspect()).accepted,false);await rejected(()=>f.make().trusted.verify('qa1','qa_key'));
 const child=f.make({taskId:'task_followup'});await rejected(()=>child.trusted.admit({...f.command,operation_id:'o2',attempt_id:'a2',effect_slot:'s2',approval_id:'ap2',grant_id:'g2',idempotency_key:'key2'}));
});
pg('pending QA crash recovery becomes inconclusive and rejects late verifier callback',async()=>{
 const f=await fixture();await f.execute();f.issue();const pending=f.call('start_qa',{grant_id:'qa1',key:'qa_key'},'d09_qa_login');
 cluster.crashRestart();assert.equal((await f.make().trusted.recover()).qa,'QA_INCONCLUSIVE');
 assert.throws(()=>f.call('finish_qa',{grant_id:'qa1',run_id:pending.run_id,proof:'{}'},'d09_qa_login'));
});
pg('concurrent QA and acceptance retries have one proof and one acceptance event',async()=>{
 const f=await fixture();await f.execute();f.issue();
 const results=await Promise.allSettled([f.host.trusted.verify('qa1','qa_key'),f.make().trusted.verify('qa1','qa_key')]);
 assert(results.some(x=>x.status==='fulfilled'));const qa=await f.make().trusted.verify('qa1','qa_key');
 f.issue('ACCEPT','own1','d09_owner_login');
 await Promise.allSettled([f.host.trusted.accept('own1',qa.proof_hash,'owner_key'),f.make().trusted.accept('own1',qa.proof_hash,'owner_key')]);
 assert.equal((await f.make().trusted.accept('own1',qa.proof_hash,'owner_key')).accepted,true);
 assert.equal(f.sql('SELECT count(*) FROM awe_int03.proofs'),'1');assert.equal(f.sql("SELECT count(*) FROM awe_int03.events WHERE kind='OWNER_ACCEPTED'"),'1');
});
pg('QA commit acknowledgement loss never returns false PASS and fences acceptance',async()=>{
 const f=await fixture();await f.execute();f.issue();f.evaluatorControl.faultNextCommit('after','finish_qa');
 await assert.rejects(()=>f.host.trusted.verify('qa1','qa_key'),/COMMIT_OUTCOME_UNKNOWN/);
 assert.equal((await f.make().trusted.inspect()).accepted,false);assert.equal((await f.make().trusted.inspect()).state,'OUTCOME_UNKNOWN');
});
pg('owner commit acknowledgement loss quarantines accepted row rather than returning success',async()=>{
 const f=await fixture();await f.execute();const qa=await f.verify();f.issue('ACCEPT','own1','d09_owner_login');f.pools.ownerPool.faultNextCommit('after','accept');
 await assert.rejects(()=>f.host.trusted.accept('own1',qa.proof_hash,'owner_key'),/COMMIT_OUTCOME_UNKNOWN/);
 assert.equal((await f.make().trusted.inspect()).accepted,false);assert.equal((await f.make().trusted.inspect()).state,'OUTCOME_UNKNOWN');
});
pg('cancel after owner acceptance revokes effective acceptance and blocks DAG child',async()=>{
 const f=await fixture();await f.execute();const qa=await f.verify();await f.accept(qa);await f.host.worker.cancel();
 assert.equal((await f.make().trusted.inspect()).accepted,false);assert.equal(f.counts().invoices,1);
});
pg('SQL payload injection remains data and cannot change project authority',async()=>{
 const f=await fixture();await rejected(()=>f.host.trusted.admit({...f.command,grant_id:"g1'); DROP SCHEMA awe_d09 CASCADE; --"}));
 assert.equal(f.sql('SELECT version FROM awe_d09.schema_version'),'1');assert.equal(f.counts().attempts,0);
});
pg('expired QA grant and removed verifier membership invalidate acceptance',async()=>{
 const f=await fixture();await f.execute();const qa=await f.verify();f.issue('ACCEPT','own1','d09_owner_login');
 f.sql("UPDATE awe_int03.authorities SET expires_at=clock_timestamp()-interval '1 second' WHERE grant_id='qa1'");
 await rejected(()=>f.host.trusted.accept('own1',qa.proof_hash,'owner_key'));
 f.sql("UPDATE awe_int03.authorities SET expires_at=clock_timestamp()+interval '1 hour' WHERE grant_id='qa1'; DELETE FROM awe_d09.memberships WHERE login='d09_qa_login'");
 assert.equal((await f.host.trusted.inspect()).effective_qa,'QA_INCONCLUSIVE');
});
pg('revoked worker and stale task fence block previously verified results',async()=>{
 const f=await fixture();await f.execute();await f.verify();f.sql("UPDATE awe_d09.tasks SET fence=fence+1 WHERE task_id='task_one'");
 assert.equal((await f.host.trusted.inspect()).effective_qa,'QA_INCONCLUSIVE');
 f.sql("UPDATE awe_d09.principals SET revoked=true WHERE login='d09_worker'");await rejected(()=>f.host.trusted.inspect());
});
pg('late callback after expired delivery lease cannot commit artifact or settlement',async()=>{
 const f=await fixture();await f.host.trusted.admit(f.command);
 await rejected(()=>f.host.trusted.execute({plan:f.job.plan,run:async()=>{
  const b=await f.job.run();f.sql("UPDATE awe_d09.attempts SET delivery_until=clock_timestamp()-interval '1 second'");return b;
 }}));assert.equal(f.counts().bundles,0);assert.equal(f.counts().invoices,0);
 assert.equal((await f.make().trusted.recover()).state,'OUTCOME_UNKNOWN');
});
pg('real backup of both schemas restores exact data and fences QA, owner and new work',async()=>{
 const f=await fixture();await f.execute();const qa=await f.verify();await f.accept(qa);
 const proof=cluster.backupIntegrated(f.name,'int03_restore');assert.equal(proof.source,proof.restored);assert.equal(proof.tables.length,24);
 const restored=f.make({workerPool:cluster.pool('d09_worker','int03_restore'),verifierPool:cluster.pool('d09_qa_login','int03_restore'),ownerPool:cluster.pool('d09_owner_login','int03_restore')});
 assert.equal((await restored.trusted.inspect()).accepted,false);
 await rejected(()=>restored.trusted.verify('qa1','qa_key'));await rejected(()=>restored.trusted.accept('own1',qa.proof_hash,'owner_key'));
 const child=f.make({workerPool:cluster.pool('d09_worker','int03_restore'),taskId:'task_followup'});
 await rejected(()=>child.trusted.admit({...f.command,operation_id:'o2',attempt_id:'a2',effect_slot:'s2',approval_id:'ap2',grant_id:'g2',idempotency_key:'key2'}));
 proof.observed_acceptance=false;proof.actual_qa_owner_and_admission_denied=true;
 writeFileSync(join(cluster.run,'integrated-backup-restore.json'),JSON.stringify(proof,null,2)+'\n');
});
pg('false tool receipt and changed immutable requirements cannot pass independent QA',async()=>{
 const f=await fixture();await f.execute();const b=f.bundle(),out=JSON.parse(Buffer.from(b.bytes_base64,'base64'));
 out.receipt.receipt.outcome='CONFIRMED';out.receipt.receipt.request_id='FORGED';const bytes=Buffer.from(canonicalize(out));
 b.bytes_base64=bytes.toString('base64');b.reference={...b.reference,version:2,bytes:bytes.length,file_hash:bytesHash(bytes)};
 const changed={...copy(b),requirements:{...b.requirements,expected_text:'forged'}};
 await rejected(()=>f.host.trusted.revise(changed,(f.call('inspect')).revision));
 await f.host.trusted.revise(b,(f.call('inspect')).revision);const qa=await f.verify();assert.equal(qa.qa,'QA_FAIL');
 assert(qa.proof.result.findings.some(x=>x.code==='FALSE_TOOL_RECEIPT'));
});
pg('malformed or copied QA proof cannot replace the actual authorized verifier run',async()=>{
 const f=await fixture();await f.execute();f.issue();const run=f.call('start_qa',{grant_id:'qa1',key:'qa_key'},'d09_qa_login');
 for(const proof of [{},{mode:'E0_SYNTHETIC_ONLY',verifier:'d09_qa_login',run_id:run.run_id,bundle_hash:run.bundle_hash,
   artifact:run.bundle.reference,result:{verdict:'QA_PASS',artifact_hash:'forged',policy_version:'D08_E0_EXACT_ARTIFACT_V1'}}])
  assert.throws(()=>f.call('finish_qa',{grant_id:'qa1',run_id:run.run_id,proof:JSON.stringify(proof)},'d09_qa_login'));
 assert.equal(f.call('inspect').qa,'QA_PENDING');assert.equal(f.call('inspect').accepted,false);
});
