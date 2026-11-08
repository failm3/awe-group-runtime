import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fixture} from './fixtures.mjs';
import {bytesHash,copy,digest} from '../../awe/qa/common.mjs';
import {evaluateExact} from '../../awe/qa/evaluator.mjs';
const pack=JSON.parse(readFileSync(new URL('./adversarial.json',import.meta.url)));
const reject=(promise,code)=>assert.rejects(promise,code?new RegExp(code):undefined);
const cannotAccept=f=>{const s=f.service.inspect();assert.equal(s.accepted,false);assert.equal(s.published,false);assert.equal(s.physical_decision,'DENY');};
const prepared=async options=>{const f=await fixture(options);await f.report();return f;};

test('D08-01 actual INT02 artifact -> NOT_RUN -> PENDING -> PASS; work and QA do not accept',async()=>{
  const f=await fixture();assert.equal(f.service.inspect().effective_qa,'QA_NOT_RUN');
  assert.equal(f.out.outcome.work,'WORK_COMPLETED');assert.equal(f.out.outcome.independent_qa,'NOT_RUN');
  await f.report();assert.equal(f.service.inspect().qa,'QA_NOT_RUN');
  const run=await f.start();assert.equal(f.j.f.task().state,'QA_PENDING');assert.equal(f.service.inspect().qa,'QA_PENDING');cannotAccept(f);
  const proof=await f.finish(run);assert.equal(proof.result.verdict,'QA_PASS',JSON.stringify(proof.result));
  assert.equal(proof.result.artifact_hash,f.head.file_hash);assert.equal(proof.result.criteria.length,7);
  assert(proof.result.trace.length>=12);assert.equal(proof.mode,'E0_SYNTHETIC_ONLY');cannotAccept(f);
  await f.accept(run);assert.equal(f.service.inspect().accepted,true);assert.equal(f.service.inspect().authoritative_complete,false);
  assert.equal(f.j.f.task().state,'QA_PENDING');assert.equal(f.out.physical_dispatches,0);
});

for(const c of pack.cases) test('D08-ADV '+c.id+' independent stored artifact MUST FAIL',async()=>{
  const f=await fixture();
  f.replace(o=>{let target=o;for(const k of c.path.slice(0,-1))target=target[k];target[c.path.at(-1)]=copy(c.value);},{rechain:c.rechain});
  const run=await f.verify();
  assert.equal(run.proof.result.verdict,'QA_FAIL',JSON.stringify(run.proof.result));
  assert(run.proof.result.findings.some(x=>x.code===c.code),JSON.stringify(run.proof.result));
  assert(run.proof.result.findings.every(x=>x.severity && x.criterion && x.trace.path));
  assert.throws(()=>f.service.owner.binding(run.handle),/PROOF_STALE/);cannotAccept(f);
});

for(const [name,extra] of [['verified',{verified:true}],['qa_actor',{qa_actor:'qa'}],['accepted',{accepted:true}],['verdict',{verdict:'PASS'}]])
  test('D08-FORGE worker '+name+' cannot confer authority',async()=>{
    const f=await fixture();await reject(f.service.worker.report({work:'WORK_COMPLETED',reference:f.head,expected_revision:0,...extra}),'MALFORMED_REQUEST');
    assert.throws(()=>f.service.worker.submitQa({verdict:'PASS',verified:true}),/WORKER_QA_FORBIDDEN/);cannotAccept(f);
  });

for(const type of ['copied-session','json-session','copied-grant','json-grant','foreign-issuer','foreign-scope','weak-binding'])
  test('D08-AUTH '+type+' denied',async()=>{
    const f=await prepared(),g=f.grant();let s=f.qaSession,grant=g;
    if(type==='copied-session')s={...s};if(type==='json-session')s={identity_id:'qa',role:'EXAMINER'};
    if(type==='copied-grant')grant={...g};if(type==='json-grant')grant={verified:true,actor:'qa',scope:f.head};
    if(type==='foreign-issuer'){const other=await fixture();s=other.qaSession;grant=other.grant();}
    if(type==='foreign-scope')assert.throws(()=>f.grant(f.service.binding(),f.issuer.control.session('foreign')),/GRANT_SCOPE/);
    else if(type==='weak-binding') {const b=f.service.binding();delete b.artifact;grant=f.grant(b);}
    if(type!=='foreign-scope')await reject(f.start('bad',grant,s));cannotAccept(f);
  });

test('D08-AUTH worker and QA subject alias rejected by issuer',async()=>{
  const f=await prepared({alias:true});assert.throws(()=>f.grant(),/SELF_QA_DENIED/);cannotAccept(f);
});
for(const role of ['worker','owner'])test('D08-AUTH '+role+' cannot issue verifier grant',async()=>{
  const f=await prepared();assert.throws(()=>f.grant(f.service.binding(),f.issuer.control.session(role)),/SELF_QA_DENIED|ROLE_DENIED/);cannotAccept(f);
});

test('D08-OWNER QA identity cannot accept, serialized proof is untrusted',async()=>{
  const f=await fixture(),run=await f.verify();
  assert.throws(()=>f.grant(f.service.owner.binding(run.handle),f.qaSession,'ACCEPT'),/ROLE_DENIED/);
  assert.throws(()=>f.service.owner.binding(copy(run.handle)),/PROOF_UNTRUSTED/);
  assert.throws(()=>f.service.owner.binding(run.proof),/PROOF_UNTRUSTED/);
  assert.throws(()=>f.service.worker.accept(),/OWNER_REQUIRED/);cannotAccept(f);
});
test('D08-OWNER owner and verifier subject alias cannot accept',async()=>{
  const f=await fixture({ownerAlias:true}),run=await f.verify();await reject(f.accept(run),'INDEPENDENT_OWNER_REQUIRED');cannotAccept(f);
});
test('D08-OWNER wrong proof hash grant denied',async()=>{
  const f=await fixture(),run=await f.verify();const b=f.service.owner.binding(run.handle);b.proof_hash=digest({fake:true});
  const g=f.grant(b,f.ownerSession,'ACCEPT');await reject(f.service.owner.accept(f.ownerSession,g,run.handle,{expected_revision:3,key:'bad'}),'GRANT_SCOPE');cannotAccept(f);
});
test('D08-OWNER owner retries idempotent; second decision conflicts',async()=>{
  const f=await fixture(),run=await f.verify(),a=await f.accept(run);
  const record=await f.service.owner.accept(f.ownerSession,a.grant,run.handle,{expected_revision:3,key:'owner-first'});
  assert.equal(record.revision,a.record.revision);assert.equal(record.history.filter(x=>x==='OWNER_ACCEPTED').length,1);
  await reject(f.service.owner.accept(f.ownerSession,a.grant,run.handle,{expected_revision:record.revision,key:'new'}),'ACCEPTANCE_CONFLICT');
});

test('D08-CAS parallel QA starts admit one job only',async()=>{
  const f=await prepared(),g=f.grant();
  const results=await Promise.allSettled([f.start('a',g),f.start('b',g)]);
  assert.equal(results.filter(x=>x.status==='fulfilled').length,1);assert.equal(results.filter(x=>x.status==='rejected').length,1);
  assert.equal(f.service.inspect().history.filter(x=>x==='QA_PENDING').length,1);cannotAccept(f);
});
test('D08-CAS duplicate start key returns same opaque job, no second pending transition',async()=>{
  const f=await prepared(),g=f.grant(),request={expected_revision:1,key:'same'};
  const a=await f.service.verifier.start(f.qaSession,g,request),b=await f.service.verifier.start(f.qaSession,g,request);
  assert.equal(a,b);await reject(f.service.verifier.start(f.qaSession,g,{...request,expected_revision:2}),'IDEMPOTENCY_CONFLICT');
});
test('D08-CAS concurrent duplicate finish shares one proof and one commit',async()=>{
  const f=await prepared(),run=await f.start();
  const results=await Promise.allSettled([f.finish(run),f.finish(run)]);
  assert.equal(results.filter(x=>x.status==='fulfilled').length,2);assert.deepEqual(results[0].value,results[1].value);
  assert.equal(f.service.inspect().history.filter(x=>x==='QA_PASS').length,1);cannotAccept(f);
});
test('D08-CAS sequential finish retry is identical',async()=>{
  const f=await fixture(),run=await f.verify();assert.deepEqual(await f.finish(run),run.proof);
});
test('D08-CAS report stale revision cannot revise a completed artifact',async()=>{
  const f=await fixture();await f.report();f.replace(()=>{});
  await reject(f.service.worker.report({reference:f.head,work:'WORK_COMPLETED',expected_revision:0}),'QA_CAS_CONFLICT');cannotAccept(f);
});
test('D08-REVISION artifact changed after QA invalidates proof and requires QA again',async()=>{
  const f=await fixture(),run=await f.verify();const old=f.head;
  f.replace(o=>{o.model.output.text='BROKEN LATER';});cannotAccept(f);
  assert.equal(f.service.inspect().effective_qa,'QA_INCONCLUSIVE');await reject(f.accept(run));
  assert.throws(()=>f.artifacts.read(old),/ARTIFACT_STALE/);
  await f.report();assert.equal(f.service.inspect().qa,'QA_NOT_RUN');
  const next=await f.start('revision-2'),proof=await f.finish(next);assert.equal(proof.result.verdict,'QA_FAIL');cannotAccept(f);
});
test('D08-REVISION mutation after OWNER_ACCEPTED withdraws effective acceptance',async()=>{
  const f=await fixture(),run=await f.verify();await f.accept(run);assert.equal(f.service.inspect().accepted,true);
  f.replace(o=>{o.model.output.text='changed';});cannotAccept(f);
});
test('D08-REVISION corrected artifact can be reverified under new scoped grant',async()=>{
  const f=await fixture();f.replace(o=>{o.model.output.text='wrong';});const failed=await f.verify();assert.equal(failed.proof.result.verdict,'QA_FAIL');
  f.replace(o=>{o.model.output.text='synthetic work result';});await f.report();const next=await f.start('corrected');
  assert.equal((await f.finish(next)).result.verdict,'QA_PASS');await f.accept(next);assert.equal(f.service.inspect().accepted,true);
});
test('D08-LATE copied job and unrequested result denied',async()=>{
  const f=await prepared(),run=await f.start();await reject(f.service.verifier.finish(run.session,run.grant,{...run.handle}),'RUN_UNTRUSTED');
  await reject(f.service.verifier.finish(run.session,run.grant,{verified:true,result:'QA_PASS'}),'RUN_UNTRUSTED');cannotAccept(f);
});
test('D08-ABORT abort is INCONCLUSIVE and late verifier reply cannot pass',async()=>{
  const f=await prepared(),run=await f.start();await f.service.verifier.abort(run.session,run.grant,run.handle);
  assert.equal(f.service.inspect().qa,'QA_INCONCLUSIVE');await reject(f.finish(run),'QA_ABORTED');cannotAccept(f);
});
test('D08-ABORT abort concurrent with evaluation cannot commit a PASS',async()=>{
  const f=await prepared(),run=await f.start();
  const results=await Promise.allSettled([f.finish(run),f.service.verifier.abort(run.session,run.grant,run.handle)]);
  assert(results.some(x=>x.status==='rejected'));cannotAccept(f);
});
for(const when of ['before-start','mid-run','after-pass','after-accept'])test('D08-REVOKE '+when+' fail closed',async()=>{
  const f=await prepared(),g=f.grant();let run;
  if(when==='before-start'){f.issuer.control.revoke(g);await reject(f.start('revoked',g));}
  else {
    run=await f.start('revoked',g);
    if(when==='mid-run'){const pending=f.finish(run);f.issuer.control.revoke(g);assert.equal((await pending).result.verdict,'QA_INCONCLUSIVE');}
    else {await f.finish(run);if(when==='after-accept')await f.accept(run);f.issuer.control.revoke(g);await reject(f.accept(run));}
  }
  cannotAccept(f);
});
test('D08-REVOKE owner grant revoked after acceptance withdraws acceptance',async()=>{
  const f=await fixture(),run=await f.verify(),a=await f.accept(run);f.issuer.control.revoke(a.grant);cannotAccept(f);
});
test('D08-REVOKE actor revoked mid-run is INCONCLUSIVE',async()=>{
  const f=await prepared(),run=await f.start(),pending=f.finish(run);f.issuer.control.revokeActor('qa');
  assert.equal((await pending).result.verdict,'QA_INCONCLUSIVE');cannotAccept(f);
});
test('D08-REVOKE expired verifier authority cannot accept historical pass',async()=>{
  const f=await fixture(),run=await f.verify();f.h.tick(5001);await reject(f.accept(run));cannotAccept(f);
});
for(const timing of ['before-start','mid-run','after-pass','after-accept'])test('D08-CANCEL sticky D03 cancellation '+timing,async()=>{
  const f=await prepared();let run,pending;
  if(timing!=='before-start'){run=await f.start();if(timing==='mid-run')pending=f.finish(run);else {await f.finish(run);if(timing==='after-accept')await f.accept(run);}}
  const task=f.j.f.task();await f.h.service.cancel(f.h.owner,f.j.f.taskScope,task.revision,'cancel-d08');
  if(pending)await reject(pending,'QA_COMMIT_UNCERTAIN');
  if(run)await reject(f.accept(run));else await reject(f.start());
  assert.equal(f.j.f.task().cancel_requested,true);assert.equal(f.j.f.task().state,'CANCELLING');cannotAccept(f);
});

for(const mutation of ['spec','epochs','revision','fence','restore_pending','acceptance_stale'])test('D08-STATE changed '+mutation+' invalidates QA',async()=>{
  const f=await fixture(),run=await f.verify();
  await f.h.storage.transaction(db=>{const p=db.projects.prj_alpha,t=p.tasks.task_one;
    if(mutation==='spec')t.spec={...t.spec,revision:2};else if(mutation==='epochs')p.epochs.auth++;
    else if(['revision','fence'].includes(mutation))t[mutation]++;else t[mutation]=true;});
  await reject(f.accept(run));cannotAccept(f);
});

for(const field of ['expected_text','task_id','spec','kind'])test('D08-REQ mismatched '+field+' fails',async()=>{
  const values={expected_text:'a different approved requirement',task_id:'task_other',spec:{revision:999},kind:'UNKNOWN'};
  const f=await fixture({requirements:{[field]:values[field]}});
  if(field==='task_id'){await reject(f.report(),'ARTIFACT_SCOPE');cannotAccept(f);return;}
  const run=await f.verify();assert.equal(run.proof.result.verdict,'QA_FAIL');cannotAccept(f);
});
for(const opinions of [['PASS','FAIL'],['PASS'],['PASS','UNKNOWN']])test('D08-DISAGREE '+opinions.join('/')+' is INCONCLUSIVE',async()=>{
  const f=await fixture();f.setOpinions(opinions);const run=await f.verify();assert.equal(run.proof.result.verdict,'QA_INCONCLUSIVE');cannotAccept(f);
});
test('D08-DISAGREE two redundant PASS opinions cannot override broken function',async()=>{
  const f=await fixture();f.setOpinions(['PASS','PASS']);f.replace(o=>{o.model.output.text='incorrect';});const run=await f.verify();assert.equal(run.proof.result.verdict,'QA_FAIL');cannotAccept(f);
});
test('D08-EVIDENCE missing chain stage fails despite recomputed digest',async()=>{
  const f=await fixture();f.chain.rows.splice(1,1);const run=await f.verify();assert.equal(run.proof.result.verdict,'QA_FAIL');cannotAccept(f);
});
test('D08-EVIDENCE OUTCOME_UNKNOWN cannot be reported as completed',async()=>{
  const f=await fixture();f.setCompletion({...f.out.outcome,work:'OUTCOME_UNKNOWN'});await reject(f.report(),'OUTCOME_UNKNOWN');cannotAccept(f);
});
test('D08-EVIDENCE receipt commit failure in actual INT02 produces no QA artifact',async()=>{
  const {j,out}=await fixture({joint:{receiptFault:'before_commit'}});assert.equal(out.outcome.work,'OUTCOME_UNKNOWN');
  assert.equal(out.artifact_file,undefined);assert.equal(j.out?.accepted??false,false);
});
test('D08-EVIDENCE tampering after PASS invalidates acceptance',async()=>{
  const f=await fixture(),run=await f.verify();f.chain.rows[0].hash=digest({fake:true});await reject(f.accept(run));cannotAccept(f);
});
test('D08-EVIDENCE corrupted D07 bytes deny access and acceptance',async()=>{
  const f=await fixture(),run=await f.verify();const key=f.j.m.primary.keys().find(k=>k.endsWith(f.head.file_hash.slice(7)));
  assert(key);f.j.m.primary.corrupt(key,Buffer.from('corrupted'));await reject(f.accept(run));cannotAccept(f);
});
test('D08-EVIDENCE current exact read returns copies; edits cannot mutate artifact',async()=>{
  const f=await fixture(),b=f.artifacts.read(f.head);b.fill(0);assert.equal(bytesHash(f.artifacts.read(f.head)),f.head.file_hash);
});
for(const caseName of ['no-proof','pending','failed','inconclusive'])test('D08-BYPASS accept '+caseName+' denied',async()=>{
  const f=await prepared();let handle={};
  if(caseName!=='no-proof'){
    if(caseName==='failed')f.setCompletion({...f.out.outcome,accepted:true});
    if(caseName==='inconclusive')f.setOpinions(['PASS','FAIL']);
    const run=await f.start();handle=run.handle;if(caseName!=='pending')await f.finish(run);
  }
  assert.throws(()=>f.service.owner.binding(handle),/PROOF_UNTRUSTED|PROOF_STALE/);cannotAccept(f);
});
test('D08-BYPASS new service instance cannot restore trusted proof handles from sidecar JSON',async()=>{
  const f=await fixture(),run=await f.verify();await f.accept(run);assert.equal(f.make().inspect().accepted,false);
});
test('D08-BYPASS raw D03 PERSISTING cannot make D08 accept',async()=>{
  const f=await fixture(),run=await f.verify();await f.h.go('PERSISTING');cannotAccept(f);await reject(f.accept(run));
});
test('D08-BYPASS worker has no issuer, storage, proof import or verifier role',async()=>{
  const f=await fixture();assert.deepEqual(Object.keys(f.service.worker).sort(),['accept','publish','report','requestPhysicalEffect','submitQa']);
  assert.equal(f.service.worker.publish().decision,'DENY');assert.equal(f.service.worker.requestPhysicalEffect().decision,'DENY');
});
test('D08-MALFORMED invalid proof bytes return typed INCONCLUSIVE',async()=>{
  const f=await fixture(),c=f.statePort.read();const result=evaluateExact({bytes:Buffer.from('{'),reference:f.head,requirements:f.requirements,evidence:f.evidence.read(),operations:c.operations,pin:c.pin});
  assert.equal(result.verdict,'QA_INCONCLUSIVE');assert.equal(result.findings[0].code,'MALFORMED_PROOF');
});
test('D08-DETERMINISM identical synthetic workflow and verifier produce identical proof',async()=>{
  const a=await fixture(),b=await fixture(),x=await a.verify(),y=await b.verify();assert.deepEqual(x.proof,y.proof);
});

test('D08-CAS simultaneous same-key starts share the same job',async()=>{
  const f=await prepared(),g=f.grant(),request={expected_revision:1,key:'duplicate'};
  const [a,b]=await Promise.all([f.service.verifier.start(f.qaSession,g,request),f.service.verifier.start(f.qaSession,g,request)]);
  assert.equal(a,b);assert.equal(f.service.inspect().history.filter(x=>x==='QA_PENDING').length,1);
});
for(const stage of ['before_commit','after_commit'])test('D08-FAULT QA '+stage+' never exposes a PASS proof',async()=>{
  const f=await prepared(),run=await f.start();f.j.f.fault(stage);
  await reject(f.finish(run),'QA_COMMIT_UNCERTAIN');f.j.f.fault(null);cannotAccept(f);
  assert.equal(f.service.inspect().effective_qa,'QA_INCONCLUSIVE');await reject(f.accept(run),'PROOF_UNTRUSTED');
});
for(const stage of ['before_commit','after_commit'])test('D08-FAULT owner '+stage+' quarantines acceptance',async()=>{
  const f=await fixture(),run=await f.verify();f.j.f.fault(stage);
  await reject(f.accept(run),'ACCEPTANCE_COMMIT_UNCERTAIN');f.j.f.fault(null);cannotAccept(f);
});
test('D08-FAULT unavailable D03 store blocks current proof',async()=>{
  const f=await fixture(),run=await f.verify();f.j.f.outage(false);cannotAccept(f);await reject(f.accept(run));
});
test('D08-FAULT async evidence port denied instead of implicit PASS',async()=>{
  const f=await fixture(),s=f.make({evidence:{read:()=>Promise.resolve(f.evidence.read())}});
  await reject(s.worker.report({work:'WORK_COMPLETED',reference:f.head,expected_revision:0}),'SYNC_EVIDENCE_REQUIRED');assert.equal(s.inspect().accepted,false);
});
test('D08-FAULT async artifact port denied instead of implicit PASS',async()=>{
  const f=await fixture(),s=f.make({artifacts:{read:()=>Promise.resolve(Buffer.from('fake'))}});
  await reject(s.worker.report({work:'WORK_COMPLETED',reference:f.head,expected_revision:0}),'ARTIFACT_CHANGED');assert.equal(s.inspect().accepted,false);
});
test('D08-LATE artifact changed mid-verification produces INCONCLUSIVE',async()=>{
  const f=await prepared(),run=await f.start(),pending=f.finish(run);f.replace(o=>{o.model.output.text='changed in flight';});
  assert.equal((await pending).result.verdict,'QA_INCONCLUSIVE');cannotAccept(f);
});
test('D08-LATE receipt evidence changed mid-verification produces INCONCLUSIVE',async()=>{
  const f=await prepared(),run=await f.start(),pending=f.finish(run);f.chain.rows[0].hash=digest({changed:true});
  assert.equal((await pending).result.verdict,'QA_INCONCLUSIVE');cannotAccept(f);
});

const citation={id:'source_one',version:1,hash:bytesHash(Buffer.from('The exact offline evidence.')),quote:'exact offline'};
for(const variant of ['valid','false-quote','false-hash','stale-version','foreign-project','foreign-task','missing-source','missing-citation'])
  test('D08-CITATION '+variant+' checks actual source text/scope/version',async()=>{
    const f=await fixture({requirements:{citations:[citation]}});
    const source={id:citation.id,project_id:'prj_alpha',task_id:'task_one',version:1,text:'The exact offline evidence.'};
    const c=copy(citation);
    if(variant==='false-quote')c.quote='invented';if(variant==='false-hash')c.hash=digest('wrong');
    if(variant==='stale-version')source.version=2;if(variant==='foreign-project')source.project_id='prj_beta';
    if(variant==='foreign-task')source.task_id='task_other';
    f.setSources(variant==='missing-source'?[]:[source]);f.replace(o=>{o.citations=variant==='missing-citation'?[]:[c];});
    const run=await f.verify();assert.equal(run.proof.result.verdict,variant==='valid'?'QA_PASS':'QA_FAIL');cannotAccept(f);
  });
test('D08-CITATION duplicate citation cannot cover another required source',async()=>{
  const f=await fixture({requirements:{citations:[citation,{...citation,id:'source_two'}]}});
  f.setSources([{id:citation.id,project_id:'prj_alpha',task_id:'task_one',version:1,text:'The exact offline evidence.'}]);
  f.replace(o=>{o.citations=[copy(citation),copy(citation)];});const run=await f.verify();assert.equal(run.proof.result.verdict,'QA_FAIL');
  assert(run.proof.result.findings.some(x=>x.code==='CITATION_COVERAGE'));cannotAccept(f);
});
for(const [name,transform] of [['foreign-project',r=>{r.project_id='prj_beta';}],['wrong-task',r=>{r.task_id='task_other';}],
  ['false-file-hash',r=>{r.file_hash=digest({fake:true});}],['wrong-length',r=>{r.bytes++;}],['wrong-path',r=>{r.path='../outside';}],
  ['stale-version',r=>{r.version++;}],['wrong-provenance',r=>{r.provenance_hash=digest({fake:true});}]])
  test('D08-REF '+name+' cannot enter QA',async()=>{
    const f=await fixture(),ref=f.head;transform(ref);await reject(f.service.worker.report({work:'WORK_COMPLETED',reference:ref,expected_revision:0}));cannotAccept(f);
  });
test('D08-STATE lease expiry blocks acceptance even if issuer grant remains valid',async()=>{
  const f=await prepared();const run=await f.start('long-grant',f.grant(f.service.binding(),f.qaSession,'VERIFY',Date.parse(f.h.now())+20000));
  await f.finish(run);f.h.tick(10001);await reject(f.accept(run));cannotAccept(f);
});
test('D08-STATE pending unresolved operation prevents PASS',async()=>{
  const f=await fixture();await f.h.intent();await f.report();const run=await f.start();const proof=await f.finish(run);
  assert.equal(proof.result.verdict,'QA_FAIL');assert(proof.result.findings.some(x=>x.code==='UNRESOLVED_OPERATION'));cannotAccept(f);
});
