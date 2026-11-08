import test from 'node:test';
import assert from 'node:assert/strict';
import {setup,examples} from './fixtures.mjs';
import {digest} from '../../awe/qa_profiles/contracts.mjs';

test('QA02 executor false PASS JSON cannot replace actual Examiner/Auditor',async()=>{
 const s=await setup('document',{text:'TODO'}),r=await s.run();
 const fake={verdict:'PASS',execution_status:'EXECUTED',artifact_sha256:s.head.file_hash};
 for(const role of ['local','examiner','auditor'])assert.equal(s.qa.gate({...s.refs(r),[role]:fake}).verdict,'BLOCKED');
 assert.equal(s.qa.gate(s.refs(r)).verdict,'FAIL');
 assert.throws(()=>s.f.service.worker.submitQa(fake),/WORKER_QA_FORBIDDEN/);
});
for(const role of ['local','examiner','auditor'])test('QA02 missing '+role+' evidence is never PASS',async()=>{
 const s=await setup(),r=await s.run();assert.equal(s.qa.gate({...s.refs(r),[role]:null}).verdict,'BLOCKED');
});
test('QA02 serialized or copied genuine report loses instance provenance',async()=>{
 const s=await setup(),r=await s.run();
 for(const forged of [{...r.examiner},JSON.parse(JSON.stringify(r.examiner)),s.qa.inspect(r.examiner)])assert.equal(s.qa.gate({...s.refs(r),examiner:forged}).verdict,'BLOCKED');
});
test('QA02 other instance reports cannot be replayed',async()=>{const a=await setup(),ar=await a.run(),b=await setup(),br=await b.run();assert.equal(b.qa.gate({...b.refs(br),examiner:ar.examiner}).verdict,'BLOCKED');});
test('QA02 altered artifact bytes after actual PASS invalidate gate',async()=>{const s=await setup(),r=await s.run();assert.equal(s.qa.gate(s.refs(r)).verdict,'PASS');s.corrupt();assert.equal(s.qa.gate(s.refs(r)).verdict,'BLOCKED');});
test('QA02 new D07 version invalidates prior PASS even with identical text',async()=>{const s=await setup(),r=await s.run();s.replace(examples.document.text);assert.equal(s.qa.gate(s.refs(r)).verdict,'BLOCKED');});
test('QA02 independent post-save reader refusal invalidates PASS',async()=>{const s=await setup(),r=await s.run();s.setPostFault(true);const g=s.qa.gate(s.refs(r));assert.equal(g.verdict,'BLOCKED');assert.equal(g.reason,'POST_SAVE_UNAVAILABLE');});
test('QA02 no post-save capability cannot pass',async()=>{
 const s=await setup(),qa=s.make({postSaveArtifacts:null}),local=await qa.local();const eg=s.f.issuer.control.grant(s.f.qaSession,'VERIFY',qa.binding(),Date.parse(s.f.h.now())+5000),examiner=await qa.examine(s.f.qaSession,eg);
 const ag=s.f.issuer.control.grant(s.auditor,'VERIFY',qa.binding(),Date.parse(s.f.h.now())+5000),auditor=await qa.audit(s.auditor,ag,{local,examiner});
 assert.equal(qa.gate({local,examiner,auditor}).verdict,'BLOCKED');
});
for(const [name,change] of [['revision',t=>t.revision++],['cancel',t=>t.cancel_requested=true],['restore',t=>t.restore_pending=true],['spec',t=>t.spec.revision++],['fence',t=>t.fence++],['stale acceptance',t=>t.acceptance_stale=true]])test('QA02 changed D03 '+name+' invalidates proof',async()=>{
 const s=await setup(),r=await s.run();await s.stateChange(change);assert.equal(s.qa.gate(s.refs(r)).verdict,'BLOCKED');
});
test('QA02 changed source after actual research PASS invalidates report',async()=>{const s=await setup('research'),r=await s.run();const sources=s.sources;sources[0].url='https://changed.invalid';s.setSources(sources);assert.equal(s.qa.gate(s.refs(r)).verdict,'BLOCKED');});
test('QA02 source expiry after research PASS is rechecked at consumption',async()=>{const s=await setup('research'),r=await s.run();s.setNow('2026-11-05T12:00:02.000Z');assert.equal(s.qa.gate(s.refs(r)).verdict,'BLOCKED');});
test('QA02 revoked Examiner cannot keep a historical PASS',async()=>{const s=await setup(),r=await s.run();s.f.issuer.control.revoke(r.eg);assert.equal(s.qa.gate(s.refs(r)).verdict,'BLOCKED');});
test('QA02 revoked Auditor cannot keep a historical PASS',async()=>{const s=await setup(),r=await s.run();s.f.issuer.control.revoke(r.ag);assert.equal(s.qa.gate(s.refs(r)).verdict,'BLOCKED');});
test('QA02 Examiner refuses or has no grant: absent report stays blocked',async()=>{
 const s=await setup(),local=await s.qa.local();await assert.rejects(s.qa.examine(s.f.qaSession,{}),/GRANT_UNTRUSTED/);assert.equal(s.qa.gate({local,examiner:null,auditor:null}).verdict,'BLOCKED');
});
test('QA02 Auditor refuses: cannot skip audit',async()=>{const s=await setup(),local=await s.qa.local(),examiner=await s.qa.examine(s.f.qaSession,s.grant());await assert.rejects(s.qa.audit(s.auditor,{}, {local,examiner}),/GRANT_UNTRUSTED/);assert.equal(s.qa.gate({local,examiner,auditor:null}).verdict,'BLOCKED');});
test('QA02 Examiner cannot be its own Auditor',async()=>{const s=await setup(),local=await s.qa.local(),eg=s.grant(),examiner=await s.qa.examine(s.f.qaSession,eg);await assert.rejects(s.qa.audit(s.f.qaSession,eg,{local,examiner}),/QA02_ROLE_DENIED/);});
test('QA02 caller-supplied actor JSON has no identity',async()=>{const s=await setup();await assert.rejects(s.qa.examine({id:'qa',role:'EXAMINER'},{}),/IDENTITY_UNTRUSTED/);});
test('QA02 runner outage timeout is BLOCKED with ERROR execution evidence',async()=>{const s=await setup('document',{runtime:{timeout_ms:1}}),r=await s.run();assert.equal(s.qa.gate(s.refs(r)).verdict,'BLOCKED');assert.equal(s.qa.inspect(r.examiner).execution_status,'ERROR');});
test('QA02 audit for another local report cannot be reused',async()=>{const s=await setup(),r=await s.run(),local=await s.qa.local();assert.equal(s.qa.gate({...s.refs(r),local}).verdict,'BLOCKED');});
test('QA02 corrected artifact needs new version AND all three fresh reports',async()=>{
 const s=await setup('document',{text:'TODO'}),r=await s.run();assert.equal(s.qa.gate(s.refs(r)).verdict,'FAIL');s.replace(examples.document.text);
 const qa=s.make(),local=await qa.local(),eg=s.f.issuer.control.grant(s.f.qaSession,'VERIFY',qa.binding(),Date.parse(s.f.h.now())+5000),examiner=await qa.examine(s.f.qaSession,eg);
 const ag=s.f.issuer.control.grant(s.auditor,'VERIFY',qa.binding(),Date.parse(s.f.h.now())+5000),auditor=await qa.audit(s.auditor,ag,{local,examiner});
 assert.equal(qa.gate({local,examiner,auditor}).verdict,'PASS');assert.equal(s.qa.gate(s.refs(r)).verdict,'BLOCKED');
});

for(const [name,overrides,action,code] of [
 ['bounded retry',{},'REWORK','REPRODUCIBLE_DEFECT'],
 ['exhaustion',{attempts_used:2},'ESCALATE','REPAIR_LIMIT_EXHAUSTED'],
 ['zero policy',{max_attempts:0},'ESCALATE','REPAIR_LIMIT_EXHAUSTED'],
 ['deadline',{now:'2026-11-05T12:00:02.000Z'},'ESCALATE','REPAIR_DEADLINE'],
 ['budget',{remaining_budget_micros:'0'},'ESCALATE','REPAIR_BUDGET'],
 ['unknown outcome',{outcome_unknown:true},'ESCALATE','OUTCOME_UNKNOWN_RECONCILIATION_REQUIRED']])test('QA02 AUTO02 '+name,async()=>{
 const s=await setup('document',{text:'TODO'}),r=await s.run(),context=s.retryContext(overrides),before=digest(s.f.statePort.read()),a=s.qa.feedback(s.refs(r),context),b=s.qa.feedback(s.refs(r),context);
 assert.equal(a.action,action);assert.equal(a.code,code);assert.equal(a.idempotency_key,b.idempotency_key);assert.equal(digest(s.f.statePort.read()),before);
 assert.equal(a.repair.requires_full_recheck,true);assert.equal(a.repair.only_affected_task,true);assert.equal(a.trust.physical_decision,'DENY');
});
test('QA02 AUTO02 cannot inflate retry limit or forge scope',async()=>{const s=await setup(),r=await s.run();assert.throws(()=>s.qa.feedback(s.refs(r),s.retryContext({max_attempts:3})),/RETRY_LIMIT/);const c=s.retryContext();c.handoff.task_id='task_foreign';assert.throws(()=>s.qa.feedback(s.refs(r),c),/AUTO02_SCOPE/);});
test('QA02 candidate PASS requests existing gate only, never dispatch/complete',async()=>{const s=await setup(),r=await s.run(),a=s.qa.feedback(s.refs(r),s.retryContext());assert.equal(a.action,'NONE');assert.equal(a.trust.requires_existing_d08_gate,true);assert.equal(a.trust.requires_current_d03_cas,true);});
test('QA02 unknown outcome vetoes even candidate profile PASS',async()=>{const s=await setup(),r=await s.run(),a=s.qa.feedback(s.refs(r),s.retryContext({outcome_unknown:true}));assert.equal(a.action,'ESCALATE');assert.equal(a.code,'OUTCOME_UNKNOWN_RECONCILIATION_REQUIRED');});
