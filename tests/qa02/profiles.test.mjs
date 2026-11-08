import test from 'node:test';
import assert from 'node:assert/strict';
import {setup,examples} from './fixtures.mjs';
import {validateProfile,digest} from '../../awe/qa_profiles/contracts.mjs';
import {toD08Evidence} from '../../awe/qa_profiles/d08-evidence.mjs';
import {validateShape} from '../../contracts/schema-validator.mjs';

for(const kind of ['document','code','research'])test('QA02 '+kind+' real D03/D07 -> Local -> blind Examiner -> mutation Auditor -> candidate PASS',async()=>{
 const s=await setup(kind),before=s.f.statePort.read(),r=await s.run(),g=s.qa.gate(s.refs(r));
 assert.equal(g.verdict,'PASS',JSON.stringify(g));assert.equal(g.authoritative_qa,'NOT_SUBMITTED');assert.equal(g.accepted,false);assert.equal(g.physical_decision,'DENY');
 assert.equal(digest(s.f.statePort.read()),digest(before));
 assert(g.evidence.every(e=>e.execution_status==='EXECUTED'&&e.rows.length===s.profile.criteria.length));
 const examiner=s.qa.inspect(r.examiner);assert(!examiner.input_keys.some(k=>/local|verdict|opinion/i.test(k)));
 assert(s.qa.inspect(r.auditor).mutations.every(m=>m.detected));
 const dto=toD08Evidence(examiner,{request_id:'req_qa02',correlation_id:'corr_qa02',actor:{identity_id:'act_examiner',role:'EXAMINER'},runner:{identity_id:'act_examiner',role:'EXAMINER'},pin:s.f.statePort.read().pin,stdout_ref:null,stderr_ref:null});
 assert.deepEqual(validateShape('qa-evidence',dto),[]);assert.equal(dto.producer_attestation,null);
});

for(const [kind,text] of [['document','# Отчёт\nTODO'],['code','module.exports.sum=(a,b)=>a-b;'],['research',JSON.stringify({claims:[{id:'claim_one',text:'Synthetic population is 99.',source_id:'source_one',quote:'Synthetic population is 42.'}]})]])test('QA02 intentionally damaged '+kind+' cannot PASS',async()=>{
 const s=await setup(kind,{text}),r=await s.run(),g=s.qa.gate(s.refs(r));assert.equal(g.verdict,'FAIL',JSON.stringify(g));assert(g.evidence.some(r=>r.rows.some(row=>row.status==='FAIL')));
 const feedback=s.qa.feedback(s.refs(r),s.retryContext());assert.equal(feedback.action,'REWORK');assert(feedback.failures.length>0);
});

test('QA02 program syntax error detected',async()=>{const s=await setup('code',{text:'module.exports.sum=()=>{'}),r=await s.run();assert.equal(s.qa.gate(s.refs(r)).verdict,'FAIL');});
test('QA02 infinite program terminates within test timeout and fails',async()=>{const s=await setup('code',{text:'module.exports.sum=()=>{while(true){}}'}),r=await s.run();assert.equal(s.qa.gate(s.refs(r)).verdict,'FAIL');});
test('QA02 program cannot use process or require in approved pure-JS harness',async()=>{const s=await setup('code',{text:'module.exports.sum=()=>process.env.USERNAME;'}),r=await s.run();assert.equal(s.qa.gate(s.refs(r)).verdict,'FAIL');});
test('QA02 arbitrary program execution requires host exact-hash allowlist',async()=>{const s=await setup('code',{runtime:{approved_artifact_hashes:[]}}),r=await s.run();assert.equal(s.qa.gate(s.refs(r)).verdict,'BLOCKED');assert.equal(s.qa.inspect(r.examiner).error,'EXECUTION_NOT_APPROVED');});
test('QA02 empty/malformed artifact fails actual criteria',async()=>{const s=await setup('document',{text:''}),r=await s.run();assert.equal(s.qa.gate(s.refs(r)).verdict,'FAIL');});
test('QA02 JSON document field checked from actual bytes',async()=>{const s=await setup('document',{text:'{"total":42}',checks:[{kind:'json-field',path:['total'],expected:42}]}),r=await s.run();assert.equal(s.qa.gate(s.refs(r)).verdict,'PASS');});

for(const variant of ['missing','hash','foreign','stale','secondary','future','forged_quote'])test('QA02 research evidence '+variant+' rejected',async()=>{
 const s=await setup('research'),sources=s.sources;
 if(variant==='missing')s.setSources([]);
 if(variant==='hash')sources[0].sha256=digest('forged');
 if(variant==='foreign')sources[0].project_id='prj_beta';
 if(variant==='stale')sources[0].fetched_at='2026-11-04T12:00:00.000Z';
 if(variant==='secondary')sources[0].primary=false;
 if(variant==='future')sources[0].fetched_at='2026-11-06T12:00:00.000Z';
 if(variant==='forged_quote'){sources[0].bytes_base64=Buffer.from('no evidence').toString('base64');const {bytesHash}=await import('../../awe/qa_profiles/contracts.mjs');sources[0].sha256=bytesHash(Buffer.from('no evidence'));}
 if(variant!=='missing')s.setSources(sources);
 const r=await s.run();assert.notEqual(s.qa.gate(s.refs(r)).verdict,'PASS');
});

test('QA02 approved criteria cannot be empty or use unknown checker',async()=>{
 const s=await setup();assert.throws(()=>validateProfile({...s.profile,criteria:[]}),/CRITERIA_REQUIRED/);
 const p=structuredClone(s.profile);p.criteria[0].check.kind='caller-pass';assert.throws(()=>validateProfile(p),/CHECK_PROFILE/);
});

test('QA02 local weak coverage audited even if its partial tests are green',async()=>{
 const s=await setup('document',{text:'# Отчёт\nTODO',local_ids:['Q01'],checks:[{kind:'contains',text:'# Отчёт'},{kind:'no-placeholder'}]}),r=await s.run();
 assert.equal(s.qa.inspect(r.local).verdict,'PASS');assert.equal(s.qa.inspect(r.examiner).verdict,'FAIL');
 assert(s.qa.inspect(r.auditor).findings.some(f=>f.code==='CRITERIA_COVERAGE'));assert.equal(s.qa.gate(s.refs(r)).verdict,'FAIL');
});

test('QA02 vacuous assertions rejected by actual mutation audit',async()=>{
 const s=await setup('document',{checks:[{kind:'contains',text:''}]}),r=await s.run();assert.equal(s.qa.inspect(r.examiner).verdict,'PASS');
 assert(s.qa.inspect(r.auditor).findings.some(f=>f.code==='MUTATION_NOT_DETECTED'));assert.equal(s.qa.gate(s.refs(r)).verdict,'UNCLEAR');
});
