import test from 'node:test';
import assert from 'node:assert/strict';
import {setup,examples} from './fixtures.mjs';

test('QA02 WEB real Chromium text/form/320+768+1440 scenarios and mutation audit',async()=>{
 const s=await setup('web'),r=await s.run(),g=s.qa.gate(s.refs(r));assert.equal(g.verdict,'PASS',JSON.stringify(g));
 assert(s.qa.inspect(r.examiner).environment.browser);assert(s.qa.inspect(r.auditor).mutations.every(m=>m.detected));
 assert.equal(s.qa.inspect(r.examiner).environment.browser_closed,true);
});
test('QA02 WEB intentionally broken form detected despite page heading PASS',async()=>{
 const s=await setup('web',{text:examples.web.text.replace(".value\"", ".value+' WRONG'\""),local_ids:['Q01']}),r=await s.run();
 assert.equal(s.qa.inspect(r.local).verdict,'PASS');assert.equal(s.qa.inspect(r.examiner).verdict,'FAIL');assert.equal(s.qa.gate(s.refs(r)).verdict,'FAIL');
});
test('QA02 WEB actual horizontal overflow rejected',async()=>{
 const s=await setup('web',{text:examples.web.text.replace('</style>','body{min-width:2000px}</style>')}),r=await s.run();assert.equal(s.qa.gate(s.refs(r)).verdict,'FAIL');
});
test('QA02 WEB unavailable browser cannot turn missing tests green',async()=>{const s=await setup('web',{withoutBrowser:true}),r=await s.run();assert.equal(s.qa.gate(s.refs(r)).verdict,'BLOCKED');assert.equal(s.qa.inspect(r.examiner).error,'BROWSER_UNAVAILABLE');});
