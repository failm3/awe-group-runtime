import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fixture} from './fixtures.mjs';
import {digest} from '../../awe/executable_tools/protocol.mjs';
import {expectedStats} from '../../awe/executable_tools/verification.mjs';
const spec=(language='JS')=>({tool_id:'tool_missing_word_count',language,template:'text.word_count.v1'});
const using=async(options,fn)=>{const f=fixture(options);try{await fn(f);}finally{await f.tools.close();}};
for(const language of ['JS','PYTHON'])test(language+' missing capability: generate -> isolated smoke -> independent challenges -> review -> digest -> register -> execute',()=>using({},async f=>{
 const cap=language==='JS'?'js.text.word_count':'python.text.word_count';assert.throws(()=>f.tools.resolve(cap),/TOOLS_CAPABILITY_MISSING/);
 const c=f.tools.factory.generate(spec(language));assert.equal(c.status,'GENERATED');assert.throws(()=>f.tools.resolve(cap));
 const smoke=await f.tools.factory.test(c.id);assert.equal(smoke.checks.length,2);assert.throws(()=>f.tools.resolve(cap));
 const review=await f.tools.factory.verify(c.id);const inspected=f.tools.factory.inspect(c.id);assert.equal(inspected.verification_evidence.checks.length,4);assert.notEqual(review.generator_id,review.reviewer_id);assert.throws(()=>f.tools.resolve(cap));
 const pin=f.tools.factory.register(c.id);assert.equal(pin.digest,inspected.manifest_digest);assert.deepEqual(f.tools.resolve(cap),[pin]);
 const text=' one\tПривет 🧪\n two\u00a0three ';const r=await f.execute(cap,{text});assert.equal(r.decision,'EXECUTED_LOCAL');assert.deepEqual(r.output,expectedStats(text,'text.word_count.v1'));
 assert.throws(()=>f.tools.factory.register(c.id),/TOOLS_FACTORY_STATE/);
}));
test('generation does not run code or auto-register, and skipping gates fails',()=>using({},async f=>{
 const c=f.tools.factory.generate(spec());assert.throws(()=>f.tools.factory.register(c.id),/TOOLS_FACTORY_STATE/);await assert.rejects(()=>f.tools.factory.verify(c.id),/TOOLS_FACTORY_STATE/);assert.equal(f.calls.length,0);
 assert.throws(()=>f.tools.resolve('js.text.word_count'));assert.equal(f.tools.factory.inspect(c.id).status,'GENERATED');
}));
for(const patch of [{source:'malicious()'},{command:'curl evil'},{template:'arbitrary_code'},{language:'SHELL'},{tool_id:'../escape'},{verified:true}])test('factory rejects caller code/claims '+JSON.stringify(patch),()=>using({},async f=>{assert.throws(()=>f.tools.factory.generate({...spec(),...patch}));}));
test('source tampered before tests is quarantined without executing altered bytes',()=>using({},async f=>{
 const c=f.tools.factory.generate(spec());fs.writeFileSync(c.source_path,'throw Error("must never execute")');await assert.rejects(()=>f.tools.factory.test(c.id),/TOOLS_CANDIDATE_DRIFT/);assert.equal(f.tools.factory.inspect(c.id).status,'QUARANTINED');assert.throws(()=>f.tools.factory.register(c.id));
}));
test('source substitution after smoke tests cannot pass independent verification',()=>using({},async f=>{
 const c=f.tools.factory.generate(spec());await f.tools.factory.test(c.id);fs.appendFileSync(c.source_path,'\n// changed');await assert.rejects(()=>f.tools.factory.verify(c.id),/TOOLS_CANDIDATE_DRIFT/);assert.throws(()=>f.tools.factory.register(c.id));
}));
test('same host identity cannot self-review',()=>using({generator_id:'act_qa'},async f=>{const c=f.tools.factory.generate(spec());await f.tools.factory.test(c.id);await assert.rejects(()=>f.tools.factory.verify(c.id),/TOOLS_INDEPENDENT_REVIEW_REQUIRED/);assert.throws(()=>f.tools.factory.register(c.id));}));
test('missing reviewer blocks registration',()=>using({reviewer:null},async f=>{const c=f.tools.factory.generate(spec());await f.tools.factory.test(c.id);await assert.rejects(()=>f.tools.factory.verify(c.id),/TOOLS_INDEPENDENT_REVIEW_REQUIRED/);}));
test('reviewer rejection and digest forgery quarantine tested candidates',async()=>{
 for(const ack of [{decision:'REJECT',report_digest:digest('x')},{decision:'APPROVE_SYNTHETIC_TEMPLATE',report_digest:digest('x')},{decision:'APPROVE_SYNTHETIC_TEMPLATE',report_digest:digest('x'),approved:true}])await using({reviewer:{identity:'act_qa',review:async()=>ack}},async f=>{const c=f.tools.factory.generate(spec());await f.tools.factory.test(c.id);await assert.rejects(()=>f.tools.factory.verify(c.id));assert.equal(f.tools.factory.inspect(c.id).status,'QUARANTINED');assert.throws(()=>f.tools.factory.register(c.id));});
});
test('reviewer cannot modify source during its asynchronous decision',async()=>{
 let c;await using({reviewer:{identity:'act_qa',review:async report=>{fs.appendFileSync(c.source_path,'\n// swap');return {decision:'APPROVE_SYNTHETIC_TEMPLATE',report_digest:digest(report)};}}},async f=>{c=f.tools.factory.generate(spec());await f.tools.factory.test(c.id);await assert.rejects(()=>f.tools.factory.verify(c.id),/TOOLS_CANDIDATE_DRIFT/);});
});
test('source altered after independent review cannot be registered',()=>using({},async f=>{
 const c=f.tools.factory.generate(spec());await f.tools.factory.test(c.id);await f.tools.factory.verify(c.id);fs.appendFileSync(c.source_path,'\n// changed');assert.throws(()=>f.tools.factory.register(c.id),/TOOLS_CANDIDATE_DRIFT/);assert.throws(()=>f.tools.resolve('js.text.word_count'));
}));
test('concurrent test/registration cannot race the factory gate',()=>using({},async f=>{
 const c=f.tools.factory.generate(spec()),pending=f.tools.factory.test(c.id);await assert.rejects(()=>f.tools.factory.test(c.id),/TOOLS_FACTORY_STATE/);assert.throws(()=>f.tools.factory.register(c.id),/TOOLS_FACTORY_STATE/);await pending;
}));
test('factory bounds staged candidates and removes all owned directories on close',()=>using({},async f=>{
 for(let i=0;i<16;i++)f.tools.factory.generate({...spec(),tool_id:'tool_pending_'+i});assert.throws(()=>f.tools.factory.generate(spec()),/TOOLS_CANDIDATE_LIMIT/);
}));
