import {mkdirSync,writeFileSync} from 'node:fs';
import {setup,examples} from '../tests/qa02/fixtures.mjs';
import {toD08Evidence} from '../awe/qa_profiles/d08-evidence.mjs';
const out=new URL('./evidence/demo/',import.meta.url);mkdirSync(out,{recursive:true});
const summary=[];
for(const kind of ['web','code','research','document']){
 const s=await setup(kind),r=await s.run(),gate=s.qa.gate(s.refs(r));
 const dto=toD08Evidence(s.qa.inspect(r.examiner),{request_id:'req_qa02_demo',correlation_id:'corr_qa02_demo',actor:{identity_id:'act_examiner',role:'EXAMINER'},runner:{identity_id:'act_examiner',role:'EXAMINER'},pin:s.f.statePort.read().pin,stdout_ref:null,stderr_ref:null});
 writeFileSync(new URL(kind+'.json',out),JSON.stringify({gate,feedback:s.qa.feedback(s.refs(r),s.retryContext()),d08_envelope:dto},null,2)+'\n');
 writeFileSync(new URL(kind+'-profile.json',out),JSON.stringify(s.profile,null,2)+'\n');
 writeFileSync(new URL(kind+'-artifact.txt',out),examples[kind].text);
 summary.push({profile:kind,verdict:gate.verdict,artifact:gate.artifact.file_hash});
 if(gate.verdict!=='PASS')process.exitCode=1;
}
const broken=await setup('document',{text:'TODO'}),r=await broken.run();
writeFileSync(new URL('auto02-rework.json',out),JSON.stringify(broken.qa.feedback(broken.refs(r),broken.retryContext()),null,2)+'\n');
console.log(JSON.stringify({version:'qa02/1',summary,authoritative_qa:'NOT_SUBMITTED',physical_decision:'DENY'}));
