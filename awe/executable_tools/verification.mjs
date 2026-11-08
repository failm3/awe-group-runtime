import {createHash} from 'node:crypto';
import {ensure,digest,bytesDigest,freeze,copy} from './protocol.mjs';
import {runProgram} from './process.mjs';
// This oracle does not import generator logic, candidate outputs or candidate tests.
// Review challenges are separate subprocess invocations from the smoke tests.
export function expectedStats(text,template='text.stats.v1'){
 const bytes=Buffer.from(text,'utf8');let points=0,lines=1;
 for(const point of text){points++;if(point==='\n')lines++;}
 const sha256='sha256:'+createHash('sha256').update(bytes).digest('hex');
 if(template==='text.word_count.v1'){let words=0,inside=false;for(const point of text){if([' ','\t','\r','\n'].includes(point))inside=false;else if(!inside){words++;inside=true;}}return {words,utf8_bytes:bytes.length,sha256};}
 ensure(template==='text.stats.v1','TOOLS_TEMPLATE');return {utf8_bytes:bytes.length,code_points:points,lines,sha256};
}
export async function verifyProgram({lock,scope,language,source,template='text.stats.v1',limits,phase}){
 ensure(['SMOKE','INDEPENDENT_CHALLENGES'].includes(phase),'TOOLS_VERIFICATION_PHASE');
 const cases=phase==='SMOKE'?['hello','one\ntwo']:['','Привет 🧪\nnext\n','a'.repeat(4096),'import os; process.exit(99); $(echo forbidden)'];
 const checks=[];
 for(const value of cases){const r=await runProgram({lock,scope,language,source,template,input:{text:value},limits});
  const expected=expectedStats(value,template);ensure(digest(r.output)===digest(expected),'TOOLS_VERIFICATION_FAILED');
  checks.push({input_digest:digest({text:value}),expected_digest:digest(expected),output_digest:digest(r.output),exit_code:r.exit_code});
 }
 return freeze({contract:'tools02.test-evidence/1',phase,source_digest:bytesDigest(Buffer.from(source)),checks});
}
