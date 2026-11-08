import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {fixture} from '../tests/executable_tools/fixtures.mjs';
import {bytesDigest,digest} from '../awe/executable_tools/protocol.mjs';
const output=fileURLToPath(new URL('./examples/',import.meta.url));fs.mkdirSync(output,{recursive:true});
const f=fixture();
try{
 const c=f.tools.factory.generate({tool_id:'tool_generated_words',language:'JS',template:'text.word_count.v1'});
 const smoke=await f.tools.factory.test(c.id),review=await f.tools.factory.verify(c.id),pin=f.tools.factory.register(c.id),manifest=f.tools.manifest(pin),v=f.tools.factory.inspect(c.id);
 if(bytesDigest(Buffer.from(v.source))!==manifest.source_digest||digest(manifest)!==pin.digest)throw Error('EXAMPLE_DIGEST');
 const result=await f.execute('js.text.word_count',{text:'synthetic example'});if(result.decision!=='EXECUTED_LOCAL')throw Error('EXAMPLE_EXECUTION');
 fs.writeFileSync(path.join(output,'word-count.mjs'),v.source);
 fs.writeFileSync(path.join(output,'registered-tool.json'),JSON.stringify({contract:'tools02.reviewable-example/1',scope:'SYNTHETIC_SELF_RUN_ONLY',registration:'REGISTERED_IN_LOCAL_HOST',pin,manifest,source_file:'word-count.mjs',smoke,independent_challenges:v.verification_evidence,review,reviewer_fixture:true,independent_acceptance:'NOT_RUN',result},null,2)+'\n');
 console.log(JSON.stringify({status:'PASS',pin,source_digest:manifest.source_digest,word_count:result.output.words,independent_acceptance:'NOT_RUN'}));
}finally{await f.tools.close();}
