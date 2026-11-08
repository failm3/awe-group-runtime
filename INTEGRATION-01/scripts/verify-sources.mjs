import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
const root=path.resolve(import.meta.dirname,'../..'),base=path.join(root,'INTEGRATION-01');
const sha=b=>createHash('sha256').update(b).digest('hex');
export function verifySources({originals=false}={}){
 const lock=JSON.parse(fs.readFileSync(path.join(base,'SOURCE-LOCK.json'))),errors=[],originalDrift=[];let snapshots=0,live=0;
 for(const s of lock.sources)for(const f of s.files){snapshots++;const p=path.join(base,'snapshots',s.id,f.path);if(!fs.existsSync(p)||sha(fs.readFileSync(p))!==f.sha256)errors.push('SNAPSHOT '+s.id+'/'+f.path);if(originals){live++;const original=path.join(s.root,f.path);if(!fs.existsSync(original)||sha(fs.readFileSync(original))!==f.sha256)originalDrift.push({source:s.id,path:f.path,snapshot_sha256:f.sha256,current_sha256:fs.existsSync(original)?sha(fs.readFileSync(original)):null});}}
 const patched=new Set(['awe/qa/evaluator.mjs','awe/execution_security/evaluation.mjs',...JSON.parse(fs.readFileSync(path.join(base,'EXCLUDED-NATIVE.json'))).map(x=>x.path)]);
 for(const f of lock.overlays){if(patched.has(f.path))continue;if(sha(fs.readFileSync(path.join(root,f.path)))!==f.sha256)errors.push('IMPORTED_SOURCE_CHANGED '+f.path);}
 for(const f of lock.supplemental??[])if(sha(fs.readFileSync(path.join(root,f.path)))!==f.sha256)errors.push('SUPPLEMENTAL_INPUT_DRIFT '+f.path);
 const unchangedNative=fs.existsSync(path.join(root,'.git'))?execFileSync('git',['-C',root,'diff','HEAD','--name-only','--','awe/integration_v3','awe/persistence','contracts','awe/state','awe/budget'],{encoding:'utf8',env:{...process.env,GIT_OPTIONAL_LOCKS:'0'},windowsHide:true}).trim():'';if(unchangedNative)errors.push('PROTECTED_BASELINE_CHANGED '+unchangedNative);
 const result={status:errors.length?'FAIL':'PASS',snapshotFiles:snapshots,originalFilesChecked:live,originals:originals?(originalDrift.length?'CHECKED_WITH_EXTERNAL_DRIFT':'CHECKED_UNCHANGED'):'NOT_RUN_REPLAY_MODE',originalDrift,recordedAt:new Date().toISOString(),importedSourceDrift:errors,base:lock.baseline,physicalDecision:'DENY',sqlApplied:false};if(errors.length)throw Object.assign(new Error(errors.join('\n')),{result});return result;
}
if(process.argv[1]&&path.resolve(process.argv[1])===path.join(base,'scripts/verify-sources.mjs')){const result=verifySources({originals:process.argv.includes('--with-originals')});console.log(JSON.stringify(result,null,2));}
