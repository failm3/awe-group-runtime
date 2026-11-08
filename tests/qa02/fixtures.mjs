import {readFileSync} from 'node:fs';
import {fixture as d08Fixture} from '../qa/fixtures.mjs';
import {createD07ArtifactReader} from '../../awe/qa/ports.mjs';
import {createProfileQa} from '../../awe/qa_profiles/service.mjs';
import {bytesHash,copy,digest} from '../../awe/qa_profiles/contracts.mjs';

export const browserPaths={
 playwright_module:'C:/Users/1/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright/index.mjs',
 chromium_executable:'C:/Users/1/AppData/Local/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-win64/chrome-headless-shell.exe'
};
export const examples={
 web:{text:'<!doctype html><html lang="ru"><meta name="viewport" content="width=device-width,initial-scale=1"><style>*{box-sizing:border-box}body{margin:0;max-width:100%}input{max-width:80%}</style><h1>Заявка</h1><label for="name">Имя</label><input id="name"><button id="submit" onclick="document.querySelector(\'#result\').textContent=\'Готово, \'+document.querySelector(\'#name\').value">Отправить</button><output id="result"></output></html>',checks:[
  {kind:'web-text',selector:'h1',expected:'Заявка'},
  {kind:'web-action',input:'#name',value:'Анна',click:'#submit',result:'#result',expected:'Готово, Анна'},
  {kind:'web-responsive',widths:[320,768,1440]}]},
 code:{text:'module.exports.sum=(a,b)=>a+b;',checks:[{kind:'code-case',export_name:'sum',args:[2,3],expected:5},{kind:'code-case',export_name:'sum',args:[-4,3],expected:-1},{kind:'code-case',export_name:'sum',args:[0,0],expected:0}]},
 research:{text:JSON.stringify({claims:[{id:'claim_one',text:'Synthetic population is 42.',source_id:'source_one',quote:'Synthetic population is 42.'}]}),checks:[{kind:'claim',claim_id:'claim_one',source_id:'source_one',expected_claim:'Synthetic population is 42.',quote:'Synthetic population is 42.',max_age_ms:1000}]},
 document:{text:'# Отчёт\n\n## Результат\nСумма: 42\n\n## Ограничения\nТолько офлайн.\n',checks:[{kind:'markdown-sections',headings:['# Отчёт','## Результат','## Ограничения']},{kind:'contains',text:'Сумма: 42'},{kind:'no-placeholder'}]}
};
export async function setup(kind='document',options={}){
 const f=await d08Fixture();
 const text=options.text??examples[kind].text;
 const criteria=(options.checks??examples[kind].checks).map((check,i)=>({id:'Q'+String(i+1).padStart(2,'0'),requirement_id:'req_'+(i+1),check:copy(check)}));
 const profile={version:'qa02/1',profile:kind,scope:f.statePort.read().pin.scope,spec:f.statePort.read().pin.spec,criteria,local_ids:options.local_ids??criteria.map(c=>c.id)};
 const file=[{path:'qa02/result.txt',media_type:'text/plain',bytes:Buffer.from(text)}];
 let out=f.j.m.stageArtifact('art_qa02_output',file),head={project_id:profile.scope.project_id,task_id:profile.scope.task_id,
  artifact:out.reference.artifact,version:out.version,file_hash:bytesHash(file[0].bytes),bytes:file[0].bytes.length,path:file[0].path,provenance_hash:out.provenance_hash};
 const artifacts=createD07ArtifactReader({artifacts:f.j.m.artifacts,token:f.j.m.session('act_examiner'),readHead:()=>head});
 const postSave=createD07ArtifactReader({artifacts:f.j.m.artifacts,token:f.j.m.session('act_auditor'),readHead:()=>head});
 let sourceText='Official synthetic census. Synthetic population is 42. Data are synthetic.',sources=[{id:'source_one',project_id:profile.scope.project_id,url:'https://census.invalid/synthetic',primary:true,fetched_at:f.h.now(),bytes_base64:Buffer.from(sourceText).toString('base64'),sha256:bytesHash(Buffer.from(sourceText))}];
 let now=f.h.now(),postFault=false;
 const runtime={approved_artifact_hashes:[head.file_hash],...options.runtime};
 if(kind==='web'&&!options.withoutBrowser){Object.assign(runtime,browserPaths);runtime.playwright_sha256=bytesHash(readFileSync(runtime.playwright_module));runtime.chromium_sha256=bytesHash(readFileSync(runtime.chromium_executable));}
 const make=(changes={})=>createProfileQa({statePort:f.statePort,artifacts,postSaveArtifacts:{read(r){if(postFault)throw Error('POST_SAVE_UNAVAILABLE');return postSave.read(r);}},issuer:f.issuer,requirements:profile,reference:head,sourceReader:()=>sources,runtime,clock:()=>now,...changes});
 const qa=make(),auditor=f.issuer.control.session('auditor');
 const grant=(session=f.qaSession)=>f.issuer.control.grant(session,'VERIFY',qa.binding(),Date.parse(f.h.now())+5000);
 async function run(){const local=await qa.local(),eg=grant(),examiner=await qa.examine(f.qaSession,eg),ag=grant(auditor),audit=await qa.audit(auditor,ag,{local,examiner});return {local,examiner,auditor:audit,eg,ag};}
 const refs=r=>({local:r.local,examiner:r.examiner,auditor:r.auditor});
 const retryContext=(overrides={})=>({handoff:{version:'auto01/1',project_id:head.project_id,task_id:head.task_id,spec:copy(profile.spec),plan_hash:digest({plan:1}),node_hash:digest({node:1}),node_id:'node_one',revision:f.statePort.read().pin.revision,fence:f.statePort.read().pin.fence},attempts_used:0,max_attempts:2,deadline:'2026-11-05T12:00:01.000Z',remaining_budget_micros:'100',now:f.h.now(),outcome_unknown:false,...overrides});
 return {f,profile,qa,head,artifacts,postSave,make,auditor,grant,run,refs,retryContext,
  setSources(value){sources=copy(value);},get sources(){return copy(sources);},setNow(value){now=value;},setPostFault(value){postFault=value;},
  corrupt(){for(const store of [f.j.m.primary,f.j.m.replica])for(const key of store.keys())if(store.bytes(key).equals(file[0].bytes))store.corrupt(key,Buffer.from('damaged'));},
  async stateChange(change){await f.h.storage.transaction(db=>change(db.projects.prj_alpha.tasks.task_one));},
  replace(value){const bytes=Buffer.from(value);out=f.j.m.stageArtifact('art_qa02_output',[{...file[0],bytes}],{version:head.version+1});head={...head,artifact:out.reference.artifact,version:out.version,file_hash:bytesHash(bytes),bytes:bytes.length,provenance_hash:out.provenance_hash};return copy(head);}
 };
}
