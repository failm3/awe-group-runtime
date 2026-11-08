import fs from 'node:fs';
import path from 'node:path';
import {harness,scope} from '../state/harness.mjs';
import {fixture as securityFixture} from '../execution_security/fixtures.mjs';
import {fixture as memoryFixture} from '../memory_artifacts/fixtures.mjs';
import {world,request,success} from '../budget/fixtures.mjs';
import {createInt04OfflineHost} from '../../awe/integration_v4/offline-host.mjs';
export async function fixture(t,options={}){
 const directory=fs.mkdtempSync(path.resolve('INT-04/sandbox/case-'));
 const runtimeDir=fs.mkdtempSync(path.resolve('RT-01/sandbox/int04-'));
 const task={project_id:'prj_alpha',task_id:'task_one',text:options.text??'Вычислить digest синтетического текста INT-04 🧪'};
 const h=harness({serviceOptions:{pep:()=>({decision:'ALLOW'})}});
 await h.project();const spec=await h.spec('prj_alpha',{requirements:[task.text],acceptance:['INT04 E0 digest + independent D08 + owner']});
 await h.task(scope(),[],spec);await h.lease();await h.go('READY');await h.go('RUNNING');
 const sec=securityFixture({cost:'0',grantCap:'0'}),m=memoryFixture();
 sec.manifest={...sec.manifest,tool_id:'tool_int04_digest'};
 sec.registry.control.register(sec.token('registry'),sec.peer('registry'),JSON.stringify(sec.manifest));
 sec.grantRequest.tools=[(await import('../../contracts/canonical.mjs')).digest(sec.manifest)];
 sec.request.tool_id=sec.manifest.tool_id;sec.request.manifest_hash=sec.grantRequest.tools[0];
 const p=h.service.getProject(h.state,'prj_alpha');
 m.bump(w=>{w.projects.prj_alpha.spec=spec;w.projects.prj_alpha.epochs=p.epochs;w.actors.act_worker={role:'EXECUTOR',active:true,memberships:{prj_alpha:['artifact.read','memory.read']}};});
 const scopes=[{id:'scope',projectId:'prj_alpha',taskId:'task_one',originId:'origin-int04',effectSlots:['slot-one'],budgetIds:['global','project','parent','task','day','month','agent','model'],accountBudgets:{acct1:'account1',acct2:'account2'},maxAttempts:1,validUntil:9000}];
 // The delivered D06 accepts only sealed mocks. This is an explicitly named
 // test-model ACK; it never supplies the digest/tool result or a QA verdict.
 const b=world({scopes,cap:options.cap??'10000',deferred:options.deferred??false,scripts:[[options.providerFailure?{status:'TIMEOUT'}:success({output:{text:'INT04_TEST_MODEL_ACK',tools:[]}})]]});
 const modelRequest=request('one',{projectId:'prj_alpha',taskId:'task_one',maxAttempts:1});
 const host=await createInt04OfflineHost({h,sec,m,b,modelRequest,directory,journalPath:path.join(runtimeDir,'journal.jsonl'),task,options});
 t?.after(()=>host.close());return {host,directory,runtimeDir,h,sec,m,b,task};
}
fs.mkdirSync('INT-04/sandbox',{recursive:true});fs.mkdirSync('RT-01/sandbox',{recursive:true});
