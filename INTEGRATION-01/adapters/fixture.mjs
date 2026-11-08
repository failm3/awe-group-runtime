import fs from 'node:fs';
import path from 'node:path';
import {harness,scope} from '../../tests/state/harness.mjs';
import {fixture as securityFixture} from '../../tests/execution_security/fixtures.mjs';
import {fixture as memoryFixture} from './d07-fixture.mjs';
import {createFileStore} from './file-store.mjs';
import {world,request,route} from '../../tests/budget/fixtures.mjs';
import {digest} from '../../contracts/canonical.mjs';
import {createInt04OfflineHost} from './int04-host.mjs';
const root=path.resolve(import.meta.dirname,'../..');
export async function createCase({directory,text,scenario='normal'}={}){
 fs.mkdirSync(directory,{recursive:true});const rtBase=path.join(root,'RT-01/sandbox');fs.mkdirSync(rtBase,{recursive:true});
 const runtimeDir=fs.mkdtempSync(path.join(rtBase,'integration01-'));
 const task={project_id:'prj_alpha',task_id:'task_one',text};
 const h=harness({serviceOptions:{pep:()=>({decision:'ALLOW'})}});
 await h.project();const spec=await h.spec('prj_alpha',{requirements:[text],acceptance:['INTEGRATION01 bounded offline digest / actual processes / fixed D08']});
 await h.task(scope(),[],spec);await h.lease();await h.go('READY');await h.go('RUNNING');
 const sec=securityFixture({cost:'0',grantCap:'0'}),m=memoryFixture({storeFactory:id=>createFileStore(path.join(directory,'d07',id),id)});
 sec.manifest={...sec.manifest,tool_id:'tool_int04_digest'};sec.registry.control.register(sec.token('registry'),sec.peer('registry'),JSON.stringify(sec.manifest));
 sec.grantRequest.tools=[digest(sec.manifest)];sec.request.tool_id=sec.manifest.tool_id;sec.request.manifest_hash=sec.grantRequest.tools[0];
 const p=h.service.getProject(h.state,'prj_alpha');m.bump(w=>{w.projects.prj_alpha.spec=spec;w.projects.prj_alpha.epochs=p.epochs;w.actors.act_worker={role:'EXECUTOR',active:true,memberships:{prj_alpha:['artifact.read','memory.read']}};});
 const scopes=[{id:'scope',projectId:'prj_alpha',taskId:'task_one',originId:'origin-int04',effectSlots:['slot-one'],budgetIds:['global','project','parent','task','day','month','agent','model'],accountBudgets:{acct1:'account1',acct2:'account2'},maxAttempts:1,validUntil:9000}];
 const r=route();r.capabilities.contextTokens=20000;r.price.binding.contextTokens=20000;
 const w=world({routes:[r],scopes,cap:'10000'}),b={ledger:w.ledger,routes:w.routes};
 const modelRequest=request('one',{projectId:'prj_alpha',taskId:'task_one',maxAttempts:1});
 const options={childFailure:scenario==='child-failure',lostAck:scenario==='lost-ack',providerFailure:scenario==='provider-timeout',qaFailure:scenario==='qa-failure'};
 const host=await createInt04OfflineHost({h,sec,m,b,modelRequest,directory,journalPath:path.join(runtimeDir,'journal.jsonl'),task,options});
 return {host,h,sec,m,b,task,directory,runtimeDir};
}
