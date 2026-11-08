import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createOfflineServer} from '../server.mjs';
// The actual integrated UI/HTTP adapter/controller/services execute on Node 24.
// Minimal DOM host does not establish browser rendering, layout or focus QA.
test('UI input -> real local HTTP -> existing coordinator/workers/model/D07/D08 -> Studio and owner action',async()=>{
 const baseDir=path.resolve(import.meta.dirname,'../sandbox');fs.mkdirSync(baseDir,{recursive:true});const app=await createOfflineServer({dataDir:fs.mkdtempSync(path.join(baseDir,'ui-'))});await new Promise(r=>app.server.listen(0,'127.0.0.1',r));
 const base='http://127.0.0.1:'+app.server.address().port,originalFetch=globalThis.fetch;
 const names=['document','window','sessionStorage','localStorage','matchMedia','CSS'];const prior=new Map(names.map(k=>[k,Object.getOwnPropertyDescriptor(globalThis,k)]));
 const listeners=new Map(),windows=new Map(),storage=()=>{const m=new Map();return {getItem:k=>m.get(k)||null,setItem:(k,v)=>m.set(k,v),removeItem:k=>m.delete(k)};};
 const element=(id='')=>({id,dataset:{},innerHTML:'',textContent:'',open:false,disabled:false,scrollTop:0,scrollHeight:100,classList:{add(){},remove(){}},focus(){document.activeElement=this;},setSelectionRange(){},contains(){return false;},querySelector(){return null;},addEventListener(){},showModal(){this.open=true;},close(){this.open=false;}});
 const body=element(),view=element('app'),dialog=element('dialog'),notice=element('notice'),composer=element('composer'),nodes=new Map([['#app',view],['#dialog',dialog],['#main',element('main')],['#composer',composer],['#notice',notice],['.chat-messages',element()]]);
 const doc={body,activeElement:body,documentElement:{dataset:{}},querySelector:s=>nodes.get(s)||null,getElementById:id=>nodes.get('#'+id)||null,addEventListener:(type,fn)=>listeners.set(type,fn)};
 const env={document:doc,window:{addEventListener:(type,fn)=>windows.set(type,fn)},sessionStorage:storage(),localStorage:storage(),matchMedia:()=>({matches:false}),CSS:{escape:s=>String(s).replace(/[^\w-]/g,'_')}};
 for(const k of names)Object.defineProperty(globalThis,k,{value:env[k],configurable:true,writable:true});globalThis.fetch=(url,options)=>originalFetch(new URL(url,base),options);
 const click=dataset=>listeners.get('click')({target:{closest:()=>({dataset,disabled:false})},preventDefault(){}});
 const until=async(fn)=>{const deadline=Date.now()+8000;while(!fn()){if(Date.now()>deadline){fs.mkdirSync('INTEGRATION-01/evidence/development',{recursive:true});fs.writeFileSync('INTEGRATION-01/evidence/development/ui-timeout.html',view.innerHTML);throw Error('Integrated UI failed to reach expected state; actual render saved.');};await new Promise(r=>setTimeout(r,20));}};
 try{
  await import('../ui/src/app.mjs?integrated-ui-test');await until(()=>view.innerHTML.includes('app-shell'));
  assert(view.innerHTML.includes('Офлайн backend'));assert(!view.innerHTML.includes('backend и Hermes не подключены'));
  click({action:'new'});const text='Сквозная задача из UI <img src=x onerror=alert(1)> 🧪';listeners.get('input')({target:{id:'composer',value:text,hasAttribute:()=>false}});listeners.get('submit')({target:{id:'composer-form'},preventDefault(){}});
  await until(()=>notice.textContent.includes('Задача принята фактическим'));await until(()=>app.controller.getSnapshot().qa.length===2);
  assert.equal(app.controller.testCase().task.text,text);assert.equal(app.controller.getSnapshot().runtime.spawn_count,2);assert(view.innerHTML.includes('&lt;img src=x onerror=alert(1)&gt;'));assert(!view.innerHTML.includes('<img src=x onerror=alert(1)>'));
  click({mode:'studio'});await until(()=>view.innerHTML.includes('INTEGRATION01-result.json'));assert(view.innerHTML.includes('INTEGRATION01_OUTPUT_V1'));assert.equal((view.innerHTML.match(/>Пройдено<\/span>/g)||[]).length,2);assert(view.innerHTML.includes('QA_PENDING'));
  assert(!/data-action="(tick|background|autoplay|scenario|reset)"/.test(view.innerHTML));
  click({action:'mock-controls'});assert(dialog.innerHTML.includes('Кнопок имитации прогресса нет'));assert(!/data-action="(tick|background|autoplay|scenario|reset)"/.test(dialog.innerHTML));click({action:'close-dialog'});
  click({action:'accept'});assert(dialog.open);click({action:'confirm-accept'});await until(()=>app.controller.getSnapshot().artifacts[0].acceptance==='ACCEPTED'&&view.innerHTML.includes('Принято'));
  const s=app.controller.getSnapshot();assert.equal(s.tasks[0].nativeState,'QA_PENDING');assert.equal(s.tasks[0].authoritativeComplete,false);assert.equal(s.artifacts[0].published,false);
  const rendered=path.resolve('INTEGRATION-01/evidence/scenarios');fs.mkdirSync(rendered,{recursive:true});fs.writeFileSync(path.join(rendered,'ui-node24.json'),JSON.stringify({status:'PASS',node:process.version,textEscaped:true,apiTransport:'actual same-origin HTTP',actualProcessCount:s.runtime.spawn_count,qa:s.qa.map(q=>({role:q.role,verdict:q.verdict})),ownerAcceptance:s.artifacts[0].acceptance,nativeTaskState:s.tasks[0].nativeState,browserQa:'NOT_RUN',layoutVerification:false},null,2));
 }finally{
  windows.get('pagehide')?.();await app.close();globalThis.fetch=originalFetch;for(const [k,d]of prior)if(d)Object.defineProperty(globalThis,k,d);else delete globalThis[k];
 }
});
