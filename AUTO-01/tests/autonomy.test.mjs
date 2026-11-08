import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../../contracts/canonical.mjs';
import {MemoryStorage} from '../../awe/state/memory-storage.mjs';
import {harness} from '../../tests/state/harness.mjs';
import {fixture} from '../fixture.mjs';
import {createMockModel,createMockExecutors} from '../mock.mjs';
import {VERSION} from '../contracts.mjs';
import {scenarios,draftFor,node} from './scenarios.mjs';

const succeeded=h=>({version:VERSION,handoff_hash:digest(h),status:'SUCCEEDED',summary:'Синтетический документ',outputs:[{name:h.deliverable,media_type:'text/markdown',text:'# Mock\n'+h.instructions}],uncertainties:[]});
const failed=h=>({...succeeded(h),status:'FAILED',summary:'Нужна другая стратегия',outputs:[]});
const assertComplete=f=>{const s=f.host.snapshot();assert.equal(s.phase,'MOCK_WORK_COMPLETED',JSON.stringify(s.blockers));assert.equal(s.realAutonomyVerified,false);assert.equal(s.accepted,false);assert.ok(Object.values(s.tasks).every(t=>t.state==='COMPLETE'));return s;};
function scenarioModel(s,overrides={}){return createMockModel({draft:c=>draftFor(s.requirements,c),plan:()=>({nodes:s.nodes}),...overrides});}

for(const scenario of scenarios)test('complex goal / '+scenario.id,async()=>{
 const f=await fixture({sessionId:scenario.id,model:scenarioModel(scenario)});
 await f.message('привет','hello');await f.message('Что ты умеешь?','capabilities');
 await f.host.converse({text:scenario.goal,idempotencyKey:'goal',expectedRevision:f.host.snapshot().revision});const s=assertComplete(f);
 const order=f.executors.calls.map(c=>c.handoff.node_id);
 for(const n of scenario.nodes)for(const dep of n.depends_on)assert.ok(order.indexOf(dep)<order.indexOf(n.id));
 assert.equal(f.model.calls.filter(c=>c.method==='next').length,scenario.nodes.length);
 assert.ok(f.model.calls.find(c=>c.method==='draft').input.history.some(m=>m.text==='привет'));
 for(const {handoff} of f.executors.calls){assert.equal(handoff.history,undefined);assert.equal(handoff.limits.network,false);assert.equal(handoff.limits.physical_decision,'DENY');assert.ok(handoff.requirements.length>0);}
 for(const [id,result] of Object.entries(s.results))for(const ref of result.artifacts){assert.ok(f.host.readArtifact(id,ref.artifact_ref).length>0);assert.match(ref.hash,/^sha256:/);}
 assert.equal(new Set(f.executors.calls.map(c=>c.id)).size>=3,true);
});

test('generated DAGs: changing size, edges, array order and policy choice',async()=>{
 let seed=17;const random=()=>{seed=(seed*1664525+1013904223)>>>0;return seed/4294967296;};
 const signatures=new Set();
 for(let k=0;k<18;k++){
  const count=3+k%9,requirements=Array.from({length:count},(_,i)=>'Цель '+k+' / результат '+i);
  let nodes=requirements.map((_,i)=>node('n'+i,i%2?'writing':'analysis',['r'+(i+1)],Array.from({length:i},(_,j)=>j).filter(()=>random()<0.3).map(j=>'n'+j)));
  const logical=structuredClone(nodes);nodes=nodes.map(n=>({n,rank:random()})).sort((a,b)=>a.rank-b.rank).map(x=>x.n);
  const model=createMockModel({draft:c=>draftFor(requirements,c),plan:()=>({nodes}),select:c=>{const n=c.ready[Math.floor(random()*c.ready.length)];return {action:'EXECUTE',node_id:n.id,executor_id:'mock_'+n.capability};}});
  const f=await fixture({model});await f.message('Произвольный комплексный проект '+k);await f.run();assertComplete(f);
  const order=f.executors.calls.map(c=>c.handoff.node_id);assert.equal(order.length,count);
  for(const n of logical)for(const dep of n.depends_on)assert.ok(order.indexOf(dep)<order.indexOf(n.id));
  signatures.add(digest(logical));
 }
 assert.equal(signatures.size,18);
});

test('dialogue context, immutable source provenance and revised spec',async()=>{
 const f=await fixture();await f.message('Привет','greeting');assert.equal(f.host.snapshot().spec,null);
 await f.message('Создай план исследования','goal');await f.run();const old=f.host.snapshot().spec;
 await f.message('Измени результат: добавь аналитическую записку','edit');
 const s=f.host.snapshot();assert.equal(s.spec.ref.revision,2);assert.equal(s.specs[0].ref.content_hash,old.ref.content_hash);assert.notEqual(s.spec.ref.content_hash,old.ref.content_hash);
 const oldTask=f.h.service.getTask(f.h.state,{project_id:'prj_alpha',task_id:'task_auto_p1_work1',operation_id:'op_auto_p1_work1'});assert.equal(oldTask.acceptance_stale,true);
 await f.run('run-v2');assertComplete(f);
});

test('material ambiguity asks once, answer becomes new draft without plan approval',async()=>{
 const model=createMockModel({draft:c=>{const d=draftFor(['План миграции'],c);if(c.history.filter(m=>m.kind==='user').length<2){d.questions=[{id:'target',text:'Какое целевое хранилище?',reason:'MISSING_DATA'}];d.assumptions=[{text:'Целевая база неизвестна',material:true}];}return d;}});
 const f=await fixture({model});await f.message('Подготовь миграцию');let s=f.host.snapshot();assert.equal(s.phase,'WAITING_FOR_USER');assert.equal(s.spec,null);assert.equal(s.plan,null);
 await f.run('waiting-run');assert.equal(f.executors.calls.length,0);
 await f.message('Только локальный mock PostgreSQL, без базы','answer');assert.equal(f.host.snapshot().drafts.length,2);assert.equal(f.host.snapshot().phase,'PLANNED');
 await f.run('after-answer');assertComplete(f);
});

test('nonmaterial assumptions do not require approval',async()=>{
 const f=await fixture({model:createMockModel({draft:c=>({...draftFor(['Текстовый отчёт'],c),assumptions:[{text:'Рабочий язык русский',material:false}]})})});
 await f.message('Подготовь отчёт');assert.equal(f.host.snapshot().questions.length,0);await f.run();assertComplete(f);
});

test('failed task triggers changed DAG and reuses exact completed predecessors',async()=>{
 const initial=[node('source','research',['r1']),node('build','coding',['r2'],['source'])];
 const repaired=[initial[0],node('diagnose','analysis',['r2'],['source']),node('build2','coding',['r2'],['diagnose'])];
 const model=createMockModel({draft:c=>draftFor(['Материал','Продукт'],c),plan:()=>({nodes:initial}),replan:()=>({nodes:repaired})});
 const executors=createMockExecutors({execute:(_,h)=>h.node_id==='build'?failed(h):succeeded(h)});
 const f=await fixture({model,executors});await f.message('Исследуй и реализуй');await f.run();const s=assertComplete(f);
 assert.equal(s.plans.length,2);assert.equal(s.replans,1);assert.equal(s.plans[1].tasks.source,s.plans[0].tasks.source);assert.equal(executors.calls.filter(c=>c.handoff.node_id==='source').length,1);
 assert.equal(f.h.service.getTask(f.h.state,{project_id:'prj_alpha',task_id:s.plans[0].tasks.build,operation_id:'op_auto_p1_build'}).state,'FAILED');
});

for(const kind of ['cycle','missing-dependency','uncovered','unknown-field','duplicate'])test('invalid plan rejected before dispatch / '+kind,async()=>{
 const nodes=[node('a','writing',['r1'])];
 if(kind==='cycle')nodes[0].depends_on=['a'];
 if(kind==='missing-dependency')nodes[0].depends_on=['missing'];
 if(kind==='uncovered')nodes[0].requirement_ids=['unknown'];
 if(kind==='unknown-field')nodes[0].authority='ALLOW';
 if(kind==='duplicate')nodes.push({...nodes[0]});
 const f=await fixture({model:createMockModel({plan:()=>({nodes})})});await f.message('Подготовь документ');assert.equal(f.host.snapshot().phase,'HOLD');assert.equal(f.executors.calls.length,0);
});

test('model cannot skip prerequisites or choose an unlisted executor',async()=>{
 for(const selection of [{node_id:'b',executor_id:'mock_writing'},{node_id:'a',executor_id:'shell'}]){
  const f=await fixture({model:createMockModel({plan:()=>({nodes:[node('a','writing',['r1']),node('b','writing',['r1'],['a'])]}),select:()=>({action:'EXECUTE',...selection})})});
  await f.message('Подготовь результат');await f.run();assert.equal(f.host.snapshot().phase,'HOLD');assert.equal(f.executors.calls.length,0);
 }
});

for(const mutation of ['binding','extra','unknown','empty'])test('structured result rejection / '+mutation,async()=>{
 const executors=createMockExecutors({execute:(_,h)=>{const r=succeeded(h);if(mutation==='binding')r.handoff_hash=digest({});if(mutation==='extra')r.actor='OWNER';if(mutation==='unknown')r.status='COMPLETE';if(mutation==='empty')r.outputs=[];return r;}});
 const f=await fixture({executors});await f.message('Подготовь отчёт');await f.run();assert.equal(f.host.snapshot().phase,'HOLD');assert.ok(Object.values(f.host.snapshot().tasks).every(t=>t.state!=='COMPLETE'));
});

test('unknown outcome stops without replanning or retry, repeat run is idempotent',async()=>{
 const executors=createMockExecutors({execute:(_,h)=>({...succeeded(h),status:'OUTCOME_UNKNOWN',outputs:[]})});
 const f=await fixture({executors});await f.message('Собери результат');await f.run();const s=f.host.snapshot();assert.equal(s.phase,'HOLD');assert.ok(s.blockers.includes('AUTO01_OUTCOME_UNKNOWN_NO_RETRY'));
 await f.run();assert.equal(executors.calls.length,1);assert.equal(f.model.calls.filter(c=>c.method==='replan').length,0);
});

test('lost result ACK exception is HOLD with no new attempt',async()=>{
 const f=await fixture({executors:createMockExecutors({execute:()=>{throw Error('lost ACK');}})});await f.message('Задача');await f.run();assert.equal(f.host.snapshot().phase,'HOLD');await f.run();assert.equal(f.executors.calls.length,1);
});

test('worker uncertainty pauses, response creates superseding spec and retires old task',async()=>{
 let once=true;const f=await fixture({executors:createMockExecutors({execute:(_,h)=>{if(once){once=false;return {...succeeded(h),status:'NEEDS_INPUT',uncertainties:[{text:'Какой язык отчёта?',material:true}]};}return succeeded(h);}})});
 await f.message('Подготовь отчёт');await f.run();assert.equal(f.host.snapshot().phase,'WAITING_FOR_USER');
 await f.message('Русский','answer');assert.equal(f.host.snapshot().spec.ref.revision,2);await f.run('resumed');assertComplete(f);
});

test('QA FAIL cannot complete task or release dependent',async()=>{
 const f=await fixture({executors:createMockExecutors({verify:()=>({verdict:'FAIL'})})});await f.message('Проверь результат');await f.run();assert.equal(f.host.snapshot().phase,'HOLD');assert.equal(Object.values(f.host.snapshot().tasks)[0].state,'QA_PENDING');
});

test('scoped artifact reads and handoff source refs cannot cross session/project',async()=>{
 const f=await fixture();await f.message('Подготовь документ');await f.run();const s=assertComplete(f),[id,result]=Object.entries(s.results)[0];
 assert.throws(()=>f.host.readArtifact('task_foreign',result.artifacts[0].artifact_ref),/ARTIFACT_SCOPE/);
 const other=await fixture({h:f.h,sessionId:'other'});assert.throws(()=>other.host.readArtifact(id,result.artifacts[0].artifact_ref),/ARTIFACT_SCOPE/);
 const foreign=await fixture({h:f.h,sessionId:'other',projectId:'prj_beta'});assert.equal(foreign.host.snapshot().history.length,0);
});

test('duplicate and concurrent intake do not create multiple specs or execute on polling',async()=>{
 const f=await fixture(),revision=f.host.snapshot().revision;
 const input={text:'Подготовь документ',idempotencyKey:'one',expectedRevision:revision};
 await Promise.all([f.host.postMessage(input),f.host.postMessage(input)]);assert.equal(f.host.snapshot().specs.length,1);assert.equal(f.executors.calls.length,0);
 assert.equal(f.host.snapshot().plan.version,1);assert.equal(f.host.snapshot().plan.version,1);
 await assert.rejects(()=>f.host.postMessage({...input,text:'Другой текст'}),/IDEMPOTENCY_CONFLICT/);
 await assert.rejects(()=>f.host.postMessage({...input,idempotencyKey:'stale'}),/STALE_REVISION/);
 await f.run();await f.run();assert.equal(f.executors.calls.length,f.host.snapshot().plan.content.nodes.length);
});

test('bounded progress yields and continues under a new command',async()=>{
 const f=await fixture();await f.message('Результат один; результат два; результат три');await f.run('step1',1);assert.equal(f.host.snapshot().phase,'YIELDED');assert.equal(f.executors.calls.length,1);
 await f.run('step2');assertComplete(f);assert.equal(f.executors.calls.length,f.host.snapshot().plan.content.nodes.length);
});

test('cancellation in flight fences late result and prevents downstream',async()=>{
 let release,entered;const gate=new Promise(r=>release=r),started=new Promise(r=>entered=r);
 const f=await fixture({executors:createMockExecutors({execute:async(_,h)=>{entered();await gate;return succeeded(h);}})});
 await f.message('Длинная работа');const running=f.run();await started;await f.host.cancel();release();await running;
 const s=f.host.snapshot();assert.equal(s.phase,'CANCELLING');assert.equal(Object.keys(s.results).length,0);assert.ok(Object.values(s.tasks).every(t=>t.cancel_requested));
});

test('expired lease and epoch change reject late structured result',async()=>{
 for(const drift of ['lease','epoch']){
  let f;f=await fixture({executors:createMockExecutors({execute:(_,h)=>{if(drift==='lease')f.h.tick(60001);else return f.h.storage.transaction(db=>{db.projects.prj_alpha.epochs.auth++;return succeeded(h);});return succeeded(h);}})});
  await f.message('Обработай данные');await f.run();assert.equal(f.host.snapshot().phase,'HOLD');assert.equal(Object.keys(f.host.snapshot().results).length,0);
 }
});

test('snapshot restore preserves conversation/spec/plan, restores HOLD without execution',async()=>{
 const f=await fixture();await f.message('Подготовь документ');await f.run('partial',1);
 const h=harness({storage:new MemoryStorage({snapshot:f.h.storage.snapshot()})}),restored=await fixture({h});
 assert.equal(restored.host.snapshot().history.length,f.host.snapshot().history.length);assert.equal(restored.host.snapshot().spec.ref.content_hash,f.host.snapshot().spec.ref.content_hash);
 await assert.rejects(()=>restored.run('restore'),/AUTO01_HOLD/);assert.equal(restored.host.snapshot().phase,'HOLD');assert.equal(restored.executors.calls.length,0);
});

test('spec semantic FAIL and invented message provenance prevent dispatch',async()=>{
 for(const kind of ['semantic','provenance']){
  const model=createMockModel();if(kind==='semantic')model.reviewSpec=async()=>({verdict:'FAIL',issues:['Intent mismatch']});
  else model.draft=async c=>{const d=draftFor(['Результат'],c);d.requirements[0].source_ids=['invented'];return d;};
  const f=await fixture({model});await f.message('Моя цель');assert.equal(f.host.snapshot().phase,'HOLD');assert.equal(f.host.snapshot().spec,null);
 }
});

test('replan bound stops an endless failing model',async()=>{
 let v=0;const model=createMockModel({plan:()=>({nodes:[node('initial','writing',['r1'])]}),replan:()=>({nodes:[node('repair'+(++v),'writing',['r1'])]})});
 const f=await fixture({model,maxReplans:1,executors:createMockExecutors({execute:(_,h)=>failed(h)})});await f.message('Сложный документ');await f.run();assert.equal(f.host.snapshot().phase,'HOLD');assert.ok(f.host.snapshot().blockers.includes('AUTO01_REPLAN_EXHAUSTED'));assert.equal(f.executors.calls.length,2);
});

test('dependency inputs are readable only through the scoped port',async()=>{
 let reads=0;
 const f=await fixture({model:createMockModel({plan:()=>({nodes:[node('first','writing',['r1']),node('second','analysis',['r1'],['first'])]})}),executors:createMockExecutors({execute:(_,h,__,readInput)=>{
  assert.throws(()=>readInput(digest({foreign:true})),/AUTO01_INPUT_SCOPE/);
  for(const ref of h.inputs){assert.match(readInput(ref.artifact_ref).toString(),/# Mock/);reads++;}
  return succeeded(h);
 }})});
 await f.message('Собери документ по предыдущему материалу');await f.run();assertComplete(f);assert.equal(reads,1);
});

test('replan retires pending nodes and preserves history of superseded work',async()=>{
 const a=node('a','writing',['r1']),b=node('b','coding',['r2'],['a']),c=node('c','qa',['r2'],['b']);
 const f=await fixture({model:createMockModel({draft:c=>draftFor(['Первое','Второе'],c),plan:()=>({nodes:[a,b,c]}),replan:()=>({nodes:[a,node('fix','writing',['r2'],['a'])]})}),executors:createMockExecutors({execute:(_,h)=>h.node_id==='b'?failed(h):succeeded(h)})});
 await f.message('Комплексная задача');await f.run();const s=assertComplete(f),old=s.plans[0].tasks.c;
 assert.equal(f.h.service.getTask(f.h.state,{project_id:'prj_alpha',task_id:old,operation_id:'op_auto_p1_c'}).state,'CANCELLING');assert.equal(f.executors.calls.some(c=>c.handoff.node_id==='c'),false);
});

test('corrupted dependency output cannot be passed to a child',async()=>{
 const {createArtifactStore}=await import('../../awe/context/store.mjs');
 const store=createArtifactStore({max_entries:20,max_bytes:100000,max_object_bytes:16384});let corrupt=false;
 const artifacts={...store,get:(...args)=>corrupt?Buffer.from('corrupt'):store.get(...args)};
 const f=await fixture({artifacts,model:createMockModel({plan:()=>({nodes:[node('a','writing',['r1']),node('b','analysis',['r1'],['a'])]})})});
 await f.message('Собери итог из исходника');await f.run('first',1);corrupt=true;await f.run('second');assert.equal(f.host.snapshot().phase,'HOLD');assert.equal(f.executors.calls.length,1);
});

test('malformed model review and material assumptions without questions are rejected',async()=>{
 for(const kind of ['review','assumption']){
  const model=createMockModel();if(kind==='review')model.reviewSpec=async()=>({verdict:'APPROVED',issues:[]});else model.draft=async c=>({...draftFor(['Документ'],c),assumptions:[{text:'Неподтверждённые личные факты',material:true}]});
  const f=await fixture({model});await f.message('Собери документ');assert.equal(f.host.snapshot().phase,kind==='review'?'HOLD':'WAITING_FOR_USER');assert.equal(f.host.snapshot().plan,null);
 }
});

test('head requests replan from a successful result and preserves completed evidence',async()=>{
 const source=node('research','research',['r1']),initial=[source,node('build','coding',['r1'],['research'])],changed=[source,node('design','writing',['r1'],['research']),node('implement','coding',['r1'],['design'])];let replanned=false;
 const model=createMockModel({plan:()=>({nodes:initial}),replan:()=>({nodes:changed}),select:c=>{
  if(c.results.length&&!replanned){replanned=true;return {action:'REPLAN',reason:'Новое свидетельство требует отдельного проектирования'};}
  const n=c.ready[0];return {action:'EXECUTE',node_id:n.id,executor_id:'mock_'+n.capability};
 }});
 const f=await fixture({model});await f.host.converse({text:'Исследуй и реализуй проект',idempotencyKey:'goal',expectedRevision:f.host.snapshot().revision});const s=assertComplete(f);
 assert.equal(s.replans,1);assert.equal(s.failures.length,0);assert.ok(s.decisions.some(d=>d.action==='REPLAN'));assert.equal(f.executors.calls.some(c=>c.handoff.node_id==='build'),false);
});

test('head asks for essential missing data without executing the ready task',async()=>{
 let asked=false;const model=createMockModel({select:c=>{if(!asked){asked=true;return {action:'ASK_USER',question:'Какая юрисдикция задана для локального исследования?',reason:'MISSING_DATA'};}const n=c.ready[0];return {action:'EXECUTE',node_id:n.id,executor_id:'mock_'+n.capability};}});
 const f=await fixture({model});await f.host.converse({text:'Подготовь сравнительное исследование правил',idempotencyKey:'goal',expectedRevision:f.host.snapshot().revision});assert.equal(f.host.snapshot().phase,'WAITING_FOR_USER');assert.equal(f.executors.calls.length,0);
 await f.host.converse({text:'Россия, без реальных юридических действий',idempotencyKey:'answer',expectedRevision:f.host.snapshot().revision});assertComplete(f);
});

test('result byte bound applies to the entire structured result',async()=>{
 const f=await fixture({executors:createMockExecutors({execute:(_,h)=>({...succeeded(h),outputs:Array.from({length:3},(_,i)=>({name:i+'.md',media_type:'text/markdown',text:'x'.repeat(6000)}))})})});
 await f.message('Большой результат');await f.run();assert.equal(f.host.snapshot().phase,'HOLD');assert.equal(Object.keys(f.host.snapshot().results).length,0);
});
