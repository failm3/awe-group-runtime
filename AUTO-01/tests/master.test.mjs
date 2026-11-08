import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fixture} from '../fixture.mjs';
import {digest} from '../../contracts/canonical.mjs';
import {createMockModel} from '../mock.mjs';

test('unseen runtime-generated goals: extract all sections and autonomously execute data-derived DAGs',async()=>{
 const seed=randomBytes(4).readUInt32LE(),corpus=[];let state=seed;
 const random=()=>{state=(state*1664525+1013904223)>>>0;return state;};
 for(let i=0;i<6;i++){
  const nonce=randomUUID(),budget=1000+random()%80000,days=2+random()%20,count=2+random()%3,resourceCount=1+random()%2;
  const goals=Array.from({length:count},(_,j)=>['Исследуй','Разработай','Подготовь','Рассчитай'][j%4]+' результат '+nonce+' номер '+j);
  const resources=Array.from({length:resourceCount},(_,j)=>'dataset_'+nonce+'_'+j+'.csv');
  const prompt='Нужно '+goals.join('; ')+'. Бюджет не более '+budget+' руб. Срок '+days+' дней. Без сети и не публиковать. У меня есть '+resources.join(', ')+'. Готово, когда: каждый результат редактируется; есть таблица источников для '+nonce+'.';
  const f=await fixture();const response=await f.host.converse({text:prompt,idempotencyKey:'unknown',expectedRevision:f.host.snapshot().revision}),s=response.snapshot;
  assert.equal(s.phase,'MOCK_WORK_COMPLETED',JSON.stringify(s.blockers));
  const spec=s.spec.content;
  assert.equal(spec.original_request.text,prompt);assert.equal(spec.original_request.hash,digest(prompt));assert.equal(spec.source_messages[0].text,prompt);
  assert.equal(spec.requirements.length,count);assert.equal(spec.resources.length,resourceCount);assert.equal(spec.completion_criteria.length,2);
  assert.ok(spec.goal.includes(nonce));assert.ok(!spec.goal.includes('Бюджет'));
  assert.equal(spec.constraints.find(c=>c.dimension==='budget').value,budget);assert.equal(spec.constraints.find(c=>c.dimension==='deadline').value,days);
  assert.equal(spec.constraints.find(c=>c.dimension==='network').value,'OFFLINE');assert.equal(spec.constraints.find(c=>c.dimension==='publication').value,'DENY');
  assert.ok(spec.resources.every(r=>r.availability==='PROVIDED'&&r.source_ids[0]===spec.original_request.message_id));
  assert.ok(spec.completion_criteria.every(c=>c.requirement_ids.length===count));
  assert.equal(s.plan.content.nodes.length,count+resourceCount+2);assert.ok(Object.values(s.tasks).every(t=>t.state==='COMPLETE'));
  const planning=f.model.calls.find(c=>c.method==='plan');assert.equal(planning.input.spec.original_request.text,prompt);assert.equal(planning.input.spec.resources.length,resourceCount);
  for(const {handoff} of f.executors.calls){assert.ok(handoff.resources.length===resourceCount);assert.ok(handoff.completion_criteria.length>0);assert.equal(handoff.history,undefined);}
  corpus.push({prompt,spec_hash:s.spec.ref.content_hash,plan:s.plan.content,phase:s.phase,budget,days});
 }
 if(process.env.AUTO01_EVIDENCE_DIR){fs.mkdirSync(process.env.AUTO01_EVIDENCE_DIR,{recursive:true});fs.writeFileSync(path.join(process.env.AUTO01_EVIDENCE_DIR,'unseen-generated-goals.json'),JSON.stringify({seed,generatedAt:new Date().toISOString(),noInjectedDraftOrPlan:true,mode:'LEXICAL_MOCK_NOT_REAL_LLM',corpus},null,2));}
});

test('contradictory budget is detected even when mock semantic reviewer says PASS',async()=>{
 const f=await fixture();const prompt='Подготовь выставку редких растений. Бюджет не более 5000 руб и не менее 12000 руб. Готово, когда: есть каталог экспонатов.';
 await f.message(prompt);let s=f.host.snapshot();assert.equal(s.phase,'WAITING_FOR_USER');assert.equal(s.spec,null);assert.ok(s.drafts[0].content.contradictions.some(c=>c.material));assert.equal(f.executors.calls.length,0);
 await f.host.converse({text:'Уточнение: бюджет максимум 15000 руб, предыдущие лимиты отменяю.',idempotencyKey:'clarify',expectedRevision:s.revision});
 s=f.host.snapshot();assert.equal(s.phase,'MOCK_WORK_COMPLETED',JSON.stringify(s.blockers));assert.equal(s.spec.content.original_request.text,prompt);assert.equal(s.spec.content.source_messages.length,2);assert.equal(s.spec.content.constraints.filter(c=>c.dimension==='budget').length,1);
});

test('network contradiction and required missing resource pause without approval of plan size',async()=>{
 for(const prompt of ['Разработай план велоинфраструктуры. Только офлайн. Обязателен доступ к сети.','Подготовь каталог архива. Нет необходимого ресурса: archive.csv.']){
  const f=await fixture();await f.host.converse({text:prompt,idempotencyKey:'goal',expectedRevision:f.host.snapshot().revision});const s=f.host.snapshot();assert.equal(s.phase,'WAITING_FOR_USER');assert.ok(s.questions.length>0);assert.equal(s.plan,null);assert.equal(f.executors.calls.length,0);
 }
});

test('supplied missing resource resolves with provenance; original request stays immutable',async()=>{
 const f=await fixture(),prompt='Подготовь индекс коллекции. Нет необходимого ресурса: archive.csv.';
 await f.message(prompt);await f.host.converse({text:'Уточнение: доступны archive.csv.',idempotencyKey:'supply',expectedRevision:f.host.snapshot().revision});const s=f.host.snapshot();
 assert.equal(s.phase,'MOCK_WORK_COMPLETED',JSON.stringify(s.blockers));assert.equal(s.spec.content.original_request.text,prompt);assert.equal(s.spec.content.resources.length,1);assert.equal(s.spec.content.resources[0].availability,'PROVIDED');assert.equal(s.drafts.length,2);
});

test('JSON Schema rejects incomplete master output and untraceable readiness criteria',async()=>{
 for(const mutate of [d=>{delete d.resources;},d=>{d.completion_criteria[0].requirement_ids=['invented'];},d=>{d.resources.push({id:'r',type:'FILE',description:'file',availability:'PROVIDED',required:true,origin:'USER',source_ids:['unknown']});}]){
  const model=createMockModel(),original=model.draft;model.draft=async c=>{const d=await original(c);mutate(d);return d;};const f=await fixture({model});await f.message('Подготовь музейную экспозицию');assert.equal(f.host.snapshot().phase,'HOLD');assert.equal(f.host.snapshot().spec,null);
 }
});

test('inferred and unknown requirements remain proposals until clarification',async()=>{
 for(const origin of ['INFERRED','UNKNOWN']){
  const model=createMockModel(),original=model.draft;model.draft=async c=>{const d=await original(c);d.requirements[0].origin=origin;return d;};
  const f=await fixture({model});await f.message('Создай каталог');const s=f.host.snapshot();assert.equal(s.phase,'WAITING_FOR_USER');assert.equal(s.spec,null);assert.equal(f.executors.calls.length,0);
 }
});
