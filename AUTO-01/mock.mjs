import {digest} from '../contracts/canonical.mjs';
import {need,VERSION} from './contracts.mjs';
import {extractMockDraft,planMockDraft} from './mock-extraction.mjs';

// Explicit local structured-model test double. No SDK, route, network, real
// reasoning claim, or goal-specific dispatch branch exists in the coordinator.
export function createMockModel({draft,plan,replan=plan,intake,select}={}){
 const calls=[];
 const model={mode:'MOCK',calls};
 const record=(name,fn)=>async input=>{calls.push({method:name,input:structuredClone(input)});return structuredClone(await fn(input));};
 model.intake=record('intake',intake??(c=>{
  const last=c.history.at(-1).text.trim();
  if(/^(привет|здравствуй|hello|hi)[!. ]*$/iu.test(last))return {kind:'CHAT',reply:'Привет! Сохраняю контекст этой локальной беседы. Опишите цель обычными словами.'};
  if(/что ты умеешь|what can you do/iu.test(last))return {kind:'CHAT',reply:'В этом кандидате доступны локальные mock ТЗ, DAG, специализации, результаты и перепланирование. Реальные модели, Hermes, сеть и внешние действия отключены.'};
  return {kind:c.questions.length?'ANSWER':'GOAL',reply:'Сформирую версию ТЗ и проверю зависимости. Результаты этого профиля синтетические.'};
 }));
 model.draft=record('draft',draft??extractMockDraft);
 model.reviewSpec=record('reviewSpec',()=>({verdict:'PASS',issues:[]}));
 const defaultPlan=planMockDraft;
 model.plan=record('plan',plan??defaultPlan);
 model.replan=record('replan',replan??defaultPlan);
 model.next=record('next',select??(c=>{
  // The mock policy may choose any ready node, independent of source order.
  const n=[...c.ready].sort((a,b)=>b.id.localeCompare(a.id))[0];
  return {action:'EXECUTE',node_id:n.id,executor_id:c.executors.find(e=>e.capabilities.includes(n.capability))?.id??'missing'};
 }));
 return model;
}

export function createMockExecutors({execute,verify,capabilities=['research','writing','coding','analysis','qa']}={}){
 const calls=[],profiles=capabilities.map(cap=>({id:'mock_'+cap,mode:'MOCK',capabilities:[cap]}));
 return {mode:'MOCK',calls,capabilities:()=>structuredClone(profiles),list:cap=>structuredClone(profiles.filter(e=>e.capabilities.includes(cap))),
  async execute(id,handoff,readInput){
   need(profiles.some(e=>e.id===id&&e.capabilities.includes(handoff.capability)),'AUTO01_MOCK_EXECUTOR');
   calls.push({id,handoff:structuredClone(handoff)});
   if(execute)return execute(id,structuredClone(handoff),calls.length,readInput);
   return {version:VERSION,handoff_hash:digest(handoff),status:'SUCCEEDED',summary:'MOCK '+handoff.capability+': '+handoff.deliverable,
    outputs:[{name:handoff.deliverable,media_type:'text/markdown',text:'# Синтетический результат AUTO-01\n\n'+handoff.instructions+'\n\nТребования: '+handoff.requirements.map(r=>r.id).join(', ')+'\nВходные артефакты: '+handoff.inputs.map(i=>i.hash).join(', ')+'\n\nНе является исследованием рынка или реальным продуктом.'}],uncertainties:[]};
  },
  async verify({handoff,result}){return verify?verify({handoff,result}):{verdict:'MOCK_PASS',handoff_hash:digest(handoff),result_hash:digest(result)};}
 };
}
