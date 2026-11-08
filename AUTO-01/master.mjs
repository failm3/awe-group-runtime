import {digest} from '../contracts/canonical.mjs';
import {need} from './contracts.mjs';

// Pure prompt-master policy in the existing AUTO01 profile, not a service or
// state owner. Model extraction is a proposal; material checks are deterministic.
export function analyzeDraft(input){
 const draft=structuredClone(input),issues=[...draft.contradictions];
 const add=(id,description,source_ids)=>{if(!issues.some(i=>i.id===id))issues.push({id,description,source_ids:[...new Set(source_ids)],material:true});};
 const groups=new Map();
 for(const c of draft.constraints){const key=c.dimension+'|'+c.unit;const rows=groups.get(key)??[];rows.push(c);groups.set(key,rows);}
 for(const rows of groups.values()){
  const numeric=rows.filter(c=>typeof c.value==='number'),equal=rows.filter(c=>c.operator==='EQ');
  const min=Math.max(-Infinity,...numeric.filter(c=>['MIN','EQ'].includes(c.operator)).map(c=>c.value));
  const max=Math.min(Infinity,...numeric.filter(c=>['MAX','EQ'].includes(c.operator)).map(c=>c.value));
  if(min>max)add('conflict_'+rows[0].id,'Несовместимые ограничения '+rows[0].dimension+': нижняя граница '+min+' выше верхней '+max,rows.flatMap(c=>c.source_ids));
  if(new Set(equal.map(c=>JSON.stringify(c.value))).size>1)add('equal_'+rows[0].id,'Указаны разные обязательные значения '+rows[0].dimension,rows.flatMap(c=>c.source_ids));
  for(const c of equal)if(rows.some(x=>x.operator==='EXCLUDE'&&x.value===c.value))add('exclude_'+c.id,'Одно значение одновременно требуется и запрещено: '+String(c.value),rows.flatMap(c=>c.source_ids));
 }
 for(const r of draft.resources)if(r.required&&r.availability!=='PROVIDED')add('resource_'+r.id,'Для цели отсутствует подтверждённый ресурс: '+r.description,r.source_ids);
 for(const r of [...draft.requirements,...draft.constraints,...draft.resources,...draft.completion_criteria])if(['UNKNOWN','INFERRED'].includes(r.origin))add('unconfirmed_'+r.id,'Источник требования требует подтверждения: '+(r.text??r.description??r.dimension),r.source_ids);
 for(let i=0;i<draft.assumptions.length;i++)if(draft.assumptions[i].material)add('assumption_'+i,'Требуется уточнить существенное допущение: '+draft.assumptions[i].text,[]);
 const questions=[...draft.questions];
 for(const issue of issues.filter(i=>i.material))if(!questions.some(q=>q.id===issue.id))questions.push({id:issue.id,text:issue.description+'. Уточните действующее требование.',reason:issue.id.startsWith('resource_')?'MISSING_DATA':'CONFLICT'});
 need(questions.length<=8,'AUTO01_TOO_MANY_MATERIAL_GAPS');
 return {...draft,contradictions:issues,questions};
}

export function sealSpecification(draft,record){
 need(draft.questions.length===0&&!draft.contradictions.some(c=>c.material),'AUTO01_UNRESOLVED_SPEC');
 const messages=record.history.filter(m=>m.kind==='user').map(m=>({id:m.id,text:m.text,hash:digest(m.text)}));
 return {...structuredClone(draft),original_request:structuredClone(record.original_request),source_messages:messages,
  provenance:{mode:'MOCK',message_ids:messages.map(m=>m.id),semantic_review:'MOCK_PASS',source_policy:'USER / PROJECT / INFERRED / UNKNOWN'}};
}
