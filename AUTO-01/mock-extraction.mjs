// Generic bounded Russian extraction for the LOCAL MOCK, with explicit lexical
// coverage. This is not a language model or evidence of general semantic skill.
// There are no topic names, scenario IDs, task lists or domain dispatch tables.
export function extractMockDraft(context){
 const users=context.history.filter(m=>m.kind==='user');
 const start=users.findIndex(m=>m.id===context.original_request?.message_id);
 const messages=users.slice(Math.max(start,0));
 const constraints=[{id:'local',dimension:'scope',operator:'EQ',value:'E0 OFFLINE MOCK',unit:'',source_ids:['policy_e0'],origin:'PROJECT'}],resources=[],goals=[],criteria=[];
 let serial=0;
 const source=m=>({source_ids:[m.id],origin:'USER'});
 for(const m of messages){
  const correction=/уточнен|исправлен|отменя|замени|вместо прежн/iu.test(m.text),newConstraints=[];
  const statements=m.text.split(/[.!?]+(?:\s+|$)|\n+/u).map(t=>t.trim()).filter(Boolean);
  for(const raw of statements){
   const t=raw.replace(/^[«»" ]+|[«»" ]+$/gu,'');
   let classified=false;
   for(const match of t.matchAll(/(?:бюджет|стоимость|затраты|расходы)?\s*(не более|не меньше|не менее|минимум|максимум|до|от|ровно)\s*(\d[\d ]*)\s*(руб(?:лей|ля)?|₽)/giu)){
    const value=Number(match[2].replaceAll(' ',''));newConstraints.push({id:'limit'+(++serial),dimension:'budget',operator:/менее|меньше|минимум|^от$/iu.test(match[1])?'MIN':/ровно/iu.test(match[1])?'EQ':'MAX',value,unit:'RUB',...source(m)});classified=true;
   }
   for(const match of t.matchAll(/(?:срок|за|через|не позднее чем через)\s*(\d+)\s*(дн\S*|недел\S*)/giu)){
    newConstraints.push({id:'limit'+(++serial),dimension:'deadline',operator:'MAX',value:Number(match[1])*(/недел/iu.test(match[2])?7:1),unit:'DAYS',...source(m)});classified=true;
   }
   if(/без сети|только офлайн|сеть запрещена/iu.test(t)){newConstraints.push({id:'limit'+(++serial),dimension:'network',operator:'EQ',value:'OFFLINE',unit:'',...source(m)});classified=true;}
   if(/обязател[а-я]* онлайн|обязател[а-я]* доступ к сети/iu.test(t)){newConstraints.push({id:'limit'+(++serial),dimension:'network',operator:'EQ',value:'ONLINE',unit:'',...source(m)});classified=true;}
   if(/не публиковать|публикация запрещена/iu.test(t)){newConstraints.push({id:'limit'+(++serial),dimension:'publication',operator:'EQ',value:'DENY',unit:'',...source(m)});classified=true;}
   if(/формат\s*[:—-]?\s*(PDF|CSV|JSON|Markdown|HTML)/iu.test(t)){newConstraints.push({id:'limit'+(++serial),dimension:'format',operator:'EQ',value:/формат\s*[:—-]?\s*(PDF|CSV|JSON|Markdown|HTML)/iu.exec(t)[1].toUpperCase(),unit:'',...source(m)});classified=true;}
   const resource=/(?:ресурсы\s*[:—-]|у меня есть|доступны|используй|необходим[а-я]* ресурс\s*[:—-]|нет необходимого ресурса\s*[:—-])\s*(.+)/iu.exec(t);
   if(resource){
    const availability=/нет необходимого|необходим[а-я]* ресурс/iu.test(t)?'MISSING':'PROVIDED';
    for(const description of resource[1].split(/;|,\s*| и /u).map(x=>x.trim()).filter(Boolean)){
     if(correction&&availability==='PROVIDED')for(let i=resources.length-1;i>=0;i--)if(resources[i].description===description)resources.splice(i,1);
     resources.push({id:'resource'+(++serial),type:/csv|данн|выборк/iu.test(description)?'DATASET':/файл|документ|pdf|md|xlsx/iu.test(description)?'FILE':'OTHER',description,availability,required:true,...source(m)});
    }
    classified=true;
   }
   const done=/(?:готово\s*,?\s*когда\s*[:—-]?|критерии готовности\s*[:—-]|результат должен\s*[:—-]?|на выходе\s*[:—-]?)\s*(.+)/iu.exec(t);
   if(done){for(const text of done[1].split(/;/u).map(x=>x.trim()).filter(Boolean))criteria.push({text,...source(m)});classified=true;}
   if(!classified&&/^ограничени[ея]\s*[:—-]/iu.test(t)){newConstraints.push({id:'limit'+(++serial),dimension:'other',operator:'EQ',value:t.replace(/^ограничени[ея]\s*[:—-]\s*/iu,''),unit:'text'+serial,...source(m)});classified=true;}
   if(!classified&&!/^(уточнение|исправление)/iu.test(t))goals.push({text:t.replace(/^(?:цель|нужно|хочу)\s*[:—-]?\s*/iu,''),...source(m)});
  }
  if(correction&&newConstraints.length){const dimensions=new Set(newConstraints.map(c=>c.dimension));for(let i=constraints.length-1;i>=0;i--)if(dimensions.has(constraints[i].dimension)&&constraints[i].origin==='USER')constraints.splice(i,1);}
  constraints.push(...newConstraints);
 }
 const previous=context.draft??context.spec;
 const requirements=goals.flatMap(g=>g.text.split(';').map(text=>({...g,text:text.trim()}))).filter(r=>r.text).map((r,i)=>({id:'r'+(i+1),text:r.text,acceptance:criteria.length?criteria.map(c=>c.text):['Предоставлен редактируемый синтетический результат: '+r.text],source_ids:r.source_ids,origin:'USER'}));
 if(!requirements.length&&previous)requirements.push(...structuredClone(previous.requirements));
 const completion_criteria=criteria.length?criteria.map((c,i)=>({id:'c'+(i+1),...c,requirement_ids:requirements.map(r=>r.id)})):requirements.map((r,i)=>({id:'c'+(i+1),text:r.acceptance[0],requirement_ids:[r.id],source_ids:r.source_ids,origin:r.origin}));
 return {goal:goals.map(g=>g.text).join('; ')||previous?.goal||context.original_request?.text||'',requirements,constraints,resources,completion_criteria,assumptions:criteria.length?[]:[{text:'Форма результата предварительно принята как локальный редактируемый mock документ; содержательная приёмка не подтверждена',material:false}],questions:[],contradictions:[]};
}

export function planMockDraft({spec}){
 const nodes=[];
 const resourceNodes=spec.resources.map((r,i)=>({id:'input'+(i+1),title:'Подготовить '+r.description.slice(0,80),capability:'analysis',instructions:'Локально смоделировать подготовку ресурса: '+r.description,requirement_ids:spec.requirements.map(r=>r.id),depends_on:[],deliverable:'input'+(i+1)+'.md'}));
 nodes.push(...resourceNodes);
 const work=spec.requirements.map((r,i)=>({id:'work'+(i+1),title:r.text.slice(0,100),capability:/исслед|сравни|изучи/iu.test(r.text)?'research':/сайт|код|программ|реализуй|разработ/iu.test(r.text)?'coding':/анализ|вычисл|рассчита/iu.test(r.text)?'analysis':'writing',instructions:r.text,requirement_ids:[r.id],depends_on:resourceNodes.map(n=>n.id),deliverable:'work'+(i+1)+'.md'}));
 nodes.push(...work);
 for(const [i,c] of spec.completion_criteria.entries())nodes.push({id:'check'+(i+1),title:'Проверить '+c.id,capability:'qa',instructions:c.text,requirement_ids:c.requirement_ids,depends_on:work.filter(n=>n.requirement_ids.some(id=>c.requirement_ids.includes(id))).map(n=>n.id),deliverable:'check'+(i+1)+'.md'});
 return {nodes};
}
