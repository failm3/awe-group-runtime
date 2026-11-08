// Structured mock LLM answers, deliberately kept outside product code.
const node=(id,capability,requirement_ids,depends_on=[])=>({id,title:id,capability,instructions:'Синтетическая работа '+id,requirement_ids,depends_on,deliverable:id+'.md'});
export const scenarios=[
 {id:'career',goal:'Исследуй вакансии по сохранённой выборке; уточни позиционирование по моим данным; подготовь CV и сайт портфолио',requirements:['Рынок вакансий','Достоверное позиционирование','CV и портфолио'],nodes:[
  node('market','research',['r1']),node('facts','analysis',['r2']),node('position','writing',['r2'],['market','facts']),node('cv','writing',['r3'],['position']),node('site','coding',['r3'],['facts']),node('package','qa',['r3'],['cv','site'])]},
 {id:'experiment',goal:'Проверь данные научного эксперимента; сравни методы; подготовь графики и воспроизводимый отчёт',requirements:['Качество данных','Сравнение методов','Воспроизводимый отчёт'],nodes:[
  node('validate','analysis',['r1']),node('literature','research',['r2']),node('compute','coding',['r2'],['validate']),node('plots','coding',['r3'],['compute']),node('report','writing',['r3'],['plots','literature'])]},
 {id:'conference',goal:'Подготовь локальный проект конференции: программа, бюджет, логистика и инструкция организаторам',requirements:['Программа конференции','Бюджет и логистика','Инструкция'],nodes:[
  node('agenda','writing',['r1']),node('venue','research',['r2']),node('costs','analysis',['r2'],['venue']),node('schedule','analysis',['r1'],['agenda','venue']),node('runbook','writing',['r3'],['schedule','costs']),node('review','qa',['r3'],['runbook'])]}
];
export const draftFor=(requirements,c)=>{
 const m=c.history.filter(m=>m.kind==='user').at(-1);
 return {goal:m.text,requirements:requirements.map((text,i)=>({id:'r'+(i+1),text,acceptance:['Получен редактируемый синтетический артефакт для '+text],source_ids:[m.id],origin:'USER'})),
  constraints:[{id:'local',dimension:'scope',operator:'EQ',value:'E0 OFFLINE MOCK',unit:'',source_ids:['policy_e0'],origin:'PROJECT'}],resources:[],
  completion_criteria:requirements.map((text,i)=>({id:'c'+(i+1),text:'Редактируемый артефакт: '+text,requirement_ids:['r'+(i+1)],source_ids:[m.id],origin:'USER'})),assumptions:[],questions:[],contradictions:[]};
};
export {node};
