// UI vocabulary only. These are not D03 or INT-04 domain contracts.
export const labels = Object.freeze({READY:'Готова к запуску',HOLD:'HOLD · нужна сверка',WORK_COMPLETED:'RT: работа подтверждена',QA_PASS:'QA PASS · вычислено',QA_FAIL:'QA FAIL',OUTCOME_UNKNOWN:'Исход неизвестен',NOT_STARTED:'Не запускался',QUEUED:'В очереди',RUNNING:'В работе',WAITING_FOR_OWNER:'Нужно решение',QA_PENDING:'Независимая QA',REWORK:'Нужна доработка',PERSISTING:'Сохранение и сверка',COMPLETE:'Завершено',FAILED:'Ошибка',BLOCKED:'Заблокировано',RECONCILING:'Исход неизвестен',CANCELLING:'Отменяется',CANCELLED:'Отменено'});
export const terminal = status => ['COMPLETE','CANCELLED'].includes(status);
export const active = task => !terminal(task.status);
export const statusTone = status => ['FAILED','REWORK'].includes(status)?'bad':['WAITING_FOR_OWNER','BLOCKED','RECONCILING','CANCELLING'].includes(status)?'warn':['COMPLETE'].includes(status)?'good':'neutral';
export const money = (micros,currency='RUB') => micros===null||micros===undefined?'Неизвестно':new Intl.NumberFormat('ru-RU',{style:'currency',currency,maximumFractionDigits:6,minimumFractionDigits:2}).format(Number(micros)/1000000);
export function budgetView(b){if(!b||[b.confirmedMicros,b.reservedMicros,b.unreconciledMicros,b.limitMicros].some(x=>x===null||!/^(0|[1-9][0-9]{0,29})$/.test(x)))return {remaining:null,blocked:true,reason:'Расходы не сверены; остаток UNKNOWN.'};const left=BigInt(b.limitMicros)-BigInt(b.confirmedMicros)-BigInt(b.reservedMicros)-BigInt(b.unreconciledMicros);return {remaining:String(left<0n?0n:left),blocked:left<=0n,reason:'D06 ledger · synthetic µRUB · единый владелец резервов'};}
export function executionView(limits) {
  if(!limits)return {blocked:true,reason:'Лимиты исполнения неизвестны'};
  const pairs=[['elapsedSeconds','maxDurationSeconds'],['toolCallsUsed','maxToolCalls'],['activeChildren','maxChildren']];
  if(pairs.some(([used,max])=>!Number.isSafeInteger(limits[used])||!Number.isSafeInteger(limits[max])||limits[used]<0||limits[max]<0))return {blocked:true,reason:'Лимиты исполнения не подтверждены'};
  return pairs.some(([used,max])=>limits[used]>=limits[max])?{blocked:true,reason:'Лимит времени, вызовов или параллельных исполнителей достигнут'}:{blocked:false,reason:'В пределах mock-лимитов исполнения'};
}
export function currentQa(snapshot,artifact) {
  if (!artifact) return [];
  const task=snapshot.tasks.find(t=>t.id===artifact.taskId);
  return snapshot.qa.filter(q=>q.artifactId===artifact.id).map(q=>({...q,stale:q.artifactVersion!==artifact.version || q.contentDigest!==artifact.contentDigest || q.specRevision!==task?.specRevision}));
}
export function canAccept(snapshot,artifact){return Boolean(!snapshot.hold&&artifact?.canAccept&&artifact.acceptance!=='ACCEPTED');}
export const escapeHtml = value => String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function applyEvent(state,event) {
  if (event.revision<=state.revision) return {action:'IGNORE',cursor:state.cursor};
  if (event.revision!==state.revision+1) return {action:'RESYNC',cursor:state.cursor};
  return {action:'READ',cursor:event.cursor};
}
