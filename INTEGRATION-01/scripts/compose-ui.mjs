import fs from 'node:fs';
import path from 'node:path';
const base=path.resolve(import.meta.dirname,'..'),snapshot=path.join(base,'snapshots/UI/UI-MVP'),ui=path.join(base,'ui');
let s=fs.readFileSync(path.join(snapshot,'src/app.mjs'),'utf8');
const edits=[
 ["import {createMockAdapter,clearMockStorage} from './adapter/mock-adapter.mjs';","import {createOfflineAdapter} from './adapter/http-adapter.mjs';"],
 ["const settingsKey='AWE_UI_MVP_VIEW_V1'","const settingsKey='AWE_INTEGRATION01_VIEW_V1'"],
 ["createMockAdapter({storage:localStore})","createOfflineAdapter()"],
 ["ui.projectId='zhiv'","ui.projectId=snapshot.projects[0].id"],
 ["max-length=\"12000\"","max-length=\"1024\""],
 ["maxlength=\"12000\"","maxlength=\"1024\""],
 ["payload});", "payload:type==='CREATE_TASK'?{...payload,scenario:ui.scenario||'normal'}:payload});"],
 ["Мок-сессия", "Офлайн-сессия"],
 ['Mock-роль · без авторизации','Тестовая E0-сессия'],
 ['<span class="mock-badge">MOCK</span>','<span class="mock-badge">E0</span>'],
 ['Синтетические данные · backend и Hermes не подключены','Офлайн backend: D03 / D06 / RT01 processes / LLM01 mock / D07 / D08 · Physical DENY'],
 ["'Управление mock-данными'","'Контур и evidence'"],
 ['Управление mock-данными','Контур и evidence'],
 ['Mock-данные и сценарии','Контур и evidence'],
 ['Подтверждённый mock-прогресс','Процент готовности не выдаётся backend'],
 ["t.progress>=[5,40,75,100][i]","t.completedStages?.[i]"],
 ["const b=snapshot.budgets.find(b=>b.taskId===t?.id)","const b=snapshot.budgets.find(b=>b.taskId===t?.id)"],
 ['b.confirmedMinor','b.confirmedMicros'],['b.reservedMinor','b.reservedMicros'],['b.unreconciledMinor','b.unreconciledMicros'],['b.limitMinor','b.limitMicros'],
 ['Mock-вердикты','Вычисленные E0-вердикты'],['Синтетический вердикт','E0-вердикт'],
 ["q.verdict==='PASS'?'Пройдено':'Не пройдено'","q.verdict==='PASS'?'Пройдено':q.verdict==='FAIL'?'Не пройдено':'Не подтверждено'"],
 ["q.verdict==='PASS'?'good':'bad'","q.verdict==='PASS'?'good':q.verdict==='FAIL'?'bad':'warn'"],
 ['Автор результата и проверяющие — разные mock-роли. Реальная независимость и подлинность отчётов должны обеспечиваться backend.','Основной SEC → D08 и повтор fixed D08 в отдельном процессе реально вычислены. Production AuthN и trust isolation не доказаны.'],
 ['Синтетический документ','Офлайн JSON-результат'],['синтетический документ','офлайн JSON-результат'],
 ["Скачать .md","Скачать .json"],['Версия принята','Версия принята тестовым OWNER'],
 ["Принять mock-версию","Принять E0-версию"],['Mock-данные','Офлайн-контур'],
 ['Постановка v${fresh?\'1\':t.specRevision}','Постановка v${fresh?\'1\':t.specRevision}'],
 ['Демонстрационный','Тестовый'],
 ['Текущий кандидат появится здесь после этапа исполнения.','Результат появится после реального выполнения ограниченного E0-сценария.'],
 ['Главный агент соберёт план и исполнителей. Вы увидите ход работы, запросы решений, результат и независимые проверки.','Этот первый срез выполняет ограниченный digest-сценарий: INT04 → LLM01 mock → отдельные RT parent/child процессы → D07 → fixed D08. Введите 1…1024 символа. Один task на профиль.'],
 ['Все суммы синтетические. Неизвестный расход не считается нулём.','Суммы из фактического D06 memory ledger; это синтетические µRUB, не реальное списание. UNKNOWN не равен нулю.'],
 ["max-height=\"12000\"","max-height=\"1024\""]
];
for(const [a,b]of edits){if(s.includes(a))s=s.replaceAll(a,b);else if(a!==b)console.log('Optional UI text anchor absent:',a);}
s=s.replace("const disabled=()=>ui.busy||snapshot.connection!=='CONNECTED';","const disabled=()=>ui.busy||snapshot.commandHold||snapshot.hold||snapshot.connection!=='CONNECTED';");
s=s.replace(/function taskButtons\(t\)\{[^\n]+/,`function taskButtons(t){if(!t)return '';return t.canCancel?btn('Запросить отмену','cancel','',disabled()?'disabled':''):'';}`);
s=s.replace(/    'mock-controls':\(\)=>[\s\S]*?\n    cancel:/,`    'mock-controls':()=>\`<p>Реальные состояния локального тестового контура. Кнопок имитации прогресса нет.</p><p class="fine">D03 — task owner. D06 — единственные деньги и attempts. RT01 — fixed процессы. Native Hermes / LIVE LLM / рабочая DB: NOT_RUN.</p><p class="fine">Профиль: одна задача, максимум 1024 символа. Новый профиль задаётся при отдельном локальном запуске.</p><label for="next-scenario">Следующая новая задача · test fault injection</label><select id="next-scenario" \${snapshot.tasks.length?'disabled':''}><option value="normal">Нормальное выполнение</option><option value="child-failure">Отказ RT child</option><option value="lost-ack">Потеря RT result ACK после commit</option><option value="provider-timeout">Неизвестный исход модели</option><option value="qa-failure">D08 отвергает ошибочный результат</option></select>\${btn('Обновить проекцию','refresh')}<p class="fine">Контекст включает только постановку задачи и immutable plan. Уточнения не передаются worker как полная история.</p>\`,
    cancel:`);
s=s.replace("if(name==='new'){ui.newTask=true;","if(name==='new'){if(snapshot.tasks.length){notify('Одна задача на профиль. Создайте отдельный локальный профиль для нового контура.');return;}ui.newTask=true;");
s=s.replace("async function action(name,el){","async function action(name,el){\n  if(name==='refresh'){await refresh();notify('Прочитана реальная проекция контура.');return;}");
s=s.replace("document.addEventListener('change',e=>{","document.addEventListener('change',e=>{if(e.target.id==='next-scenario'){ui.scenario=e.target.value;return;}");
s=s.replace("const t=task();if(!t)return '<div", "const t=task();if(!t)return '<div");
s=s.replace("${t.progress===null?'Неизвестно':t.progress+'%'}", "${t.progress===null?'Неизвестно':t.progress+'%'}");
s=s.replace('<code>rev ${h(t.revision)}</code>','<code>rev ${h(t.revision)}</code></div><p class="fine">D03: ${h(t.nativeState)} · контур: ${h(t.phase)} · authoritative COMPLETE: нет</p><div>');
s=s.replace(/if\(!a\)return `[^\n]+?;return `<section class=\"surface studio-panel\">/,"if(!a)return `<section class=\"surface studio-panel\">${empty('Результат ещё готовится','Документ появится после фактического выполнения E0-контура.')}</section>`;return `<section class=\"surface studio-panel\">");
s=s.replace("name==='confirm-reset'","name==='unused-confirm-reset'");
s=s.replace("if(localStore)clearMockStorage(localStore);location.reload();","location.reload();");
s=s.replace('Сбросить повреждённый mock-снимок','Повторить чтение контура').replace('Mock-пространство недоступно','Офлайн-контур недоступен');
s=s.replace('Синтетические счётчики · не телеметрия Hermes','Лимиты fixed RT01 процессов · native Hermes не запускался').replace('Подагенты одновременно','RT процессы одновременно');
s=s.replace('${h(l.elapsedSeconds)} /','${l.elapsedSeconds===null?\'Неизвестно\':h(l.elapsedSeconds)} /');
s=s.replace('Синтетический запрос','Тестовый запрос');
s=s.replace("void boot();","document.addEventListener('keydown',e=>{const d=document.querySelector('#dialog');if(e.key!=='Tab'||!d.open)return;const list=Array.from(d.querySelectorAll('button:not([disabled]),a[href],input:not([disabled]),select:not([disabled]),textarea:not([disabled]),summary,[tabindex]:not([tabindex=\\\"-1\\\"])')).filter(el=>el.getClientRects().length>0);if(!list.length)return;const first=list[0],last=list.at(-1);if(e.shiftKey&&(document.activeElement===first||!d.contains(document.activeElement))){e.preventDefault();last.focus();}else if(!e.shiftKey&&(document.activeElement===last||!d.contains(document.activeElement))){e.preventDefault();first.focus();}});\n"+'void boot();');
s=s.replace('AWE GROUP / MOCK','AWE GROUP / E0');
s=s.replace('${snapshot.tasks.filter(t=>t.authorAgentId===a.id).length} назначенных задач · mock-проекция','Состояние из backend · E0-контур');
s=s.replace('Расходы задачи · mock','Расходы задачи · D06');
s=s.replace("${labels[t.status]}</small>","${labels[a.status]||h(a.status)}</small>");
s=s.replace("['Постановка и план','Работа исполнителей','Независимая проверка','Сохранение и сверка']","['Постановка и план','Работа исполнителей','Сохранение и сверка','Независимая проверка']");

s=s.replace('function treeMarkup(',"function artifactPreview(a){let o;try{o=JSON.parse(a.content);}catch{return '<pre class=\\\"document-preview\\\">'+h(a.content)+'</pre>';}const x=o.execution?.output,pe=o.processEvidence;return `<article class=\"result-preview\"><p class=\"eyebrow\">${a.historical?'Исторический снимок · HOLD':'Результат ограниченной операции'}</p><h3>Digest и размер входного текста</h3><p>Текст задачи обработан фиксированной операцией. Каждый RT worker вернул структурированный результат и ссылку.</p><dl class=\"budget-lines\"><div><dt>Текст задачи · UTF-8</dt><dd>${h(x?.text_bytes??'Неизвестно')} байт</dd></div><div><dt>Отдельных RT процессов</dt><dd>${h(pe?.processes?.spawn_count??'Неизвестно')}</dd></div><div><dt>Подтверждённый выход</dt><dd>${h(pe?.processes?.runs?.filter(p=>p.exited&&p.exit_code===0).length??0)} / ${h(pe?.processes?.spawn_count??0)}</dd></div><div><dt>LLM01 mock-вызовов</dt><dd>${h(o.model?.execution?.attempts?.length??'Неизвестно')}</dd></div></dl><p class=\"fine\">Hash входного payload</p><code class=\"digest\">${h(x?.input_hash??'Неизвестно')}</code><details class=\"raw-evidence\"><summary>Полный JSON и доказательства</summary><pre>${h(a.content)}</pre></details></article>`;}\n"+'function treeMarkup(');
s=s.replace('<pre class="document-preview">${h(a.content)}</pre>','${artifactPreview(a)}');
s=s.replace('Сохраняем mock-команду…','Передаём команду офлайн-контурy…');
s=s.replace("if(open&&!d.open){ui.returnFocus","const scenarioSelect=d.querySelector('#next-scenario');if(scenarioSelect)scenarioSelect.value=ui.scenario||'normal';if(open&&!d.open){ui.returnFocus");
s=s.replace('Новая задача сохранена в mock-пространстве.','Задача принята фактическим офлайн-контуром.');
s=s.replace('Сообщение сохранено в mock-диалоге.','Сообщение записано в INT04 inbox.');
s=s.replace('UI-кандидат 0.1 · контракт PROPOSED','INTEGRATION-01 · E0 candidate');
s=s.replace('<span>Офлайн-контур</span>',"<span>Контур: ${fresh?'NEW':h(t.phase)} · D03: ${fresh?'NEW':h(t.nativeState)}</span>");
s=s.replace("if(name==='connection'||name==='reconnect'){await perform(()=>adapter.simulateConnection(name==='reconnect'||snapshot.connection!=='CONNECTED'));return;}","if(name==='connection'||name==='reconnect'){await refresh();return;}");
if(!s.includes('createOfflineAdapter()')||s.includes("import {createMockAdapter"))throw Error('UI_TRANSPORT_NOT_REPLACED');
s=s.split('\n').filter(line=>!['if(name===\'unused-confirm-reset\')','if(name===\'autoplay\')','if(name===\'tick\'||name===\'background\')','if(name===\'scenario\')','if(name===\'retry\'||name===\'rework\')'].some(x=>line.includes(x))).join('\n');
s=s.replace("type:'text/markdown;charset=utf-8'","type:'application/json;charset=utf-8'");
fs.writeFileSync(path.join(ui,'src/app.mjs'),s);
let domain=fs.readFileSync(path.join(snapshot,'src/domain.mjs'),'utf8');
domain=domain.replace("QUEUED:'В очереди'","READY:'Готова к запуску',HOLD:'HOLD · нужна сверка',WORK_COMPLETED:'RT: работа подтверждена',QA_PASS:'QA PASS · вычислено',QA_FAIL:'QA FAIL',OUTCOME_UNKNOWN:'Исход неизвестен',NOT_STARTED:'Не запускался',QUEUED:'В очереди'");
domain=domain.replace(/export const money =[^\n]+/,`export const money = (micros,currency='RUB') => micros===null||micros===undefined?'Неизвестно':new Intl.NumberFormat('ru-RU',{style:'currency',currency,maximumFractionDigits:6,minimumFractionDigits:2}).format(Number(micros)/1000000);`);
domain=domain.replace(/export function budgetView\(budget\) \{[\s\S]*?\n\}/,`export function budgetView(b){if(!b||[b.confirmedMicros,b.reservedMicros,b.unreconciledMicros,b.limitMicros].some(x=>x===null||!/^(0|[1-9][0-9]{0,29})$/.test(x)))return {remaining:null,blocked:true,reason:'Расходы не сверены; остаток UNKNOWN.'};const left=BigInt(b.limitMicros)-BigInt(b.confirmedMicros)-BigInt(b.reservedMicros)-BigInt(b.unreconciledMicros);return {remaining:String(left<0n?0n:left),blocked:left<=0n,reason:'D06 ledger · synthetic µRUB · единый владелец резервов'};}`);
domain=domain.replace(/export function canAccept\(snapshot,artifact\) \{[\s\S]*?\n\}/,`export function canAccept(snapshot,artifact){return Boolean(!snapshot.hold&&artifact?.canAccept&&artifact.acceptance!=='ACCEPTED');}`);
fs.writeFileSync(path.join(ui,'src/domain.mjs'),domain);
let html=fs.readFileSync(path.join(snapshot,'index.html'),'utf8').replace('Рабочее пространство','INTEGRATION-01 · E0').replace('с изолированным mock-адаптером','с настоящим локальным офлайн-контуром');fs.writeFileSync(path.join(ui,'index.html'),html);
console.log('UI composed from frozen UI MVP with same-origin HTTP adapter');

const publicFiles=new Set(['index.html','styles.css','src/app.mjs','src/domain.mjs','src/adapter/http-adapter.mjs']);function prune(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const p=path.resolve(dir,e.name);if(!p.startsWith(ui+path.sep))throw Error('UI_PRUNE_PATH');if(e.isDirectory())prune(p);else if(!publicFiles.has(path.relative(ui,p).replaceAll('\\','/')))fs.unlinkSync(p);}}prune(ui);

let css=fs.readFileSync(path.join(snapshot,'styles.css'),'utf8');css+='\n.result-preview{background:var(--surface);border:1px solid var(--line);border-radius:5px;padding:20px;margin:18px 0}.result-preview h3{font-size:19px;margin:6px 0 12px}.result-preview>p{font-size:12px;line-height:1.8;color:var(--muted)}.result-preview .digest{display:block;overflow-wrap:anywhere}.raw-evidence{margin-top:17px;border-top:1px solid var(--line);padding-top:12px}.raw-evidence summary{font-size:11px;cursor:pointer}.raw-evidence pre{max-height:250px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font-size:10px;line-height:1.7}\n';fs.writeFileSync(path.join(ui,'styles.css'),css);

fs.appendFileSync(path.join(ui,'styles.css'),'\n@media(max-width:359px){.chat-subhead>div>span:last-child{display:inline}}\n');
