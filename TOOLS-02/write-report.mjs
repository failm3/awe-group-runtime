import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url)),r=JSON.parse(fs.readFileSync(path.join(root,'TOOLS-02/evidence/current/receipt.json')));
if(r.status!=='PASS')throw Error('FINAL_EVIDENCE_NOT_PASS');
const suites=r.commands.filter(c=>c.id.startsWith('baseline-')),baseline=suites.reduce((n,c)=>n+c.pass,0),tr=r.commands.find(c=>c.id==='tr01-offline'),tools=r.commands.find(c=>c.id==='tools02');
const demo=JSON.parse(fs.readFileSync(path.join(root,'TOOLS-02/evidence/current/demo.stdout'))),rt=JSON.parse(fs.readFileSync(path.join(root,'TOOLS-02/evidence/current/rt01-conformance.stdout')));
if(demo.status!=='PASS'||rt.status!=='PASS')throw Error('DEMO_CONFORMANCE');
const md=`# TOOLS-02 — результаты проверки

Финальный статус: **PASS для E0 LOCAL SYNTHETIC**, independent acceptance NOT_RUN, production_ready=false. Дата: 2026-11-06, Europe/Moscow. Evidence interval UTC: ${r.started} — ${r.finished}.

| Проверка | Результат |
|---|---|
| Frozen baseline, 11 offline suites | ${baseline}/${baseline} PASS |
| Исходные TR01 registry/sync synthetic regressions | ${tr.pass}/${tr.tests} PASS |
| TOOLS02 execution/admission/factory/compatibility | ${tools.pass}/${tools.tests} PASS, fail=${tools.fail}, skip=${tools.skipped} |
| Итого тестов | ${baseline+tr.pass+tools.pass} PASS |
| Demo: filesystem, JS, Python, Node/Git CLI, browser/API fixtures, generated missing capability | ${demo.results.length}/${demo.results.length} EXECUTED_LOCAL; missing capability absent before factory=true |
| Фактический RT01 read-only conformance | ${rt.checks.length} checks PASS; proposals dispatched=${rt.tool_dispatches} |
| Tracked baseline bytes / git diff | ${r.tracked_files} files unchanged; tracked_diff_empty=${r.tracked_diff_empty} |
| 19 selected TR01 inputs | imported_bytes_stable=${r.imported_bytes_stable} |
| Owned process cleanup и sandbox | Все child results требуют close; sandbox_empty=${r.sandbox_empty} |

Node ${r.environment.node}, Windows ${r.environment.arch}; установленный Python ${r.environment.python}, Git ${r.environment.git}. Exact executable и 12 implementation file pins: runtime-lock.json; lock digest ${r.environment.runtime_lock_digest}. Никаких dependency installations.

Негативные сценарии включают path traversal/absolute paths/ADS/UNC/reserved names; hardlink/junction; file/byte quotas; input/command/source/credential/URL injection; foreign project/actor/run/control operation; metadata вместо executable pin; tampered payload/digest; duplicate/poison JSON; one-use callback; durable-port replay denial; revocation after await и при readback; missing/incorrect/early commit ACK; retained callback; timeouts/output overflow; source/binary drift; close during a child; rejected/self/missing reviewer; source tampering до test, после smoke, во время review и перед registration; неправильный порядок и concurrent factory gates; staged-candidate quota. Непроверенный hostile source в interpreter не запускался: byte equality проверяется до subprocess.

Изоляция теста: каждый template invocation в отдельном owned временном каталоге и ChildProcess; clean environment; shell=false; fixed executables/arguments; Node permission flags и JS network regression guard; Python -I -S -B. Это не доказательство OS sandbox или полного egress enforcement для произвольного кода. Hardlink/junction test выполнен на host с разрешением локальных link fixtures, без SKIP; restricted sandbox может запрещать их создание.

Изменение лимита: диагностический прогон с 1500ms прошёл 1038 baseline + 86 TR01 + 78 TOOLS02 tests, но его последующий factory demo завершился TOOLS_TIMEOUT. Он сохранён в evidence/initial-1500ms и не считается финальным PASS. После установки bounded cap 5000ms и добавления candidate-quota/shutdown tests проведён полный свежий прогон выше. В реализации нет автоматического retry: timeout остаётся UNKNOWN/QUARANTINED; повторный self-run выполнялся отдельно как проверка окончательного кандидата.

NOT_RUN: PostgreSQL D09/INT03/TR01; реальные admission/issuer/QA ports; полный AUTO/INT04→RT01→TOOLS02→D07/D08 e2e; native browser/API/egress; реальные credentials/providers/paid calls; REAL Hermes; hostile-code OS containment; независимая человеческая/организационная приёмка. Commit/merge/push/deploy не выполнялись.

Точные команды, stdout/stderr SHA256 и неизменность исходников: evidence/current/receipt.json, tracked-bytes.json и EVIDENCE.sha256. Фактические прочитанные owning RT sources с hashes: evidence/current/rt01-conformance.stdout. Точный review diff и byte-replay proof: delivery/FILES.json и DIFF-SUMMARY.json после export-diff.
`;
fs.writeFileSync(path.join(root,'TOOLS-02/TEST-REPORT.md'),md);console.log(JSON.stringify({status:'PASS',baseline,tr01:tr.pass,tools02:tools.pass,total:baseline+tr.pass+tools.pass,demo:demo.results.length,rt01_checks:rt.checks.length}));
