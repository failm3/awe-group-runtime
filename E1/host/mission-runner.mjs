import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {createHash, randomBytes} from 'node:crypto';
import {fork} from 'node:child_process';
import {digest, need} from '../contracts/index.mjs';

export const RUNTIME_ROOT = fileURLToPath(new URL('../../', import.meta.url));
export function readHostJson(filename, limit = 2 * 1024 * 1024) {
  const st = fs.lstatSync(filename); need(st.isFile() && !st.isSymbolicLink() && st.nlink === 1 && st.size <= limit, 'REPAIR_HOST_FILE');
  return JSON.parse(fs.readFileSync(filename, 'utf8'));
}
export function writeHostJson(filename, value) {
  fs.mkdirSync(path.dirname(filename), {recursive: true, mode: 0o700});
  const temporary = filename + '.tmp';
  if (fs.existsSync(temporary)) { const st = fs.lstatSync(temporary); need(st.isFile() && !st.isSymbolicLink() && st.nlink === 1, 'REPAIR_HOST_FILE'); }
  const fd = fs.openSync(temporary, 'w', 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value, null, 2) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, filename);
}
export function repairSourcePins() {
  const result = [];
  for (const area of ['E1/host/coding', 'E1/host/program-runner', 'E1/coordinator', 'E1/broker', 'E1/qa-coding', 'E1/qa-repair']) {
    function walk(relative) { if (!fs.existsSync(path.join(RUNTIME_ROOT, relative))) return; for (const e of fs.readdirSync(path.join(RUNTIME_ROOT, relative), {withFileTypes: true})) {
      const p = relative + '/' + e.name;
      if (e.isDirectory() && !['evidence', '__pycache__'].includes(e.name) && !e.name.startsWith('.')) walk(p);
      else if (e.isFile() && /\.(mjs|sql|py|json)$/.test(p)) result.push({path: p, sha256: createHash('sha256').update(fs.readFileSync(path.join(RUNTIME_ROOT, p))).digest('hex')});
    }} walk(area);
  }
  result.push({path: 'E1/host/mission-runner.mjs', sha256: createHash('sha256').update(fs.readFileSync(fileURLToPath(import.meta.url))).digest('hex')});
  return result.sort((a, b) => a.path.localeCompare(b.path, 'en'));
}
export function validateRepairConfig(config) {
  need(config?.schema === 'awe.e1.two-file-repair-config/1' && /^[a-z][a-z0-9_]{0,39}$/.test(config.run_id), 'REPAIR_CONFIG');
  for (const key of ['resourcePath', 'issueSnapshotPath', 'priorReportPath', 'priorWitnessPath']) need(typeof config[key] === 'string' && path.isAbsolute(config[key]), 'REPAIR_CONFIG_PATH');
  need(config.max_restarts === 2 && JSON.stringify(config.faults) === JSON.stringify(['AFTER_MODEL_PERSISTED', 'AFTER_NATIVE_COMPLETED']), 'REPAIR_FAULT_PROFILE');
  return config;
}

/** An explicit bounded host supervisor for the existing E1 application. It does
 * not schedule tasks or account attempts; those remain exclusively in A2/D09.
 * Only its observed child exit permits the two declared synthetic restarts. */
export async function superviseRepair(configFile) {
  const config = validateRepairConfig(readHostJson(configFile, 65536));
  const directory = path.join(RUNTIME_ROOT, '.private', 'repair-' + config.run_id);
  fs.mkdirSync(directory, {recursive: true, mode: 0o700});
  const lock = path.join(directory, 'supervisor.lock');
  fs.writeFileSync(lock, JSON.stringify({pid: process.pid}), {flag: 'wx', mode: 0o600});
  const stateFile = path.join(directory, 'SUPERVISOR.json');
  need(!fs.existsSync(stateFile), 'REPAIR_SUPERVISOR_ALREADY_STARTED');
  const source_pins = repairSourcePins(), source_digest = digest(source_pins);
  const prepared = {...config, privateRoot: directory, started_at: new Date().toISOString(), source_digest, source_pins};
  writeHostJson(path.join(directory, 'config.json'), prepared);
  let state = {schema: 'awe.e1.automatic-repair-supervisor/1', run_id: config.run_id, supervisor_pid: process.pid, nonce: randomBytes(16).toString('hex'), source_digest, started_at: prepared.started_at, max_restarts: 2, observed_exits: [], current_child_pid: null, status: 'RUNNING', operator_phase_commands: 0};
  writeHostJson(stateFile, state);
  const env = Object.fromEntries(['SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP'].filter(k => process.env[k]).map(k => [k, process.env[k]]));
  try {
    for (let generation = 0; generation <= config.max_restarts; generation++) {
      need(digest(repairSourcePins()) === source_digest, 'REPAIR_SOURCE_CHANGED');
      const observed = await new Promise((resolve, reject) => {
        const child = fork(fileURLToPath(import.meta.url), ['--repair-child', path.join(directory, 'config.json')], {cwd: RUNTIME_ROOT, env, stdio: ['ignore', 'pipe', 'pipe', 'ipc'], windowsHide: true});
        state = {...state, current_child_pid: child.pid}; writeHostJson(stateFile, state);
        let stdout = ''; const timer = setTimeout(() => { child.kill(); }, 15 * 60000);
        child.stdout.on('data', b => { stdout = (stdout + b.toString('utf8')).slice(-4096); });
        child.stderr.on('data', () => {});
        child.once('error', error => { clearTimeout(timer); reject(error); });
        child.once('exit', (code, signal) => { clearTimeout(timer); resolve({pid: child.pid, exit_code: code, signal, ended_at: new Date().toISOString(), stdout}); });
        child.send({type: 'SUPERVISED_START', nonce: state.nonce, generation});
      });
      const fault = observed.exit_code === 90 ? readHostJson(path.join(directory, 'FAULT-' + generation + '.json'), 65536) : null;
      if (fault) need(fault.pid === observed.pid && fault.stage === config.faults[generation] && fault.supervisor_pid === process.pid, 'REPAIR_FAULT_WITNESS');
      const cleanObserved = {...observed, stdout: undefined}; delete cleanObserved.stdout;
      state = {...state, observed_exits: [...state.observed_exits, {...cleanObserved, known_injected_fault: fault?.stage ?? null, original_process_observed_dead: true}], current_child_pid: null};
      writeHostJson(stateFile, state);
      if (observed.exit_code === 90 && generation < config.max_restarts) continue;
      state = {...state, status: observed.exit_code === 0 ? 'FINISHED' : 'STOPPED', finished_at: new Date().toISOString()}; writeHostJson(stateFile, state);
      const publicState = {...state}; delete publicState.nonce;
      writeHostJson(path.join(RUNTIME_ROOT, 'E1/coding/evidence', 'SUPERVISOR-' + config.run_id + '.json'), publicState);
      console.log(JSON.stringify({status: state.status, run_id: config.run_id, automatic_restarts: state.observed_exits.filter(x => x.known_injected_fault).length, final_child_exit: observed.exit_code, child_summary: observed.stdout.trim(), new_paid_calls: 0}));
      return state;
    }
    throw Error('REPAIR_RESTART_CAP');
  } finally { if (fs.existsSync(lock) && readHostJson(lock).pid === process.pid) fs.unlinkSync(lock); }
}

export function createRepairFaultHook(config, generation) {
  const stateFile = path.join(config.privateRoot, 'SUPERVISOR.json');
  return async (stage, metadata) => {
    const state = readHostJson(stateFile);
    need(state.supervisor_pid === process.ppid && state.current_child_pid === process.pid && state.status === 'RUNNING', 'REPAIR_SUPERVISOR_IDENTITY');
    if (config.faults[generation] !== stage) return;
    const filename = path.join(config.privateRoot, 'FAULT-' + generation + '.json');
    need(!fs.existsSync(filename), 'REPAIR_FAULT_DUPLICATE');
    writeHostJson(filename, {schema: 'awe.e1.repair-injected-process-fault/1', stage, pid: process.pid, supervisor_pid: process.ppid, at: new Date().toISOString(), metadata});
    process.exit(90);
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv[2] === '--authorized-two-file-repair' && process.argv.length === 4) {
    superviseRepair(path.resolve(process.argv[3])).catch(error => { console.error(JSON.stringify({status: 'REPAIR_SUPERVISOR_BLOCKED', reason: error.code ?? error.message})); process.exitCode = 1; });
  } else if (process.argv[2] === '--repair-child' && process.argv.length === 4 && process.send) {
    process.once('message', async message => {
      try {
        const config = readHostJson(process.argv[3]), state = readHostJson(path.join(config.privateRoot, 'SUPERVISOR.json'));
        need(message.type === 'SUPERVISED_START' && message.nonce === state.nonce && state.current_child_pid === process.pid && state.supervisor_pid === process.ppid, 'REPAIR_SUPERVISED_CHILD');
        need(digest(repairSourcePins()) === config.source_digest, 'REPAIR_CHILD_SOURCE_CHANGED');
        const {runRepairDriver} = await import('./coding/repair-driver.mjs');
        const result = await runRepairDriver(config, {fault: createRepairFaultHook(config, message.generation)});
        console.log(JSON.stringify(result)); process.disconnect();
      } catch (error) {
        console.error(JSON.stringify({status: 'REPAIR_CHILD_BLOCKED', reason: error.code ?? error.message})); process.exitCode = 1; process.disconnect();
      }
    });
  } else throw Error('REPAIR_EXPLICIT_AUTHORIZED_COMMAND');
}
