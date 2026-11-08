import fs from 'node:fs';
import path from 'node:path';
import {fork} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {randomUUID} from 'node:crypto';
import {canonicalize, digest} from '../../contracts/canonical.mjs';
import {validateInfraConfig, configScope} from './config.mjs';
import {assertScopedPath} from './paths.mjs';
import {ensureFixtureStorage, readJson, writeJson, checkpointEnvelope, verifyCheckpoint} from './storage.mjs';
import {createReleaseManifest, validateReleaseManifest, sanitizedStatus} from './manifest.mjs';
import {deepFreeze, deny, hold, InfraError} from './errors.mjs';

export const FIXTURE_CHILD_PATH = fileURLToPath(new URL('./fixture-worker.mjs', import.meta.url));
export const FIXTURE_GUARD_PATH = fileURLToPath(new URL('./fixture-guard.cjs', import.meta.url));
const knownReasons = new Set(['VAULT_UNAVAILABLE', 'VAULT_REVOKED', 'VAULT_GRANT_EXPIRED']);

// This supervises one fixed fixture process; it does not schedule AWE tasks,
// implement a second queue, reserve money or mutate D03/D09 state.
export function createFixtureSupervisor({config: input, vault = null, vault_access = null, manifest = null} = {}) {
  const config = validateInfraConfig(input), scope = configScope(config);
  const runtimeManifest = manifest === null ? createReleaseManifest({config}) : validateReleaseManifest(config, manifest);
  if (vault && (vault.kind !== 'SCOPED_HANDLE_FIXTURE' || typeof vault.status !== 'function')) deny('C1_FIXTURE_VAULT_REQUIRED');
  if (vault_access && (!vault || typeof vault.resolveHandle !== 'function' || !vault_access.handle || !vault_access.context)) deny('C1_FIXTURE_VAULT_REQUIRED');
  const access = vault_access ? structuredClone(vault_access) : null;
  const stateFile = path.join(config.paths.state, 'lifecycle.json');
  const lockFile = path.join(config.paths.state, 'supervisor.lock');
  const lockToken = randomUUID();
  let child = null, childExit = null, intentionalStop = false, locked = false, transitioning = false;
  let state = {status: 'STOPPED', reason: 'IDLE', generation: 0, restarts: 0, recovery_required: false, restart_exhausted: false, workload_digest: null, cursor: null};

  function status() {
    return sanitizedStatus({...state, cursor_digest: state.cursor === null ? null : digest(state.cursor), manifest_digest: runtimeManifest.manifest_digest});
  }
  function persist() {
    try { writeJson(config, stateFile, checkpointEnvelope(scope, state)); }
    catch (error) { state.status = 'HOLD'; state.reason = 'STORAGE_FAILURE'; throw error; }
  }
  function readCheckpoint() {
    assertScopedPath(config.paths.root, stateFile);
    if (!fs.existsSync(stateFile)) return;
    const saved = verifyCheckpoint(scope, readJson(config, stateFile));
    if (Object.keys(saved).sort().join(',') !== 'cursor,generation,reason,recovery_required,restart_exhausted,restarts,status,workload_digest' ||
        !['STOPPED', 'STARTING', 'RUNNING', 'WAIT', 'HOLD', 'CRASHED'].includes(saved.status) ||
        !Number.isSafeInteger(saved.generation) || saved.generation < 0 || !Number.isSafeInteger(saved.restarts) || saved.restarts < 0 ||
        typeof saved.recovery_required !== 'boolean' || typeof saved.restart_exhausted !== 'boolean' ||
        (saved.workload_digest !== null && !/^sha256:[0-9a-f]{64}$/.test(saved.workload_digest)) || Buffer.byteLength(canonicalize(saved.cursor)) > 2048) hold('C1_CHECKPOINT_INTEGRITY_FAILED');
    state = saved;
  }
  function acquireLock() {
    assertScopedPath(config.paths.root, lockFile);
    try { writeJson(config, lockFile, {token: lockToken, pid: process.pid, scope_digest: scope}, {exclusive: true}); locked = true; }
    catch { hold('C1_SUPERVISOR_ALREADY_OWNED'); }
  }
  function releaseLock() {
    if (!locked) return;
    try {
      assertScopedPath(config.paths.root, lockFile);
      const record = readJson(config, lockFile);
      if (record.token !== lockToken || record.scope_digest !== scope) hold('C1_LOCK_OWNERSHIP_LOST');
      fs.unlinkSync(lockFile); locked = false;
    } catch (error) { state.status = 'HOLD'; state.reason = 'STORAGE_FAILURE'; throw error; }
  }
  function vaultWait() {
    if (!vault) return 'VAULT_UNAVAILABLE';
    let result;
    try { result = access ? vault.resolveHandle(access.handle, access.context) : vault.status(); } catch { return 'VAULT_UNAVAILABLE'; }
    return result?.status === 'READY' ? null : knownReasons.has(result?.reason) ? result.reason : 'VAULT_UNAVAILABLE';
  }
  async function stopChild() {
    if (!child) return;
    intentionalStop = true;
    const owned = child, done = childExit;
    if (owned.connected) owned.send({type: 'STOP'}, () => {});
    const timer = setTimeout(() => { if (child === owned && owned.exitCode === null) owned.kill(); }, config.supervisor.stop_timeout_ms);
    try { await done; } finally { clearTimeout(timer); }
  }
  async function serialized(operation) {
    if (transitioning) deny('C1_LIFECYCLE_BUSY');
    transitioning = true;
    try { return await operation(); } finally { transitioning = false; }
  }
  async function launch() {
    state.status = 'STARTING'; state.reason = 'IDLE'; state.generation++;
    persist(); intentionalStop = false;
    const env = {AWE_E1_FIXTURE: '1'};
    if (process.platform === 'win32' && process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot;
    // No shell, inherited credentials, arbitrary entrypoint, arguments or env.
    const owned = fork(FIXTURE_CHILD_PATH, [], {execPath: process.execPath, execArgv: ['--require', FIXTURE_GUARD_PATH], cwd: config.paths.root,
      env, stdio: ['ignore', 'ignore', 'ignore', 'ipc'], windowsHide: true, serialization: 'json'});
    child = owned;
    childExit = new Promise(resolve => {
      owned.once('error', () => { if (child === owned) child = null; resolve({code: null, signal: null}); });
      owned.once('exit', (code, signal) => {
      if (child === owned) {
        child = null;
        if (!intentionalStop) {
          state.status = 'CRASHED'; state.reason = 'FIXTURE_CRASHED'; state.recovery_required = true;
          try { persist(); } catch { /* memory remains HOLD; restart cannot proceed */ }
        }
      }
      resolve({code, signal});
      });
    });
    try {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => { clean(); reject(new InfraError('C1_FIXTURE_START_TIMEOUT', 'HOLD')); }, 3000);
        const clean = () => { clearTimeout(timer); owned.off('message', onMessage); owned.off('error', onError); owned.off('exit', onExit); };
        const onMessage = message => {
          if (message?.type === 'READY' && message.composition === 'AWE_E1' && message.kind === 'LOCAL_PROCESS_FIXTURE') { clean(); resolve(); }
        };
        const onError = () => { clean(); reject(new InfraError('C1_FIXTURE_START_FAILED', 'HOLD')); };
        const onExit = () => { clean(); reject(new InfraError('C1_FIXTURE_START_FAILED', 'HOLD')); };
        owned.on('message', onMessage); owned.once('error', onError); owned.once('exit', onExit);
      });
      state.status = 'RUNNING'; state.reason = 'FIXTURE_RUNNING'; state.recovery_required = false; persist();
    } catch (error) {
      await stopChild(); state.status = 'HOLD'; state.reason = 'START_FAILED'; persist(); throw error;
    }
    return status();
  }
  return Object.freeze({
    kind: 'LOCAL_PROCESS_FIXTURE', live_ready: false,
    status,
    start({workload_id = null, initial_cursor = null} = {}) {
      return serialized(async () => {
        validateInfraConfig(config);
        ensureFixtureStorage(config);
        if (!locked) {
          acquireLock();
          try { readCheckpoint(); } catch (error) { releaseLock(); throw error; }
        }
        if (state.status === 'HOLD') hold('C1_CHECKPOINT_REQUIRES_REVIEW');
        if (workload_id !== null) {
          if (typeof workload_id !== 'string' || !workload_id || workload_id.length > 256) deny('C1_WORKLOAD_INVALID');
          const workloadDigest = digest({workload_id});
          if (state.workload_digest !== null && state.workload_digest !== workloadDigest) deny('C1_WORKLOAD_SCOPE_MISMATCH');
          if (state.workload_digest === null) {
            if (Buffer.byteLength(canonicalize(initial_cursor)) > 2048) deny('C1_CURSOR_TOO_LARGE');
            state.workload_digest = workloadDigest; state.cursor = structuredClone(initial_cursor);
          }
        }
        const wait = vaultWait();
        if (wait) { await stopChild(); state.status = 'WAIT'; state.reason = wait; persist(); return status(); }
        if (child) { state.status = 'RUNNING'; state.reason = 'FIXTURE_RUNNING'; persist(); return status(); }
        if (state.restart_exhausted) { state.status = 'WAIT'; state.reason = 'RESTART_LIMIT'; persist(); return status(); }
        if (state.recovery_required || state.status === 'RUNNING' || state.status === 'STARTING') {
          if (state.restarts >= config.supervisor.max_restarts) { state.restart_exhausted = true; state.status = 'WAIT'; state.reason = 'RESTART_LIMIT'; persist(); return status(); }
          state.restarts++;
        }
        return launch();
      });
    },
    checkpoint(cursor) {
      if (transitioning || !locked || state.status !== 'RUNNING') deny('C1_CHECKPOINT_NOT_RUNNING');
      validateInfraConfig(config);
      const wait = vaultWait();
      if (wait) { state.status = 'WAIT'; state.reason = wait; persist(); deny('C1_CHECKPOINT_VAULT_WAIT'); }
      let encoded;
      try { encoded = canonicalize(cursor); } catch { deny('C1_CURSOR_INVALID'); }
      if (Buffer.byteLength(encoded) > 2048) deny('C1_CURSOR_TOO_LARGE');
      const previous = state.cursor;
      state.cursor = structuredClone(cursor);
      try { persist(); } catch (error) { state.cursor = previous; throw error; }
      return deepFreeze({status: 'TESTED_OFFLINE', cursor_digest: digest(cursor), live_ready: false});
    },
    stop() {
      return serialized(async () => {
        if (!locked) return status();
        validateInfraConfig(config); await stopChild();
        if (state.status !== 'HOLD') { state.status = 'STOPPED'; state.reason = 'FIXTURE_STOPPED'; }
        persist(); releaseLock(); return status();
      });
    },
    crashFixture() {
      return serialized(async () => {
        if (!child) deny('C1_FIXTURE_NOT_RUNNING');
        const owned = child, done = childExit;
        intentionalStop = false; owned.kill(); await done;
        return status();
      });
    },
    readFixtureCursor() {
      if (!locked) deny('C1_FIXTURE_NOT_OWNED');
      return structuredClone(state.cursor);
    }
  });
}
