import {copy, freeze, parseIntent, requireKeys} from '../policy/json.mjs';
import {ensure} from '../tools/registry.mjs';

const transports = new WeakSet();
export const isSyntheticTransport = value => transports.has(value);
export const RUNTIME_INTERFACE = 'awe-hermes-runtime-adapter/1.0.0';

/** Local simulation of launch/status/interrupt/reconcile. This is not Hermes RPC wire compatibility. */
export function createFakeHermesTransport({loseLaunchCallback = false, loseInterruptCallback = false} = {}) {
  const handles = new WeakMap();
  let launches = 0;
  const get = handle => { const r = handles.get(handle); ensure(r, 'HELPER_HANDLE_LOST'); return r; };
  const api = Object.freeze({
    launch(grant) {
      const handle = Object.freeze({}); launches++;
      handles.set(handle, {run_id: grant.run_id, status: 'RUNNING', output: null});
      ensure(!loseLaunchCallback, 'LAUNCH_CALLBACK_LOST'); return handle;
    },
    status: handle => freeze(copy(get(handle))),
    interrupt(handle) {
      const r = get(handle); r.status = 'CANCEL_REQUESTED';
      ensure(!loseInterruptCallback, 'INTERRUPT_CALLBACK_LOST');
      r.status = 'CANCELLED'; return freeze(copy(r));
    },
    complete(handle, output) {
      const r = get(handle); ensure(r.status === 'RUNNING', 'HELPER_NOT_RUNNING');
      r.status = 'WORK_COMPLETED'; r.output = copy(output); return freeze(copy(r));
    },
    reconcile: handle => freeze(copy(get(handle))),
    inspect: () => ({interface: RUNTIME_INTERFACE, launches, physical_dispatches: 0})
  });
  transports.add(api); return api;
}

/** A-01: rebind the row after selection; never validate A's policy row against B. */
export function selectModelRow(text, selectedId, now) {
  // Catalog is synthetic data, not a provider lookup or a model recommendation.
  const rows = parseIntent(text);
  ensure(typeof now === 'string' && Number.isFinite(Date.parse(now)) && new Date(now).toISOString() === now, 'CLOCK_INVALID');
  ensure(Array.isArray(rows) && rows.length <= 128, 'MODEL_CATALOG_INVALID');
  const matches = rows.filter(row => row.id === selectedId);
  ensure(matches.length === 1, 'MODEL_ROW_AMBIGUOUS');
  const row = matches[0];
  requireKeys(row, ['id', 'enabled', 'reviewed', 'fingerprint', 'tested_fingerprint', 'expires_at']);
  ensure(row.enabled === true && row.reviewed === true && row.expires_at > now
    && /^sha256:[a-f0-9]{64}$(?![\s\S])/.test(row.fingerprint)
    && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[.]\d{3}Z$/.test(row.expires_at)
    && Number.isFinite(Date.parse(row.expires_at)) && new Date(row.expires_at).toISOString() === row.expires_at
    && row.fingerprint === row.tested_fingerprint, 'MODEL_ROW_NOT_ADMITTED');
  return freeze(copy(row));
}
