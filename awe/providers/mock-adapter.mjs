import {canonicalize} from '../../contracts/canonical.mjs';
import {requireThat} from '../budget/money.mjs';

const instances = new WeakMap();
const copy = value => JSON.parse(canonicalize(value));
// No arbitrary callbacks, URLs, SDKs, credentials or pluggable transport functions.
export function createMockAdapter({provider, script = [], deferred = false}) {
  requireThat(['router.cheap', 'OpenRouter', 'Requesty', 'direct'].includes(provider), 'PROVIDER_UNKNOWN');
  const token = Object.freeze({kind: 'D06_OPAQUE_MOCK'});
  const data = {provider, script: copy(script), deferred, calls: [], pending: []};
  instances.set(token, data);
  return {adapter: token, control: Object.freeze({
    calls: () => copy(data.calls),
    completeNext: () => { const next = data.pending.shift(); requireThat(next, 'NO_PENDING_MOCK'); next(); }
  })};
}
export function mockProvider(adapter) {
  const data = instances.get(adapter); requireThat(data, 'MOCK_ADAPTER_REQUIRED'); return data.provider;
}
export function invokeMock(adapter, request) {
  const data = instances.get(adapter); requireThat(data, 'MOCK_ADAPTER_REQUIRED');
  data.calls.push(copy(request));
  const scripted = data.script.shift() ?? {status: 'TIMEOUT'};
  const response = {...copy(scripted), correlationId: request.correlationId, logicalRequestId: request.logicalRequestId,
    attemptId: request.attemptId, idempotencyKey: request.idempotencyKey,
    providerRequestId: 'synthetic-' + request.attemptId, modelId: request.modelId, ...copy(scripted)};
  if (data.deferred) return new Promise(resolve => data.pending.push(() => resolve(response)));
  return Promise.resolve(response);
}
