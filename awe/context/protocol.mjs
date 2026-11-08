import {canonicalize, digest, bytesHash, requireThat, copy, integer} from './common.mjs';

export function validateHistory(history, operations, tools) {
  requireThat(Array.isArray(history) && history.length <= 256 && Array.isArray(operations), 'PROTOCOL_INVALID');
  const ids = new Set(), calls = new Map(), results = new Set();
  const operationIds = new Set(), callIds = new Set();
  for (const op of operations) {
    requireThat(!operationIds.has(op.operation_id) && !callIds.has(op.call_id)
      && ['PENDING', 'COMPLETE', 'OUTCOME_UNKNOWN'].includes(op.status), 'PROTOCOL_INVALID');
    operationIds.add(op.operation_id); callIds.add(op.call_id);
  }
  for (const message of history) {
    requireThat(message && typeof message.id === 'string' && !ids.has(message.id)
      && ['user', 'assistant', 'call', 'result'].includes(message.kind)
      && typeof message.text === 'string' && typeof message.critical === 'boolean', 'PROTOCOL_INVALID');
    ids.add(message.id);
    const keys = ['id', 'kind', 'text', 'critical'];
    if (message.kind === 'call') {
      keys.push('call_id', 'operation_id', 'tool', 'arguments');
      const op = operations.find(o => o.operation_id === message.operation_id);
      requireThat(op && op.call_id === message.call_id && op.tool === message.tool
        && op.arguments_hash === digest(message.arguments) && !calls.has(message.call_id)
        && tools.some(t => t.id === message.tool), 'PROTOCOL_INVALID');
      calls.set(message.call_id, op);
    }
    if (message.kind === 'result') {
      keys.push('call_id', 'operation_id', 'output');
      const op = calls.get(message.call_id);
      requireThat(op && op.operation_id === message.operation_id && op.status === 'COMPLETE'
        && !results.has(message.call_id) && message.output, 'PROTOCOL_INVALID');
      const output = message.output;
      requireThat(op.output_hash === digest(output), 'TOOL_RESULT_UNVERIFIED');
      requireThat(typeof output.hash === 'string' && integer(output.bytes) && typeof output.truncated === 'boolean'
        && ['TEXT', 'BINARY', 'BROKEN_STREAM'].includes(output.format), 'PROTOCOL_INVALID');
      if (output.truncated || output.format !== 'TEXT') requireThat(typeof output.artifact_ref === 'string', 'PROTOCOL_INVALID');
      else requireThat(typeof output.inline === 'string' && output.hash === bytesHash(Buffer.from(output.inline))
        && output.bytes === Buffer.byteLength(output.inline), 'PROTOCOL_INVALID');
      results.add(message.call_id);
    }
    requireThat(Object.keys(message).every(k => keys.includes(k)), 'PROTOCOL_INVALID');
    canonicalize(message);
  }
  for (const [call, op] of calls) requireThat(op.status !== 'COMPLETE' || results.has(call), 'PROTOCOL_INVALID');
  for (const op of operations.filter(o => o.status !== 'COMPLETE')) requireThat(calls.has(op.call_id), 'PENDING_OPERATION_MISSING');
  return copy(history);
}

// Extractive compaction deliberately forbids free-form semantic rewriting, including in untrusted data.
export function compactHistory(original, proposed) {
  requireThat(Array.isArray(proposed), 'COMPACTION_INVALID');
  const byId = new Map(original.map(m => [m.id, m]));
  let previousIndex = -1;
  for (const message of proposed) {
    const index = original.findIndex(m => m.id === message.id);
    requireThat(byId.has(message.id) && digest(message) === digest(byId.get(message.id)) && index > previousIndex, 'COMPACTION_INVALID');
    previousIndex = index;
  }
  const kept = new Set(proposed.map(m => m.id));
  requireThat(original.every(m => !(m.critical || ['call', 'result'].includes(m.kind)) || kept.has(m.id)), 'COMPACTION_INVALID');
  return {history: copy(proposed), omissions: original.filter(m => !kept.has(m.id))
    .map(m => ({id: m.id, hash: digest(m), reason: 'NONCRITICAL_HISTORY', recoverable_from: 'input_manifest'}))};
}
