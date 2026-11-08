import {canonicalize, digest} from '../../contracts/canonical.mjs';
import {parseIntent, copy, freeze, requireKeys} from '../policy/json.mjs';

const hash = /^sha256:[a-f0-9]{64}$(?![\s\S])/;
export const ensure = (ok, code) => { if (!ok) throw new Error(code); };
export const same = (a, b) => digest(a) === digest(b);
export const denied = error => freeze({decision: 'DENY', physical_decision: 'DENY',
  reason: /^[A-Z0-9_]+$(?![\s\S])/.test(error.message) ? error.message : 'RUNTIME_BOUNDARY_DENIED'});

/** Trusted host registry. No handler, URL, credential, terminal or executable is accepted. */
export function createToolRegistry() {
  const tools = new Map();
  return Object.freeze({
    register(text) {
      const tool = parseIntent(text);
      requireKeys(tool, ['id', 'digest', 'input_schema_hash', 'output_schema_hash', 'action', 'resource', 'effect_class', 'mode']);
      ensure(/^tool_[a-z0-9][a-z0-9_-]{0,63}$(?![\s\S])/.test(tool.id), 'TOOL_ID_INVALID');
      ensure(['digest', 'input_schema_hash', 'output_schema_hash'].every(k => hash.test(tool[k])), 'TOOL_PIN_REQUIRED');
      ensure(typeof tool.action === 'string' && tool.action.length > 0 && tool.action.length <= 128
        && typeof tool.resource === 'string' && tool.resource.length > 0 && tool.resource.length <= 256, 'TOOL_SCOPE_INVALID');
      ensure(['READ_ONLY', 'IDEMPOTENT_WRITE', 'NON_IDEMPOTENT'].includes(tool.effect_class)
        && tool.mode === 'SYNTHETIC_ONLY', 'PHYSICAL_DISPATCH_DISABLED');
      ensure(!tools.has(tool.id), 'TOOL_ALREADY_REGISTERED');
      tools.set(tool.id, freeze(copy(tool))); return tool.id;
    },
    get(id) { ensure(tools.has(id), 'TOOL_NOT_REGISTERED'); return tools.get(id); },
    inspect: () => freeze(copy([...tools.values()])),
    dispatch: () => denied(new Error('PHYSICAL_DISPATCH_DISABLED'))
  });
}

/** Useful deterministic subtask: summarize the exact synthetic body without reading artifacts. */
export function summarizeSyntheticPayload(payload) {
  const text = canonicalize(payload);
  return freeze({payload_hash: digest(payload), utf8_bytes: Buffer.byteLength(text, 'utf8')});
}
