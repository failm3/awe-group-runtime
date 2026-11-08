import {immutable, inspectBoundSchema} from '../contracts/index.mjs';

const text = maxLength => ({type: 'string', minLength: 1, maxLength});
const id = {...text(80), pattern: '^[a-z][a-z0-9_.-]{0,79}$'};
const object = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false});
const list = (items, maxItems, minItems = 0) => ({type: 'array', items, minItems, maxItems, uniqueItems: true});
export const INSTRUCTION_SCHEMA = inspectBoundSchema(object({instruction: text(8192)}));
export const TEXT_SCHEMA = inspectBoundSchema(object({text: text(8192)}));
export const HEAD_DRAFT_SCHEMA = inspectBoundSchema(object({
  reason: text(512),
  tasks: list(object({
    task_id: id, title: text(160),
    capability_id: {...text(80), enum: ['e1.code.parse', 'e1.code.review']},
    instruction: text(1024), depends_on: list(id, 5), criterion_ids: list(id, 8, 1)
  }), 5, 1)
}));
export const MODEL_POLICY = immutable({
  version: 'awe.e1.local-model-policy/1', route_id: 'ollama.local.qwen3-4b-instruct',
  endpoint: 'http://127.0.0.1:11434', model: 'qwen3:4b-instruct',
  digest: '0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0',
  provider: 'ollama', region: 'LOCAL_HOST', api_cost_micros: 0,
  max_parallel: 1, max_wire_attempts: 1, context_tokens: [4096, 8192],
  min_output_tokens: 512, max_output_tokens: 2048, max_timeout_ms: 120000,
  allowed_data_labels: ['SYNTHETIC', 'CLEAN_CODE'], allowed_data_classes: ['PUBLIC', 'PROJECT'],
  cloud_fallback: false, automatic_retry: false
});
