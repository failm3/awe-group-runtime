import {canonicalize} from '../../contracts/canonical.mjs';
import {requireThat, usage, BUCKETS} from '../budget/money.mjs';

// Intentionally bounded E0 schema vocabulary; unsupported schemas fail closed.
export function validateShape(value, schema) {
  requireThat(schema && schema.additionalProperties === false && Array.isArray(schema.required)
    && schema.properties && Object.keys(schema).sort().join() === 'additionalProperties,properties,required', 'SCHEMA_UNSUPPORTED');
  canonicalize(value);
  requireThat(value && !Array.isArray(value) && typeof value === 'object', 'JSON_SHAPE');
  requireThat(schema.required.every(k => Object.hasOwn(value, k)) && Object.keys(value).every(k => Object.hasOwn(schema.properties, k)), 'JSON_SHAPE');
  for (const [key, type] of Object.entries(schema.properties)) {
    requireThat(['string', 'boolean', 'integer'].includes(type), 'SCHEMA_UNSUPPORTED');
    if (Object.hasOwn(value, key)) requireThat(type === 'integer' ? Number.isSafeInteger(value[key]) : typeof value[key] === type, 'JSON_SHAPE');
  }
}
export function validateResponse(response, request, route, attempt) {
  canonicalize(response);
  for (const key of ['correlationId', 'logicalRequestId']) requireThat(response[key] === request[key], 'RESPONSE_ID_MISMATCH');
  requireThat(response.attemptId === attempt.id && response.idempotencyKey === attempt.idempotencyKey, 'RESPONSE_ID_MISMATCH');
  requireThat(typeof response.providerRequestId === 'string' && response.providerRequestId.startsWith('synthetic-'), 'PROVIDER_RECEIPT_MISSING');
  requireThat(response.modelId === route.modelId, 'MODEL_SUBSTITUTION');
  requireThat(response.complete === true, 'PARTIAL_RESPONSE');
  usage(response.usage);
  for (const key of [...BUCKETS, 'toolCalls']) requireThat(response.usage[key] <= request.bounds[key], 'USAGE_EXCEEDS_BOUND');
  requireThat(response.output && typeof response.output.text === 'string' && Array.isArray(response.output.tools), 'OUTPUT_INVALID');
  const tools = response.output.tools;
  requireThat(tools.length <= response.usage.toolCalls && (request.features.tools || tools.length === 0), 'UNREQUESTED_TOOL');
  const ids = new Set();
  for (const tool of tools) {
    requireThat(typeof tool.id === 'string' && tool.id.length > 0 && !ids.has(tool.id)
      && Object.hasOwn(request.toolSchemas, tool.name), 'TOOL_INVALID');
    ids.add(tool.id); validateShape(tool.arguments, request.toolSchemas[tool.name]);
  }
  if (request.features.json) validateShape(response.output.json, request.jsonSchema);
  if (request.features.stream) {
    requireThat(Array.isArray(response.stream) && response.stream.length > 0, 'STREAM_MISSING');
    for (let i = 0; i < response.stream.length; i++) {
      const chunk = response.stream[i];
      requireThat(chunk.seq === i && (i === response.stream.length - 1 ? chunk.type === 'done' : chunk.type === 'text' && typeof chunk.data === 'string'), 'STREAM_INVALID');
    }
  }
  return response.usage;
}
