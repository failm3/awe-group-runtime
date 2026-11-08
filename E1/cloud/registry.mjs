import {digest, immutable, need, utc, validateCapabilityDescriptor} from '../contracts/index.mjs';
import {priceBounds, validateSource} from './pricing.mjs';

export const CLOUD_ENDPOINT = 'https://router.cheap/v1/chat/completions';
export const CATALOG_VERSION = 'awe.e1.router-cheap.catalog/1';
const FEATURES = ['chat_completions', 'strict_json_schema', 'non_streaming', 'source_identity', 'provider_request_id', 'usage', 'actual_billed_charge', 'bounded_input_tokens'];
const positive = value => Number.isSafeInteger(value) && value > 0;
/** Normalization is local and never discovers a model or invents missing prices. */
export function validateCloudCatalog(input, now) {
  utc(now);
  const catalog = immutable(input);
  need(catalog.version === CATALOG_VERSION && catalog.provider === 'router.cheap' && catalog.endpoint === CLOUD_ENDPOINT && catalog.currency === 'USD', 'CLOUD_CATALOG_IDENTITY');
  utc(catalog.observed_at); utc(catalog.expires_at);
  need(catalog.observed_at <= now && now < catalog.expires_at && Date.parse(catalog.expires_at) - Date.parse(catalog.observed_at) <= 86400000, 'CLOUD_PRICE_STALE');
  need(catalog.official_source === 'https://router.cheap' || typeof catalog.official_source === 'string' && catalog.official_source.startsWith('https://router.cheap/'), 'CLOUD_CATALOG_PROVENANCE');
  need(/^sha256:[a-f0-9]{64}$/.test(catalog.source_digest), 'CLOUD_CATALOG_PROVENANCE');
  need(Array.isArray(catalog.routes) && catalog.routes.length > 0 && catalog.routes.length <= 64 && new Set(catalog.routes.map(x => x.route_id)).size === catalog.routes.length, 'CLOUD_ROUTES_UNKNOWN');
  for (const route of catalog.routes) {
    need(typeof route.route_id === 'string' && /^router\.cheap\.chat\.[a-z0-9_.-]{1,90}$/.test(route.route_id) && typeof route.model_id === 'string' && /^[A-Za-z0-9][A-Za-z0-9/_.:-]{0,127}$/.test(route.model_id) && typeof route.route_version === 'string' && /^[1-9][0-9]*\.[0-9]+\.[0-9]+$/.test(route.route_version), 'CLOUD_ROUTE_IDENTITY');
    need(positive(route.context_tokens) && route.context_tokens <= 4000000 && positive(route.max_output_tokens) && route.max_output_tokens <= route.context_tokens, 'CLOUD_LIMITS_UNKNOWN');
    need(route.features && FEATURES.every(key => route.features[key] === 'CONFIRMED'), 'CLOUD_FEATURE_UNKNOWN');
    need(route.input_token_bound === 'HOST_VERIFIED_UPPER_BOUND' && typeof route.input_bound_evidence_digest === 'string' && /^sha256:[a-f0-9]{64}$/.test(route.input_bound_evidence_digest), 'CLOUD_INPUT_BOUND_UNKNOWN');
    need(Array.isArray(route.sources) && route.sources.length > 0 && route.sources.length <= 64 && new Set(route.sources.map(x => x.source_id)).size === route.sources.length, 'CLOUD_SOURCE_UNKNOWN');
    route.sources.forEach(validateSource);
  }
  return catalog;
}
export function requireCloudCapability(registry, capability_id, route, now) {
  need(registry && Array.isArray(registry.entries), 'CLOUD_REGISTRY_REQUIRED');
  const entry = registry.entries.find(x => x.descriptor?.ref?.capability_id === capability_id);
  need(entry, 'CLOUD_CAPABILITY_MISSING');
  const cap = validateCapabilityDescriptor(entry.descriptor);
  need(cap.executor_kind === 'llm' && cap.state === 'ACTIVE' && cap.effect_class === 'NONE' && cap.max_attempts === 1 && now < cap.health_until && entry.installed === true && entry.approved_status === 'BOUNDED_CANARY', 'CLOUD_CAPABILITY_DENIED');
  need(Array.isArray(entry.cloud_routes) && entry.cloud_routes.some(x => x.route_id === route.route_id && x.route_version === route.route_version), 'CLOUD_CAPABILITY_ROUTE_DENIED');
  return cap;
}
export function cloudQuote({catalog: input, route_id, max_input_tokens, max_output_tokens, now}) {
  const catalog = validateCloudCatalog(input, now), route = catalog.routes.find(x => x.route_id === route_id);
  need(route, 'CLOUD_ROUTE_DENIED');
  need(positive(max_input_tokens) && positive(max_output_tokens) && max_output_tokens <= route.max_output_tokens && max_input_tokens + max_output_tokens <= route.context_tokens, 'CLOUD_TOKEN_LIMIT');
  const price = priceBounds(route, max_input_tokens, max_output_tokens);
  const route_snapshot = immutable({schema: 'awe.e1.cloud-route/1', provider: catalog.provider, endpoint: catalog.endpoint, source_digest: catalog.source_digest, observed_at: catalog.observed_at, expires_at: catalog.expires_at, ...route});
  const quote = {version: 'awe.e1.router-cheap.quote/1', route_id, route_version: route.route_version, model_id: route.model_id, provider: catalog.provider, endpoint: catalog.endpoint, catalog_digest: digest(catalog), route_snapshot, route_snapshot_digest: digest(route_snapshot), source_digest: catalog.source_digest, observed_at: catalog.observed_at, expires_at: catalog.expires_at, max_input_tokens, max_output_tokens, ...price};
  return immutable({...quote, quote_digest: digest(quote)});
}
