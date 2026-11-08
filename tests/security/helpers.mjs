import {readFileSync} from 'node:fs';
import {digest} from '../../contracts/canonical.mjs';
import {createOfflineSecurity} from '../../awe/policy/security.mjs';

export const world = () => JSON.parse(readFileSync(new URL('./fixtures/world.json', import.meta.url)));
export const hash = char => 'sha256:' + char.repeat(64);
export const text = value => JSON.stringify(value);
export function setup({seed = world(), role = 'EXECUTOR', action = 'publish', resource = 'site:page',
  clock = () => '2026-11-05T12:00:00.000Z', quoteStatus = 'QUOTED', outputLimit = 16384,
  attempts = 5} = {}) {
  const system = createOfflineSecurity(seed, {clock}), {control, worker} = system;
  const scope = {project_id: 'prj_site_zhiv', task_id: 'task_page', operation_id: 'op_synthetic'};
  const ctx = id => worker.authenticate(control.issueSession(id), scope);
  const owner = ctx('act_owner'), supervisor = ctx('act_supervisor');
  const actor = seed.principals.find(p => p.actor.role === role).actor;
  const auth = ctx(actor.identity_id);
  const meta = who => ({schema_version: '1.0.0', request_id: 'req_synthetic', correlation_id: 'corr_synthetic',
    causation_id: null, actor: who, scope: structuredClone(scope), epochs: {policy: 1, auth: 1, stop: 0, owner: 1},
    spec: structuredClone(seed.projects[0].tasks[0].spec), created_at: '2026-11-05T11:59:00.000Z', expected_revision: 3});
  // Authored independently of D-01 fixtures. Contracts validate the emitted DTOs.
  const capability = {contract: 'tool-capability', ...meta(supervisor.actor), tool_id: 'tool_recorder',
    tool_version: '1.0.0', tool_digest: hash('d'), input_schema_hash: hash('e'), output_schema_hash: hash('f'),
    effect_class: action === 'read' ? 'READ_ONLY' : 'NON_IDEMPOTENT', timeout_ms: 1000,
    max_output_bytes: outputLimit, network_scope: 'NONE', credential_handle: null, retry_eligible: false};
  const policy = {actions: [action], resources: seed.resources.filter(r => r.project_id === scope.project_id &&
    r.task_id === scope.task_id).map(r => r.id), roles: [role], cost_micros: '10'};
  control.registerTool(supervisor, capability, policy);
  const grant = {contract: 'run-grant', ...meta(supervisor.actor), run_id: 'run_parent', parent_run_id: null,
    capabilities: [capability.tool_id], deadline: '2026-11-05T12:05:00.000Z', budget_ref: hash('1'),
    config_hash: hash('2'), manifest_hash: hash('3'), depth: 0, max_children: 2, max_physical_attempts: attempts};
  control.registerGrant(supervisor, grant, actor.identity_id);
  const payload = {recipient: 'synthetic-local-recorder', content: 'synthetic-example'};
  const approval = {contract: 'approval', ...meta(owner.actor), approval_id: 'appr_once', action, resource,
    payload_hash: digest(payload), approver: owner.actor, expires_at: '2026-11-05T12:05:00.000Z',
    max_uses: 1, uses: 0, revoked_at: null, policy_revision: 1};
  control.registerApproval(owner, approval, actor.identity_id);
  const quote = {schema_version: '1.0.0', contract: 'provider-price', price_profile_id: 'price_synthetic',
    status: quoteStatus, seller: 'synthetic-seller.invalid', model: 'synthetic-model',
    currency: quoteStatus === 'QUOTED' ? 'USD' : null,
    input_micros_per_million: quoteStatus === 'QUOTED' ? '1' : null,
    output_micros_per_million: quoteStatus === 'QUOTED' ? '2' : null,
    quote_ref: quoteStatus === 'QUOTED' ? hash('4') : null,
    checked_at: quoteStatus === 'QUOTED' ? '2026-11-05T11:59:00.000Z' : null,
    expires_at: quoteStatus === 'QUOTED' ? '2026-11-05T12:01:00.000Z' : null,
    reason: quoteStatus === 'QUOTED' ? null : 'Synthetic quote unknown'};
  if (['charge', 'inference'].includes(action)) control.registerQuote(supervisor, quote, {scope, tool_id: capability.tool_id});
  const intent = {scope, actor: structuredClone(actor), action, resource, payload, payload_hash: digest(payload),
    epochs: {policy: 1, auth: 1, stop: 0, owner: 1}, spec: structuredClone(grant.spec), expected_revision: 3,
    tool_id: capability.tool_id, tool_digest: capability.tool_digest, input_schema_hash: capability.input_schema_hash,
    run_id: grant.run_id, approval_id: approval.approval_id,
    quote_id: ['charge', 'inference'].includes(action) ? quote.price_profile_id : null, reservation_micros: '10'};
  return {...system, auth, owner, supervisor, intent, approval, grant, capability, policy, quote, meta, ctx};
}
