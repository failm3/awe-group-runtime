import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {fixture, pending} from './harness.mjs';
import {digest, copy} from '../../awe/context/common.mjs';
import {boundToolOutput} from '../../awe/context/store.mjs';
import {validateShape} from '../../contracts/schema-validator.mjs';
import {createValidationContext, validate} from '../../contracts/validate.mjs';

export function dtoFixtures() {
  const f = fixture(), binding = {project_id: 'prj_alpha', task_id: 'task_context', auth_epoch: 1};
  const output = boundToolOutput(f.artifacts, binding, 'synthetic cross-module output '.repeat(30), {inline_bytes: 64});
  pending(f, 'COMPLETE', output); let built = f.build(); assert.equal(built.decision, 'READY_OFFLINE');
  built = f.engine.compact(f.session, built.ref); assert.equal(built.decision, 'READY_OFFLINE');
  const scope = {schema_version: '1.0.0', contract: 'scope-ids', scope: {project_id: f.state.project_id, task_id: f.state.task_id, operation_id: 'op_pending'}};
  const artifact = {schema_version: '1.0.0', contract: 'artifact-ref', artifact: {project_id: f.state.project_id,
    artifact_id: 'art_context_output', content_hash: output.hash, bytes: output.bytes, media_type: 'text/plain', aggregate_hash: digest({fixture: output.hash})}};
  assert.deepEqual(validateShape('scope-ids', scope), []); assert.deepEqual(validateShape('artifact-ref', artifact), []);
  const positives = JSON.parse(readFileSync(new URL('../contracts/fixtures/positive.json', import.meta.url)));
  const d01 = ['spec-revision', 'approval', 'attempt-receipt', 'provider-price'].map(id => {
    const fixture = positives.find(f => f.id === id); assert(fixture, id);
    const verdict = validate(fixture.contract, fixture.value, createValidationContext(fixture.context)); assert.equal(verdict.ok, true, JSON.stringify(verdict));
    return {contract: id, value: fixture.value, trusted_fixture_hash: digest(fixture.context), status: 'UNCHANGED_D01_SYNTHETIC_FIXTURE'};
  });
  return {fixture_version: 'd05-cross-module-v1', status: 'PROPOSED_OFFLINE_PORTS_ONLY', d01: {scope, artifact, readonly_fixtures: d01},
    d04: {build_request: copy(f.input), build_result: built, preflight: f.engine.preflight(f.session, built.ref), physical_dispatch: 'DENY'},
    d06: {root_budget_id: f.state.root_budget_id, reservation_refs: [built.manifest.reservation_ref], ledger: f.ledger.inspect(), real_usage: null, real_cost_micros: null},
    d07: {retrieval_query: {project_id: f.state.project_id, role: f.state.role, purpose: f.state.purpose, auth_epoch: f.state.auth_epoch},
      source_refs: built.manifest.selected_sources, tool_result: output, artifact_binding: binding},
    contract_change_requests: 'awe/context/CONTRACT-CHANGE-REQUESTS.md'};
}
if (process.argv[1] === fileURLToPath(import.meta.url))
  console.log(JSON.stringify(dtoFixtures(), null, 2));
