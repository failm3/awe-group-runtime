import test from 'node:test';
import assert from 'node:assert/strict';
import {VERSION, validateDraft, validatePlan} from '../../../AUTO-01/contracts.mjs';
import {scenarios, draftFor} from '../../../AUTO-01/tests/scenarios.mjs';
import {fixture} from '../../../AUTO-01/fixture.mjs';
import {createMockModel} from '../../../AUTO-01/mock.mjs';
import {canonicalize as e0Canonicalize, digest as e0Digest} from '../../../contracts/canonical.mjs';
import {canonicalize, digest, RELEASE} from '../../contracts/index.mjs';

test('E0 schemas/serialization and existing three domain fixtures remain compatible', () => {
  assert.equal(VERSION, 'auto01/1'); assert.equal(RELEASE, 'AWE_E1/1');
  for (const scenario of scenarios) {
    const history = [{id: 'user_fixture', kind: 'user', text: scenario.goal}], draft = draftFor(scenario.requirements, {history});
    const validatedDraft = validateDraft(draft, history), validatedPlan = validatePlan({nodes: scenario.nodes}, validatedDraft);
    assert.deepEqual(validatedPlan.nodes, scenario.nodes); assert.equal(canonicalize(validatedDraft), e0Canonicalize(validatedDraft)); assert.equal(digest(validatedPlan), e0Digest(validatedPlan));
  }
});
test('historical E0 AUTO01 host still executes its synthetic profile without live effects', async () => {
  const scenario = scenarios[0], model = createMockModel({draft: c => draftFor(scenario.requirements, c), plan: () => ({nodes: scenario.nodes})});
  const run = await fixture({sessionId: 'e1compat', model}); await run.message(scenario.goal); await run.run();
  const state = run.host.snapshot(); assert.equal(state.phase, 'MOCK_WORK_COMPLETED'); assert.equal(state.realAutonomyVerified, false); assert.equal(state.accepted, false);
  const called = run.executors.calls.map(call => call.handoff.node_id); assert.deepEqual([...called].sort(), scenario.nodes.map(node => node.id).sort());
  for (const node of scenario.nodes) for (const dependency of node.depends_on) assert.ok(called.indexOf(dependency) < called.indexOf(node.id));
});
