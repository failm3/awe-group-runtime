import test from 'node:test';
import assert from 'node:assert/strict';
import {dtoFixtures} from './cross-module.mjs';

test('D04 build and preflight DTO bind the same manifest, payload and operation identities', () => {
  const x = dtoFixtures(); assert.equal(x.d04.build_result.ref, x.d04.preflight.ref);
  assert.equal(x.d04.preflight.request_hash, x.d04.build_result.request_hash); assert.equal(x.d04.preflight.physical_decision, 'DENY');
  assert.equal(x.d04.build_result.manifest.operations[0].operation_id, x.d01.scope.scope.operation_id);
});
test('D06 reservations stay rooted and D07 artifact/source DTOs carry provenance without authority promotion', () => {
  const x = dtoFixtures(); assert.equal(x.d06.ledger.reservations.length, 2);
  assert(x.d06.ledger.reservations.every(r => r.root_budget_id === x.d06.root_budget_id));
  assert.equal(x.d07.tool_result.hash, x.d01.artifact.artifact.content_hash);
  assert.equal(x.d07.tool_result.bytes, x.d01.artifact.artifact.bytes); assert.equal(x.d06.real_cost_micros, null);
  assert(x.d07.source_refs.every(s => s.trust === 'UNTRUSTED_SOURCE'));
});
test('D01 DTO shapes/semantic fixtures remain readable without modifications or new authority', () => {
  const x = dtoFixtures(); assert.equal(x.d01.readonly_fixtures.length, 4); assert.equal(x.status, 'PROPOSED_OFFLINE_PORTS_ONLY');
});
