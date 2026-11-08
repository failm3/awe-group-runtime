import test from 'node:test';
import assert from 'node:assert/strict';
import {readPlan, readProbes, inspectPlan} from '../../awe/sandbox/inspect-plan.mjs';

test('M03/S01 future sandbox manifest is a default-deny proposal, not executed isolation proof', () => {
  assert.deepEqual(inspectPlan(readPlan(), readProbes()), []);
});
for (const [name, change] of [
  ['egress', p => {p.network.default = 'ALLOW';}],
  ['IPv6', p => {p.network.ipv6 = 'ALLOW';}],
  ['host mount', p => {p.lifecycle.host_mounts.push('synthetic-host');}],
  ['database privilege', p => {p.database.bypassrls = true;}],
  ['QA sharing', p => {p.storage.qa_hidden_volume = 'WORKER_CHECKOUT';}],
  ['false PASS', p => {p.acceptance.real_isolation = 'PASS';}],
  ['deployment', p => {p.deployment_authorized = true;}]
]) test(`M03/S02-${name} unsafe or misleading manifest rejected`, () => {
  const plan = readPlan(); change(plan); assert(inspectPlan(plan, readProbes()).length > 0);
});
test('M03/S03 future probes cannot silently disappear or claim executed results', () => {
  const probes = readProbes(); probes.probes.pop(); assert(inspectPlan(readPlan(), probes).length > 0);
  const lied = readProbes(); lied.probes[0].status = 'PASS'; assert(inspectPlan(readPlan(), lied).length > 0);
});
