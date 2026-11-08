import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {setup, text} from './helpers.mjs';

export const negatives = JSON.parse(readFileSync(new URL('./fixtures/negative-intents.json', import.meta.url)));
export function runNegative(row) {
  const h = setup(), before = h.control.inspect();
  const path = row.path.split('.');
  let cursor = h.intent;
  for (const name of path.slice(0, -1)) cursor = cursor[name];
  cursor[path.at(-1)] = structuredClone(row.value);
  const pdp = h.worker.pdp(h.auth, text(h.intent));
  const actual = h.worker.execute(h.auth, text(h.intent));
  assert.deepEqual(pdp, {decision: 'DENY', reason: row.reason});
  assert.deepEqual(actual, {decision: 'DENY', reason: row.reason});
  assert.deepEqual(h.control.inspect(), before, 'deny must precede any effect, consume or quota mutation');
  return {id: row.id, criterion: row.criterion, expected: 'DENY:' + row.reason,
    actual: actual.decision + ':' + actual.reason, effects: 0, result: 'PASS'};
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  for (const row of negatives) console.log(JSON.stringify(runNegative(row)));
