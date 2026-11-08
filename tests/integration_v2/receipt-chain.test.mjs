import test from 'node:test';
import assert from 'node:assert/strict';
import {createReceiptChain} from '../../awe/integration_v2/execution.mjs';
import {digest} from '../../awe/integration_v2/ports.mjs';

const sequence = ['CONTEXT_PREFLIGHT', 'SYNTHETIC_CHILD', 'D06_SETTLED', 'INT01_CANARY', 'D03_RECEIPT', 'D07_ARTIFACT'];

test('INT02-AUD-01 direct append makes OUTCOME_UNKNOWN terminal at every normal prefix', () => {
  for (let prefix = 0; prefix <= sequence.length; prefix++) {
    const chain = createReceiptChain();
    for (const kind of sequence.slice(0, prefix)) chain.append(kind, {});
    const unknown = chain.append('OUTCOME_UNKNOWN', {reason: 'DIRECT_APPEND'});
    assert.equal(unknown.kind, 'OUTCOME_UNKNOWN');
    assert.equal(chain.inspect().quarantined, true);
    assert.equal(chain.completion().work, 'OUTCOME_UNKNOWN');
    const frozen = chain.inspect();
    for (const kind of [...sequence, 'OUTCOME_UNKNOWN']) {
      assert.throws(() => chain.append(kind, {}), /CHAIN_BLOCKED/);
      assert.deepEqual(chain.inspect(), frozen);
      assert.equal(chain.completion().work, 'OUTCOME_UNKNOWN');
    }
  }
});

test('INT02-AUD-01 independent audit reproduction cannot reach WORK_COMPLETED', () => {
  const chain = createReceiptChain();
  chain.append('OUTCOME_UNKNOWN', {});
  for (const kind of sequence.slice(1)) {
    assert.throws(() => chain.append(kind, {}), /CHAIN_BLOCKED/);
  }
  assert.equal(chain.inspect().rows.length, 1);
  assert.equal(chain.completion().work, 'OUTCOME_UNKNOWN');
});

test('INT02-AUD-01 repeated quarantine is a no-op and preserves the first reason and hash', () => {
  const chain = createReceiptChain();
  chain.append('CONTEXT_PREFLIGHT', {});
  chain.quarantine('FIRST_REASON');
  const frozen = chain.inspect();
  chain.quarantine('SECOND_REASON');
  chain.quarantine('FIRST_REASON');
  assert.deepEqual(chain.inspect(), frozen);
  assert.equal(frozen.rows.at(-1).evidence.reason, 'FIRST_REASON');
  assert.equal(frozen.rows.at(-1).evidence.replay_allowed, false);
  assert.throws(() => chain.append('SYNTHETIC_CHILD', {}), /CHAIN_BLOCKED/);
  assert.equal(chain.completion().work, 'OUTCOME_UNKNOWN');
});

test('INT02-AUD-01 quarantine after direct OUTCOME_UNKNOWN neither appends nor rewrites evidence', () => {
  const chain = createReceiptChain();
  chain.append('OUTCOME_UNKNOWN', {reason: 'DIRECT_REASON'});
  const frozen = chain.inspect();
  chain.quarantine('LATER_REASON');
  chain.quarantine('LATER_REASON');
  assert.deepEqual(chain.inspect(), frozen);
  assert.equal(chain.inspect().rows.length, 1);
  assert.throws(() => chain.append('OUTCOME_UNKNOWN', {}), /CHAIN_BLOCKED/);
  assert.equal(chain.completion().work, 'OUTCOME_UNKNOWN');
});

test('INT02-AUD-01 normal ordered chain completes with intact causal hashes and no acceptance authority', () => {
  const chain = createReceiptChain();
  assert.equal(chain.completion().work, 'INCOMPLETE');
  for (const kind of sequence) {
    chain.append(kind, {});
    assert.equal(chain.completion().work, kind === 'D07_ARTIFACT' ? 'WORK_COMPLETED' : 'INCOMPLETE');
    assert.equal(chain.inspect().quarantined, false);
  }
  const {rows} = chain.inspect();
  for (let i = 0; i < rows.length; i++) {
    const {hash, ...body} = rows[i];
    assert.equal(hash, digest(body));
    assert.equal(body.previous, i === 0 ? null : rows[i - 1].hash);
  }
  assert.deepEqual(chain.completion(), {
    work: 'WORK_COMPLETED', independent_qa: 'NOT_RUN', accepted: false,
    published: false, authoritative_complete: false, physical_decision: 'DENY'
  });
});
