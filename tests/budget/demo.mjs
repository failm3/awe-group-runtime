import {world, request, approve, success, notSent, route, readback, assertCaps} from './fixtures.mjs';

export async function scenarios() {
  const fallback = world({routes: [route(), route('r2', 'OpenRouter')], scripts: [[notSent()], [success()]]});
  const r = request('one', {allowedRoutes: ['r1', 'r2']}), a = approve(fallback, r);
  const first = await fallback.broker.execute(r, a.approval.id); fallback.ledger.advanceClock(first.retryAt);
  const second = await fallback.broker.execute(r, a.approval.id); assertCaps(fallback);
  const unknown = world({scripts: [[{status: 'SPLIT_COMMIT'}]]}), u = request(), b = approve(unknown, u);
  const splitCommit = await unknown.broker.execute(u, b.approval.id);
  const before = unknown.ledger.inspect().totals.global;
  const sibling = request('two'), c = approve(unknown, sibling);
  const bypass = await unknown.broker.execute(sibling, c.approval.id);
  unknown.ledger.reconcile(u.operationId, readback(unknown)); assertCaps(unknown);
  return {data: 'SYNTHETIC_ONLY', physicalDecision: 'DENY', actualProviderRequests: 0,
    fallback: {first, second, attempts: fallback.ledger.operation(r.operationId).attempts, totals: fallback.ledger.inspect().totals},
    splitCommit: {response: splitCommit, exposureBeforeReadback: before, siblingBypass: bypass,
      statusAfterReadback: unknown.ledger.operation(u.operationId).status, exposureAfterReadback: unknown.ledger.inspect().totals.global},
    notRun: ['POSTGRESQL', 'CROSS_PROCESS_CONCURRENCY', 'ACTUAL_PROVIDER_USAGE_PRICE', 'REAL_BALANCE_FX_TIMEOUT_CHARGING', 'NETWORK_COMPATIBILITY']};
}
console.log(JSON.stringify(await scenarios(), null, 2));
