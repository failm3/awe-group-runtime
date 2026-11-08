// D-09 additive port. No default connection, transport, credentials or physical executor.
// Supply a dedicated authenticated pg-compatible pool from a reviewed trusted host.
export const PHYSICAL_DECISION = 'DENY';
export class PersistenceError extends Error {
  constructor(code, {cause, outcomeUnknown = false} = {}) {
    super(code, {cause}); this.code = code; this.outcomeUnknown = outcomeUnknown;
  }
}
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x)
  && [Object.prototype, null].includes(Object.getPrototypeOf(x));
const id = x => typeof x === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(x);
export function micros(value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,29})$/.test(value)) throw new PersistenceError('MICROS_INVALID');
  return value;
}
function command(value, allowed, required) {
  if (!object(value) || Object.keys(value).some(k => !allowed.includes(k))
    || required.some(k => !Object.hasOwn(value, k))) throw new PersistenceError('COMMAND_INVALID');
  const result = structuredClone(value);
  for (const key of ['project_id','task_id','operation_id','attempt_id','effect_slot','approval_id','grant_id','idempotency_key']) {
    if (Object.hasOwn(result,key) && !id(result[key])) throw new PersistenceError('ID_INVALID');
  }
  for (const key of ['plan_hash','payload_hash','evidence_hash']) {
    if (Object.hasOwn(result,key) && !/^sha256:[a-f0-9]{64}$/.test(result[key])) throw new PersistenceError('HASH_INVALID');
  }
  for (const key of ['reserve_micros','actual_micros']) if (Object.hasOwn(result,key)) micros(result[key]);
  for (const key of ['fence','input_tokens','output_tokens']) {
    if (Object.hasOwn(result,key) && (!Number.isSafeInteger(result[key]) || result[key] < 0)) throw new PersistenceError('INTEGER_INVALID');
  }
  if (result.result !== undefined && !['SUCCEEDED','FAILED','CANCELLED'].includes(result.result)) throw new PersistenceError('RESULT_INVALID');
  for (const key of ['provider','invoice_id']) {
    if (Object.hasOwn(result,key) && !id(result[key])) throw new PersistenceError('ID_INVALID');
  }
  return result;
}
const definitions = Object.freeze({
  admit: ['admit', ['project_id','task_id','operation_id','attempt_id','effect_slot','approval_id','grant_id','idempotency_key','plan_hash','payload_hash','reserve_micros']],
  inspect: ['inspect_attempt', ['project_id','attempt_id']],
  claim: ['claim_attempt', ['project_id','attempt_id']],
  markSent: ['mark_sent', ['project_id','attempt_id','fence']],
  cancel: ['cancel_attempt', ['project_id','attempt_id']],
  recordResult: ['record_result', ['project_id','attempt_id','result','evidence_hash']],
  reconcile: ['reconcile_charge', ['project_id','attempt_id','provider','invoice_id','actual_micros','input_tokens','output_tokens','evidence_hash']],
  proveNotSent: ['prove_not_sent', ['project_id','attempt_id','evidence_hash']],
  recover: ['recover_project', ['project_id']],
  advanceEpoch: ['advance_epoch', ['project_id','epoch']]
});
// One transaction and one fixed function call. Never auto-retry an ambiguous COMMIT.
// Role/membership and actor identity come from session_user, NEVER command JSON/GUCs.
export function createPostgresPersistence(pool) {
  return createFixedPersistence(pool,definitions,false);
}
const localDefinitions=Object.freeze({
  admit:['admit_local_master01',definitions.admit[1]],
  claim:['claim_local_master01',['project_id','attempt_id']],
  markSent:['sent_local_master01',['project_id','attempt_id','fence']],
  recordResult:['result_local_master01',['project_id','attempt_id','result','evidence_hash','output']],
  cancel:['cancel_local_master01',['project_id','attempt_id']],
  inspect:['inspect_local_master01',['project_id','attempt_id']],
  recover:['recover_local_master01',['project_id','task_id']],
  flagUnknown:['unknown_local_master01',['project_id','attempt_id']]
});
export function createPostgresLocalPersistence(pool){return createFixedPersistence(pool,localDefinitions,true);}
function createFixedPersistence(pool,methods,local) {
  if (!pool || typeof pool.connect !== 'function') throw new PersistenceError('POOL_REQUIRED');
  let cleanupFailed=false;
  async function invoke(method, value) {
    if(cleanupFailed)throw new PersistenceError('CLIENT_CLEANUP_UNPROVEN');
    const [fn, fields] = methods[method];
    const body = command(value, fields, fields);
    if (method === 'advanceEpoch' && !['auth','policy','owner','stop'].includes(body.epoch)) throw new PersistenceError('EPOCH_INVALID');
    let client;
    try { client = await pool.connect(); }
    catch (cause) { throw new PersistenceError('CONNECTION_UNAVAILABLE', {cause}); }
    if (!client || typeof client.query !== 'function' || typeof client.release !== 'function') {
      try { client?.release?.(true); } catch {}
      throw new PersistenceError('CLIENT_CONTRACT_INVALID');
    }
    let began = false, committing = false, broken = false;
    try {
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE'); began = true;
      await client.query("SET LOCAL synchronous_commit = on");
      await client.query("SET LOCAL statement_timeout = '10s'");
      await client.query("SET LOCAL lock_timeout = '5s'");
      const response = await client.query(`SELECT awe_d09.${fn}($1::jsonb) AS result`, [JSON.stringify(body)]);
      if (response.rows?.length !== 1 || !object(response.rows[0].result)
        || response.rows[0].result.physical_decision !== 'DENY') throw new PersistenceError('DATABASE_CONTRACT_INVALID');
      const result = structuredClone(response.rows[0].result);
      if (Object.hasOwn(result,'reserve_micros')) micros(result.reserve_micros);
      if (result.actual_micros !== null && Object.hasOwn(result,'actual_micros')) micros(result.actual_micros);
      committing = true;
      await client.query('COMMIT'); began = false;
      return Object.freeze(local?{...result,committed:true}:result);
    } catch (cause) {
      broken = true;
      if (began) { try { await client.query('ROLLBACK'); } catch {} }
      // Even a failed rollback cannot disambiguate a missing COMMIT acknowledgement.
      if (committing) throw new PersistenceError('COMMIT_OUTCOME_UNKNOWN', {cause, outcomeUnknown: true});
      throw new PersistenceError(cause instanceof PersistenceError ? cause.code : 'TRANSACTION_REJECTED', {cause});
    } finally {
      // A pool bookkeeping failure must not replace a known COMMIT result or
      // erase the explicit unknown outcome from the transaction above.
      try { const closed=await client.release(broken);if(closed?.released===false)cleanupFailed=true; } catch { cleanupFailed=true; }
    }
  }
  return Object.freeze(Object.fromEntries(Object.keys(methods).map(k => [k, value => invoke(k,value)])));
}
