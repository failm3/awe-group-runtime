import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {evaluateExact} from '../qa/evaluator.mjs';
import {bytesHash,canonicalize,digest,need} from '../qa/common.mjs';

// Trusted evaluator service implementation. Its DB credential belongs to a
// separate process, never to the verifier requester, worker or owner. The only
// input is a durable run identity; there is NO proof/verdict/signing callback API.
export async function evaluatePendingRun(pool,request) {
  need(request && Object.getPrototypeOf(request)===Object.prototype
    && Object.keys(request).sort().join()===['project_id','run_id','task_id'].join(),'EVALUATOR_REQUEST_INVALID');
  for(const key of Object.keys(request))need(typeof request[key]==='string' && request[key].length<=128,'EVALUATOR_REQUEST_INVALID');
  async function transaction(fn,body) {
    const client=await pool.connect();let began=false,committing=false,broken=false;
    try {
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');began=true;
      await client.query('SET LOCAL synchronous_commit = on');
      await client.query("SET LOCAL statement_timeout = '10s'");
      const response=await client.query(`SELECT awe_int03.${fn}($1::jsonb) AS result`,[JSON.stringify({...body,...request})]);
      const result=response.rows?.[0]?.result;need(result?.physical_decision==='DENY','EVALUATOR_DB_CONTRACT');
      committing=true;await client.query('COMMIT');began=false;return result;
    } catch(cause) {
      broken=true;if(began)try{await client.query('ROLLBACK');}catch{}
      if(committing){const error=new Error('COMMIT_OUTCOME_UNKNOWN',{cause});error.outcomeUnknown=true;throw error;}
      throw cause;
    } finally {try{client.release(broken);}catch{}}
  }
  const pending=await transaction('read_evaluation',{});
  const sha=path=>createHash('sha256').update(readFileSync(path)).digest('hex');
  const evaluatorSha=sha(new URL('../qa/evaluator.mjs',import.meta.url)),serviceSha=sha(new URL('./evaluator-service.mjs',import.meta.url));
  need(evaluatorSha===pending.evaluator_sha256 && serviceSha===pending.service_sha256,'EVALUATOR_SOURCE_PIN_MISMATCH');
  if(pending.bundle?.requirements?.kind==='OWNER02_TEXT_STATS_V1'){
    need(sha(new URL('../qa/dynamic-output.mjs',import.meta.url))===pending.dynamic_output_sha256,'DYNAMIC_EVALUATOR_OWNER_PIN_NOT_BOUND');
    need(pending.dynamic_evidence_readback===true,'DYNAMIC_TRUSTED_READBACK_NOT_BOUND');
  }
  if(pending.proof)return pending; // Only an already committed service proof.
  const bundle=pending.bundle,bytes=Buffer.from(bundle.bytes_base64,'base64');
  need(bytesHash(bytes)===bundle.reference.file_hash,'ARTIFACT_CHANGED');
  // Fixed imported implementation, actually invoked before any proof is built.
  const result=evaluateExact({bytes,reference:bundle.reference,requirements:bundle.requirements,
    evidence:bundle.evidence,operations:bundle.operations,pin:bundle.pin});
  const proof={mode:'E0_SYNTHETIC_ONLY',run_id:pending.run_id,verifier:pending.actor,bundle_hash:pending.bundle_hash,
    artifact:bundle.reference,requirements_hash:digest(bundle.requirements),result};
  const stored=await transaction('finish_qa',{grant_id:pending.grant_id,proof:canonicalize(proof)});
  return {...stored,evaluation_execution:{calls:1,evaluator_sha256:evaluatorSha,service_sha256:serviceSha}};
}
