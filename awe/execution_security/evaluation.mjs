import {readFileSync} from 'node:fs';
import {evaluateExact} from '../qa/evaluator.mjs';
import {isDynamicRequirements} from '../qa/literal-output.mjs';
import {parseIntent,digest,hashBytes,requireKeys,need,freeze,copy,denial} from './common.mjs';
export const evaluationPins=()=>Object.freeze(Object.fromEntries([
 './evaluation.mjs','./identity.mjs','./common.mjs','../policy/json.mjs','../memory/boundary.mjs','../qa/evaluator.mjs','../qa/dynamic-output.mjs','../qa/literal-output.mjs','../integration_v4/literal-contract.mjs','../executable_tools/protocol.mjs','../tool_registry/common.mjs','../qa/common.mjs','../../contracts/canonical.mjs',
 '../qa_profiles/worker.mjs','../qa_profiles/runner.mjs','../qa_profiles/contracts.mjs','../qa_profiles/node-guard.cjs','../qa_profiles/service.mjs','../qa_profiles/sec-issuer.mjs','../qa_profiles/auto02.mjs','../qa_profiles/d08-evidence.mjs','../qa/dynamic-store.mjs','../qa/state-port.mjs','../qa/service.mjs','../state/literal-guards.mjs','../state/artifact-catalogue.mjs','../state/service.mjs','../artifacts/d03-artifact-port.mjs','../artifacts/service.mjs'
].map(path=>[path,hashBytes(readFileSync(new URL(path,import.meta.url)))])));
/** AUD01 defense: requester supplies only run identity. Fixed evaluator computes
 * the verdict; no proof, hash-only PASS, evaluator callback or model opinion API.
 * Store must atomically enforce current authority at commit and acceptance.
 */
export function createEvaluationBoundary({verifier,issuer,store,pins}){
 need(digest(evaluationPins())===digest(pins),'EVALUATOR_SOURCE_PIN_MISMATCH');
 const parse=text=>{const r=parseIntent(text);requireKeys(r,['project_id','task_id','run_id']);return r;};
 return Object.freeze({
  async start(identity,peer,text){try{const r=parse(text),a=verifier.authenticate(identity,peer,r.project_id,'VERIFIER'),s=await store.start(r,a);
   need(s?.qa==='QA_PENDING'&&s.physical_decision==='DENY'&&s.committed===true,'EVALUATION_STORE_INVALID');return freeze({qa:'QA_PENDING',physical_decision:'DENY'});
  }catch(e){return denial(e);}},
  async evaluateRun(identity,peer,text){
   let r,committing=false;
   try{
    r=parse(text);const a=verifier.authenticate(identity,peer,r.project_id,'EVALUATOR');
    need(digest(evaluationPins())===digest(pins),'EVALUATOR_SOURCE_PIN_MISMATCH');
    const pending=await store.readPending(r,a);need(pending.physical_decision==='DENY','EVALUATION_STORE_INVALID');
    const requestingVerifier=verifier.principal(pending.verifier_id,r.project_id),producer=verifier.principal(pending.producer_id,r.project_id);
    need(requestingVerifier.role==='VERIFIER'&&requestingVerifier.generation===pending.verifier_generation&&producer.generation===pending.producer_generation,'QA_IDENTITY_REVOKED');
    need(pending.verifier_id!==a.principal_id&&pending.verifier_subject!==a.subject&&pending.producer_subject!==a.subject,'SELF_QA_DENIED');
    const b=pending.bundle;need(b.reference.project_id===r.project_id&&b.reference.task_id===r.task_id,'EVALUATION_SCOPE_DENIED');
    need(digest(pending.pin)===digest(verifier.snapshot(r.project_id,r.task_id)),'QA_STATE_STALE');
    const bytes=Buffer.from(b.bytes_base64,'base64');need(hashBytes(bytes)===b.reference.file_hash,'ARTIFACT_CHANGED');
    let evidence=b.evidence;
    if(isDynamicRequirements(b.requirements)){
     need(typeof store.readDynamicEvidence==='function','DYNAMIC_TRUSTED_READBACK_NOT_BOUND');
     evidence=await store.readDynamicEvidence(r,a,b.reference);
     verifier.authenticate(identity,peer,r.project_id,'EVALUATOR');
     need(digest(pending.pin)===digest(verifier.snapshot(r.project_id,r.task_id)),'QA_STATE_STALE');
    }
    const evaluated=evaluateExact({bytes,reference:b.reference,requirements:b.requirements,evidence,operations:b.operations,pin:b.pin});
    // D08 trace paths can contain artifact-supplied citation IDs. Public reports
    // retain a hash and fixed verdict/criteria, never raw trace paths or text.
    const result={verdict:evaluated.verdict,policy_version:evaluated.policy_version,artifact_hash:evaluated.artifact_hash,result_hash:digest(evaluated),criteria:evaluated.criteria};
    // Re-authenticate and re-read state after asynchronous I/O, before signing.
    verifier.authenticate(identity,peer,r.project_id,'EVALUATOR');need(digest(pending.pin)===digest(verifier.snapshot(r.project_id,r.task_id)),'QA_STATE_STALE');
    const proof=issuer.seal('evaluation','sec01.acceptance',{project_id:r.project_id,task_id:r.task_id,run_id:r.run_id,evaluator_id:a.principal_id,evaluator_generation:a.generation,
     verifier_id:pending.verifier_id,verifier_generation:pending.verifier_generation,producer_id:pending.producer_id,producer_generation:pending.producer_generation,producer_subject:pending.producer_subject,binding:pending.binding,plan_hash:pending.plan_hash,artifact_hash:b.reference.file_hash,artifact_version:b.reference.version,pin_hash:digest(pending.pin),source_pins:copy(pins),result},60000);
    committing=true;const stored=await store.finish(r,a,proof,result);
    need(stored.physical_decision==='DENY'&&stored.committed===true&&stored.qa===result.verdict,'EVALUATION_STORE_INVALID');return freeze({qa:result.verdict,committed:true,physical_decision:'DENY',proof,evaluator_calls:1});
   }catch(e){if(committing){try{await store.flagUnknown(r);}catch{}return freeze({decision:'DENY',physical_decision:'DENY',code:'QA_OUTCOME_UNKNOWN'});}return denial(e);}
  },
  async accept(identity,peer,text,proof){let r,committing=false;try{
   r=parse(text);const owner=verifier.authenticate(identity,peer,r.project_id,'OWNER'),p=verifier.open(proof,'evaluation','sec01.acceptance');
   const evaluator=verifier.principal(p.evaluator_id,r.project_id),v=verifier.principal(p.verifier_id,r.project_id),producer=verifier.principal(p.producer_id,r.project_id);
   need(evaluator.role==='EVALUATOR'&&evaluator.kind==='SERVICE'&&evaluator.generation===p.evaluator_generation&&v.role==='VERIFIER'&&v.generation===p.verifier_generation&&producer.generation===p.producer_generation,'QA_IDENTITY_REVOKED');
   need(owner.subject!==p.producer_subject&&owner.subject!==evaluator.subject&&owner.subject!==v.subject,'SELF_ACCEPTANCE_DENIED');
   need(p.project_id===r.project_id&&p.task_id===r.task_id&&p.run_id===r.run_id&&p.result.verdict==='QA_PASS','QA_NOT_PASS');
   need(p.pin_hash===digest(verifier.snapshot(r.project_id,r.task_id))&&digest(p.source_pins)===digest(pins),'QA_STATE_STALE');
   committing=true;const accepted=await store.accept(r,owner,proof,p);
   need(accepted?.committed===true&&accepted.accepted===true&&accepted.physical_decision==='DENY','EVALUATION_STORE_INVALID');
   return freeze({accepted:true,acceptance:'OWNER_ACCEPTED',qa:'QA_PASS',published:false,authoritative_complete:false,physical_decision:'DENY'});
  }catch(e){if(committing){try{await store.flagUnknown(r);}catch{}return freeze({decision:'DENY',physical_decision:'DENY',code:'ACCEPTANCE_OUTCOME_UNKNOWN'});}return denial(e);}},
  submitProof:()=>freeze({decision:'DENY',physical_decision:'DENY',code:'CALLER_PROOF_FORBIDDEN'})
 });
}
