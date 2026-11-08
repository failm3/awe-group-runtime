import {bytesHash, copy, digest, fields, frozen, need, physical, POLICY} from './common.mjs';
import {evaluateExact} from './evaluator.mjs';
import {isDynamicRequirements} from './literal-output.mjs';

// Host factory. Ports/requirements/issuer are trusted synthetic configuration, never agent JSON.
export function createQaService({statePort, artifacts, evidence, issuer, requirements, initialReference}) {
  const r=frozen(copy(requirements)), jobs=new WeakMap(), keys=new Map(), proofs=new Map();
  let unavailable=false, startTail=Promise.resolve();
  const empty=()=>({revision:0,work:'INCOMPLETE',qa:'QA_NOT_RUN',acceptance:'REJECTED',reference:copy(initialReference),
    proof_hash:null,run_id:null,history:[]});
  function binding(reference=statePort.read().record?.reference??initialReference) {
    const {pin}=statePort.read(); statePort.live(pin);
    return {scope:pin.scope,spec:pin.spec,epochs:pin.epochs,config_revision:pin.config_revision,fence:pin.fence,
      lease_epoch:pin.lease_epoch,requirements_hash:digest(r),artifact:copy(reference),policy_version:POLICY};
  }
  function exact(reference) {
    fields(reference,['project_id','task_id','version','artifact','file_hash','bytes','path','provenance_hash']);
    need(reference.project_id===r.project_id && reference.task_id===r.task_id
      && Number.isSafeInteger(reference.version) && reference.version>0,'ARTIFACT_SCOPE');
    const bytes=artifacts.read(copy(reference));
    need(Buffer.isBuffer(bytes) && bytesHash(bytes)===reference.file_hash && bytes.length===reference.bytes,'ARTIFACT_CHANGED');
    return Buffer.from(bytes);
  }
  function context(reference) {
    need(!unavailable,'QA_INSTANCE_QUARANTINED');
    const s=statePort.read(); statePort.live(s.pin);
    const bytes=exact(reference), e=evidence.read();
    need(e && !e.then,'SYNC_EVIDENCE_REQUIRED');
    need(digest(statePort.read().pin)===digest(s.pin),'STATE_CHANGED');
    return {...s,bytes,e:copy(e),binding:binding(reference)};
  }
  function recordChange(old,changes,event) {
    return {...old,...copy(changes),revision:old.revision+1,history:[...old.history,event]};
  }
  function authenticProof(handle) {
    const job=jobs.get(handle); need(job?.proof,'PROOF_UNTRUSTED');
    issuer.check(job.session,job.grant,'VERIFY',job.binding);
    const c=context(job.reference), stored=c.record;
    need(stored?.qa==='QA_PASS' && stored.proof_hash===digest(job.proof) && job.proof.result.verdict==='QA_PASS'
      && stored.run_id===job.id && digest(c.pin)===digest(job.pin) && digest(c.binding)===digest(job.binding)
      && digest(c.e)===job.proof.evidence_hash,'PROOF_STALE');
    return {job,c};
  }
  const worker=Object.freeze({
    async report(request) {
      fields(request,['work','reference','expected_revision']);
      need(request.work==='WORK_COMPLETED','WORK_NOT_COMPLETED');
      const c=context(request.reference);
      need(c.e.completion?.work==='WORK_COMPLETED','OUTCOME_UNKNOWN');
      return statePort.transact(c.pin,old=>{
        old??=empty(); need(old.revision===request.expected_revision,'QA_CAS_CONFLICT');
        need(old.qa!=='QA_PENDING','QA_BUSY');
        if(old.work==='WORK_COMPLETED') need(request.reference.version>old.reference.version,'REVISION_REQUIRED');
        let rework=old.rework??null;
        if(isDynamicRequirements(r)){
          const lineage=digest({scope:c.pin.scope,spec:c.pin.spec,goal:r.original_user_goal_hash});
          need(!rework||rework.lineage===lineage,'REWORK_LINEAGE_CHANGED');
          const used=(rework?.used??-1)+1;
          need(used<=2,'REWORK_LIMIT_EXHAUSTED');
          rework={lineage,used,max:2};
        }
        const record=recordChange(old,{work:'WORK_COMPLETED',qa:'QA_NOT_RUN',acceptance:'REJECTED',reference:request.reference,
          proof_hash:null,run_id:null,...(rework?{rework,sec_evaluation:null}:{})},'WORK_REPORTED');
        return {record,value:record};
      });
    },
    submitQa() { throw new Error('WORKER_QA_FORBIDDEN'); },
    accept() { throw new Error('OWNER_REQUIRED'); },
    publish:physical, requestPhysicalEffect:physical
  });
  const verifier=Object.freeze({
    async start(session,grant,request) {
      const attempt=startTail.then(async()=>{
      fields(request,['expected_revision','key']);
      need(typeof request.key==='string' && /^[a-z0-9_-]{1,64}$/.test(request.key),'IDEMPOTENCY_KEY');
      const current=statePort.read().record??empty(), b=binding(current.reference);
      const actor=issuer.check(session,grant,'VERIFY',b), k=actor.id+':'+request.key;
      const requestHash=digest({request,b});
      if(keys.has(k)) {const entry=keys.get(k);need(entry.hash===requestHash,'IDEMPOTENCY_CONFLICT');return entry.handle;}
      need(current.work==='WORK_COMPLETED','WORK_REQUIRED');
      const before=context(current.reference);
      // D03 performs its own CAS, lease/fence and sticky-cancel checks.
      const pin=await statePort.enterPending(before.pin);
      const handle=Object.freeze({}), id=digest({request,b,actor,pin});
      const job={id,reference:copy(current.reference),binding:b,actor,session,grant,pin,finished:false,aborted:false,proof:null};
      await statePort.transact(pin,old=>{
        need(old?.revision===request.expected_revision,'QA_CAS_CONFLICT');
        need(old.qa!=='QA_PENDING','QA_BUSY');
        if(isDynamicRequirements(r))need((old.qa_runs??0)<3,'QA_RUN_LIMIT_EXHAUSTED');
        issuer.check(session,grant,'VERIFY',b); exact(old.reference);
        const record=recordChange(old,{qa:'QA_PENDING',acceptance:'REJECTED',run_id:id,proof_hash:null,...(isDynamicRequirements(r)?{qa_runs:(old.qa_runs??0)+1}:{})},'QA_PENDING');
        return {record,value:null};
      });
      jobs.set(handle,job); keys.set(k,{hash:requestHash,handle}); return handle;
      });
      startTail=attempt.catch(()=>{}); return attempt;
    },
    async finish(session,grant,handle) {
      const job=jobs.get(handle); need(job && job.session===session && job.grant===grant,'RUN_UNTRUSTED');
      need(!job.aborted,'QA_ABORTED');
      if(job.finished) {authenticResult(job);return frozen(copy(job.proof));}
      if(job.completing) return job.completing;
      job.completing=(async()=>{
      let c,result,reason=null;
      try {
        issuer.check(session,grant,'VERIFY',job.binding); c=context(job.reference);
        need(digest(c.pin)===digest(job.pin) && digest(c.binding)===digest(job.binding),'PROOF_STALE');
        result=evaluateExact({bytes:c.bytes,reference:job.reference,requirements:r,evidence:c.e,operations:c.operations,pin:c.pin});
      } catch {reason='VERIFICATION_INPUT_UNAVAILABLE';}
      // Scheduling boundary deliberately exercises cancel/revoke/abort while verification is pending.
      await Promise.resolve();
      try {
        need(!job.aborted,'QA_ABORTED'); issuer.check(session,grant,'VERIFY',job.binding);
        const latest=context(job.reference);
        need(c && digest(latest.e)===digest(c.e) && digest(latest.pin)===digest(job.pin),'VERIFICATION_CHANGED');
      } catch {reason='VERIFICATION_CHANGED';}
      if(reason) result={verdict:'QA_INCONCLUSIVE',policy_version:POLICY,artifact_hash:job.reference.file_hash,
        findings:[{code:reason,severity:'BLOCKER',criterion:'ARTIFACT',trace:{path:'$'}}],criteria:[],trace:[]};
      const proof={mode:'E0_SYNTHETIC_ONLY',run_id:job.id,verifier:job.actor,artifact:job.reference,
        requirements_hash:digest(r),state_hash:digest(job.pin),evidence_hash:c?digest(c.e):null,result};
      try {
        await statePort.transact(job.pin,old=>{
          need(old?.run_id===job.id && old.qa==='QA_PENDING' && !job.aborted,'LATE_RESULT');
          // Final synchronous authority/artifact/evidence barrier is inside the same D03 storage queue.
          if(result.verdict==='QA_PASS') {
            issuer.check(session,grant,'VERIFY',job.binding); exact(job.reference);
            need(digest(evidence.read())===proof.evidence_hash,'EVIDENCE_CHANGED');
          }
          const record=recordChange(old,{qa:result.verdict,acceptance:'REJECTED',proof_hash:digest(proof)},result.verdict);
          return {record,value:null};
        });
      } catch {
        // Lost ACK or D03 conflict never returns a successful proof; instance stays quarantined.
        unavailable=true; throw new Error('QA_COMMIT_UNCERTAIN');
      }
      job.finished=true; job.proof=frozen(copy(proof)); proofs.set(digest(proof),handle);
      return frozen(copy(proof));
      })();
      return job.completing;
    },
    async abort(session,grant,handle) {
      const job=jobs.get(handle);need(job && !job.finished && !job.aborted && job.session===session && job.grant===grant,'RUN_UNTRUSTED');
      issuer.check(session,grant,'VERIFY',job.binding);job.aborted=true;
      return statePort.transact(job.pin,old=>{
        need(old?.run_id===job.id && old.qa==='QA_PENDING','LATE_RESULT');
        const record=recordChange(old,{qa:'QA_INCONCLUSIVE',acceptance:'REJECTED',proof_hash:null},'QA_ABORTED');
        return {record,value:record};
      });
    }
  });
  function authenticResult(job) {
    issuer.check(job.session,job.grant,'VERIFY',job.binding);
    const c=context(job.reference); need(digest(c.pin)===digest(job.pin) && c.record?.proof_hash===digest(job.proof),'PROOF_STALE');
  }
  const owner=Object.freeze({
    binding(handle) {const {job}=authenticProof(handle);return {...copy(job.binding),proof_hash:digest(job.proof)};},
    async accept(session,grant,handle,request) {
      fields(request,['expected_revision','key']);
      need(typeof request.key==='string' && /^[a-z0-9_-]{1,64}$/.test(request.key),'IDEMPOTENCY_KEY');
      const {job,c}=authenticProof(handle), b={...copy(job.binding),proof_hash:digest(job.proof)};
      const actor=issuer.check(session,grant,'ACCEPT',b);
      need(actor.id!==job.actor.id && actor.subject!==job.actor.subject,'INDEPENDENT_OWNER_REQUIRED');
      try { return await statePort.transact(c.pin,old=>{
        authenticProof(handle); issuer.check(session,grant,'ACCEPT',b);
        if(old.acceptance==='OWNER_ACCEPTED') {
          need(old.acceptance_key===request.key && old.acceptance_actor.id===actor.id,'ACCEPTANCE_CONFLICT');
          return {record:old,value:old};
        }
        need(old.revision===request.expected_revision && old.qa==='QA_PASS','QA_CAS_CONFLICT');
        const record=recordChange(old,{acceptance:'OWNER_ACCEPTED',acceptance_key:request.key,acceptance_actor:actor},'OWNER_ACCEPTED');
        job.owner={session,grant,binding:b};
        return {record,value:record};
      }); } catch(error) {
        if(['QA_CAS_CONFLICT','ACCEPTANCE_CONFLICT'].includes(error.message)) throw error;
        unavailable=true; throw new Error('ACCEPTANCE_COMMIT_UNCERTAIN');
      }
    }
  });
  function inspect() {
    let s;
    try {
      s=statePort.read().record??empty();
      if(s.qa==='QA_PASS') {
        const h=proofs.get(s.proof_hash); authenticProof(h);
        if(s.acceptance==='OWNER_ACCEPTED') {const o=jobs.get(h).owner;need(o,'OWNER_REQUIRED');issuer.check(o.session,o.grant,'ACCEPT',o.binding);}
      } else context(s.reference);
      return frozen({...copy(s),effective_qa:s.qa,accepted:s.qa==='QA_PASS' && s.acceptance==='OWNER_ACCEPTED',
        published:false,authoritative_complete:false,physical_decision:'DENY',mode:'E0_SYNTHETIC_ONLY'});
    } catch {
      return frozen({revision:s?.revision??0,qa:s?.qa??'QA_NOT_RUN',effective_qa:'QA_INCONCLUSIVE',acceptance:'REJECTED',
        accepted:false,published:false,authoritative_complete:false,physical_decision:'DENY',mode:'E0_SYNTHETIC_ONLY',code:'CURRENT_PROOF_UNAVAILABLE'});
    }
  }
  return Object.freeze({worker,verifier,owner,binding,inspect});
}
