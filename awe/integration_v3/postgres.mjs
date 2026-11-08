import {createPostgresPersistence} from '../persistence/postgres.mjs';
import {bytesHash, digest, need} from '../qa/common.mjs';
import {storageEnvelope} from './storage.mjs';
import {parseNativeAdmission,checkNativeReceipt,NativeBindingError,nativeDenial} from './native-contract.mjs';

// Trusted host composition root. Pools are authenticated, project-bound sessions;
// no pool, evaluator, issuer or job factory is exposed through the agent facade.
export function createIntegratedHost({workerPool, verifierPool, ownerPool, evaluator, projectId, taskId}) {
  const persistence=createPostgresPersistence(workerPool);
  const scope={project_id:projectId,task_id:taskId};
  let uncertain=false;
  let nativeTail=Promise.resolve();
  const nativeSerial=fn=>{const next=nativeTail.then(fn);nativeTail=next.catch(()=>{});return next;};
  const fields=(x,keys)=>need(x && Object.getPrototypeOf(x)===Object.prototype
    && Object.keys(x).sort().join()===keys.slice().sort().join(),'COMMAND_INVALID');
  async function transaction(pool,fn,body,{allowUncertain=false,validate=null,native=false}={}) {
    need(!uncertain || allowUncertain,'HOST_QUARANTINED');
    let client,began=false,committing=false,broken=false;
    try {
      client=await pool.connect();
      if(native)need(!uncertain||allowUncertain,'HOST_QUARANTINED');
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE'); began=true;
      await client.query("SET LOCAL synchronous_commit = on");
      await client.query("SET LOCAL statement_timeout = '10s'");
      const response=await client.query(`SELECT awe_int03.${fn}($1::jsonb) AS result`,[JSON.stringify({...body,...scope})]);
      let value=structuredClone(response.rows?.[0]?.result);
      need(value?.physical_decision==='DENY','DATABASE_CONTRACT_INVALID');
      if(validate)value=validate(value);
      if(native)need(!uncertain||allowUncertain,'HOST_QUARANTINED');
      committing=true; await client.query('COMMIT'); began=false;
      if(native)need(!uncertain||allowUncertain,'HOST_QUARANTINED');
      return structuredClone(value);
    } catch(error) {
      broken=true;
      let rollbackFailed=false;
      if(began)try{await client.query('ROLLBACK');}catch{rollbackFailed=true;}
      if(committing) {
        uncertain=true;
        // Separate best-effort durable latch. If the DB is unavailable, every
        // local action remains denied; restart must inspect/recover DB state.
        if(fn!=='flag_uncertain'&&fn!=='hold_native_cr01')try {await transaction(workerPool,native?'hold_native_cr01':'flag_uncertain',native?{}:{reason:'COMMIT_ACK_LOST'},{allowUncertain:true});}catch{}
        if(native)throw new NativeBindingError('NATIVE_COMMIT_OUTCOME_UNKNOWN',{outcomeUnknown:true});
        const unknown=new Error('COMMIT_OUTCOME_UNKNOWN',{cause:error}); unknown.outcomeUnknown=true; throw unknown;
      }
      if(native){
        if(rollbackFailed){uncertain=true;throw new NativeBindingError('NATIVE_ROLLBACK_UNKNOWN',{outcomeUnknown:true});}
        throw new NativeBindingError('NATIVE_TRANSACTION_REJECTED');
      }
      throw error;
    } finally {try{client?.release(broken);}catch{}}
  }
  const inspect=async()=>{
    const value=await transaction(workerPool,'inspect',{}, {allowUncertain:true});
    return uncertain?{...value,state:'OUTCOME_UNKNOWN',effective_qa:'QA_INCONCLUSIVE',acceptance:'REJECTED',accepted:false,uncertain:true}:value;
  };
  const trusted=Object.freeze({
    async admit(command) {
      fields(command,['operation_id','attempt_id','effect_slot','approval_id','grant_id','idempotency_key','plan_hash','payload_hash','reserve_micros']);
      return transaction(workerPool,'admit',{command});
    },
    // Additive CR-01 entry in this SAME coordinator/transaction owner. Native
    // SQL hooks remain NOT_CONFIGURED; no local token/flag can replace them.
    async admitNative(text) {
      if(uncertain)throw new NativeBindingError('NATIVE_HOLD',{outcomeUnknown:true});
      const command=parseNativeAdmission(text,scope);
      return nativeSerial(async()=>{
      if(uncertain)throw new NativeBindingError('NATIVE_HOLD',{outcomeUnknown:true});
      try{const value=await transaction(workerPool,'admit_native_cr01',command,{native:true,validate:value=>checkNativeReceipt(value,command,scope)});return {...value,committed:true};}
      catch{if(uncertain)throw new NativeBindingError('NATIVE_HOLD',{outcomeUnknown:true});throw new NativeBindingError('NATIVE_TRANSACTION_REJECTED');}
      });
    },
    async inspectNative(){
      try{const value=await transaction(workerPool,'inspect_native_cr01',{}, {allowUncertain:true,native:true,validate:value=>checkNativeReceipt(value,null,scope)});
        return {...value,status:'HOLD',qa:'QA_INCONCLUSIVE',accepted:false};
      }catch{throw new NativeBindingError('NATIVE_INSPECTION_UNAVAILABLE',{outcomeUnknown:uncertain});}
    },
    nativeDispatch:nativeDenial,
    async execute(job) {
      need(!uncertain,'HOST_QUARANTINED');
      const before=await inspect();
      need(before.execution_profile===undefined||before.execution_profile==='E0','NATIVE_PROFILE_REQUIRES_NATIVE_API');
      need(before.state==='ADMITTED' && before.qa==='QA_NOT_RUN','EXECUTION_NOT_ADMITTED');
      need(digest(job.plan)===before.plan_hash,'PLAN_BINDING');
      await transaction(workerPool,'begin_execution',{});
      let bundle;
      try {
        bundle=await job.run();
        need(bundle.physical_dispatches===0 && bundle.evidence.completion.physical_decision==='DENY','PHYSICAL_CLAIM');
        need(digest(bundle.plan)===before.plan_hash,'PLAN_BINDING');
      } catch(error) {
        try{await transaction(workerPool,'flag_uncertain',{reason:'EXECUTION_CALLBACK_LOST'},{allowUncertain:true});}catch{}
        throw error;
      }
      const body=storageEnvelope(bundle);
      return transaction(workerPool,'complete',{body,bundle_hash:bytesHash(Buffer.from(body))});
    },
    async revise(bundle,expectedRevision) {
      const body=storageEnvelope(bundle);
      return transaction(workerPool,'revise',{body,bundle_hash:bytesHash(Buffer.from(body)),expected_revision:expectedRevision});
    },
    async verify(grantId,key) {
      const pending=await transaction(verifierPool,'start_qa',{grant_id:grantId,key});
      if(pending.proof) return pending;
      need(evaluator && typeof evaluator.evaluateRun==='function','EVALUATOR_SERVICE_REQUIRED');
      try {return await evaluator.evaluateRun({...scope,run_id:pending.run_id});}
      catch(error) {
        if(error.outcomeUnknown) {
          uncertain=true;
          try{await transaction(workerPool,'flag_uncertain',{reason:'EVALUATOR_COMMIT_ACK_LOST'},{allowUncertain:true});}catch{}
        }
        throw error;
      }
    },
    accept:(grantId,proofHash,key)=>transaction(ownerPool,'accept',{grant_id:grantId,proof_hash:proofHash,key}),
    inspect,
    cancel:()=>transaction(workerPool,'cancel',{}),
    recover:()=>transaction(workerPool,'recover',{}, {allowUncertain:true}),
    persistence
  });
  return Object.freeze({trusted,worker:Object.freeze({
    inspect, cancel:trusted.cancel,
    submitQa(){throw Error('WORKER_QA_FORBIDDEN');},
    accept(){throw Error('OWNER_REQUIRED');},
    requestPhysicalEffect(){return {decision:'DENY',code:'E0_PHYSICAL_EGRESS_DISABLED'};},
    publish(){return {decision:'DENY',code:'E0_PUBLICATION_DISABLED'};}
  })});
}
