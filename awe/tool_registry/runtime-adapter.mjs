import {VERSION,bounded,copy,digest,ensure,hash} from './common.mjs';
// Proposed D04/SEC interface; this port has no dispatch, spawn, eval or install.
// A metadata manifest digest is deliberately separate from the runtime binary digest.
export function prepareRuntimeReview(binding,{runtimeArtifactDigest,adapterId}){
 const r=bounded(binding,16384);
 ensure(r.contract===VERSION&&r.status==='BOUND_E0_ONLY'&&r.physical_decision==='DENY'&&r.runtime_dispatch===false,'TR_RUNTIME_BINDING');
 ensure(hash(runtimeArtifactDigest)&&typeof adapterId==='string'&&/^d04_[a-z0-9_]{1,64}$/.test(adapterId),'TR_RUNTIME_ARTIFACT');
 return Object.freeze({contract:'tr01-d04-review/1.0.0',scope:copy(r.proposal),runtime_artifact_digest:runtimeArtifactDigest,
  adapter_id:adapterId,binding_digest:digest(r.proposal),manifest_is_not_binary:true,
  requires:['D04_PINNED_ADAPTER','SEC01_CURRENT_ISSUER_PEP','D09_DURABLE_ADMISSION','OS_EGRESS'],physical_decision:'DENY',dispatch_supported:false});
}
