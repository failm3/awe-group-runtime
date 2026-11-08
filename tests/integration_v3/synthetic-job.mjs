import {jointFixture} from '../integration_v2/harness.mjs';
import {createReceiptChain} from '../../awe/integration_v2/execution.mjs';
import {createD03QaPort} from '../../awe/qa/state-port.mjs';
import {bytesHash,canonicalize,copy,need} from '../../awe/qa/common.mjs';

// Trusted E0 fixture composition: same actual D01-D07/INT02 modules and actual
// artifact store as INT02. Split the existing workflow at its admission barrier.
// This fixture owns no live service, provider URL, credentials or physical tool.
export async function prepareSyntheticJob() {
  const j=await jointFixture(),chain=createReceiptChain();
  const built=j.build();need(built.decision==='READY_OFFLINE','CONTEXT_NOT_READY');
  chain.append('CONTEXT_PREFLIGHT',{ref:built.ref,payload_hash:built.request_hash,profile_hash:built.manifest.profile_hash,
    memory:j.memoryDescriptor,artifact:j.artifactDescriptor});
  const proposal=j.prepare();
  const requirements={kind:'INT02_OUTPUT_V1',project_id:'prj_alpha',task_id:'task_one',spec:copy(j.f.task().spec),
    expected_text:'synthetic work result',expected_tools:[{id:'call_model',name:j.f.tool.id,arguments:copy(j.f.payload)}],
    citations:[],forbidden_literals:['FOREIGN_CANARY_SECRET']};
  const plan={d06_plan_hash:proposal.plan_hash,payload_hash:built.request_hash,reserve_micros:proposal.bound_micros,
    requirements,project_id:'prj_alpha',task_id:'task_one',dag:{task_one:[],task_followup:['task_one']}};
  let ran=false;
  return {plan,j,async run() {
    need(!ran,'SYNTHETIC_JOB_ALREADY_RAN');ran=true;
    j.approve();j.arm();const launched=await j.launch();
    chain.append('SYNTHETIC_CHILD',{parent:launched.parentRun.grant,child:launched.childRun.grant});
    const model=await j.execution.run();need(model.status==='SUCCEEDED','MODEL_NOT_SUCCEEDED');
    chain.append('D06_SETTLED',{operation:j.b.ledger.operation('op-one'),model});j.execution.preflight();
    j.runtime.control.registerAdmission('run_int02_child',{intent:j.f.intent,handle:j.f.handle});
    const dispatch=await j.runtime.worker.executeTool(j.f.executorSession,'run_int02_child',j.f.opScope.operation_id);
    need(dispatch.decision==='CANARY_RECORDED','CANARY_NOT_RECORDED');chain.append('INT01_CANARY',dispatch);
    const receipt=await j.runtime.worker.collectToolReceipt(j.f.executorSession,'run_int02_child',j.f.opScope.operation_id);
    need(receipt.receipt?.outcome==='CONFIRMED','RECEIPT_UNKNOWN');chain.append('D03_RECEIPT',receipt);
    for(const id of ['run_int02_child','run_int02_parent'])need((await j.runtime.worker.complete(j.f.executorSession,id)).status==='WORK_COMPLETED','CHILD_INCOMPLETE');
    const bytes=Buffer.from(canonicalize({model,receipt,chain:chain.inspect()}));
    const staged=j.m.stageArtifact('art_int02_output',j.m.files(bytes.toString('utf8')));
    const reference={project_id:'prj_alpha',task_id:'task_one',artifact:copy(staged.reference.artifact),version:staged.version,
      file_hash:bytesHash(bytes),bytes:bytes.length,path:'site/index.txt',provenance_hash:staged.provenance_hash};
    const readback=j.m.artifacts.read(j.m.session('act_worker'),JSON.stringify({artifact_id:'art_int02_output',version:reference.version,path:reference.path}));
    need(readback.ok && bytesHash(Buffer.from(readback.value.bytes_base64,'base64'))===reference.file_hash,'D07_READBACK');
    chain.append('D07_ARTIFACT',{reference:staged.reference,version:reference.version,provenance_hash:reference.provenance_hash,
      file_hash:reference.file_hash,readback:'SCOPED_E0_LOCAL_READ_ONLY',independent_qa:'NOT_RUN'});
    await j.f.h.go('QA_PENDING');
    const port=createD03QaPort({state:j.f.h.service,storage:j.f.h.storage,reader:j.f.h.state,
      supervisor:j.f.h.supervisor,scope:j.f.taskScope,clock:j.f.h.now});
    const {pin,operations}=port.read();
    const snapshot=JSON.parse(j.f.h.storage.snapshot());
    return {plan:copy(plan),requirements:copy(requirements),reference,bytes_base64:bytes.toString('base64'),pin,operations,
      evidence:{chain:chain.inspect(),completion:chain.completion(),model_operation:j.b.ledger.operation('op-one'),sources:[],opinions:null},
      checkpoint:{d03:{format:'INT03_D03_PROJECT_SNAPSHOT_V1',data:{projects:{prj_alpha:copy(snapshot.data.projects.prj_alpha)}}},d06:j.b.ledger.inspect()},
      cost:{actual_micros:model.costMicros,input_tokens:model.usage.uncachedInput+model.usage.cacheRead+model.usage.cacheWrite,output_tokens:model.usage.output},
      physical_dispatches:j.runtime.control.inspect().physical_dispatches};
  }};
}
