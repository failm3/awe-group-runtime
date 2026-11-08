import {bytesHash,copy,digest,fields,need} from './contracts.mjs';
import {validateShape} from '../../contracts/schema-validator.mjs';

// Existing D01 qa-evidence envelope; no schema extension, signing or producer
// attestation. Consumer still needs the trusted D08/INT04 service boundary.
export function toD08Evidence(report,host){
 fields(host,['request_id','correlation_id','actor','runner','pin','stdout_ref','stderr_ref']);
 need(report.scope.project_id===host.pin.scope.project_id&&report.scope.task_id===host.pin.scope.task_id&&digest(report.spec)===digest(host.pin.spec),'D08_EVIDENCE_SCOPE');
 const dto={schema_version:'1.0.0',contract:'qa-evidence',request_id:host.request_id,correlation_id:host.correlation_id,
  causation_id:null,actor:copy(host.actor),scope:copy(report.scope),epochs:copy(host.pin.epochs),spec:copy(report.spec),
  created_at:report.executed_at,expected_revision:host.pin.revision,criterion_ids:report.rows.map(r=>r.criterion_id),
  artifact:copy(report.artifact.artifact),profile_hash:report.profile_hash,test_code_hash:report.test_code_hash,
  input_hash:report.binding_hash??bytesHash(Buffer.alloc(0)),runner:copy(host.runner),run_id:report.run_id,
  environment_version:'qa02/1 Node '+(report.environment?.node??'UNKNOWN'),execution_status:report.execution_status,
  verdict:report.verdict,exit_code:report.execution_status==='EXECUTED'?0:null,
  stdout_ref:copy(host.stdout_ref),stderr_ref:copy(host.stderr_ref),producer_attestation:null,
  reason:'QA02 candidate evidence; native evaluator adoption NOT_RUN'};
 const errors=validateShape('qa-evidence',dto);need(errors.length===0,'D08_EVIDENCE_SCHEMA: '+errors.join(','));return dto;
}
