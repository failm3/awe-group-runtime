import assert from 'node:assert/strict';
import test from 'node:test';
import {digest} from '../../contracts/index.mjs';
import {MODEL_POLICY} from '../../broker/schemas.mjs';
import {REPAIR_HEAD_SCHEMA} from '../../host/coding/repair-contracts.mjs';
import {checkHeadReceipt,actualPromptHash} from '../../qa-repair/bindings.mjs';

function fixture(){
 const input={instruction:'Synthetic QA check: CLI public failure.'},usage={wire_attempts:1,input_tokens:2,output_tokens:2};
 const scope={task_id:'head_plan',mission_id:'synthetic',attempt_id:'a1',logical_request_id:'l1',worker_id:'w1',fence:1};
 const request_hash=actualPromptHash(input.instruction,REPAIR_HEAD_SCHEMA,512);
 const attempt={...scope,usage,request_hash,state:'CONFIRMED',route_id:MODEL_POLICY.route_id};
 const output={decision:'REPAIR',reason:'CLI error',focus:'CLI data parsing',max_code_attempts:1};
 const response={evidence_level:'LIVE_LOCAL_MODEL',accounting_status:'CONFIRMED',decision:'PROPOSED',wire_attempts:1,output,usage,request_hash,response_digest:digest('raw')};
 const evidence={request_hash,response_digest:response.response_digest,usage,model_receipt:{response,native_attempt:structuredClone(attempt),scope,input}};
 return {task:{document:{input:structuredClone(input)},result:{output,evidence}},attempt};
}
test('Head metadata and complete request hash bind to the admitted prompt',()=>{
 const {task,attempt}=fixture();checkHeadReceipt(task,attempt);
});
for(const [name,edit] of [
 ['admitted task prompt',t=>t.document.input.instruction+='x'],
 ['output substituted',t=>t.result.output={...t.result.output,max_code_attempts:2}],
 ['model origin',t=>t.result.evidence.model_receipt.response.evidence_level='OFFLINE_TEST_DOUBLE'],
 ['logical request',t=>t.result.evidence.model_receipt.scope.logical_request_id='wrong'],
 ['response cost receipt',t=>t.result.evidence.model_receipt.native_attempt.state='OUTCOME_UNKNOWN'],
])test('Head rejects changed '+name,()=>{const {task,attempt}=fixture();edit(task);assert.throws(()=>checkHeadReceipt(task,attempt));});
