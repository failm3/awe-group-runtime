import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
import {runtimeFixture} from '../tests/runtime/fixtures.mjs';
import {createExecutableTools} from '../awe/executable_tools/host.mjs';
import {createRt01ToolPort,matchRt01Proposal} from '../awe/executable_tools/facade.mjs';
import {digest,bytesDigest} from '../awe/executable_tools/protocol.mjs';
// Read-only conformance against the actual RT01 owning worktree. No journal,
// config, process, or generated file is written there. Portable replay does not require it.
const rt='C:/Users/1/AWE-GROUP-RT01/awe/hermes_runtime/';
const names=['adapter.mjs','protocol.mjs','d03-port.mjs','synthetic.mjs','profile.mjs','profile.json','config.yaml','hermes-source-lock.json','ports.d.ts'];
const context=names.map(name=>({path:rt+name,digest:bytesDigest(fs.readFileSync(rt+name))}));
const {createHermesRuntime,planHash}=await import(pathToFileURL(rt+'adapter.mjs'));
const {createD03ReadPort}=await import(pathToFileURL(rt+'d03-port.mjs'));
const {createSyntheticTransport}=await import(pathToFileURL(rt+'synthetic.mjs'));
const {configHash,manifestHash}=await import(pathToFileURL(rt+'profile.mjs'));
const f=await runtimeFixture(),toolCalls=[];
const tools=createExecutableTools({scope:f.taskScope,admission:{current:()=>true,execute:async(b,effect)=>{toolCalls.push(b);await effect();return {status:'COMMITTED',request_digest:digest(b)};}},reviewer:null,generator_id:'act_generator',limits:{timeout_ms:5000,max_output_bytes:8192}});
try{
 const pin=tools.resolve('js.text.stats')[0],transport=createSyntheticTransport(),rows=[],counts={begin:0,result:0};
 const state=createD03ReadPort({service:f.h.service,reader:f.h.state});
 const host=createHermesRuntime({state,security:{authorizeLaunch:()=>true,current:()=>true,authenticate:()=>true},
  context:{read:()=> 'synthetic tools02 context'},artifacts:{verify:()=>true},models:{check:()=>true},tools:createRt01ToolPort(tools),
  attempts:{begin:async a=>{counts.begin++;return {attempt_id:a.attempt_id,physical_decision:'DENY'};},result:async()=>{counts.result++;return {physical_decision:'DENY'};},cancel:async()=>({physical_decision:'DENY'})},
  journal:{read:()=>rows,append:entry=>{rows.push({entry:structuredClone(entry)});return digest(entry);}},transport:transport.api,clock:f.h.now,supervisor:'act_supervisor',timeoutMs:1000});
 const grant=f.grant('run_tools02_rt',{config_hash:configHash,manifest_hash:manifestHash,capabilities:[pin.id],max_children:0,max_physical_attempts:1});
 const s=state.read(grant.scope),contextHash=digest({text:'synthetic tools02 context'});
 const request={version:'rt01/1',grant,actor_id:'act_worker',child_id:'child_tools02',context:{project_id:grant.scope.project_id,task_id:grant.scope.task_id,revision:1,readonly:true,hash:contextHash,artifact_ref:digest({fixture:'context'})},
  model:{id:'synthetic_model',revision:'rev_one',route_id:'synthetic_route',route_revision:'route_one'},tools:[pin],
  admission:{project_id:grant.scope.project_id,task_id:grant.scope.task_id,operation_id:'op_rt_launch',attempt_id:'attempt_tools02_rt',effect_slot:'slot_tools02_rt',approval_id:'approval_tools02_rt',grant_id:'grant_tools02_rt',idempotency_key:'key_tools02_rt',plan_hash:digest({}),payload_hash:contextHash,reserve_micros:'0'},runtime_pin:s.runtime_pin};
 request.admission.plan_hash=planHash(request);const launched=await host.launchChild(JSON.stringify(request));assert.equal(launched.status,'RUNNING');
 const command={scope:{...grant.scope,operation_id:'op_rt_tool'},pin,input:{text:'fixture'}};
 const proposal={operation_id:command.scope.operation_id,tool_id:pin.id,tool_digest:pin.digest,input_hash:digest(command.input)};assert(matchRt01Proposal(proposal,command));
 transport.control.emit(transport.control.handle(grant.run_id),'TOOL_PROPOSAL',proposal);const polled=await host.streamEvents(grant.run_id);assert.equal(polled.status,'RUNNING');assert.equal(toolCalls.length,0);
 tools.quarantine(pin.id);const revoked=await host.streamEvents(grant.run_id);assert.equal(revoked.status,'OUTCOME_UNKNOWN');assert.equal(revoked.reason,'CAPABILITY_PIN_STALE');
 for(const entry of context)assert.equal(bytesDigest(fs.readFileSync(entry.path)),entry.digest);
 console.log(JSON.stringify({status:'PASS',contract:'rt01/1',checks:['ACTUAL_RT01_LAUNCH_WITH_EXECUTABLE_PIN','TOOL_PROPOSAL_CAUSES_ZERO_DISPATCH','QUARANTINED_PIN_STOPS_ACTUAL_RT01'],counts,tool_dispatches:toolCalls.length,owning_sources_unchanged:true,context,real_hermes:'NOT_RUN',full_int04_e2e:'NOT_RUN'},null,2));
}finally{await tools.close();}
