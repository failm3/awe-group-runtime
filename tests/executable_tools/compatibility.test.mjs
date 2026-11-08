import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture} from './fixtures.mjs';
import {bindAgentTools,createRt01ToolPort,matchRt01Proposal,prepareExecutableReview} from '../../awe/executable_tools/facade.mjs';
import {createToolRegistry} from '../../awe/tools/registry.mjs';
import {digest} from '../../awe/executable_tools/protocol.mjs';
const using=async fn=>{const f=fixture();try{await fn(f);}finally{await f.tools.close();}};
test('AUTO worker facade executes the same contract without exposing host controls',()=>using(async f=>{
 const pin=f.tools.resolve('js.text.stats')[0],agent=bindAgentTools(f.tools,{run_id:'run_tools02',actor_id:'act_worker',project_id:'prj_tools02',task_id:'task_tools02',pins:[pin]});
 assert.deepEqual(Object.keys(agent).sort(),['contract','execute']);
 const q={contract:'tools02/1',operation_id:'op_auto',pin,input:{text:'fixture'}};
 assert.equal((await agent.execute(JSON.stringify(q))).decision,'EXECUTED_LOCAL');
 for(const patch of [{actor_id:'act_admin'},{scope:{project_id:'prj_foreign'}},{factory:{verified:true}},{pin:f.tools.resolve('fs.list')[0]}])assert.equal((await agent.execute(JSON.stringify({...q,...patch}))).decision,'DENY');
}));
test('RT01 tools.check is synchronous and exact, without granting execution',()=>using(async f=>{
 const p=createRt01ToolPort(f.tools),pin=f.tools.resolve('js.text.stats')[0];assert.equal(p.check([pin]),true);assert.equal(p.check([{...pin,digest:digest('metadata')}]),false);assert.equal(p.check([pin,pin]),false);
 assert.deepEqual(Object.keys(p),['check']);assert.equal(f.calls.length,0);f.tools.quarantine(pin.id);assert.equal(p.check([pin]),false);
}));
test('RT TOOL_PROPOSAL must match operation, input and runtime artifact pin',()=>using(async f=>{
 const q=f.request('js.text.stats',{text:'fixture'}),p={operation_id:q.scope.operation_id,tool_id:q.pin.id,tool_digest:q.pin.digest,input_hash:q.input_hash};assert(matchRt01Proposal(p,q));
 for(const patch of [{operation_id:'op_foreign'},{tool_id:'tool_other'},{tool_digest:digest('other')},{input_hash:digest('other')},{approved:true}])assert.throws(()=>matchRt01Proposal({...p,...patch},q));assert.equal(f.calls.length,0);
}));
test('metadata manifest remains distinct from executable manifest/artifact and cannot authorize',()=>using(async f=>{
 const pin=f.tools.resolve('js.text.stats')[0],m=f.tools.manifest(pin),binding={contract:'tr01/1.0.0',status:'BOUND_E0_ONLY',physical_decision:'DENY',runtime_dispatch:false,proposal:{tool_id:pin.id,manifest_digest:digest('metadata'),artifact_digest:m.artifact_digest}};
 const r=prepareExecutableReview(f.tools,binding,pin);assert.equal(r.execution_authority,false);assert.notEqual(r.metadata_manifest_digest,r.executable_manifest_digest);
 assert.throws(()=>prepareExecutableReview(f.tools,{...binding,proposal:{...binding.proposal,artifact_digest:digest('other')}},pin));assert.equal(f.calls.length,0);
}));
test('unchanged D04 descriptor accepts the executable pin without enabling its dispatcher',()=>using(async f=>{
 const registry=createToolRegistry(),pin=f.tools.resolve('js.text.stats')[0],m=f.tools.manifest(pin);
 registry.register(JSON.stringify({id:pin.id,digest:pin.digest,input_schema_hash:m.input_schema_hash,output_schema_hash:m.output_schema_hash,action:'read',resource:'tools02:synthetic',effect_class:m.effect_class,mode:'SYNTHETIC_ONLY'}));
 assert.equal(registry.get(pin.id).digest,pin.digest);assert.equal(registry.dispatch().decision,'DENY');
}));
