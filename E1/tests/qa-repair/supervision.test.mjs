import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../../contracts/index.mjs';
import {inspectSupervisor} from '../../qa-repair/supervision.mjs';

function sample(){
 const stages=['AFTER_MODEL_PERSISTED','AFTER_NATIVE_COMPLETED'];
 const time=n=>'2026-11-08T10:00:0'+n+'.000Z';
 const sourceDigest=digest('pinned source'),runId='synthetic',pid=100;
 const faults=stages.map((stage,i)=>({schema:'awe.e1.repair-injected-process-fault/1',stage,supervisor_pid:pid,pid:pid+i+1,at:time(2*i+1),metadata:{ref:digest('synthetic '+i)}}));
 const exits=[...stages,null].map((stage,i)=>({known_injected_fault:stage,pid:pid+i+1,exit_code:stage?90:0,signal:null,ended_at:time(2*i+2),original_process_observed_dead:true}));
 const state={schema:'awe.e1.automatic-repair-supervisor/1',run_id:runId,status:'FINISHED',source_digest:sourceDigest,started_at:time(0),finished_at:time(7),
   supervisor_pid:pid,max_restarts:2,operator_phase_commands:0,current_child_pid:null,observed_exits:exits};
 return {state,faults,runId,sourceDigest};
}
test('controlled two-point automatic fork traces require three distinct exited children',()=>{
 const proof=inspectSupervisor(sample());assert.equal(proof.child_pids.length,3);assert.equal(proof.power_loss_or_service_relaunch,'NOT_TESTED');
});
for(const [name,edit] of [
 ['source drift',s=>s.state.source_digest=digest('other')],['same pid',s=>s.state.observed_exits[1].pid=s.state.observed_exits[0].pid],
 ['manual continuation',s=>s.state.operator_phase_commands=1],['fake second stage',s=>s.faults[1].stage='AFTER_MODEL_PERSISTED'],
 ['failed final process',s=>s.state.observed_exits[2].exit_code=1],['exit before fault',s=>s.faults[0].at=s.state.finished_at],
 ['missing observation',s=>delete s.state.observed_exits[0].original_process_observed_dead],
])test('reject misleading supervision evidence: '+name,()=>{const s=sample();edit(s);assert.throws(()=>inspectSupervisor(s));});
