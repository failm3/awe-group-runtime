import assert from 'node:assert/strict';
import {digest} from '../contracts/index.mjs';

const stages=['AFTER_MODEL_PERSISTED','AFTER_NATIVE_COMPLETED'];

export function inspectSupervisor({state,faults,runId,sourceDigest}){
  assert.equal(state.schema,'awe.e1.automatic-repair-supervisor/1');
  assert.equal(state.run_id,runId);assert.equal(state.status,'FINISHED');
  assert.equal(state.source_digest,sourceDigest);
  assert.ok(Number.isSafeInteger(state.supervisor_pid)&&state.supervisor_pid>0);
  assert.equal(state.max_restarts,2);assert.equal(state.operator_phase_commands,0);assert.equal(state.current_child_pid,null);
  assert.equal(state.observed_exits.length,3);assert.equal(faults.length,2);
  const ids=new Set([state.supervisor_pid]);
  let previous=Date.parse(state.started_at);
  assert.ok(Number.isFinite(previous));
  for(const [i,exit] of state.observed_exits.entries()){
    assert.ok(Number.isSafeInteger(exit.pid)&&exit.pid>0&&!ids.has(exit.pid));ids.add(exit.pid);
    assert.equal(exit.original_process_observed_dead,true);
    assert.equal(exit.exit_code,i<2?90:0);assert.equal(exit.signal,null);
    assert.equal(exit.known_injected_fault,i<2?stages[i]:null);
    const end=Date.parse(exit.ended_at);assert.ok(Number.isFinite(end)&&end>=previous);
    if(i<2){
      const fault=faults[i],at=Date.parse(fault.at);
      assert.equal(fault.schema,'awe.e1.repair-injected-process-fault/1');
      assert.equal(fault.supervisor_pid,state.supervisor_pid);assert.equal(fault.pid,exit.pid);assert.equal(fault.stage,stages[i]);
      assert.ok(Number.isFinite(at)&&previous<=at&&at<=end);assert.ok(fault.metadata&&Object.keys(fault.metadata).length>0);
    }
    previous=end;
  }
  assert.ok(Date.parse(state.finished_at)>=previous);
  return {supervisor_pid:state.supervisor_pid,child_pids:state.observed_exits.map(e=>e.pid),exit_codes:state.observed_exits.map(e=>e.exit_code),
    fault_stages:stages,fault_metadata_digests:faults.map(f=>digest(f.metadata)),evidence_digest:digest(state),source_digest:sourceDigest,
    operator_phase_commands:0,observation:'PARENT_OBSERVED_CONTROLLED_CHILD_EXIT_AND_AUTOMATIC_FORK',power_loss_or_service_relaunch:'NOT_TESTED'};
}
