import {ready} from './fixtures.mjs';
const f = await ready();
const dispatch = await f.exec(), receipt = await f.collect();
await f.finish('run_child'); const parent = await f.finish('run_parent');
console.log(JSON.stringify({profile: 'D04_SYNTHETIC_PARENT_CHILD_TOOL_V1', dispatch,
  receipt, parent, runtime: f.adapter.control.inspect(), operation: f.operation(), task_state: f.task().state,
  d02_recorded_attempts: f.inspect().effects.length, physical_dispatches: f.inspect().actual_external_dispatches,
  independent_qa: 'NOT_RUN'}));
