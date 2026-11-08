import {processFixture} from './fixture.mjs';
// Only invoked by the parent test. It is intentionally killed before cleanup.
const f=await processFixture({after(){}},{syntheticFaults:{run_parent:'ignore_cancel',run_child:'ignore_cancel'}});
await f.launch();await f.launch(f.child());
process.stdout.write(JSON.stringify({pids:f.adapter.inspectProcesses().runs.map(r=>r.pid),spawn_count:2,physical_decision:'DENY'})+'\n');
setInterval(()=>{},1000);
