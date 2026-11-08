import {fixture} from '../tests/executable_tools/fixtures.mjs';
import {bindAgentTools,createRt01ToolPort} from '../awe/executable_tools/facade.mjs';
const f=fixture();
try{
 const results=[];
 results.push(await f.execute('fs.write',{path:'input.txt',text:'Synthetic AWE 🧪\n'}));
 results.push(await f.execute('fs.read',{path:'input.txt'}));
 for(const cap of ['js.text.stats','python.text.stats'])results.push(await f.execute(cap,{text:'Synthetic AWE 🧪\n'}));
 results.push(await f.execute('cli.node_version'));
 results.push(await f.execute('cli.git_version'));
 results.push(await f.execute('browser.snapshot',{fixture_id:'welcome',credential:'TEST_BROWSER_ONLY'}));
 results.push(await f.execute('api.get',{fixture_id:'inventory',credential:'TEST_API_ONLY'}));
 const missing_before=!f.tools.inspect().registered.some(e=>e.capability==='js.text.word_count');
 const candidate=f.tools.factory.generate({tool_id:'tool_generated_words',language:'JS',template:'text.word_count.v1'});
 await f.tools.factory.test(candidate.id);await f.tools.factory.verify(candidate.id);const pin=f.tools.factory.register(candidate.id);
 const agent=bindAgentTools(f.tools,{run_id:'run_tools02',actor_id:'act_worker',project_id:'prj_tools02',task_id:'task_tools02',pins:[pin]});
 results.push(await agent.execute(JSON.stringify({contract:'tools02/1',operation_id:'op_generated',pin,input:{text:'generated fixture'}})));
 console.log(JSON.stringify({contract:'tools02.demo/1',status:results.every(r=>r.decision==='EXECUTED_LOCAL')?'PASS':'FAIL',results,missing_capability_before:missing_before,rt01_pin_check:createRt01ToolPort(f.tools).check([pin]),external_requests:0,real_hermes:'NOT_RUN',independent_acceptance:'NOT_RUN',production_ready:false},null,2));
 if(results.some(r=>r.decision!=='EXECUTED_LOCAL'))process.exitCode=1;
}finally{await f.tools.close();}
