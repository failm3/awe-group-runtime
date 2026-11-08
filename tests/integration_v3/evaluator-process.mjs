import {createPsqlPool} from './psql-pool.mjs';
import {evaluatePendingRun} from '../../awe/integration_v3/evaluator-service.mjs';

// Private inherited pipe from the trusted fixture supervisor. Not a public
// server, no network listener, no environment-supplied proof/plugin or eval code.
let input='';for await(const chunk of process.stdin){input+=chunk;if(input.length>32768)throw Error('BOOTSTRAP_TOO_LARGE');}
let output;
try {
  const config=JSON.parse(input),queries=[];
  if(config.failBeforeEvaluation)throw Error('INJECTED_EVALUATOR_STOP_BEFORE_EVALUATION');
  const pool=createPsqlPool({...config.pg,record:entry=>queries.push(entry)});
  if(config.fault)pool.faultNextCommit(config.fault.mode,config.fault.fn);
  try {
    const value=await evaluatePendingRun(pool,config.request);
    output={ok:true,value,queries,process_id:process.pid};
  } catch(error) {output={ok:false,error:error.message,outcomeUnknown:error.outcomeUnknown===true,queries,process_id:process.pid};}
} catch(error){output={ok:false,error:error.message,outcomeUnknown:false,process_id:process.pid};}
process.stdout.write(JSON.stringify(output)+'\n');
if(!output.ok)process.exitCode=1;
