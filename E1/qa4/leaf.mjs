import {createAuthorityClient} from '../coordinator/authority-server.mjs';
import {digest} from '../contracts/index.mjs';
import {createFrozenOracle,evaluateTask} from './oracle.mjs';
import fs from 'node:fs';

// One independently credentialed QA process. Tokens arrive only over IPC and
// are never written, returned, placed in argv/env, or supplied to model inputs.
let busy=false;
const need=(value,code)=>{if(!value)throw Object.assign(new Error(code),{code});};
process.on('message',async message=>{
 if(busy){process.send?.({type:'ERROR',pid:process.pid,code:'QA4_QA_BUSY'});return;}busy=true;
 try{
  need(message&&typeof message==='object'&&message.binding&&message.evaluation,'QA4_QA_ENVELOPE');
  const {binding,evaluation}=message,client=createAuthorityClient({url:message.url,token:message.token});
  const oracle=createFrozenOracle({variant:evaluation.oracle?.variant??'public'});
  need(evaluation.oracle?.oracle_digest===oracle.oracle_digest,'QA4_ORACLE_SUBSTITUTED');
  const snapshot=await client.snapshot(),task=snapshot.tasks.find(x=>x.mission_id===binding.mission_id&&x.task_id===binding.task_id);
  need(task&&task.state==='WAIT_QA'&&task.plan_digest===binding.plan_digest&&task.result_hash===binding.result_hash&&digest(task.result)===binding.result_hash,'QA4_STORED_RESULT_BINDING');
  need(evaluation.task_id===binding.task_id&&digest(evaluation.output)===digest(task.result.output),'QA4_EVALUATION_OUTPUT_SUBSTITUTED');
  const dependencies={};for(const id of task.document.depends_on){const dep=snapshot.tasks.find(x=>x.mission_id===binding.mission_id&&x.task_id===id&&x.plan_digest===binding.plan_digest);need(dep&&dep.state==='ACCEPTED'&&digest(dep.result)===dep.result_hash,'QA4_DEPENDENCY_NOT_ACCEPTED');dependencies[id]=dep.result.output;}
  // Review's model-origin evidence is taken from the authenticated QA DB view,
  // never from caller-provided usage or a model's text claiming success.
  dependencies.__native_attempts=snapshot.attempts.filter(x=>x.mission_id===binding.mission_id&&x.task_id===binding.task_id);
  if(binding.task_id==='rank'){const stage=JSON.parse(task.result.output.payload);if(stage.code_execution){const id=/^mission_recruit_([a-z0-9_]{1,24})$/.exec(stage.code_execution.author_mission_id)?.[1];need(id,'QA4_CODE_AUTHOR_SCOPE');dependencies.__code_witness=JSON.parse(fs.readFileSync('E1/qa4/CODE-AUTHOR-'+id+'.json','utf8'));}}
  const result=evaluateTask(binding.task_id,task.result.output,dependencies,oracle);
  const value=await client.qaEvaluate({...binding,verdict:result.verdict,checks:result.checks});
  process.send?.({type:'EVALUATED',pid:process.pid,evaluation:result,value});
 }catch(error){const code=typeof error?.code==='string'&&/^(?:QA4_|A2_)[A-Z_]+$/.test(error.code)?error.code:'QA4_QA_REJECT';process.send?.({type:'ERROR',pid:process.pid,code});}
 finally{busy=false;}
});
process.on('disconnect',()=>process.exit(0));
process.send?.({type:'QA_READY',pid:process.pid});
