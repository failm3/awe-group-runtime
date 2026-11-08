import test from 'node:test';
import assert from 'node:assert/strict';
import {createD09AttemptPort} from '../../awe/hermes_runtime/d09-port.mjs';
import {digest} from '../../awe/hermes_runtime/protocol.mjs';
const command={project_id:'prj_alpha',task_id:'task_one',operation_id:'op_launch',attempt_id:'attempt_one',effect_slot:'slot_one',approval_id:'approval_one',grant_id:'grant_one',idempotency_key:'key_one',plan_hash:digest({}),payload_hash:digest({}),reserve_micros:'0'};
function pool({failCommit=false,alreadySent=false,foreign=false}={}) {
 const queries=[];
 return {queries,connect:async()=>({query:async(sql,params)=>{queries.push({sql,params});if(failCommit&&sql==='COMMIT')throw Error('DISCONNECTED');
  return {rows:sql.startsWith('SELECT')?[{result:{physical_decision:'DENY',dispatch_authorized:false,project_id:foreign?'prj_beta':'prj_alpha',task_id:'task_one',attempt_id:'attempt_one',delivery_fence:'1',status:alreadySent||sql.includes('mark_sent')?'SENT':'ADMITTED'}}]:[]};},release(){}})};
}
test('unchanged D09 SERIALIZABLE API maps admit, claim, markSent with decimal money',async()=>{
 const p=pool(),port=createD09AttemptPort(p);assert.equal((await port.begin(command)).physical_decision,'DENY');
 const selects=p.queries.filter(q=>q.sql.startsWith('SELECT'));assert.deepEqual(selects.map(q=>q.sql.split('.')[1].split('(')[0]),['admit','claim_attempt','mark_sent']);
 assert.equal(p.queries.filter(q=>q.sql==='COMMIT').length,3);assert.equal(JSON.parse(selects[0].params[0]).reserve_micros,'0');
});
test('D09 ambiguous COMMIT is not retried',async()=>{const p=pool({failCommit:true}),port=createD09AttemptPort(p);await assert.rejects(()=>port.begin(command),/COMMIT_OUTCOME_UNKNOWN/);assert.equal(p.queries.filter(q=>q.sql.includes('awe_d09.admit')).length,1);});
test('D09 SENT readback is never fresh launch authorization',async()=>{const p=pool({alreadySent:true});await assert.rejects(()=>createD09AttemptPort(p).begin(command),/D09_ALREADY_ATTEMPTED/);assert.equal(p.queries.filter(q=>q.sql.startsWith('SELECT')).length,1);});
test('D09 foreign-project acknowledgement denied',async()=>{const p=pool({foreign:true});await assert.rejects(()=>createD09AttemptPort(p).begin(command),/D09_BINDING_DENIED/);});
test('D09 result, cancel and inspect use fixed scoped existing API',async()=>{const p=pool(),port=createD09AttemptPort(p);await port.result(command,'SUCCEEDED',digest({}));await port.cancel(command);await port.inspect(command);
 assert.deepEqual(p.queries.filter(q=>q.sql.startsWith('SELECT')).map(q=>q.sql.split('.')[1].split('(')[0]),['record_result','cancel_attempt','inspect_attempt']);});
