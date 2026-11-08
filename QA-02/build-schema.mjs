import {readFileSync,writeFileSync} from 'node:fs';
const common=JSON.parse(readFileSync(new URL('../contracts/v1/common.schema.json',import.meta.url))).$defs;
const object=properties=>({type:'object',properties,required:Object.keys(properties),additionalProperties:false});
const text={type:'string',minLength:1},integer={type:'integer',minimum:0,maximum:9007199254740991};
const hash={type:'string',pattern:'^sha256:[a-f0-9]{64}$'},bool=value=>({const:value});
const artifact=object({project_id:text,task_id:text,version:{...integer,minimum:1},artifact:{$ref:'#/$defs/artifact'},file_hash:hash,bytes:integer,path:text,provenance_hash:hash});
const feedback=object({version:{const:'qa02.auto02/1'},scope:{$ref:'#/$defs/scope'},spec:{$ref:'#/$defs/spec'},handoff_hash:hash,plan_hash:text,node_hash:text,node_id:text,expected_revision:integer,fence:integer,artifact,profile_hash:hash,evidence_hash:hash,
 verdict:{enum:['PASS','FAIL','UNCLEAR','BLOCKED']},action:{enum:['NONE','REWORK','COLLECT_EVIDENCE','ESCALATE']},code:text,
 failures:{type:'array',maxItems:96,items:object({role:{enum:['local','independent','auditor']},criterion_id:{type:'string',pattern:'^Q[0-9]{2}$'},requirement_id:text,code:text,status:{enum:['FAIL','UNCLEAR','BLOCKED']},evidence_hash:hash})},
 repair:object({attempts_used:integer,max_attempts:{...integer,maximum:2},next_attempt:{oneOf:[{type:'integer',minimum:1,maximum:2},{type:'null'}]},deadline:{type:'string',format:'date-time'},remaining_budget_micros:{type:'string',pattern:'^(0|[1-9][0-9]*)$'},only_affected_task:bool(true),requires_new_artifact_version:bool(true),requires_full_recheck:bool(true)}),
 trust:object({authority:{const:'CANDIDATE_ONLY'},requires_existing_d08_gate:bool(true),requires_current_d03_cas:bool(true),physical_decision:{const:'DENY'}}),idempotency_key:hash});
const schema={$schema:'https://json-schema.org/draft/2020-12/schema',$id:'https://awe.invalid/qa02/auto02-feedback.schema.json',$defs:{scope:common.scope,spec:common.spec,artifact:common.artifact},...feedback};
writeFileSync(new URL('./auto02-feedback.schema.json',import.meta.url),JSON.stringify(schema,null,2)+'\n');
console.log('WROTE auto02-feedback.schema.json');
