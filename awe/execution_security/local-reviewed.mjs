import fs from 'node:fs';
import path from 'node:path';
import {canonicalize,digest,hashBytes,need,freeze,copy,requireKeys,id} from './common.mjs';
import {loadPins,verifyPins} from '../executable_tools/pins.mjs';
import {sourceFor} from '../executable_tools/programs.mjs';
import {verifyExecutionPins,executionLock} from '../hermes_runtime/execution-profile.mjs';
import {fileName,text as toolText} from '../executable_tools/protocol.mjs';
export const LOCAL_PROFILE='E0_LOCAL_REVIEWED_ONLY';
export const LOCAL_LIMITS=freeze({external_network:0,max_processes:3,wall_ms:1000,cpu_ms:200,memory_bytes:134217728,output_bytes:8192,max_attempts:2});
export const LOCAL_INPUT=freeze({type:'object',required:['text'],properties:{text:{type:'string',maxLength:4096}},additionalProperties:false});
export const LOCAL_OUTPUT=freeze({type:'object',required:['utf8_bytes','code_points','lines','sha256'],properties:{utf8_bytes:{type:'integer',minimum:0,maximum:4096},code_points:{type:'integer',minimum:0,maximum:4096},lines:{type:'integer',minimum:1,maximum:4097},sha256:{type:'string',pattern:'^sha256:[a-f0-9]{64}$'}},additionalProperties:false});
const root=path.resolve(import.meta.dirname,'../..');
function verifySourceLock(){
 const lock=JSON.parse(fs.readFileSync(path.join(root,'OWNER-02/source-lock.json'),'utf8'));
 need(lock.profile===LOCAL_PROFILE,'LOCAL_SOURCE_LOCK_INVALID');
 for(const [file,pin] of Object.entries(lock.files)){const p=path.join(root,file);need(!fs.lstatSync(p).isSymbolicLink()&&hashBytes(fs.readFileSync(p))===pin,'LOCAL_SOURCE_DRIFT');}
 return lock;
}
export function verifyLocalPins(){const lock=verifySourceLock();verifyPins(loadPins(),'node');verifyExecutionPins();return lock;}
export function verifyWritePins(){const lock=verifySourceLock();verifyPins(loadPins(),'node');return lock;}
export const LOCAL_WRITE_INPUT=freeze({type:'object',required:['path','text'],properties:{path:{type:'string'},text:{type:'string',maxLength:4096}},additionalProperties:false});
export function reviewedWriteManifest(project_id){
 const lock=verifyWritePins(),tools=loadPins();
 const binding={adapter:'MASTER01_TOOLS02_CREATE_EXCLUSIVE_V1',tools02_manifest_digest:digest({capability:'fs.write',implementation:'awe/executable_tools/scope.mjs',write_semantics:'CREATE_EXCLUSIVE',pins:tools.files}),runtime_artifact_digest:digest({node:tools.binaries.node,node_version:tools.node_version}),input_schema_digest:digest(LOCAL_WRITE_INPUT),output_schema_digest:digest({path:'filename',bytes:'uint',sha256:'digest'}),source_lock_digest:digest(lock)};
 return freeze({v:'sec01.tool.v1',project_id,tool_id:'tool_fs_write',version:'master01.1',code_digest:hashBytes(fs.readFileSync(path.join(root,'awe/executable_tools/scope.mjs'))),schema_hash:digest(LOCAL_WRITE_INPUT),risk:'PROJECT_WRITE',resources:['resource:local-reviewed-write'],paths:['result.txt'],domains:[],cost_micros:'0',max_input_bytes:8192,max_output_bytes:8192,implementation:LOCAL_PROFILE,local_binding:{...binding,execution_binding_digest:digest(binding),limits:copy(LOCAL_LIMITS)}});
}
// Closed registry dialect: one reviewed TOOLS02 repository template, supervised
// by the existing RT02 Windows Job host. No generated candidate, source or path input.
export function reviewedManifest(project_id){
 const lock=verifyLocalPins(),tools=loadPins();
 const toolsManifest={contract:'tools02.manifest/1',id:'tool_js_stats',version:'1.0.0',capability:'js.text.stats',adapter:'js.template/1',source_digest:hashBytes(Buffer.from(sourceFor('JS'))),artifact_digest:digest(tools),input_schema_hash:digest({contract:'tools02.input/1',capability:'js.text.stats',additionalProperties:false,max_text_utf8:4096}),output_schema_hash:digest({contract:'tools02.output/1',capability:'js.text.stats',max_bytes:8192}),input_schema:{contract:'tools02.input/1',capability:'js.text.stats',additionalProperties:false,max_text_utf8:4096},output_schema:{contract:'tools02.output/1',capability:'js.text.stats',max_bytes:8192},effect_class:'READ_ONLY',write_semantics:null,timeout_ms:1000,max_output_bytes:8192,network_scope:'NONE',credential_policy:'FIXTURE_VALUES_ONLY',mode:'E0_LOCAL_SYNTHETIC'};
 const binding={adapter:'INT04_OWNER02_FIXED_STATS_JOB_V1',tools02_manifest_digest:digest(toolsManifest),runtime_artifact_digest:digest({tools,runtime:executionLock}),input_schema_digest:digest(LOCAL_INPUT),output_schema_digest:digest(LOCAL_OUTPUT),source_lock_digest:digest(lock)};
 return freeze({v:'sec01.tool.v1',project_id,tool_id:'tool_js_stats',version:'owner02.1',code_digest:toolsManifest.source_digest,schema_hash:digest(LOCAL_INPUT),risk:'READ',resources:['resource:local-reviewed'],paths:[],domains:[],cost_micros:'0',max_input_bytes:8192,max_output_bytes:8192,implementation:LOCAL_PROFILE,local_binding:{...binding,execution_binding_digest:digest(binding),limits:copy(LOCAL_LIMITS)}});
}
export function validateLocalManifest(m){need(digest(m)===digest(m.tool_id==='tool_fs_write'?reviewedWriteManifest(m.project_id):reviewedManifest(m.project_id)),'LOCAL_REVIEW_PIN_MISMATCH');}
export function validateLocalInput(payload,m){requireKeys(payload,m?.tool_id==='tool_fs_write'?['path','text']:['text']);need(typeof payload.text==='string'&&Buffer.byteLength(payload.text)<=4096&&Buffer.byteLength(canonicalize(payload))<=8192,'LOCAL_INPUT_INVALID');if(m?.tool_id==='tool_fs_write'){fileName(payload.path);toolText(payload.text);need(payload.path.endsWith('.txt'),'LOCAL_TEXT_PATH');}}
export function validateLocalOutput(output){requireKeys(output,LOCAL_OUTPUT.required);for(const key of ['utf8_bytes','code_points','lines']){const schema=LOCAL_OUTPUT.properties[key];need(Number.isSafeInteger(output[key])&&output[key]>=schema.minimum&&output[key]<=schema.maximum,'LOCAL_OUTPUT_SCHEMA');}need(typeof output.sha256==='string'&&new RegExp(LOCAL_OUTPUT.properties.sha256.pattern).test(output.sha256),'LOCAL_OUTPUT_SCHEMA');}
export function validateLocalRequest(r,m,verifier,auth){
 validateLocalManifest(m);validateLocalInput(r.payload,m);
 requireKeys(r.local,['profile','spec','lease','lease_until','deadline','d09_approval_id','tools02_manifest_digest','runtime_artifact_digest','execution_binding_digest','input_schema_digest','output_schema_digest','limits']);
 id(r.local.d09_approval_id); // Reference only: D09 alone verifies/consumes approval.
 need(r.local.profile===LOCAL_PROFILE,'LOCAL_PROFILE_DENIED');
 for(const key of ['tools02_manifest_digest','runtime_artifact_digest','execution_binding_digest','input_schema_digest','output_schema_digest','limits'])need(digest(r.local[key])===digest(m.local_binding[key]),'LOCAL_BINDING_MISMATCH');
 const s=verifier.snapshot(r.project_id,r.task_id);
 need(s.spec&&digest(s.spec)===digest(r.local.spec),'LOCAL_SPEC_STALE');
 need(s.lease&&typeof s.lease.holder==='string'&&Number.isSafeInteger(s.lease.lease_epoch)&&s.lease.lease_epoch>0&&s.lease.fence===r.fence&&digest(s.lease)===digest(r.local.lease)&&Date.parse(s.lease.expires_at)===s.lease_until,'LOCAL_LEASE_BINDING');
 need(r.local.lease_until===s.lease_until&&r.local.deadline===r.expires_at&&r.expires_at<=s.lease_until&&r.expires_at<=auth.expires_at,'LOCAL_LEASE_DEADLINE');
 need(auth.lineage.length>0&&auth.lineage.every(g=>g.max_attempts<=LOCAL_LIMITS.max_attempts),'LOCAL_ATTEMPT_LIMIT');
 need(r.reserve_micros===m.cost_micros,'LOCAL_RESERVATION_REQUIRED');
 return freeze({profile:LOCAL_PROFILE,launch_authorized:false,physical_decision:'DENY',binding:digest(r),limits:copy(LOCAL_LIMITS)});
}
