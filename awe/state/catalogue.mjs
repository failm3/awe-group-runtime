import {canonicalize,digest} from '../../contracts/canonical.mjs';
import {createHash} from 'node:crypto';
import {copy,requireState as need} from './errors.mjs';
const hash=b=>'sha256:'+createHash('sha256').update(b).digest('hex');
const exact=(v,keys)=>need(v&&Object.keys(v).sort().join()===keys.sort().join(),'CATALOGUE_SHAPE');
const empty=()=>({entries:[],sources:{},heads:{memory:{},artifacts:{}},tombstones:{memory:[],artifacts:[]},ACL:{}});
export function catalogueContext(db,scope,{readOnly=false}={}){
 const p=db.projects[scope.project_id],t=p?.tasks[scope.task_id];
 need(p&&t&&t.control_operation_id===scope.operation_id,'CATALOGUE_SCOPE');
 need(p.status==='READY'&&!t.cancel_requested&&!t.restore_pending&&(!['CANCELLED','COMPLETE','FAILED'].includes(t.state)||(readOnly&&t.state==='COMPLETE'&&!t.acceptance_stale)),'CATALOGUE_STATE_BLOCKED');
 need(!Object.values(p.specs).some(x=>x.dto.spec.spec_id===t.spec.spec_id&&x.dto.spec.revision>t.spec.revision),'CATALOGUE_SPEC_STALE');
 return {p,t,c:p.catalogue??empty(),pin:{project_id:p.id,task_id:t.id,authority_revision:db.commit,current_spec:copy(t.spec),epochs:copy(p.epochs),revision:t.revision,fence:t.fence,restore_pending:t.restore_pending}};
}
export function catalogueView(db,scope,principals,actor){
 const {p,t,c,pin}=catalogueContext(db,scope,{readOnly:true});
 const actors=Object.fromEntries(Object.entries(principals).filter(([,v])=>v.projects.includes(p.id)).map(([id,v])=>[id,{active:v.active!==false,role:v.role,memberships:{[p.id]:v.role==='OWNER'?[...new Set(['memory.ingest','memory.read','memory.audit','memory.delete','provenance.produce',...(c.ACL[id]??[])])]:c.ACL[id]??[]}}]));
 const entries=c.entries.filter(e=>e.reader_ids.includes(actor.identity_id));
 const state={schema_version:'1.0.0',authority_revision:db.commit,projects:{[p.id]:{status:p.status,revision:p.revision,spec:copy(t.spec),epochs:copy(p.epochs),restore_pending:t.restore_pending,cancel_requested:t.cancel_requested}},actors,sources:copy(c.sources),heads:copy(c.heads),tombstones:copy(c.tombstones),promotions:{},qa_attestations:{}};
 return {pin,catalogue:{project_id:p.id,authority_revision:db.commit,entries:entries.map(({exact_ref,project_id,authority_revision,...e})=>({...e,ref:exact_ref}))},artifacts:Object.values(c.artifacts??{}).filter(x=>x.reader_ids.includes(actor.identity_id)).map(copy),artifact_history:Object.values(c.artifact_history??{}).filter(x=>x.reader_ids.includes(actor.identity_id)).map(copy),state,owner_state:{current_spec:copy(t.spec),epochs:copy(p.epochs),heads:copy(c.heads),tombstones:copy(c.tombstones),ACL:copy(c.ACL),restore_pending:t.restore_pending},durable_binding:'NOT_BOUND'};
}
export function prepareCatalogue(db,scope,input,principals,owner,now){
 exact(input,['record_id','version','kind','text','source_id','reader_ids','purposes','retention_until']);
 need(/^mem_[a-z0-9_-]{1,64}$/.test(input.record_id)&&/^src_[a-z0-9_-]{1,64}$/.test(input.source_id),'CATALOGUE_ID');
 need(['GOAL','SPEC','RESULT','NOTE','SUMMARY'].includes(input.kind)&&input.kind!=='SUMMARY','CATALOGUE_KIND');
 need(typeof input.text==='string'&&Buffer.byteLength(input.text)>0&&Buffer.byteLength(input.text)<=16384,'CATALOGUE_TEXT');
 const {p,t,c,pin}=catalogueContext(db,scope),key=p.id+'/'+input.record_id,head=c.heads.memory[key];
 need(!c.tombstones.memory.includes(key)&&input.version===(head?.version??0)+1,'CATALOGUE_VERSION_OR_TOMBSTONE');
 need(!c.sources[input.source_id],'CATALOGUE_SOURCE_IMMUTABLE');
 need(Array.isArray(input.reader_ids)&&input.reader_ids.length>0&&input.reader_ids.length<=32&&new Set(input.reader_ids).size===input.reader_ids.length&&input.reader_ids.includes(owner.identity_id)&&input.reader_ids.every(id=>principals[id]?.active!==false&&principals[id]?.projects.includes(p.id)),'CATALOGUE_ACL');
 need(Array.isArray(input.purposes)&&input.purposes.length>0&&new Set(input.purposes).size===input.purposes.length&&input.purposes.every(x=>['PERSIST','HISTORY','CONTEXT','BUILD'].includes(x)),'CATALOGUE_PURPOSE');
 need(typeof input.retention_until==='string'&&new Date(input.retention_until).toISOString()===input.retention_until&&input.retention_until>now,'CATALOGUE_RETENTION');
 const source={source_id:input.source_id,project_id:p.id,subject_id:input.record_id,version:input.version,kind:'MEMORY',content_hash:hash(Buffer.from(input.text)),project_stamp:digest({project_id:p.id,revision:p.revision,spec:t.spec,epochs:p.epochs}),producer_id:owner.identity_id,status:'VERIFIED',expires_at:input.retention_until,reader_ids:copy(input.reader_ids),shareable:false,parents:[]};
 const provenance={source_id:source.source_id,source_hash:digest(source)};
 const record={schema:'DATA02_RECORD_V1',project_id:p.id,record_id:input.record_id,version:input.version,kind:input.kind,text:input.text,created_at:now,expires_at:input.retention_until,provenance,sources:[],artifacts:[]};
 const entry={project_id:p.id,authority_revision:db.commit+1,exact_ref:hash(Buffer.from(canonicalize(record))),record_id:input.record_id,version:input.version,kind:input.kind,source_id:source.source_id,provenance_hash:provenance.source_hash,reader_ids:copy(input.reader_ids),purposes:copy(input.purposes),retention_until:input.retention_until};
 return {pin,input:copy(input),record,source,entry};
}
export function commitCatalogue(db,scope,prepared,principals,owner,now){
 const {p,c,pin}=catalogueContext(db,scope);need(digest(pin)===digest(prepared.pin),'CATALOGUE_AUTHORITY_STALE');
 const current=prepareCatalogue(db,scope,prepared.input,principals,owner,prepared.record.created_at);
 need(prepared.record.created_at<=now&&prepared.entry.retention_until>now&&digest(current)===digest(prepared),'CATALOGUE_SOURCE_DRIFT');
 p.catalogue??=c;need(c.entries.length<128,'CATALOGUE_CAPACITY');
 c.entries.push(copy(prepared.entry));c.sources[prepared.source.source_id]=copy(prepared.source);
 c.heads.memory[p.id+'/'+prepared.entry.record_id]={version:prepared.entry.version,source_hash:prepared.entry.provenance_hash};
 for(const id of prepared.entry.reader_ids)c.ACL[id]=[...new Set([...(c.ACL[id]??[]),'memory.read'])];
 return {status:'CATALOGUE_COMMITTED_E0',exact_ref:prepared.entry.exact_ref,authority_revision:db.commit+1,physical_decision:'DENY',production_binding:false};
}
