import {canonicalize,digest} from '../../contracts/canonical.mjs';
import {hashBytes,projectStamp} from '../memory/boundary.mjs';
import {safePathSet} from '../artifacts/paths.mjs';
import {catalogueContext} from './catalogue.mjs';
import {copy,requireState as need} from './errors.mjs';
const exact=(o,keys)=>need(o&&Object.keys(o).sort().join()===keys.sort().join(),'ARTIFACT_CATALOGUE_SHAPE');
export function prepareArtifact(db,scope,input,principals,now){
 exact(input,['artifact_id','version','files','producer_id','reader_ids','retention_until']);
 const {p,t,c}=catalogueContext(db,scope);p.catalogue??=c;c.artifacts??={};c.artifact_history??={};
 need(/^art_[a-z0-9][a-z0-9_-]{0,50}$/.test(input.artifact_id)&&Number.isSafeInteger(input.version)&&input.version>0,'ARTIFACT_CATALOGUE_ID');
 const key=p.id+'/'+input.artifact_id,previous=c.artifacts[key];
 need(!c.tombstones.artifacts.includes(key)&&input.version===(previous?.record.version??0)+1&&(!previous||previous.status==='PERSISTED'),'ARTIFACT_CATALOGUE_VERSION');
 need(Array.isArray(input.files)&&input.files.length>0&&input.files.length<=64,'ARTIFACT_CATALOGUE_FILES');safePathSet(input.files.map(f=>f.path));
 for(const f of input.files){exact(f,['path','content_hash','bytes','media_type']);need(/^sha256:[a-f0-9]{64}$/.test(f.content_hash)&&Number.isSafeInteger(f.bytes)&&f.bytes>=0&&f.bytes<=32768&&['application/json','text/plain','application/octet-stream'].includes(f.media_type),'ARTIFACT_CATALOGUE_FILE');}
 const files=copy(input.files).sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
 need(files.reduce((s,f)=>s+f.bytes,0)<=49152,'ARTIFACT_CATALOGUE_SIZE');
 need(Array.isArray(input.reader_ids)&&input.reader_ids.length>=3&&new Set(input.reader_ids).size===input.reader_ids.length&&input.reader_ids.includes(input.producer_id)&&input.reader_ids.every(id=>principals[id]?.active!==false&&principals[id]?.projects.includes(p.id)),'ARTIFACT_CATALOGUE_ACL');
 need(['EXECUTOR','EXAMINER','AUDITOR','ARTIFACT_SERVICE'].includes(principals[input.producer_id]?.role)&&new Date(input.retention_until).toISOString()===input.retention_until&&input.retention_until>now,'ARTIFACT_CATALOGUE_PRODUCER');
 const source_id='src_'+input.artifact_id+'_'+input.version;
 need(!c.sources[source_id],'ARTIFACT_CATALOGUE_SOURCE_IMMUTABLE');
 const source={source_id,project_id:p.id,kind:'ARTIFACT',subject_id:input.artifact_id,version:input.version,content_hash:digest(files),project_stamp:projectStamp(p.id,{revision:p.revision,spec:t.spec,epochs:p.epochs}),producer_id:input.producer_id,status:'VERIFIED',expires_at:input.retention_until,shareable:false,parents:[],reader_ids:copy(input.reader_ids)};
 const provenance={source_id,source_hash:digest(source)};
 const manifest={schema_version:'1.0.0',format:'awe-artifact-manifest-v1',project_id:p.id,artifact_id:input.artifact_id,version:input.version,spec:copy(t.spec),epochs:copy(p.epochs),provenance,files};
 const bytes=Buffer.from(canonicalize(manifest)),h=hashBytes(bytes),reference={project_id:p.id,artifact_id:input.artifact_id,content_hash:h,bytes:bytes.length,media_type:'application/json',aggregate_hash:h};
 const record={manifest,reference,version:input.version,payload_hash:digest(files),stamp:source.project_stamp,producer_id:input.producer_id,previous_manifest_hash:previous?.record.reference.content_hash??null};
 const binding={scope:copy(scope),spec:copy(t.spec),epochs:copy(p.epochs),revision:t.revision,fence:t.fence};
 const prepared={status:'PREPARED',record,source,binding,reader_ids:copy(input.reader_ids)};
 if(previous)c.artifact_history[key+'/'+previous.record.version]??=copy(previous);
 c.artifacts[key]=copy(prepared);c.sources[source_id]=copy(source);c.heads.artifacts[key]={version:input.version,source_hash:provenance.source_hash};
 for(const id of input.reader_ids)c.ACL[id]=[...new Set([...(c.ACL[id]??[]),'artifact.read',...(id===input.producer_id?['artifact.write','provenance.produce']:[])])];
 return prepared;
}
export function commitArtifact(db,scope,prepared,readbacks,principals,now){
 const {p,t,c}=catalogueContext(db,scope),key=p.id+'/'+prepared.record.manifest.artifact_id,current=c.artifacts?.[key];
 need(current?.status==='PREPARED'&&digest(current)===digest(prepared),'ARTIFACT_CATALOGUE_STALE');
 need(prepared.source.expires_at>now&&t.lease?.expires_at>now,'ARTIFACT_CATALOGUE_LEASE_OR_RETENTION_EXPIRED');
 need(digest(prepared.binding)===digest({scope,spec:t.spec,epochs:p.epochs,revision:t.revision,fence:t.fence}),'ARTIFACT_CATALOGUE_STATE_CHANGED');
 need(Array.isArray(readbacks)&&readbacks.length===2&&new Set(readbacks.map(r=>r.reader_id)).size===2&&new Set(readbacks.map(r=>r.storage_id)).size===2,'ARTIFACT_CATALOGUE_READERS');
 for(const r of readbacks)need(r.reader_id!==prepared.record.producer_id&&prepared.reader_ids.includes(r.reader_id)&&principals[r.reader_id]?.active!==false&&principals[r.reader_id]?.projects.includes(p.id)&&r.manifest_hash===prepared.record.reference.content_hash&&r.file_count===prepared.record.manifest.files.length&&r.provenance_hash===prepared.record.manifest.provenance.source_hash,'ARTIFACT_CATALOGUE_READBACK');
 c.artifacts[key]={...copy(prepared),status:'PERSISTED',readbacks:copy(readbacks)};
 c.artifact_history[key+'/'+prepared.record.version]=copy(c.artifacts[key]);
 return {status:'PERSISTED',record:copy(prepared.record),readbacks:copy(readbacks),physical_decision:'DENY'};
}
