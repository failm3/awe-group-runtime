import {createOfflineAuthority,digest,canonicalize,hashBytes,sourceFor,need} from '../memory/boundary.mjs';
import {createOfflineArtifacts,fileCatalogue} from './service.mjs';
import {objectKey,regularBytes} from './paths.mjs';
// Existing D03 owns heads, ACL, provenance and descriptors. D07 owns immutable
// files and verification. Restart rebuilds only a cache from current D03 rows.
export function createD03ArtifactPort({state,writer,reader,producerId,scope,stores,readers,clock}){
 need(stores.length===2&&readers.length===2&&new Set(stores.map(s=>s.storage_id)).size===2,'D07_TWO_STORES');
 const view=()=>state.readCatalogue(reader,scope);
 const authority=createOfflineAuthority({readState:()=>view().state,clock,advancingClock:true});
 const artifacts=createOfflineArtifacts({authority,stores,readers,readCatalogue:()=>{const v=view();return [...v.artifacts,...v.artifact_history];}});
 const token=id=>authority.openSession(id,scope.project_id);
 function read(reference,readerId){
  const session=token(readerId),v=authority.check(session,'artifact.read');
  const result=artifacts.read(session,JSON.stringify({artifact_id:reference.artifact.artifact_id,version:reference.version,path:reference.path}));need(result.ok,'D07_READ_DENIED');
  need(digest(result.value.artifact)===digest(reference.artifact),'D07_REFERENCE_CHANGED');
  const descriptor=view().artifacts.find(x=>x.status==='PERSISTED'&&digest(x.record.reference)===digest(reference.artifact)&&x.record.version===reference.version);need(descriptor,'D07_CATALOGUE_REFERENCE');
  const source=sourceFor(v,{project_id:scope.project_id,kind:'ARTIFACT',subject_id:reference.artifact.artifact_id,version:reference.version,content_hash:descriptor.record.payload_hash,provenance:descriptor.record.manifest.provenance});need(source.reader_ids.includes(readerId),'D07_READ_ACL');
  const store=readers.find(r=>r.reader_id===readerId)?.store??stores[0],manifest=regularBytes(store,objectKey(scope.project_id,reference.artifact.content_hash));
  need(manifest.toString('utf8')===canonicalize(descriptor.record.manifest),'D07_READER_MANIFEST_CHANGED');
  const bytes=regularBytes(store,objectKey(scope.project_id,reference.file_hash));need(bytes.length===reference.bytes&&hashBytes(bytes)===reference.file_hash,'D07_BYTES_CHANGED');authority.finish(v,session,'artifact.read');return bytes;
 }
 return Object.freeze({
  async persist({artifact_id,version=1,files,reader_ids,retention_until}){
   const prepared=await state.prepareArtifact(writer,scope,{artifact_id,version,files:fileCatalogue(files),producer_id:producerId,reader_ids,retention_until});
   const out=artifacts.put(token(producerId),JSON.stringify({artifact_id,expected_version:version-1,provenance:prepared.record.manifest.provenance,files:files.map(f=>({path:f.path,media_type:f.media_type,bytes_base64:f.bytes.toString('base64')}))}));
   need(out.ok&&digest(out.value.reference.artifact)===digest(prepared.record.reference),'D07_PERSIST_FAILED');
   const readbacks=readers.map((reader,i)=>{
    need(reader.store===stores[i]&&reader.reader_id!==producerId,'D07_INDEPENDENT_READER');
    const v=authority.check(token(reader.reader_id),'artifact.read');sourceFor(v,{project_id:scope.project_id,kind:'ARTIFACT',subject_id:artifact_id,version,content_hash:prepared.record.payload_hash,provenance:prepared.record.manifest.provenance});
    const manifest=regularBytes(reader.store,objectKey(scope.project_id,prepared.record.reference.content_hash));need(manifest.toString('utf8')===canonicalize(prepared.record.manifest),'D07_MANIFEST_CHANGED');
    for(const f of prepared.record.manifest.files){const bytes=regularBytes(reader.store,objectKey(scope.project_id,f.content_hash));need(bytes.length===f.bytes&&hashBytes(bytes)===f.content_hash,'D07_INDEPENDENT_READBACK');}
    authority.finish(v,token(reader.reader_id),'artifact.read');
    return {reader_id:reader.reader_id,storage_id:reader.store.storage_id,manifest_hash:hashBytes(manifest),file_count:files.length,provenance_hash:prepared.record.manifest.provenance.source_hash};
   });
   const ack=await state.commitArtifact(writer,scope,prepared,readbacks);need(ack.status==='PERSISTED','D07_COMMIT_FAILED');
   return files.map(f=>({project_id:scope.project_id,task_id:scope.task_id,version,artifact:out.value.reference.artifact,file_hash:hashBytes(f.bytes),bytes:f.bytes.length,path:f.path,provenance_hash:out.value.provenance_hash}));
  },
  reader:readerId=>Object.freeze({read:ref=>read(ref,readerId)}),
  read,
  inspect:()=>view().artifacts
 });
}
