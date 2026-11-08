import {id,sourceFor} from '../../awe/memory/boundary.mjs';
import {copy,digest,canonicalize,hashBytes,hash,integer,time,exact,input,need,result,sync,DataError} from './common.mjs';
const kinds=new Set(['GOAL','SPEC','RESULT','NOTE','SUMMARY']);
const recordKeys=['schema','project_id','record_id','version','kind','text','created_at','expires_at','provenance','sources','artifacts'];

export function validateRecord(raw){
  const r=copy(exact(raw,recordKeys));
  need(r.schema==='DATA02_RECORD_V1');id(r.project_id,'prj');id(r.record_id,'mem');integer(r.version,1);need(kinds.has(r.kind));
  need(typeof r.text==='string'&&r.text.length>0&&Buffer.byteLength(r.text)<=16384);
  time(r.created_at);time(r.expires_at);need(r.created_at<r.expires_at);
  exact(r.provenance,['source_id','source_hash']);id(r.provenance.source_id,'src');hash(r.provenance.source_hash);
  need(Array.isArray(r.sources)&&r.sources.length<=8&&Array.isArray(r.artifacts)&&r.artifacts.length<=8);
  for(const s of r.sources){
    exact(s,['source_id','source_hash','uri']);id(s.source_id,'src');hash(s.source_hash);
    need(typeof s.uri==='string'&&s.uri.length<=1024);
    const u=new URL(s.uri);need(['https:','artifact:'].includes(u.protocol)&&!u.username&&!u.password,'LINK_DENIED');
  }
  for(const a of r.artifacts){
    exact(a,['project_id','artifact_id','version','content_hash','source_id','source_hash']);
    need(a.project_id===r.project_id,'SCOPE_DENIED');id(a.artifact_id,'art');integer(a.version,1);hash(a.content_hash);id(a.source_id,'src');hash(a.source_hash);
  }
  return r;
}
export const recordRef=r=>hashBytes(Buffer.from(canonicalize(validateRecord(r))));

// Catalogue is a coherent READ-ONLY projection supplied by the existing owner.
// Immutable files can never reconstruct heads, ACLs, deletion or permissions.
export function createProjectMemory({project_id,authority,readCatalogue,stores}){
  id(project_id,'prj');
  need(authority&&typeof readCatalogue==='function'&&Array.isArray(stores)&&stores.length===2);
  need(stores.every(s=>typeof s.storage_id==='string'&&s.storage_id.length>0)&&stores[0].storage_id!==stores[1].storage_id,'REPLICA_CONFIGURATION_INVALID');
  need(!stores[0].root_identity||!stores[1].root_identity||stores[0].root_identity!==stores[1].root_identity,'REPLICA_CONFIGURATION_INVALID');
  function begin(token,permission){
    const v=authority.check(token,permission);need(v.project_id===project_id,'SCOPE_DENIED');
    const c=sync(()=>readCatalogue(v),'CATALOGUE_UNAVAILABLE');
    exact(c,['project_id','authority_revision','entries']);
    need(c.project_id===v.project_id&&c.authority_revision===v.state.authority_revision,'CATALOGUE_UNAVAILABLE');
    need(Array.isArray(c.entries)&&c.entries.length<=128,'CATALOGUE_UNAVAILABLE');
    const refs=new Set(),versions=new Set();
    for(const e of c.entries){
      exact(e,['ref','record_id','version','kind','source_id','provenance_hash','reader_ids','purposes','retention_until']);id(e.source_id,'src');
      hash(e.ref);id(e.record_id,'mem');integer(e.version,1);hash(e.provenance_hash);time(e.retention_until);need(kinds.has(e.kind));
      need(!refs.has(e.ref)&&!versions.has(e.record_id+'/'+e.version),'CATALOGUE_UNAVAILABLE');refs.add(e.ref);versions.add(e.record_id+'/'+e.version);
      need(Array.isArray(e.reader_ids)&&e.reader_ids.every(x=>typeof x==='string')&&Array.isArray(e.purposes)&&e.purposes.every(x=>typeof x==='string'),'CATALOGUE_UNAVAILABLE');
    }
    return {v,c,token,permission};
  }
  function finish(ctx){
    authority.finish(ctx.v,ctx.token,ctx.permission);
    need(digest(sync(()=>readCatalogue(ctx.v),'CATALOGUE_UNAVAILABLE'))===digest(ctx.c),'STATE_CHANGED');
    authority.finish(ctx.v,ctx.token,ctx.permission);
  }
  function entry(ctx,ref,purpose){const e=ctx.c.entries.find(e=>e.ref===ref);need(e&&e.reader_ids.includes(ctx.v.actor_id)&&e.purposes.includes(purpose),'NOT_AVAILABLE');return e;}
  function live(ctx,e){
    const k=ctx.v.project_id+'/'+e.record_id;
    need(!ctx.v.state.tombstones.memory.includes(k)&&e.retention_until>ctx.v.now,'NOT_AVAILABLE');
    const h=ctx.v.state.heads.memory[k];need(h&&h.version>=e.version,'NOT_AVAILABLE');return h;
  }
  function source(ctx,ref,{historical=false,depth=0,seen=new Set(),visits={n:0}}={}){
    need(depth<=8&&!seen.has(ref.source_id)&&++visits.n<=64,'PROVENANCE_REJECTED');
    const s=ctx.v.state.sources[ref.source_id];
    need(s&&digest(s)===ref.source_hash&&s.project_id===ctx.v.project_id&&s.status==='VERIFIED'&&s.reader_ids.includes(ctx.v.actor_id)&&s.expires_at>ctx.v.now,'PROVENANCE_REJECTED');
    const ns=s.kind==='MEMORY'?'memory':'artifacts',key=s.project_id+'/'+s.subject_id,h=ctx.v.state.heads[ns][key];
    need(h&&(h.version>s.version||h.version===s.version&&h.source_hash===ref.source_hash)&&!ctx.v.state.tombstones[ns].includes(key),'PROVENANCE_REJECTED');
    const p=ctx.v.state.actors[s.producer_id];need(p?.active&&p.memberships?.[ctx.v.project_id]?.includes('provenance.produce'),'PROVENANCE_REJECTED');
    if(!historical)sourceFor(ctx.v,{project_id:s.project_id,kind:s.kind,subject_id:s.subject_id,version:s.version,content_hash:s.content_hash,provenance:{source_id:ref.source_id,source_hash:ref.source_hash}});
    const next=new Set(seen);next.add(ref.source_id);
    for(const parent of s.parents){const a=source(ctx,parent,{historical,depth:depth+1,seen:next,visits});need(s.reader_ids.every(x=>a.reader_ids.includes(x))&&(!s.shareable||a.shareable),'PROVENANCE_REJECTED');}
    return s;
  }
  function validate(ctx,e,r,{historical=false}={}){
    need(recordRef(r)===e.ref&&r.project_id===ctx.v.project_id&&r.record_id===e.record_id&&r.version===e.version&&r.kind===e.kind&&r.provenance.source_hash===e.provenance_hash,'INTEGRITY_FAILURE');
    const h=live(ctx,e);need(historical||h.version===r.version&&h.source_hash===r.provenance.source_hash,'NOT_AVAILABLE');
    need(r.created_at<=ctx.v.now&&r.expires_at>ctx.v.now,'NOT_AVAILABLE');
    const s=source(ctx,r.provenance,{historical});
    need(s.kind==='MEMORY'&&s.subject_id===r.record_id&&s.version===r.version&&s.content_hash===hashBytes(Buffer.from(r.text))&&r.expires_at<=s.expires_at,'PROVENANCE_REJECTED');
    if(r.kind==='SUMMARY')need(r.sources.length>0&&r.sources.every(ref=>s.parents.some(p=>p.source_id===ref.source_id&&p.source_hash===ref.source_hash)),'SUMMARY_LINEAGE_REQUIRED');
    for(const ref of r.sources)source(ctx,ref,{historical});
    for(const a of r.artifacts){const s=source(ctx,a,{historical});need(s.kind==='ARTIFACT'&&s.subject_id===a.artifact_id&&s.version===a.version&&s.content_hash===a.content_hash,'PROVENANCE_REJECTED');}
    return r;
  }
  function preflight(ctx,e,historical=false){
    const h=live(ctx,e);need(historical||h.version===e.version&&h.source_hash===e.provenance_hash,'NOT_AVAILABLE');
    const s=source(ctx,{source_id:e.source_id,source_hash:e.provenance_hash},{historical});
    need(s.kind==='MEMORY'&&s.subject_id===e.record_id&&s.version===e.version,'PROVENANCE_REJECTED');
  }
  function readObject(e){
    const valid=[];
    for(const store of stores){try{
      const x=store.read(e.ref);
      need(x&&typeof x.then!=='function'&&x.kind==='file'&&x.reparse===false&&x.link_count===1&&x.canonical_key===e.ref&&Buffer.isBuffer(x.bytes)&&x.bytes.length<=65536&&hashBytes(x.bytes)===e.ref,'INTEGRITY_FAILURE');
      const r=validateRecord(JSON.parse(x.bytes.toString('utf8')));need(canonicalize(r)===x.bytes.toString('utf8'),'INTEGRITY_FAILURE');valid.push({r,id:store.storage_id});
    }catch{/* Try only the other exact pinned replica. Never scan directories. */}}
    need(valid.length>0,'INTEGRITY_FAILURE');
    return {record:valid[0].r,readback:{ref:e.ref,verified_stores:valid.map(x=>x.id),degraded:valid.length!==stores.length,physical_decision:'DENY'}};
  }
  const persist=(token,text)=>result(()=>{
    const ctx=begin(token,'memory.ingest'),r=validateRecord(input(text,recordKeys));need(r.project_id===ctx.v.project_id,'SCOPE_DENIED');
    const ref=recordRef(r),e=entry(ctx,ref,'PERSIST');validate(ctx,e,r);const bytes=Buffer.from(canonicalize(r));
    try{for(const s of stores)need(['CREATED','EXISTS'].includes(s.putIfAbsent(ref,bytes)),'WRITE_UNCERTAIN');}
    catch(err){if(err instanceof DataError)throw err;throw new DataError('WRITE_UNCERTAIN');}
    const out=readObject(e);need(!out.readback.degraded,'READBACK_FAILED');finish(ctx);
    return {status:'PERSISTED_CANDIDATE',project_id:ctx.v.project_id,spec_ref:ctx.v.project.spec.content_hash,...out.readback,bytes:bytes.length,authoritative_complete:false};
  });
  const read=(token,text)=>result(()=>{
    const x=input(text,['ref']),ctx=begin(token,'memory.read'),e=entry(ctx,x.ref,'CONTEXT');preflight(ctx,e);
    const out=readObject(e);validate(ctx,e,out.record);finish(ctx);return {...out,trust:'REFERENCE_DATA_ONLY',historical:false};
  });
  const history=(token,text)=>result(()=>{
    const x=input(text,['record_id','limit']);id(x.record_id,'mem');integer(x.limit,1,32);
    const ctx=begin(token,'memory.audit');need(ctx.v.actor.role==='OWNER','DENIED');
    const all=ctx.c.entries.filter(e=>e.record_id===x.record_id&&e.reader_ids.includes(ctx.v.actor_id)&&e.purposes.includes('HISTORY')).sort((a,b)=>a.version-b.version);
    need(all.length<=x.limit,'HISTORY_TOO_LARGE');const rows=[];let bytes=0;
    for(const e of all){preflight(ctx,e,true);const out=readObject(e);validate(ctx,e,out.record,{historical:true});bytes+=Buffer.byteLength(canonicalize(out));need(bytes<=49152,'HISTORY_TOO_LARGE');rows.push({...out,historical:true,trust:'HISTORICAL_REFERENCE_ONLY'});}
    finish(ctx);return {versions:rows,authoritative_spec:false};
  });
  const recover=(token,text)=>result(()=>{
    const x=input(text,['refs']);need(Array.isArray(x.refs)&&x.refs.length<=64&&new Set(x.refs).size===x.refs.length);
    const ctx=begin(token,'memory.read'),recovered=[];
    for(const ref of x.refs){const e=entry(ctx,ref,'CONTEXT');preflight(ctx,e);const out=readObject(e);validate(ctx,e,out.record);recovered.push({ref,record_id:e.record_id,version:e.version,...out.readback});}
    finish(ctx);return {status:'RECOVERED_REFERENCES_ONLY',project_id:ctx.v.project_id,spec_ref:ctx.v.project.spec.content_hash,recovered,resume:false,new_attempt:false,physical_decision:'DENY'};
  });
  // Host binds exact need-to-know IDs and purpose once. Workers receive pack only.
  function workerPort(token,{record_ids,purpose,max_bytes=8192}){
    need(Array.isArray(record_ids)&&record_ids.length>0&&record_ids.length<=32&&new Set(record_ids).size===record_ids.length);
    record_ids=copy(record_ids);record_ids.forEach(x=>id(x,'mem'));need(typeof purpose==='string'&&purpose.length<=64);integer(max_bytes,256,16384);
    return Object.freeze({pack:()=>result(()=>{
      const ctx=begin(token,'memory.read'),records=[];
      for(const record_id of record_ids){
        const h=ctx.v.state.heads.memory[ctx.v.project_id+'/'+record_id],e=ctx.c.entries.find(e=>e.record_id===record_id&&e.version===h?.version);need(e,'NOT_AVAILABLE');
        entry(ctx,e.ref,purpose);preflight(ctx,e);const out=readObject(e);validate(ctx,e,out.record);
        records.push({ref:e.ref,record_id,version:e.version,kind:e.kind,text:out.record.text,sources:out.record.sources,artifacts:out.record.artifacts,trust:'REFERENCE_DATA_ONLY'});
      }
      const pack={schema:'DATA02_CONTEXT_V1',project_id:ctx.v.project_id,spec_ref:ctx.v.project.spec.content_hash,records,full_transcript:false,physical_decision:'DENY'};
      need(Buffer.byteLength(canonicalize(pack))<=max_bytes,'CONTEXT_TOO_LARGE');finish(ctx);return pack;
    })});
  }
  const sweep=(token,text)=>result(()=>{
    input(text,[]);const ctx=begin(token,'memory.delete');need(ctx.v.actor.role==='OWNER','DENIED');let removed=0;
    const eligible=ctx.c.entries.filter(e=>e.reader_ids.includes(ctx.v.actor_id)&&(e.retention_until<=ctx.v.now||ctx.v.state.tombstones.memory.includes(ctx.v.project_id+'/'+e.record_id)));
    finish(ctx);for(const e of eligible){finish(ctx);for(const s of stores){need(typeof s.remove==='function','PURGE_UNAVAILABLE');if(s.remove(e.ref))removed++;}}
    return {removed_objects:removed,authority_changed:false};
  });
  // D05 is bound to a host-issued D07 session; worker JSON cannot switch scope.
  function contextPort(token,{purpose='BUILD'}={}){
    need(typeof purpose==='string'&&purpose.length>0&&purpose.length<=64);
    function check(req,ctx){need(req.project_id===ctx.v.project_id&&req.auth_epoch===ctx.v.project.epochs.auth,'SCOPE_DENIED');}
    function metadata(ctx,e){
      need(e.reader_ids.includes(ctx.v.actor_id)&&e.purposes.includes('CONTEXT')&&e.purposes.includes(purpose),'NOT_AVAILABLE');preflight(ctx,e);
      const out=readObject(e);validate(ctx,e,out.record);
      return {id:e.record_id,version:e.version,hash:digest(out.record.text),raw_content_hash:hashBytes(Buffer.from(out.record.text)),acl_epoch:ctx.v.project.epochs.auth,project_id:ctx.v.project_id,current:true,deleted:false,classification:e.kind==='SPEC'?'SPEC':e.kind==='RESULT'?'ARTIFACT':'WORKER_CHAT',priority:0};
    }
    return Object.freeze({
      list(req){const ctx=begin(token,'memory.read');check(req,ctx);need(req.role===ctx.v.actor.role&&req.purpose===purpose,'SCOPE_DENIED');const rows=[];for(const e of ctx.c.entries){const h=ctx.v.state.heads.memory[ctx.v.project_id+'/'+e.record_id];if(h?.version!==e.version||!e.reader_ids.includes(ctx.v.actor_id)||!e.purposes.includes('CONTEXT')||!e.purposes.includes(purpose))continue;try{rows.push(metadata(ctx,e));}catch(err){if(err instanceof DataError&&['NOT_AVAILABLE','PROVENANCE_REJECTED'].includes(err.code))continue;throw err;}}finish(ctx);return rows;},
      metadata(req){const ctx=begin(token,'memory.read');need(req.project_id===ctx.v.project_id,'SCOPE_DENIED');const h=ctx.v.state.heads.memory[ctx.v.project_id+'/'+req.id],e=ctx.c.entries.find(e=>e.record_id===req.id&&e.version===h?.version);need(e,'NOT_AVAILABLE');const m=metadata(ctx,e);finish(ctx);return m;},
      read(req){const ctx=begin(token,'memory.read');check(req,ctx);const e=ctx.c.entries.find(e=>e.record_id===req.id&&e.version===req.version);need(e,'NOT_AVAILABLE');const m=metadata(ctx,e),out=readObject(e);validate(ctx,e,out.record);finish(ctx);return {id:m.id,version:m.version,hash:m.hash,text:out.record.text};}
    });
  }
  return Object.freeze({project_id,persist,read,history,recover,workerPort,contextPort,sweep});
}
