import fs from 'node:fs';
import path from 'node:path';
import {createOfflineAuthority,projectStamp} from '../../awe/memory/boundary.mjs';
import {createProjectMemory,recordRef} from '../src/memory.mjs';
import {createFileStore} from '../src/file-store.mjs';
import {copy,digest,hashBytes} from '../src/common.mjs';
export const sandbox=path.resolve(import.meta.dirname,'../sandbox');
export const json=JSON.stringify;
export function fixture({directory=fs.mkdtempSync(path.join(sandbox,'test-')),saved=null,storeOptions={}}={}){
  fs.mkdirSync(directory,{recursive:true});let available=true,catalogueAvailable=true;
  let now=saved?.now??'2026-11-06T00:00:00.000Z';
  const p=suffix=>({status:'READY',revision:1,restore_pending:false,cancel_requested:false,
    epochs:{auth:1,policy:1,owner:1,stop:0},spec:{spec_id:'spec_'+suffix,revision:1,content_hash:digest({spec:suffix})}});
  const owner=['memory.ingest','memory.read','memory.audit','memory.delete','provenance.produce'];
  const world=saved?.world??{schema_version:'1.0.0',authority_revision:1,projects:{prj_alpha:p('alpha'),prj_beta:p('beta')},
    actors:{act_owner:{active:true,role:'OWNER',memberships:{prj_alpha:owner,prj_beta:owner}},
      act_child:{active:true,role:'EXECUTOR',memberships:{prj_alpha:['memory.read']}},
      act_beta:{active:true,role:'CONTEXT_BUILDER',memberships:{prj_beta:['memory.read']}}},
    sources:{},heads:{memory:{},artifacts:{}},tombstones:{memory:[],artifacts:[]},promotions:{},qa_attestations:{}};
  const catalogues=saved?.catalogues??{prj_alpha:[],prj_beta:[]};
  let sequence=saved?.sequence??0;
  const bump=fn=>{fn?.(world);world.authority_revision++;};
  const authority=createOfflineAuthority({readState:()=>{if(!available)throw Error('LOST_AUTHORITY_SECRET');return world;},clock:()=>now});
  const storesFor=project=>['primary','replica'].map(name=>createFileStore(path.join(directory,project,name),project+'_'+name,storeOptions[name]));
  let readHook=null,readCount=0;
  const readCatalogue=v=>{if(!catalogueAvailable)throw Error('LOST_CATALOGUE_SECRET');readCount++;if(readHook)readHook(v,readCount);return {project_id:v.project_id,authority_revision:world.authority_revision,entries:catalogues[v.project_id]};};
  const stores=storesFor('prj_alpha'),betaStores=storesFor('prj_beta');
  const memory=createProjectMemory({project_id:'prj_alpha',authority,readCatalogue,stores});
  const beta=createProjectMemory({project_id:'prj_beta',authority,readCatalogue,stores:betaStores});
  const session=(actor='act_owner',project='prj_alpha')=>authority.openSession(actor,project);
  function source({project='prj_alpha',record_id,version=1,text='Source',kind='MEMORY',readers=['act_owner','act_child'],parents=[],expires_at='2027-02-01T00:00:00.000Z'}){
    const s={source_id:'src_data_'+(++sequence),project_id:project,subject_id:record_id,version,kind,
      content_hash:hashBytes(Buffer.from(text)),project_stamp:projectStamp(project,world.projects[project]),producer_id:'act_owner',
      status:'VERIFIED',expires_at,reader_ids:readers,shareable:false,parents};
    bump(w=>{w.sources[s.source_id]=s;w.heads[kind==='MEMORY'?'memory':'artifacts'][project+'/'+record_id]={version,source_hash:digest(s)};});
    return {source_id:s.source_id,source_hash:digest(s)};
  }
  function register({record_id='mem_goal',version=1,text='Сохранить цель. НЕ публиковать.',kind='GOAL',project='prj_alpha',readers=['act_owner','act_child'],purposes=['PERSIST','HISTORY','CONTEXT','BUILD'],sources=[],artifacts=[],expires_at='2027-01-01T00:00:00.000Z',parents=[]}={}){
    const provenance=source({project,record_id,version,text,readers,parents});
    const record={schema:'DATA02_RECORD_V1',project_id:project,record_id,version,kind,text,created_at:now,expires_at,provenance,sources,artifacts};
    const ref=recordRef(record);
    bump(()=>catalogues[project].push({ref,record_id,version,kind,source_id:provenance.source_id,provenance_hash:provenance.source_hash,reader_ids:readers,purposes,retention_until:expires_at}));
    return {record,ref};
  }
  return {directory,world,catalogues,authority,stores,betaStores,memory,beta,session,source,register,bump,
    file:(ref,replica=false,project='prj_alpha')=>path.join(directory,project,replica?'replica':'primary',ref.slice(7)+'.json'),
    persist:r=>(r.record.project_id==='prj_alpha'?memory:beta).persist(session('act_owner',r.record.project_id),json(r.record)),
    read:r=>memory.read(session(),json({ref:r.ref})),
    lostAuthority:()=>{available=false;},lostCatalogue:()=>{catalogueAvailable=false;},
    time:x=>{now=x;},onCatalogue:fn=>{readHook=fn;},
    save:()=>copy({world,catalogues,sequence,now})};
}
