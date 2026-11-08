import {canonicalize,digest} from '../../contracts/canonical.mjs';
import {createHash} from 'node:crypto';
import {createOfflineAuthority} from '../memory/boundary.mjs';
import {createProjectMemory} from '../../DATA-02/src/memory.mjs';
const hash=b=>'sha256:'+createHash('sha256').update(b).digest('hex');
const need=(ok,code)=>{if(!ok)throw Error(code);};
// Existing D03 owns every authoritative mutation. File stores hold bytes only.
// New/reopened adapters always HOLD; files never bootstrap ACL, heads or spec.
export function createData02CataloguePort({state,owner,reader,scope,stores,clock}){
 need(stores?.length===2&&stores[0].storage_id!==stores[1].storage_id,'CATALOGUE_REPLICAS_REQUIRED');
 let held=true;
 const view=()=>state.readCatalogue(reader,scope);
 const ready=()=>need(!held,'HOLD_FOR_OWNER_RECONCILIATION');
 const authority=createOfflineAuthority({readState:()=>{ready();return view().state;},clock,advancingClock:true});
 const memory=createProjectMemory({project_id:scope.project_id,authority,readCatalogue:v=>{ready();const x=view();need(v.project_id===scope.project_id&&v.state.authority_revision===x.catalogue.authority_revision,'CATALOGUE_AUTHORITY_STALE');return x.catalogue;},stores});
 return Object.freeze({
  status:()=>({status:held?'HOLD_FOR_OWNER_RECONCILIATION':'READY_E0',durable_writer:held?'NOT_BOUND':view().durable_binding,physical_decision:'DENY'}),
  reconcile(session,pin){need(session===owner,'OWNER_SESSION_REQUIRED');const x=state.readCatalogue(session,scope);need(digest(x.pin)===digest(pin),'CATALOGUE_AUTHORITY_STALE');held=false;return {status:'READY_E0',production_binding:false};},
  projection:()=>{ready();return view();},
  session:actor=>{ready();return authority.openSession(actor,scope.project_id);},
  memory,
  async persist(input){
   ready();const prepared=state.prepareCatalogue(owner,scope,input),bytes=Buffer.from(canonicalize(prepared.record));
   const check=()=>{ready();need(digest(view().pin)===digest(prepared.pin),'CATALOGUE_AUTHORITY_STALE');};
   try{
    check();for(const s of stores){check();need(['CREATED','EXISTS'].includes(s.putIfAbsent(prepared.entry.exact_ref,bytes)),'CATALOGUE_FILESYSTEM_UNCERTAIN');check();}
    for(const s of stores){check();const x=s.read(prepared.entry.exact_ref);need(x?.kind==='file'&&x.reparse===false&&x.link_count===1&&x.canonical_key===prepared.entry.exact_ref&&Buffer.isBuffer(x.bytes)&&hash(x.bytes)===prepared.entry.exact_ref,'CATALOGUE_READBACK_FAILED');check();}
    // Final CAS and current spec/cancel/restore barrier run inside D03's queue.
    const ack=await state.commitCatalogue(owner,scope,prepared);
    need(ack.status==='CATALOGUE_COMMITTED_E0'&&ack.exact_ref===prepared.entry.exact_ref&&ack.authority_revision===prepared.entry.authority_revision,'CATALOGUE_COMMIT_ACK_INVALID');
    return {ok:true,receipt:ack,record:prepared.record,ref:prepared.entry.exact_ref};
   }catch{held=true;return {ok:false,code:'HOLD_FOR_OWNER_RECONCILIATION',orphan_ref:prepared.entry.exact_ref,success:false};}
  }
 });
}
