import {createInt04OfflineHost} from './adapters/int04-host.mjs';
const exact=(x,keys)=>{if(!x||Object.keys(x).sort().join()!==keys.sort().join())throw Error('MASTER_UI_COMMAND_SHAPE');};
// Thin UI inbox for the SAME coordinator profile. Authentication is host-owned;
// no actor, role, credential or verdict can be set in a command payload.
export async function createMasterController({host,sessionId,authenticateOwner}={}){
 const coordinator=await createInt04OfflineHost({profile:'MASTER01',host,sessionId});
 return Object.freeze({
  getSnapshot:()=>coordinator.snapshot?.()??{profile:'MASTER01',phase:'BLOCKED',code:'OWNER_POSTGRESQL_ADMISSION_REQUIRED',accepted:false,authoritative_complete:false,physical_decision:'DENY'},
  async command(command,ingress){
   exact(command,['type','payload']);
   if(command.type==='CREATE_LITERAL_TASK'){exact(command.payload,['goal','filename','text']);return coordinator.prepare(command.payload);}
   if(command.type==='EXECUTE_LITERAL_TASK'){exact(command.payload,[]);if(!coordinator.execute)throw Error('OWNER_POSTGRESQL_ADMISSION_REQUIRED');return coordinator.execute();}
   if(command.type==='VERIFY_LITERAL_TASK'){exact(command.payload,[]);if(!coordinator.verify)throw Error('OWNER_POSTGRESQL_ADMISSION_REQUIRED');return coordinator.verify();}
   if(command.type==='ACCEPT_LITERAL_ARTIFACT'){exact(command.payload,['proof_hash']);if(!authenticateOwner||!coordinator.accept)throw Error('MASTER_OWNER_AUTHENTICATION_REQUIRED');const owner=await authenticateOwner(ingress);return coordinator.accept(owner.identity,owner.peer,command.payload.proof_hash);}
   throw Error('MASTER_UI_COMMAND_DENIED');
  }
 });
}
