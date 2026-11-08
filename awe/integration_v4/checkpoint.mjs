import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {MemoryStorage} from '../state/memory-storage.mjs';
import {MemoryLedger} from '../budget/memory-ledger.mjs';
// E0 test checkpoint, not an authoritative DB/backup/anti-rollback mechanism.
// Startup never substitutes a new state/ledger after missing or damaged data.
export function writeCheckpoint(directory,data){
 const file=path.join(directory,'checkpoint.json'),tmp=file+'.tmp';
 const bytes=JSON.stringify({format:'INT04_E0_CHECKPOINT_V1',digest:checkpointHash(data),data})+'\n';
 const fd=fs.openSync(tmp,'wx',0o600);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 fs.renameSync(tmp,file);
}
export function restoreCheckpoint(directory){
 const p=JSON.parse(fs.readFileSync(path.join(directory,'checkpoint.json'),'utf8'));
 if(p.format!=='INT04_E0_CHECKPOINT_V1'||checkpointHash(p.data)!==p.digest)throw Error('INT04_CHECKPOINT_CORRUPT');
 const storage=new MemoryStorage({snapshot:p.data.d03});
 const ledger=new MemoryLedger({checkpoint:p.data.d06,authority:p.data.d06.state.authority,now:p.data.d06.state.now});
 return {storage,ledger,checkpoint:p.data,physical_decision:'DENY',accepted:false,resumable:false,recovery:'RECONCILE_REQUIRED'};
}
const checkpointHash=data=>createHash('sha256').update(JSON.stringify(data)).digest('hex');
