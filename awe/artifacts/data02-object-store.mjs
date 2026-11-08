import {createFileStore} from '../../DATA-02/src/file-store.mjs';
// Narrow key adapter; each DATA02 store is already rooted in one project.
export function createD07FileStore(directory,storage_id,projectId){
 const store=createFileStore(directory,storage_id);
 const digest=key=>{const prefix=projectId+'/objects/';if(typeof key!=='string'||!key.startsWith(prefix)||!/^[a-f0-9]{64}$/.test(key.slice(prefix.length)))throw Error('D07_STORE_SCOPE');return 'sha256:'+key.slice(prefix.length);};
 return Object.freeze({storage_id,putIfAbsent:(key,bytes)=>store.putIfAbsent(digest(key),bytes),read:key=>({...store.read(digest(key)),canonical_key:key})});
}
