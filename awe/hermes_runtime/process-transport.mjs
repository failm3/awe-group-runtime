import {createProcessSupervisor} from './process-supervisor.mjs';
// Backward-compatible rt01/1 facade: one fixed Node process per logical run.
export function createSyntheticProcessTransport() {
 const supervisor=createProcessSupervisor();
 return Object.freeze({...supervisor.api,close:()=>supervisor.close()});
}
