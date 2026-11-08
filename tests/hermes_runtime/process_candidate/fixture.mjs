import {fixture} from '../fixtures.mjs';
import {createInt04ProcessAdapter,INT04_PROCESS_CONTRACT} from '../../../awe/hermes_runtime/int04-process-adapter.mjs';
export async function processFixture(t,options={}){
 const f=await fixture(t),{transport,artifacts,...rest}=f.args;const ports={...rest,timeoutMs:1000};
 let adapter=createInt04ProcessAdapter(ports,{contract:INT04_PROCESS_CONTRACT,...options});t.after(()=>adapter.close());
 return {...f,ports,get adapter(){return adapter;},launch:(q=f.request())=>adapter.runtime.launchChild(JSON.stringify(q)),
  async restart(checkpoint){await adapter.close();f.restart();ports.journal=f.journal;adapter=createInt04ProcessAdapter(ports,{contract:INT04_PROCESS_CONTRACT,...options,...(checkpoint?{startupCheckpoint:checkpoint}:{})});return adapter;}};
}
