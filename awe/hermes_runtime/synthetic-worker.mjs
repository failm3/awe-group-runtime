import {createInterface} from 'node:readline';
import {createSyntheticTransport} from './synthetic.mjs';
import {parseIntent,exact,need} from './protocol.mjs';
const transport=createSyntheticTransport({autoWork:true}).api;
for await(const line of createInterface({input:process.stdin})) {
 let id=null;
 try {
  const request=parseIntent(line);exact(request,['id','method','args']);id=request.id;
  need(Number.isSafeInteger(id)&&id>0&&['launchChild','streamEvents','cancel','reconcile'].includes(request.method)&&Array.isArray(request.args),'RPC_DENIED');
  const value=await transport[request.method](...request.args);
  process.stdout.write(JSON.stringify({id,ok:true,value})+'\n');
 }catch(e){process.stdout.write(JSON.stringify({id,ok:false,code:e.message})+'\n');}
}
