import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {verifyCandidate} from './scripts/verify-candidate.mjs';
import {createController} from './controller.mjs';
const root=path.resolve(import.meta.dirname,'..'),uiRoot=path.join(root,'INTEGRATION-01/ui');
export async function createOfflineServer({dataDir,controllerOptions={}}={}){
 const controller=await createController({dataDir,...controllerOptions}),token=randomBytes(24).toString('hex');
 const headers={'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cache-Control':'no-store'};
 const allowed=new Set(['index.html','styles.css','src/app.mjs','src/domain.mjs','src/adapter/http-adapter.mjs']);
 const server=http.createServer(async(req,res)=>{
  const send=(status,value)=>{res.writeHead(status,{...headers,'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(value));};
  try{
   const port=server.address().port,hosts=['127.0.0.1:'+port,'localhost:'+port];
   if(!hosts.includes(req.headers.host))return send(403,{code:'HOST_DENIED'});
   const url=new URL(req.url,'http://127.0.0.1:'+port);
   if(url.pathname==='/api/session'&&req.method==='GET')return send(200,{version:'integration01.http/1',csrfToken:token,identity:'E0_LOCAL_TEST_OWNER',productionAuth:'NOT_RUN',physicalDecision:'DENY'});
   if(url.pathname==='/api/snapshot'&&req.method==='GET')return send(200,controller.getSnapshot());
   if(url.pathname==='/api/commands/by-key'&&req.method==='GET'){
    const key=url.searchParams.get('key')??'';if(!/^[A-Za-z0-9_-]{8,128}$/.test(key))return send(400,{code:'INVALID_KEY'});
    const receipt=controller.lookup(key);return send(receipt?200:404,receipt??{code:'COMMAND_NOT_FOUND'});
   }
   if(url.pathname==='/api/commands'&&req.method==='POST'){
    if(req.headers['x-integration-csrf']!==token)return send(403,{code:'CSRF_DENIED'});
    const origin=req.headers.origin;if(origin&&!hosts.some(h=>'http://'+h===origin))return send(403,{code:'ORIGIN_DENIED'});
    let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>16384)return send(413,{code:'COMMAND_TOO_LARGE'});}
    let command;try{command=JSON.parse(raw);}catch{return send(400,{code:'INVALID_JSON'});}
    const receipt=await controller.command(command);
    // Fixed E0 test hook: commit the SAME command, drop only its transport ACK.
    if(req.headers['x-integration-test-drop-ack']==='once'){res.destroy();return;}
    return send(202,receipt);
   }
   if(url.pathname.startsWith('/api/'))return send(404,{code:'ENDPOINT_NOT_IMPLEMENTED'});
   if(!['GET','HEAD'].includes(req.method)){res.writeHead(405,{...headers,Allow:'GET, HEAD'});res.end();return;}
   const decoded=decodeURIComponent(req.url.split('?')[0]),relative=decoded==='/'?'index.html':decoded.slice(1);
   if(!allowed.has(relative))return send(404,{code:'NOT_FOUND'});
   const file=path.join(uiRoot,relative),body=fs.readFileSync(file),type=relative.endsWith('.mjs')?'text/javascript':relative.endsWith('.css')?'text/css':'text/html';
   res.writeHead(200,{...headers,'Content-Type':type+'; charset=utf-8'});res.end(req.method==='HEAD'?undefined:body);
  }catch(e){if(!res.destroyed)send(e.status??500,{code:e.code??'OFFLINE_CONTOUR_ERROR',message:e.status?e.message:'Офлайн-контур отказал. Смотрите локальное evidence; новый attempt не создан.'});}
 });
 let stopping=false;
 return {server,controller,async close(){if(stopping)return;stopping=true;server.closeAllConnections();if(server.listening)await new Promise(r=>server.close(r));await controller.close();}};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 verifyCandidate();
 if(process.version!=='v24.21.0')throw Error('NODE_24_21_0_REQUIRED_BY_RT01');
 const profile=process.env.AWE_INT01_PROFILE??'local';if(!/^[a-zA-Z0-9_-]{1,60}$/.test(profile))throw Error('PROFILE_ID_INVALID');
 const port=Number(process.env.AWE_INT01_PORT??4910);if(!Number.isInteger(port)||port<1024||port>65535)throw Error('PORT_INVALID');
 const app=await createOfflineServer({dataDir:path.join(root,'INTEGRATION-01/sandbox',profile)});
 app.server.on('error',async e=>{console.error(e.message);await app.close();process.exitCode=1;});
 app.server.listen(port,'127.0.0.1',()=>console.log(`AWE GROUP INTEGRATION-01 · E0 OFFLINE · http://127.0.0.1:${port} · profile=${profile} · Physical DENY`));
 for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>void app.close().then(()=>process.exit(0)));
}
