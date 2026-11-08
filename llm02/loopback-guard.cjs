const net=require('node:net'),{syncBuiltinESMExports}=require('node:module');
const deny=()=>{throw Error('LLM02_EXTERNAL_EGRESS_DISABLED');};
const connect=net.Socket.prototype.connect,listen=net.Server.prototype.listen;
net.Socket.prototype.connect=function(...args){
 const first=Array.isArray(args[0])?args[0][0]:args[0];
 const host=typeof first==='object'?first.host:args[1];
 if(host!=='127.0.0.1'||typeof first==='object'&&first.path)deny();
 return connect.apply(this,args);
};
net.Server.prototype.listen=function(...args){const first=args[0],host=typeof first==='object'?first.host:args[1];if(host!=='127.0.0.1')deny();return listen.apply(this,args);};
for(const [module,names] of [['node:tls',['connect','createServer']],['node:https',['request','get','createServer']],['node:http2',['connect','createServer','createSecureServer']],['node:dgram',['createSocket']],['node:dns',['lookup','resolve']]])for(const n of names)require(module)[n]=deny;
require('node:dns').lookup=(host,options,callback)=>{if(host!=='127.0.0.1')deny();const cb=typeof options==='function'?options:callback;queueMicrotask(()=>options?.all?cb(null,[{address:host,family:4}]):cb(null,host,4));};
for(const n of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])require('node:child_process')[n]=deny;
globalThis.fetch=deny;globalThis.WebSocket=class{constructor(){deny();}};globalThis.EventSource=class{constructor(){deny();}};
syncBuiltinESMExports();
