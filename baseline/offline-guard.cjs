const {syncBuiltinESMExports}=require('node:module');
const deny=()=>{throw new Error('D01_NETWORK_DISABLED');};
for(const [module,names] of [['node:net',['connect','createConnection','createServer']],['node:tls',['connect','createServer']],['node:http',['request','get','createServer']],['node:https',['request','get','createServer']],['node:http2',['connect','createServer','createSecureServer']],['node:dgram',['createSocket']],['node:dns',['lookup','resolve']]]) {
 const api=require(module);for(const name of names) api[name]=deny;
}
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork']) require('node:child_process')[name]=()=>{throw new Error('D01_CHILD_PROCESS_DISABLED');};
globalThis.fetch=deny;
globalThis.WebSocket=class {constructor(){deny();}};
globalThis.EventSource=class {constructor(){deny();}};
syncBuiltinESMExports();
