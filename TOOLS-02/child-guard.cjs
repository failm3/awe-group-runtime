// Defense in depth for the fixed reviewed JS template; not a hostile-code sandbox.
const {syncBuiltinESMExports}=require('node:module');
const deny=()=>{throw Error('TOOLS_NETWORK_DISABLED');};
for(const [name,methods] of [['net',['connect','createConnection','createServer']],['tls',['connect','createServer']],['http',['request','get','createServer']],['https',['request','get','createServer']],['http2',['connect','createServer','createSecureServer']],['dns',['lookup','resolve']],['dgram',['createSocket']]]){
 const api=require('node:'+name);for(const key of methods)api[key]=deny;
}
for(const key of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])require('node:child_process')[key]=deny;
globalThis.fetch=deny;globalThis.WebSocket=class{constructor(){deny();}};globalThis.EventSource=class{constructor(){deny();}};
syncBuiltinESMExports();
