const {syncBuiltinESMExports}=require('node:module');
const deny=()=>{throw Error('OWNER02_NETWORK_DISABLED');};
for(const [name,keys] of [['net',['connect','createConnection','createServer']],['tls',['connect','createServer']],['http',['request','get','createServer']],['https',['request','get','createServer']],['http2',['connect','createServer','createSecureServer']],['dns',['lookup','resolve']],['dgram',['createSocket']]])for(const key of keys)require('node:'+name)[key]=deny;
globalThis.fetch=deny;globalThis.WebSocket=class{constructor(){deny();}};globalThis.EventSource=class{constructor(){deny();}};syncBuiltinESMExports();
