// E0 test harness guard, not an OS security boundary. Chromium uses local pipes.
const {syncBuiltinESMExports}=require('node:module');
const deny=()=>{throw new Error('QA02_NETWORK_DISABLED');};
for(const [mod,names] of [['node:net',['connect','createConnection','createServer']],['node:tls',['connect']],['node:http',['request','get','createServer']],['node:https',['request','get','createServer']],['node:dgram',['createSocket']],['node:dns',['lookup','resolve']]])for(const name of names)require(mod)[name]=deny;
globalThis.fetch=deny;globalThis.WebSocket=class {constructor(){deny();}};syncBuiltinESMExports();
