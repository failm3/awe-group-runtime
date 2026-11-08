// Real PG tools need child_process; JS network/provider egress stays disabled.
const {syncBuiltinESMExports}=require('node:module');
const deny=()=>{throw Error('INT03_NETWORK_DISABLED');};
for(const [name,methods] of [['node:net',['connect','createConnection','createServer']],['node:tls',['connect']],
 ['node:http',['request','get','createServer']],['node:https',['request','get','createServer']],
 ['node:http2',['connect','createServer']],['node:dgram',['createSocket']],['node:dns',['lookup','resolve']]]) {
 const api=require(name);for(const key of methods)api[key]=deny;
}
globalThis.fetch=deny;globalThis.WebSocket=class{constructor(){deny();}};syncBuiltinESMExports();
