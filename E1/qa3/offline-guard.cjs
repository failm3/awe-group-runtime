'use strict';
// Independent QA boundary: this process may use mock transports only. Any
// accidentally introduced provider/WSL/cluster call fails before dispatch.
const {syncBuiltinESMExports} = require('node:module');
const denied = () => { throw Object.assign(new Error('QA3_OFFLINE_EFFECT_DENIED'), {code:'QA3_OFFLINE_EFFECT_DENIED'}); };
Object.defineProperty(globalThis,'__QA3_OFFLINE_GUARD_ACTIVE__',{value:true,writable:false,configurable:false});
globalThis.fetch = denied;
for (const [name, methods] of Object.entries({
  'node:http':['request','get'], 'node:https':['request','get'],
  'node:net':['connect','createConnection','createServer'],
  'node:tls':['connect','createServer'], 'node:dgram':['createSocket'],
  'node:child_process':['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork']
})) { const mod=require(name); for (const method of methods) mod[method]=denied; }
syncBuiltinESMExports();
