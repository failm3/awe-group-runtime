'use strict';

// Test-only JavaScript API guard. This is not OS network isolation, an authority
// boundary, or permission to run a database/provider. Child-process APIs remain
// available for the fixed local C1 fixture; preload this guard in its process.
const {syncBuiltinESMExports} = require('node:module');
function denied() {
  const error = new Error('E1_QA_NETWORK_DISABLED');
  error.code = 'E1_QA_NETWORK_DISABLED';
  throw error;
}
for (const [name, methods] of [
  ['node:net', ['connect', 'createConnection', 'createServer']],
  ['node:tls', ['connect', 'createServer']],
  ['node:http', ['request', 'get', 'createServer']],
  ['node:https', ['request', 'get', 'createServer']],
  ['node:http2', ['connect', 'createServer', 'createSecureServer']],
  ['node:dgram', ['createSocket']],
]) {
  const api = require(name);
  for (const method of methods) api[method] = denied;
}
require('node:net').Socket.prototype.connect = denied;
require('node:net').Server.prototype.listen = denied;
require('node:dgram').Socket.prototype.bind = denied;
require('node:dgram').Socket.prototype.connect = denied;
require('node:dgram').Socket.prototype.send = denied;
const dns = require('node:dns');
for (const api of [dns, dns.promises]) {
  for (const key of Object.keys(api)) {
    if (typeof api[key] === 'function' && /^(?:lookup|resolve|reverse)/.test(key)) api[key] = denied;
  }
}
for (const Constructor of [dns.Resolver, dns.promises.Resolver]) {
  for (const key of Object.getOwnPropertyNames(Constructor.prototype)) {
    if (/^(?:lookup|resolve|reverse)/.test(key)) Constructor.prototype[key] = denied;
  }
}
globalThis.fetch = denied;
globalThis.WebSocket = class { constructor() { denied(); } };
globalThis.EventSource = class { constructor() { denied(); } };
syncBuiltinESMExports();
