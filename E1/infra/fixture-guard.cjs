'use strict';
// Defense in depth for the fixed local fixture. JavaScript API interception is
// not an OS sandbox; no claim about untrusted code isolation follows from this.
const {syncBuiltinESMExports} = require('node:module');
function deny() { const error = new Error('C1_FIXTURE_NETWORK_DISABLED'); error.code = error.message; throw error; }
for (const [name, methods] of [
  ['node:net', ['connect', 'createConnection', 'createServer']],
  ['node:tls', ['connect', 'createServer']],
  ['node:http', ['request', 'get', 'createServer']],
  ['node:https', ['request', 'get', 'createServer']],
  ['node:http2', ['connect', 'createServer', 'createSecureServer']],
  ['node:dgram', ['createSocket']]
]) for (const method of methods) require(name)[method] = deny;
require('node:net').Socket.prototype.connect = deny;
require('node:net').Server.prototype.listen = deny;
for (const method of ['bind', 'connect', 'send']) require('node:dgram').Socket.prototype[method] = deny;
const dns = require('node:dns');
for (const api of [dns, dns.promises]) for (const method of Object.keys(api)) if (/^(?:lookup|resolve|reverse)/.test(method) && typeof api[method] === 'function') api[method] = deny;
for (const Constructor of [dns.Resolver, dns.promises.Resolver]) for (const method of Object.getOwnPropertyNames(Constructor.prototype)) if (/^(?:lookup|resolve|reverse)/.test(method)) Constructor.prototype[method] = deny;
for (const method of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) require('node:child_process')[method] = deny;
globalThis.fetch = deny;
globalThis.WebSocket = class { constructor() { deny(); } };
globalThis.EventSource = class { constructor() { deny(); } };
syncBuiltinESMExports();
