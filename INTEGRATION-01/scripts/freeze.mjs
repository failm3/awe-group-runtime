import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
const root=path.resolve(import.meta.dirname,'../..'),base=path.join(root,'INTEGRATION-01');
function files(p){const s=fs.lstatSync(p);if(s.isSymbolicLink())throw Error('SOURCE_LINK_DENIED');if(!s.isDirectory())return [p];return fs.readdirSync(p).flatMap(n=>files(path.join(p,n)));}
const paths=['awe','contracts','baseline/offline-guard.cjs','tests/integration_v4/qa-worker.mjs','tests/state/harness.mjs','tests/memory_artifacts/fixtures.mjs','tests/execution_security/fixtures.mjs','tests/budget/fixtures.mjs','INTEGRATION-01/adapters','INTEGRATION-01/ui','INTEGRATION-01/controller.mjs','INTEGRATION-01/server.mjs'];
const rows=[...new Set(paths.flatMap(p=>files(path.join(root,p))))].sort().map(p=>({path:path.relative(root,p).replaceAll('\\','/'),bytes:fs.statSync(p).size,sha256:createHash('sha256').update(fs.readFileSync(p)).digest('hex')}));
fs.writeFileSync(path.join(base,'CANDIDATE-SOURCES.json'),JSON.stringify({version:'INTEGRATION01_CANDIDATE_SOURCES_V1',node:'v24.21.0',physicalDecision:'DENY',files:rows},null,2)+'\n');
for(const p of files(path.join(base,'snapshots')))fs.chmodSync(p,0o444);
console.log(JSON.stringify({status:'FROZEN',files:rows.length,snapshots:'READ_ONLY_ATTRIBUTE',securityClaim:'local exact-byte inventory, not authenticated anti-rollback'},null,2));
