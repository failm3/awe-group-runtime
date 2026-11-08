import {writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {root, manifestPath, inventory, checkPackage, BASE} from './package.mjs';
checkPackage({frozen: false});
writeFileSync(join(root, manifestPath), JSON.stringify({release_id: 'awe-int01-e0-1', base_sha: BASE,
  status: 'PROPOSED_FOR_OWNER_REVIEW', scope: 'OFFLINE_CANARY_ONLY',
  excludes: ['.git', manifestPath, 'tests/integration/evidence/**'],
  evidence_integrity: 'Each new run has its own EVIDENCE.sha256. Historical evidence remains unchanged.',
  entries: inventory()}, null, 2) + '\n');
console.log(JSON.stringify(checkPackage()));
