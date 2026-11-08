import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
const root=path.resolve(import.meta.dirname,'../..');
export function verifyCandidate(){const m=JSON.parse(fs.readFileSync(path.join(root,'INTEGRATION-01/CANDIDATE-SOURCES.json')));if(process.version!==m.node||m.physicalDecision!=='DENY')throw Error('CANDIDATE_ENVIRONMENT_MISMATCH');for(const f of m.files){const p=path.resolve(root,f.path);if(!p.startsWith(root+path.sep)||fs.lstatSync(p).isSymbolicLink()||createHash('sha256').update(fs.readFileSync(p)).digest('hex')!==f.sha256)throw Error('CANDIDATE_SOURCE_DRIFT '+f.path);}return {status:'PASS',files:m.files.length,node:process.version,physicalDecision:'DENY'};}
if(process.argv[1]&&path.resolve(process.argv[1])===path.join(root,'INTEGRATION-01/scripts/verify-candidate.mjs'))console.log(JSON.stringify(verifyCandidate(),null,2));
