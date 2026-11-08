// Fixed E0 evaluator in a separate guarded Node process. No caller verdict,
// code loading, callback, path, process launch or network transport.
import fs from 'node:fs';
import {evaluateExact} from '../../awe/qa/evaluator.mjs';
import {evaluationPins} from '../../awe/execution_security/evaluation.mjs';
import {digest} from '../../contracts/canonical.mjs';
const raw=fs.readFileSync(0,'utf8');if(Buffer.byteLength(raw)>65536)throw Error('QA_INPUT_TOO_LARGE');
const {bundle:b,source_pins:p}=JSON.parse(raw);
if(digest(p)!==digest(evaluationPins()))throw Error('QA_SOURCE_PIN_MISMATCH');
const result=evaluateExact({bytes:Buffer.from(b.bytes_base64,'base64'),reference:b.reference,requirements:b.requirements,evidence:b.evidence,operations:b.operations,pin:b.pin});
process.stdout.write(JSON.stringify({source_pins:evaluationPins(),result,physical_decision:'DENY',mode:'FIXED_OFFLINE_D08_PROCESS'})+'\n');
