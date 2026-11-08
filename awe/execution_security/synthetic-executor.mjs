import {readFileSync} from 'node:fs';
import {canonicalize,hashBytes,need} from './common.mjs';
export const FIXED_CODE_DIGEST=hashBytes(readFileSync(new URL('./synthetic-executor.mjs',import.meta.url)));
// No callbacks, shell, filesystem writes, imports from requests or network transport.
export function simulateDigest(manifest,payload){
 need(manifest.implementation==='FIXED_SYNTHETIC_DIGEST'&&manifest.code_digest===FIXED_CODE_DIGEST,'RUNTIME_PIN_DENIED');
 const result={mode:'E0_SYNTHETIC_ONLY',physical_decision:'DENY',input_hash:hashBytes(Buffer.from(canonicalize(payload))),text_bytes:Buffer.byteLength(payload.text)};
 need(Buffer.byteLength(canonicalize(result))<=manifest.max_output_bytes,'OUTPUT_LIMIT');return result;
}
