import {registerHooks} from 'node:module';
// Read-only test instrumentation: count real evaluateExact entries without
// changing any reviewed source bytes. Used by the pre-fix reproduction only.
globalThis.__aud01EvaluatorCalls=0;
registerHooks({load(url,context,nextLoad){
 const loaded=nextLoad(url,context);
 if(url.endsWith('/awe/qa/evaluator.mjs'))return {...loaded,source:String(loaded.source).replace(
  'export function evaluateExact({bytes, reference, requirements:r, evidence:e, operations, pin}) {',
  'export function evaluateExact({bytes, reference, requirements:r, evidence:e, operations, pin}) { globalThis.__aud01EvaluatorCalls++;')};
 return loaded;
}});
