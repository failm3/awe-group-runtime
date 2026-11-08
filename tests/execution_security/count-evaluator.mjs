import {registerHooks} from 'node:module';
// Preload with --import BEFORE test module loading. Read-only instrumentation
// counts actual fixed D08 entries; neither evaluator source nor result changes.
globalThis.__sec01EvaluatorCalls=0;
registerHooks({load(url,context,nextLoad){
 const loaded=nextLoad(url,context);
 if(url.endsWith('/awe/qa/evaluator.mjs')){
  const needle='export function evaluateExact({bytes, reference, requirements:r, evidence:e, operations, pin}) {';
  if(!String(loaded.source).includes(needle))throw Error('D08_INSTRUMENTATION_SOURCE_CHANGED');
  return {...loaded,source:String(loaded.source).replace(needle,needle+' globalThis.__sec01EvaluatorCalls++;')};
 }return loaded;
}});
