import fs from 'node:fs';
import path from 'node:path';
import {createCase} from '../adapters/fixture.mjs';
const base=path.resolve(import.meta.dirname,'../sandbox');fs.mkdirSync(base,{recursive:true});
const directory=fs.mkdtempSync(path.join(base,'smoke-'));
const f=await createCase({directory,text:'Первый интегрированный офлайн-текст 🧪'});
try{console.log('START',JSON.stringify(await f.host.start()));console.log('FINISH',JSON.stringify(await f.host.finish()));console.log('PHASE',f.host.read().phase);if(f.host.bundle){const q=await f.host.verify();console.log('QA',JSON.stringify({qa:q.qa,decision:q.decision,evaluator_calls:q.evaluator_calls}));fs.writeFileSync(path.join(directory,'qa-debug.json'),JSON.stringify(q,null,2));}console.log('DIR',directory);}finally{await f.host.close();}
