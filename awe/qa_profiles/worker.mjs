import {parentPort,workerData,threadId} from 'node:worker_threads';
import vm from 'node:vm';
import {pathToFileURL} from 'node:url';
import {bytesHash,digest,verdict} from './contracts.mjs';

// Fixed entry point. Input contains exact artifact + approved criteria, never Local QA,
// caller opinions, authority handles, storage, productive paths, or evaluator callbacks.
const {profile,bytes_base64,sources,role,runtime,now,mode}=workerData;
const original=Buffer.from(bytes_base64,'base64');
let browser;
async function evaluate(bytes,criteria){
 let text;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{return criteria.map(c=>row(c,'FAIL','UTF8_INVALID',null));}
 let page,context;
 try{
  if(profile.profile==='web'){
   if(!runtime.playwright_module||!runtime.chromium_executable)throw new Error('BROWSER_UNAVAILABLE');
   const {chromium}=await import(pathToFileURL(runtime.playwright_module).href);
   const browserEnv={CHROME_LOG_FILE:process.platform==='win32'?'NUL':'/dev/null'};
   for(const key of ['SystemRoot','WINDIR','TEMP','TMP','PATH'])if(process.env[key])browserEnv[key]=process.env[key];
   browser??=await chromium.launch({executablePath:runtime.chromium_executable,headless:true,env:browserEnv,args:['--disable-background-networking','--disable-component-update','--disable-sync','--disable-logging','--no-first-run','--host-resolver-rules=MAP * ~NOTFOUND']});
   context=await browser.newContext({offline:true,serviceWorkers:'block',acceptDownloads:false});
   await context.route('**/*',route=>route.abort());
   page=await context.newPage();await page.setContent(text,{waitUntil:'domcontentloaded',timeout:3000});
  }
  const rows=[];
  for(const c of criteria){
   const k=c.check;let actual,status='PASS',code='ASSERTION_PASSED';
   try{
    if(k.kind==='web-text'){actual=await page.locator(k.selector).innerText({timeout:1000});status=actual===k.expected?'PASS':'FAIL';}
    if(k.kind==='web-action'){
     await page.locator(k.input).fill(k.value,{timeout:1000});await page.locator(k.click).click({timeout:1000});
     actual=await page.locator(k.result).innerText({timeout:1000});status=actual===k.expected?'PASS':'FAIL';
    }
    if(k.kind==='web-responsive'){
     actual=[];for(const width of k.widths){await page.setViewportSize({width,height:800});actual.push({width,overflow:await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth)});}
     status=actual.some(a=>a.overflow)?'FAIL':'PASS';
    }
    if(k.kind==='code-case'){
     // Only host-approved synthetic pure JS hashes reach this harness. vm is NOT a security sandbox.
     const sandbox=vm.createContext({},{codeGeneration:{strings:false,wasm:false}});
     const script=new vm.Script('"use strict";const module={exports:{}};const exports=module.exports;\n'+text+'\n;JSON.stringify(module.exports['+JSON.stringify(k.export_name)+'](...'+JSON.stringify(k.args)+'))');
     const json=script.runInContext(sandbox,{timeout:100});actual=json===undefined?null:JSON.parse(json);status=digest(actual)===digest(k.expected)?'PASS':'FAIL';
    }
    if(k.kind==='claim'){
     const report=JSON.parse(text),claims=report.claims;
     const claim=Array.isArray(claims)?claims.find(x=>x.id===k.claim_id):null;
     const source=sources.find(s=>s.id===k.source_id);
     if(!source){status='UNCLEAR';code='SOURCE_MISSING';actual=null;}
     else{
      const data=Buffer.from(source.bytes_base64,'base64'),sourceText=new TextDecoder('utf-8',{fatal:true}).decode(data);
      const age=Date.parse(now)-Date.parse(source.fetched_at);
      actual={source_id:source.id,source_hash:bytesHash(data),age_ms:Number.isFinite(age)?age:null};
      if(bytesHash(data)!==source.sha256||source.project_id!==profile.scope.project_id){status='FAIL';code='SOURCE_PROVENANCE';}
      else if(!Number.isFinite(age)||age<0||age>k.max_age_ms||source.primary!==true){status='UNCLEAR';code='SOURCE_STALE_OR_SECONDARY';}
      else if(!claim||claims.filter(x=>x.id===k.claim_id).length!==1||claim.text!==k.expected_claim||claim.source_id!==source.id||claim.quote!==k.quote||!sourceText.includes(k.quote)||!k.quote.includes(k.expected_claim)){status='FAIL';code='CLAIM_UNSUPPORTED';}
     }
    }
    if(k.kind==='contains'){actual=text.includes(k.text);status=actual?'PASS':'FAIL';}
    if(k.kind==='exact-text'){actual=text;status=text===k.text?'PASS':'FAIL';}
    if(k.kind==='bytes-sha256'){actual=bytesHash(bytes);status=actual===k.expected?'PASS':'FAIL';}
    if(k.kind==='markdown-sections'){actual=k.headings.map(h=>({heading:h,present:text.split(/\r?\n/).some(line=>line.trim()===h)}));status=actual.every(x=>x.present)?'PASS':'FAIL';}
    if(k.kind==='json-field'){let value=JSON.parse(text);for(const key of k.path)value=value?.[key];actual=value??null;status=digest(actual)===digest(k.expected)?'PASS':'FAIL';}
    if(k.kind==='no-placeholder'){actual=/\b(TODO|FIXME|TBD|lorem ipsum)\b/i.test(text);status=actual?'FAIL':'PASS';}
   }catch(error){actual={error:error.name};status='FAIL';code='ASSERTION_ERROR';}
   if(status==='FAIL'&&code==='ASSERTION_PASSED')code='ASSERTION_FAILED';
   rows.push(row(c,status,code,actual));
  }
  return rows;
 }catch(error){return criteria.map(c=>row(c,'BLOCKED',error.message==='BROWSER_UNAVAILABLE'?'BROWSER_UNAVAILABLE':'RUNNER_UNAVAILABLE',null));}
 finally{await context?.close().catch(()=>{});}
}
function row(c,status,code,actual){return {criterion_id:c.id,requirement_id:c.requirement_id,status,code,expected:c.check,actual,artifact_sha256:bytesHash(original)};}
let payload;
try{
 const criteria=role==='local'?profile.criteria.filter(c=>profile.local_ids.includes(c.id)):profile.criteria;
 const rows=await evaluate(original,criteria),mutations=[];
 if(mode==='audit'){
  // Mutants exist only in test memory. Never write original artifacts or approved requirements.
   const candidates=profile.criteria.some(c=>c.check.kind==='exact-text')?[original.toString('utf8')+'\n',original.toString('utf8')+'X']:profile.profile==='code'?['module.exports={};','module.exports=new Proxy({}, {get(){return ()=>{throw Error("mutant")}}});']:profile.profile==='web'?['<!doctype html><html><body>damaged</body></html>']:profile.profile==='research'?['{"claims":[]}']:['','TODO'];
  for(const [i,text] of candidates.entries()){
   const bytes=Buffer.from(text),checks=await evaluate(bytes,profile.criteria);
   mutations.push({id:'mutant_'+i,artifact_sha256:bytesHash(bytes),detected:checks.some(c=>c.status==='FAIL'),checks});
  }
 }
 payload={execution_status:'EXECUTED',verdict:verdict(rows),rows,mutations,environment:{node:process.version,browser:browser?.version()??null,worker_thread_id:threadId,parent_pid:process.pid,network:'NODE_DENY_BROWSER_OFFLINE_ROUTE_ABORT'},input_keys:Object.keys(workerData).sort()};
}catch(error){payload={execution_status:'ERROR',verdict:'BLOCKED',rows:[],mutations:[],error:error.name};}
finally{
 if(browser)try{await browser.close();if(payload.environment)payload.environment.browser_closed=true;}
 catch{payload={execution_status:'ERROR',verdict:'BLOCKED',rows:[],mutations:[],error:'BROWSER_CLEANUP_FAILED'};}
}
// Publish only after resources are closed; parent may terminate the worker on receipt.
parentPort.postMessage(payload);
