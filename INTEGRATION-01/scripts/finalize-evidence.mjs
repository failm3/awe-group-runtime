import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {verifyCandidate} from './verify-candidate.mjs';
import {verifySources} from './verify-sources.mjs';
const root=path.resolve(import.meta.dirname,'../..'),base=path.join(root,'INTEGRATION-01');
const sha=b=>createHash('sha256').update(b).digest('hex'),hashFile=p=>sha(fs.readFileSync(p));
const json=p=>JSON.parse(fs.readFileSync(path.join(base,p)));
const write=(p,o)=>fs.writeFileSync(path.join(base,p),JSON.stringify(o,null,2)+'\n');
const latest=json('LATEST-TESTS.json'),results=JSON.parse(fs.readFileSync(path.join(root,latest.directory,'results.json')));
assert.equal(results.status,'PASS');assert.equal(results.totalPass,1604);assert(results.rows.every(r=>r.status==='PASS'&&!r.reusedFrom&&r.fail===0&&r.skipped===0&&r.cancelled===0));
assert.equal(results.candidateSourceManifestSha256,hashFile(path.join(base,'CANDIDATE-SOURCES.json')));
const obs=json('evidence/browser/files-browser-observations.json'),download=fs.readFileSync(obs.downloadPath);
assert.equal('sha256:'+sha(download),obs.expectedArtifactDigest);
const matches=[];
for(const store of ['primary','replica']){
 const dir=path.join(base,'sandbox/browser-files/case/d07',store);
 const found=fs.readdirSync(dir).filter(n=>sha(fs.readFileSync(path.join(dir,n)))===sha(download));assert.equal(found.length,1);
 const file=path.join(dir,found[0]);matches.push({store,path:path.relative(root,file).replaceAll('\\','/'),bytes:fs.statSync(file).size,sha256:hashFile(file)});
}
assert(obs.responsive.every(r=>!r.horizontalOverflow));assert(obs.modalFocus.every(r=>r.inside));assert(obs.draftPreserved&&obs.escapeRestored&&obs.testOwnerAccepted&&!obs.authoritativeComplete&&!obs.published);assert.equal(obs.consoleErrors.length,0);
fs.copyFileSync(obs.downloadPath,path.join(base,'evidence/browser/downloaded-result.json'));
fs.copyFileSync(path.join(base,'sandbox/browser-files/case/independent-d08.stdout.json'),path.join(base,'evidence/browser/independent-d08.stdout.json'));
const initial=json('BROWSER-QA.json');if(initial.status==='NOT_RUN')write('evidence/development/browser-initial-not-run.json',initial);
const browser={status:'PASS',scope:'LIMITED_BROWSER_SMOKE_NOT_FULL_WCAG',tool:'cua_repl / ChatGPT in-app browser',recordedAt:obs.checkedAt,profile:obs.profile,url:obs.origin,node:process.version,observations:'evidence/browser/files-browser-observations.json',actualPipeline:true,d07Filesystem:true,download:{evidence:'evidence/browser/downloaded-result.json',bytes:download.length,sha256:sha(download),expected:obs.expectedArtifactDigest,stores:matches},checks:['actual UI task → existing INT04/D03 → one LLM01 sealed D06 call → two exited RT processes → D07 files → two computed D08 reports','exact-version test OWNER acceptance; native D03 QA_PENDING, authoritativeComplete false, published false','download matches displayed digest and actual bytes in both D07 filesystem stores','Studio 1440/1024/768/390/320: no horizontal document overflow','dark/light visual review, modal Tab containment, Escape restores focus','draft preserved while navigating agents and returning','no captured browser console errors'],screenshots:obs.screenshots.map(p=>'evidence/browser/'+p),notRun:['full WCAG/screen-reader/cross-browser/performance audit','all negative scenarios in browser; corresponding Node/HTTP/process scenarios executed'],initialAttempt:'evidence/development/browser-initial-not-run.json'};
write('BROWSER-QA.json',browser);
// Test counters/commands/raw TAP remain untouched. Supplement only the runner's
// earlier browser-availability metadata after actual browser QA has finished.
results.notRun=results.notRun.filter(r=>!['browser layout/keyboard/responsive QA','full WCAG/screen-reader/cross-browser/performance audit'].includes(r.scope));
results.notRun.push({scope:'full WCAG/screen-reader/cross-browser/performance audit',status:'NOT_RUN',reason:'Limited actual browser smoke completed separately; see BROWSER-QA.json.'});
results.browserQa={status:browser.status,report:'INTEGRATION-01/BROWSER-QA.json',metadataAddedAfterRun:true};
fs.writeFileSync(path.join(root,latest.directory,'results.json'),JSON.stringify(results,null,2)+'\n');
const sourceCheck=verifySources({originals:process.argv.includes('--with-originals')}),candidateCheck=verifyCandidate();write('evidence/FINAL-SOURCE-CHECK.json',sourceCheck);
const lock=json('SOURCE-LOCK.json'),active=json('CANDIDATE-SOURCES.json');
const result={version:'INTEGRATION01_FINAL_RESULTS_V1',recordedAt:new Date().toISOString(),offlineStatus:'PASS',nativeStatus:'BLOCKED_PENDING_INDEPENDENT_INT04_REVIEW',physicalDecision:'DENY',node:results.node,nodeSha256:results.nodeSha256,fullFreshRun:latest.directory+'/results.json',totalPass:results.totalPass,totalFail:results.totalFail,integrationTests:results.rows.find(r=>r.name==='integration01').pass,browser,candidateCheck,sourceCheck,sourceCounts:lock.sources.map(s=>({id:s.id,files:s.files.length})),hashes:{sourceLock:hashFile(path.join(base,'SOURCE-LOCK.json')),candidateSources:hashFile(path.join(base,'CANDIDATE-SOURCES.json')),fullResults:hashFile(path.join(root,latest.directory,'results.json'))},notRun:[{scope:'genuine PG D09/INT03/AUD01/TR01',tests:121,reason:'Prohibited working DB / SQL003; no DB harness invoked.'},{scope:'real Hermes / LIVE LLM / Physical ALLOW',reason:'Explicit prohibition.'},{scope:'native independent acceptance and production trust isolation',status:'BLOCKED'},{scope:'full browser accessibility and all browser-negative paths',reason:'See browser.notRun.'}],historicalFailures:{initialBroadRun:'evidence/2026-11-06T10-43-14.514Z/results.json',fail:19,cause:'Missing pinned catalog data/evidence directories; raw failures retained; final full fresh run passes.',development:'evidence/development'},nativeCompletion:false,nativeFinalCancellation:false,sqlApplied:false};
write('FINAL-RESULTS.json',result);
if(fs.existsSync(path.join(base,'evidence/PACKAGE-REPLAY.json'))){result.packageReplay=json('evidence/PACKAGE-REPLAY.json');write('FINAL-RESULTS.json',result);}
const lines=['# Exact hashes','','All values are SHA-256 of raw file bytes. Local inventories are integrity evidence, not signed provenance.','','| Inventory | SHA-256 |','|---|---|',...Object.entries(result.hashes).map(([k,v])=>'| '+k+' | `'+v+'` |'),'','## Frozen sources',''];
for(const s of lock.sources){lines.push('### '+s.id,'','Root at capture: `'+s.root+'`  ','Branch: `'+s.branch+'`  ','HEAD: `'+s.head+'`  ','Files: '+s.files.length,'','| Path | Bytes | SHA-256 |','|---|---:|---|',...s.files.map(f=>'| `'+f.path+'` | '+f.bytes+' | `'+f.sha256+'` |'),'');}
fs.writeFileSync(path.join(base,'HASHES.md'),lines.join('\n')+'\n');
console.log(JSON.stringify({status:'PASS',tests:result.totalPass,integration:result.integrationTests,browser:browser.status,downloadSha256:sha(download),sourceFiles:sourceCheck.snapshotFiles,activeFiles:active.files.length,sourceCounts:result.sourceCounts},null,2));
