import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {reviewRows} from '../../awe/tool_registry/importer.mjs';
import {classify,parseCapabilityRequest} from '../../awe/tool_registry/taxonomy.mjs';
import {bounded,digest} from '../../awe/tool_registry/common.mjs';
import {createDiscovery,normalizeRequest} from '../../awe/tool_registry/discovery.mjs';
import {createPostgresRegistry} from '../../awe/tool_registry/postgres.mjs';
import {prepareRuntimeReview} from '../../awe/tool_registry/runtime-adapter.mjs';
import {NOW,principal,publicKey,tool,request,bind,memoryRepository,raw} from './fixtures.mjs';
const opts={snapshotId:'a'.repeat(64),observedAt:new Date(NOW).toISOString()};
test('catalog accounts for 4504 rows and immutable raw mapping',()=>{
 const base=new URL('../../TR-01/source/catalog/90 - Данные/',import.meta.url);
 const rows=JSON.parse(readFileSync(new URL('all-records-classified.json',base),'utf8').replace(/^\uFEFF/,''));
 const r=reviewRows(rows,opts);assert.equal(r.records.length,4504);assert.equal(r.failures.length,0);assert.equal(r.coverage.unique_url_groups,4466);
 assert.equal(new Set(r.records.map(x=>x.original_id)).size,4504);assert(r.records.every(x=>!x.lifecycle.permitted&&x.lifecycle.verified==='NOT_RUN'&&x.installed==='UNKNOWN'));
});
test('URL duplicate keeps every original row and query/scheme distinctions',()=>{
 const r=reviewRows([raw(),raw({id:'r2',url:'https://www.example.org/tool/'}),raw({id:'r3',url:'https://example.org/tool?x=1'}),raw({id:'r4',url:'http://example.org/tool'})],opts);
 assert.equal(r.records.length,4);assert.equal(r.coverage.unique_url_groups,3);assert.equal(r.records[0].duplicate_ids.length,2);
});
for(const [name,bad] of [['missing URL',{url:null}],['invalid URL',{url:'file:///etc/passwd'}],['missing description',{description:''}],['bad row',{source_row:0}],['credentials',{url:'https://user:pass@example.org'}]])test('corrupt row quarantined: '+name,()=>{const r=reviewRows([raw(bad)],opts);assert.equal(r.records.length,0);assert.equal(r.failures.length,1);assert.deepEqual(r.failures[0].raw,raw(bad));});
test('duplicate IDs reported instead of silently overwritten',()=>{const r=reviewRows([raw(),raw()],opts);assert.equal(r.failures.length,1);});
test('prototype and deeply nested/oversize metadata rejected',()=>{
 assert.throws(()=>bounded(JSON.parse('{"__proto__":{"admin":true}}')));let a={};for(let i=0;i<30;i++)a={x:a};assert.throws(()=>bounded(a));assert.throws(()=>bounded({s:'x'.repeat(20)},10));
});
for(const [description,capability] of [['Playwright browser screenshot','browser.screenshot'],['pandoc generate docx','document.generate'],['pytest code test','code.test']])test('taxonomy infers '+capability,()=>{const r=classify(raw({description}));assert(r.capabilities.includes(capability));assert(r.rules.every(x=>x.certainty==='INFERRED_FROM_DESCRIPTION'));});
test('unmatched source is unresolved and price claims do not authorize',()=>{const r=reviewRows([raw({description:'Free tokens 100% secure',url:'https://example.org'})],opts).records[0];assert.equal(r.classification,'UNRESOLVED');assert.equal(r.cost.basis,'UNKNOWN');assert.equal(r.security,'NOT_TESTED');});
const setup=(rows,extra={})=>createDiscovery({repository:memoryRepository(rows),principal,clock:()=>NOW,issuerKeys:{test:publicKey},...extra});
for(const [need,cap] of [['Сделать скриншот браузера','browser.screenshot'],['Создать документ docx','document.generate'],['Запустить тест кода','code.test']])test('realistic search canary: '+cap,async()=>{
 const rows=[tool('browser.screenshot',1),tool('document.generate',2),tool('code.test',3)];const d=setup(rows),r=await d.searchCapabilities(request(need));assert.equal(r.results.length,1);assert.deepEqual(r.results[0].capabilities,[cap]);assert.equal(r.physical_decision,'DENY');assert(!('description' in r.results[0]));
});
for(const [name,patch] of [['disabled',{disabled:true}],['compromised',{compromised:true}],['hazardous',{hazards:['REVIEW']}],['unverified',{verified:'NOT_RUN'}],['unavailable',{available:'UNAVAILABLE'}],['stale',{valid_until:'2026-11-04T12:00:00Z'}]])test('verified discovery denies '+name,async()=>{const r=await setup([{...tool(),...patch}]).searchCapabilities(request());assert.equal(r.results.length,0);});
test('candidate mode returns untested metadata with review and no permission',async()=>{const r=await setup([{...tool(),verified:'NOT_RUN',available:'UNKNOWN'}]).searchCapabilities({...request(),mode:'CANDIDATES'});assert.equal(r.results.length,1);assert.equal(r.results[0].permitted,false);assert.equal(r.results[0].requires_review,true);});
test('platform and known price filters reject unknown or incompatible',async()=>{
 const d=setup([tool(),{...tool('browser.screenshot',2),cost:{amount_micros:null,currency:null}}]);assert.equal((await d.searchCapabilities({...request(),platform:'windows'})).results.length,0);assert.equal((await d.searchCapabilities({...request(),max_cost_micros:'0',currency:'RUB'})).results.length,1);
});
test('ranking is bounded and deterministic without full descriptions',async()=>{const d=setup(Array.from({length:30},(_,i)=>tool('browser.screenshot',i+1)));const r=await d.searchCapabilities({...request(),limit:3});assert.equal(r.results.length,3);assert.equal(JSON.stringify(r),JSON.stringify(await d.searchCapabilities({...request(),limit:3})));});
for(const patch of [{project_id:'project_b'},{actor_id:'mallory'},{tenant_id:'tenant_b'}])test('spoofed search scope fails closed '+JSON.stringify(patch),async()=>{const d=setup([tool()],patch.actor_id||patch.tenant_id?{principal:{...principal,...patch}}:{});await assert.rejects(()=>d.searchCapabilities({...request(),...(patch.project_id?patch:{})}));});
test('store outage fails closed and leaves trail',async()=>{const d=setup([],{repository:{search:async()=>{throw Error('offline');},get:async()=>null}});await assert.rejects(()=>d.searchCapabilities(request()));assert.equal(d.reviewTrail().at(-1).decision,'DENY');});
test('unknown fields, capabilities and unbounded shortlist rejected',()=>{for(const r of [{...request(),actor_id:'admin'},{...request(),limit:100},{...request(),capabilities:['exec']},{...request(),need:'unknown'},{...request(),max_cost_micros:'-1',currency:'RUB'}])assert.throws(()=>normalizeRequest(r));});
const pep={review:async({request:r})=>({decision:'ALLOW_E0_PROPOSAL',approval_digest:digest('approval'),request_digest:digest(r)})};
test('signed manifest plus host PEP creates only a denied physical proposal',async()=>{const t=tool(),d=setup([t],{pep}),r=await d.bindTool(bind(t));assert.equal(r.status,'BOUND_E0_ONLY');assert.equal(r.physical_decision,'DENY');assert.equal(r.runtime_dispatch,false);assert.equal(d.reviewTrail().at(-1).action,'BIND');});
test('D04 protocol requires independently pinned runtime artifact and remains DENY',async()=>{const t=tool(),binding=await setup([t],{pep}).bindTool(bind(t));const proposal=prepareRuntimeReview(binding,{runtimeArtifactDigest:digest('runtime artifact'),adapterId:'d04_synthetic'});assert.equal(proposal.dispatch_supported,false);assert.equal(proposal.physical_decision,'DENY');assert.notEqual(proposal.runtime_artifact_digest,binding.proposal.manifest_digest);assert.throws(()=>prepareRuntimeReview({...binding,status:'DENIED'},{runtimeArtifactDigest:digest('x'),adapterId:'d04_synthetic'}));});
test('canonical manifest signature survives property reordering',async()=>{const t=tool();t.signed_manifest.payload=Object.fromEntries(Object.entries(t.signed_manifest.payload).reverse());assert.equal((await setup([t],{pep}).bindTool(bind(t))).status,'BOUND_E0_ONLY');});
for(const [name,patch] of [['revision',{revision:2}],['version',{version:'2.0.0'}],['schema',{input_schema_digest:digest('bad')}],['project',{project_id:'project_b'}],['epoch',{epochs:{auth:2,policy:1,tool:1,project:1}}],['tool',{tool_id:'absent'}]])test('stale/foreign binding denied: '+name,async()=>{const t=tool();assert.equal((await setup([t],{pep}).bindTool({...bind(t),...patch})).status,'DENIED');});
test('forged signature and stale signed payload denied',async()=>{const t=tool();t.signed_manifest.signature=Buffer.alloc(64).toString('base64');assert.equal((await setup([t],{pep}).bindTool(bind(t))).reason,'TR_SIGNATURE');});
test('issuer key and PEP are mandatory and cannot be read from the database',async()=>{const t=tool();for(const options of [{issuerKeys:{}},{pep:null},{pep:{review:async()=>({decision:'ALLOW'})}}])assert.equal((await setup([t],{pep,...options}).bindTool(bind(t))).status,'DENIED');});
for(const patch of [{disabled:true},{compromised:true},{verified:'NOT_RUN'},{available:'UNKNOWN'},{hazards:['poison']}])test('binding gate denies changed current state '+JSON.stringify(patch),async()=>{const t=tool();assert.equal((await setup([{...t,...patch}],{pep}).bindTool(bind(t))).status,'DENIED');});
test('SQL adapter uses scoped parameters, rollback and release on failure',async()=>{
 const calls=[];let released=false;const c={query:async(sql,params)=>{calls.push({sql,params});if(sql.includes('check_scope'))return {rows:[{ok:false}]};return {rows:[]};},release:()=>released=true};
 const d=createPostgresRegistry({readerPool:{connect:async()=>c}});await assert.rejects(()=>d.search(request(),principal));assert(calls.some(x=>x.sql==='ROLLBACK'));assert(released);assert(calls[1].sql.includes('$1,$2,$3'));assert.deepEqual(calls[1].params,['project_a','tenant_a','alice']);
});
