import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fixture,json,sandbox} from './fixture.mjs';
import {digest,copy,canonicalize} from '../src/common.mjs';
import {createFileStore} from '../src/file-store.mjs';
import {createProjectMemory} from '../src/memory.mjs';
import {fixture as contextFixture} from '../../tests/context/harness.mjs';
import {createContextEngine} from '../../awe/context/engine.mjs';
import {createCoordinatorPorts} from '../src/integration-ports.mjs';
const yes=r=>{assert.equal(r.ok,true,json(r));return r.value;};
const no=(r,code)=>{assert.equal(r.ok,false,json(r));if(code)assert.equal(r.code,code);return r;};
const ready=options=>{const f=fixture(options),r=f.register();yes(f.persist(r));return {f,r};};

test('durable write requires two exact independent file reads; duplicate is idempotent',()=>{
  const {f,r}=ready();const first=f.read(r);assert.equal(yes(first).record.text,r.record.text);
  const second=yes(f.persist(r));assert.equal(second.verified_stores.length,2);assert.equal(second.authoritative_complete,false);
  for(const name of ['primary','replica'])assert.equal(fs.readdirSync(path.join(f.directory,'prj_alpha',name)).length,1);
});
test('new service and authority instances restore exact records with fresh sessions',()=>{
  const {f,r}=ready(),oldToken=f.session(),g=fixture({directory:f.directory,saved:f.save()});
  assert.deepEqual(yes(g.read(r)).record,r.record);
  no(g.memory.read(oldToken,json({ref:r.ref})),'DENIED');
  const recovery=yes(g.memory.recover(g.session(),json({refs:[r.ref]})));
  assert.equal(recovery.status,'RECOVERED_REFERENCES_ONLY');assert.equal(recovery.resume,false);assert.equal(recovery.new_attempt,false);
});
test('lost authoritative state cannot be reconstructed from immutable files',()=>{
  const {f,r}=ready(),token=f.session();f.lostAuthority();no(f.memory.read(token,json({ref:r.ref})),'STATE_UNAVAILABLE');
  const g=fixture({directory:f.directory});no(g.read(r),'NOT_AVAILABLE');assert.ok(fs.existsSync(f.file(r.ref)));
});
test('lost catalogue never triggers a disk scan or self-registration',()=>{
  const {f,r}=ready();f.lostCatalogue();no(f.read(r),'CATALOGUE_UNAVAILABLE');
});
test('corrupt primary falls back to the exact replica with degraded receipt',()=>{
  const {f,r}=ready();fs.writeFileSync(f.file(r.ref),'{broken');
  const read=yes(f.read(r));assert.equal(read.record.text,r.record.text);assert.equal(read.readback.degraded,true);assert.deepEqual(read.readback.verified_stores,['prj_alpha_replica']);
});
test('two damaged files fail closed and expose no raw content or paths',()=>{
  const {f,r}=ready();for(const replica of [false,true])fs.writeFileSync(f.file(r.ref,replica),'PRIVATE_CANARY_BROKEN');
  const out=no(f.read(r),'INTEGRITY_FAILURE');assert.equal(json(out).includes('PRIVATE_CANARY'),false);assert.equal(json(out).includes(f.directory),false);
});
test('loss of a primary object is recovered using current pinned catalogue',()=>{
  const {f,r}=ready();fs.unlinkSync(f.file(r.ref));assert.equal(yes(f.read(r)).readback.degraded,true);
  yes(f.persist(r));assert.equal(yes(f.read(r)).readback.degraded,false);
});
test('loss of both copies is explicit and fresh directories do not fabricate records',()=>{
  const {f,r}=ready();fs.unlinkSync(f.file(r.ref));fs.unlinkSync(f.file(r.ref,true));no(f.read(r),'INTEGRITY_FAILURE');
});
test('same-project versions survive restart; historical versions are never current context',()=>{
  const f=fixture();for(const kind of ['GOAL','SPEC']){
    const id='mem_'+kind.toLowerCase(),one=f.register({record_id:id,kind,text:'v1: НЕ публиковать.'});yes(f.persist(one));
    if(kind==='SPEC')f.bump(w=>{w.projects.prj_alpha.revision++;w.projects.prj_alpha.spec.revision++;w.projects.prj_alpha.spec.content_hash=digest({spec:2});});
    const two=f.register({record_id:id,version:2,kind,text:'v2: НЕ публиковать. Лимит 17.'});yes(f.persist(two));
    no(f.read(one),'NOT_AVAILABLE');assert.equal(yes(f.read(two)).record.version,2);
    const g=fixture({directory:f.directory,saved:f.save()});
    const hist=yes(g.memory.history(g.session(),json({record_id:id,limit:2})));
    assert.deepEqual(hist.versions.map(x=>x.record.version),[1,2]);assert.equal(hist.authoritative_spec,false);
  }
});
test('history is bounded and refuses silent omission',()=>{
  const f=fixture();yes(f.persist(f.register()));yes(f.persist(f.register({version:2,text:'next'})));
  no(f.memory.history(f.session(),json({record_id:'mem_goal',limit:1})),'HISTORY_TOO_LARGE');
});
test('cross-project read, restore and writes are denied with physically separated stores',()=>{
  const {f,r}=ready(),b=f.register({project:'prj_beta',text:'BETA_SECRET',readers:['act_owner','act_beta']});yes(f.persist(b));
  no(f.memory.read(f.session('act_owner','prj_beta'),json({ref:r.ref})),'SCOPE_DENIED');
  no(f.memory.read(f.session(),json({ref:b.ref})),'NOT_AVAILABLE');
  no(f.memory.recover(f.session(),json({refs:[b.ref]})),'NOT_AVAILABLE');
  no(f.memory.persist(f.session(),json(b.record)),'SCOPE_DENIED');
  assert.equal(fs.existsSync(f.file(b.ref)),false);assert.equal(fs.existsSync(f.file(b.ref,false,'prj_beta')),true);
});
test('current ACL filters records before any body read',()=>{
  const {f,r}=ready();const original=f.stores.map(s=>({...s,read(){throw Error('BODY_SHOULD_NOT_BE_READ');}}));
  f.bump(()=>{f.catalogues.prj_alpha[0].reader_ids=['act_owner'];});
  const m=createProjectMemory({project_id:'prj_alpha',authority:f.authority,readCatalogue:v=>({project_id:v.project_id,authority_revision:f.world.authority_revision,entries:f.catalogues[v.project_id]}),stores:original});
  no(m.read(f.session('act_child'),json({ref:r.ref})),'NOT_AVAILABLE');
});
test('authoritative tombstone suppresses surviving data after restart and purge removes both copies',()=>{
  const {f,r}=ready();f.bump(w=>w.tombstones.memory.push('prj_alpha/mem_goal'));
  const g=fixture({directory:f.directory,saved:f.save()});no(g.read(r),'NOT_AVAILABLE');
  no(g.memory.history(g.session(),json({record_id:'mem_goal',limit:2})),'NOT_AVAILABLE');
  assert.equal(yes(g.memory.sweep(g.session(),'{}')).removed_objects,2);assert.equal(fs.existsSync(f.file(r.ref)),false);
});
test('expired data is unavailable and owner retention sweep removes approved expired objects',()=>{
  const {f,r}=ready();f.time('2027-01-02T00:00:00.000Z');no(f.read(r),'NOT_AVAILABLE');
  assert.equal(yes(f.memory.sweep(f.session(),'{}')).removed_objects,2);
});
test('revoked source invalidates reads and history after restart',()=>{
  const {f,r}=ready();f.bump(w=>w.sources[r.record.provenance.source_id].status='REVOKED');
  const g=fixture({directory:f.directory,saved:f.save()});no(g.read(r),'PROVENANCE_REJECTED');
  no(g.memory.history(g.session(),json({record_id:r.record.record_id,limit:2})),'PROVENANCE_REJECTED');
});
test('project epoch advance and restore_pending invalidate old sessions and cached data',()=>{
  const {f,r}=ready(),token=f.session();f.bump(w=>w.projects.prj_alpha.epochs.auth++);
  no(f.memory.read(token,json({ref:r.ref})),'DENIED');no(f.read(r),'PROVENANCE_REJECTED');
  f.bump(w=>w.projects.prj_alpha.restore_pending=true);assert.throws(()=>f.session(),/DENIED/);
});
test('source links, artifact links and lineage remain pinned and revocation propagates',()=>{
  const f=fixture(),parent=f.source({record_id:'mem_source',text:'Source'}),artifact=f.source({record_id:'art_result',kind:'ARTIFACT',text:'result'});
  const s=f.world.sources[artifact.source_id];
  const r=f.register({kind:'RESULT',sources:[{...parent,uri:'https://github.com/example/repo/blob/abc/spec.md'}],
    artifacts:[{project_id:'prj_alpha',artifact_id:'art_result',version:1,content_hash:s.content_hash,...artifact}],parents:[parent]});
  yes(f.persist(r));assert.deepEqual(yes(f.read(r)).record.artifacts,r.record.artifacts);
  f.bump(w=>w.tombstones.memory.push('prj_alpha/mem_source'));no(f.read(r),'PROVENANCE_REJECTED');
});
test('worker gets only host-selected bounded records and cannot widen scope',()=>{
  const f=fixture(),parent=f.source({record_id:'mem_summary_source',text:'Цель: offline. Запрет: НЕ публиковать. Лимит 17.'});
  const needed=f.register({record_id:'mem_summary',kind:'SUMMARY',text:'Цель: offline. Запрет: НЕ публиковать. Лимит 17.',parents:[parent],sources:[{...parent,uri:'artifact:summary-source'}]});yes(f.persist(needed));
  yes(f.persist(f.register({record_id:'mem_dialog',text:'UNNEEDED_FULL_DIALOG_CANARY'})));
  const ids=['mem_summary'],port=f.memory.workerPort(f.session('act_child'),{record_ids:ids,purpose:'BUILD',max_bytes:1024});ids.push('mem_dialog');
  const pack=yes(port.pack());assert.equal(pack.records.length,1);assert.equal(pack.full_transcript,false);assert.equal(json(pack).includes('UNNEEDED'),false);
  assert.equal(pack.records[0].trust,'REFERENCE_DATA_ONLY');assert.deepEqual(Object.keys(port),['pack']);
});
test('worker context overflow denies without truncating a prohibition',()=>{
  const f=fixture(),r=f.register({text:'НЕ публиковать. '.repeat(120)});yes(f.persist(r));
  const p=f.memory.workerPort(f.session('act_child'),{record_ids:['mem_goal'],purpose:'BUILD',max_bytes:512});no(p.pack(),'CONTEXT_TOO_LARGE');
});
test('worker purpose, revocation and forged sessions fail closed',()=>{
  const {f,r}=ready();no(f.memory.workerPort(f.session('act_child'),{record_ids:['mem_goal'],purpose:'UNAPPROVED'}).pack(),'NOT_AVAILABLE');
  no(f.memory.read({},json({ref:r.ref})),'DENIED');
  const p=f.memory.workerPort(f.session('act_child'),{record_ids:['mem_goal'],purpose:'BUILD'});f.bump(w=>w.actors.act_child.active=false);no(p.pack(),'DENIED');
});
test('D05 port translates raw-text D07 hash to canonical-string D05 hash explicitly',()=>{
  const {f,r}=ready(),port=f.memory.contextPort(f.session('act_child'));
  const req={project_id:'prj_alpha',auth_epoch:1,role:'EXECUTOR',purpose:'BUILD'};const meta=port.list(req)[0];
  assert.equal(meta.hash,digest(r.record.text));assert.notEqual(meta.hash,meta.raw_content_hash);
  assert.equal(port.read({...req,id:'mem_goal',version:1}).hash,meta.hash);
  assert.throws(()=>port.list({...req,project_id:'prj_beta'}),/SCOPE_DENIED/);
  assert.throws(()=>port.list({...req,role:'OWNER'}),/SCOPE_DENIED/);
});
test('actual unchanged D05 engine builds and preflights using DATA02 port',()=>{
  const {f,r}=ready(),d=contextFixture();const memory=f.memory.contextPort(f.session('act_child'));
  const engine=createContextEngine({...d.ports,memory});const request={...d.input,source_ids:[r.record.record_id]};
  const built=engine.build(d.session,request);assert.equal(built.decision,'READY_OFFLINE',json(built));
  const pre=engine.preflight(d.session,built.ref);assert.equal(pre.decision,'READY_OFFLINE',json(pre));
  f.bump(w=>w.tombstones.memory.push('prj_alpha/mem_goal'));assert.notEqual(engine.preflight(d.session,built.ref).decision,'READY_OFFLINE');
});
test('catalogue revision mismatch and async catalogues fail closed',()=>{
  const {f,r}=ready();const make=readCatalogue=>createProjectMemory({project_id:'prj_alpha',authority:f.authority,readCatalogue,stores:f.stores});
  no(make(()=>({project_id:'prj_alpha',authority_revision:0,entries:[]})).read(f.session(),json({ref:r.ref})),'CATALOGUE_UNAVAILABLE');
  no(make(async()=>({})).read(f.session(),json({ref:r.ref})),'CATALOGUE_UNAVAILABLE');
});
test('read races are rechecked before data is returned',()=>{
  const {f,r}=ready();let calls=0;f.onCatalogue(()=>{if(++calls===2)f.bump(w=>w.tombstones.memory.push('prj_alpha/mem_goal'));});
  no(f.read(r),'STATE_CHANGED');
});
test('strict JSON rejects duplicate and unknown fields and scope injection',()=>{
  const {f,r}=ready();no(f.memory.read(f.session(),'{"ref":"one","ref":"two"}'));
  no(f.memory.read(f.session(),json({ref:r.ref,project_id:'prj_beta'})));
  no(f.memory.persist(f.session(),json({...r.record,task_state:'COMPLETE'})));
});
test('partial dual-store write retains immutable data; retry with exact bytes deduplicates',()=>{
  let fail=true;const f=fixture({storeOptions:{replica:{fault:stage=>{if(fail&&stage==='after_stage')throw Error('DISK_FAULT');}}}}),r=f.register();
  no(f.persist(r),'WRITE_UNCERTAIN');assert.equal(fs.existsSync(f.file(r.ref)),true);assert.equal(fs.existsSync(f.file(r.ref,true)),false);
  fail=false;yes(f.persist(r));yes(f.persist(r));assert.equal(yes(f.read(r)).readback.degraded,false);
});
test('readback corruption prevents successful persistence despite write acknowledgement',()=>{
  const f=fixture(),r=f.register();const bad=f.stores.map(s=>({...s,read:k=>({...s.read(k),bytes:Buffer.from('bad')})}));
  const m=createProjectMemory({project_id:'prj_alpha',authority:f.authority,readCatalogue:v=>({project_id:v.project_id,authority_revision:f.world.authority_revision,entries:f.catalogues[v.project_id]}),stores:bad});
  no(m.persist(f.session(),json(r.record)),'INTEGRITY_FAILURE');
});
test('writer lock holds writes after an unclean exit but does not block verified reads',()=>{
  const {f,r}=ready();fs.writeFileSync(path.join(f.directory,'prj_alpha','primary','.writer.lock'),'unknown old owner');
  yes(f.read(r));no(f.persist(r),'WRITER_HOLD');assert.ok(fs.existsSync(path.join(f.directory,'prj_alpha','primary','.writer.lock')));
});
test('store capacity is bounded without evicting live history',()=>{
  const f=fixture({storeOptions:{primary:{max_objects:1}}}),one=f.register();yes(f.persist(one));
  const two=f.register({record_id:'mem_other'});no(f.persist(two),'STORAGE_CAPACITY');yes(f.read(one));
});
test('store refuses traversal and paths outside DATA02',()=>{
  assert.throws(()=>createFileStore(path.resolve(sandbox,'../../awe'),'bad'),/STORAGE_ROOT_DENIED/);
  const s=createFileStore(fs.mkdtempSync(path.join(sandbox,'paths-')),'safe');assert.throws(()=>s.read('../../secret'),/INPUT_INVALID/);
});
test('hardlinked object is unsafe and only the valid replica may be returned',()=>{
  const {f,r}=ready();fs.linkSync(f.file(r.ref),path.join(f.directory,'linked.json'));
  assert.equal(yes(f.read(r)).readback.degraded,true);
});
test('checksums cannot replace exact catalogue pins',()=>{
  const {f,r}=ready(),bad=copy(r.record);bad.text='FORGED';
  for(const replica of [false,true])fs.writeFileSync(f.file(r.ref,replica),canonicalize(bad));no(f.read(r),'INTEGRITY_FAILURE');
});
test('summary lineage is mandatory and source supersession invalidates child packs',()=>{
  const f=fixture(),unbound=f.register({record_id:'mem_bad_summary',kind:'SUMMARY'});no(f.persist(unbound),'SUMMARY_LINEAGE_REQUIRED');
  const p=f.source({record_id:'mem_parent',text:'Проверенный источник.'});
  const r=f.register({record_id:'mem_summary',kind:'SUMMARY',text:'Ограниченная сводка.',parents:[p],sources:[{...p,uri:'artifact:source'}]});yes(f.persist(r));
  const port=f.memory.workerPort(f.session('act_child'),{record_ids:['mem_summary'],purpose:'BUILD'});yes(port.pack());
  f.source({record_id:'mem_parent',version:2,text:'Changed source.'});no(port.pack(),'PROVENANCE_REJECTED');
});
test('same filesystem directory cannot masquerade as two replicas',()=>{
  const f=fixture(),same=createFileStore(path.join(f.directory,'prj_alpha','primary'),'different_id');
  assert.throws(()=>createProjectMemory({project_id:'prj_alpha',authority:f.authority,readCatalogue:()=>({}),stores:[f.stores[0],same]}),/REPLICA_CONFIGURATION_INVALID/);
});
test('AUTO01/INT04 ports return HOLD and expose only bounded pack to the child',()=>{
  const {f,r}=ready();let b={schema:'DATA02_BINDINGS_V1',project_id:'prj_alpha',task_id:'task_memory',revision:1,spec_ref:f.world.projects.prj_alpha.spec.content_hash,required_refs:[r.ref],child_record_ids:['mem_goal'],purpose:'BUILD',context_bytes:1024};
  const ports=createCoordinatorPorts({memory:f.memory,readerSession:f.session(),writerSession:f.session(),childSession:f.session('act_child'),readBindings:()=>b});
  const out=yes(ports.host.restoreView());assert.equal(out.status,'HOLD_FOR_OWNER_RECONCILIATION');assert.equal(out.resume,false);yes(ports.child.pack());
  assert.deepEqual(Object.keys(ports.child),['pack']);assert.equal('reserve' in ports.host,false);assert.equal('start' in ports.host,false);
  b={...b,project_id:'prj_beta'};no(ports.host.restoreView(),'SCOPE_DENIED');
});
test('coordinator binding change during read prevents returning a stale pack',()=>{
  const {f,r}=ready();let n=0;
  const ports=createCoordinatorPorts({memory:f.memory,childSession:f.session('act_child'),readBindings:()=>({schema:'DATA02_BINDINGS_V1',project_id:'prj_alpha',task_id:'task_memory',revision:++n,spec_ref:f.world.projects.prj_alpha.spec.content_hash,required_refs:[r.ref],child_record_ids:['mem_goal'],purpose:'BUILD',context_bytes:1024})});
  no(ports.child.pack(),'BINDINGS_CHANGED');
});
test('coordinator ports reject a stale spec pin or unpinned new memory version',()=>{
  const {f,r}=ready();let spec_ref=digest({wrong:1});
  const ports=createCoordinatorPorts({memory:f.memory,readerSession:f.session(),childSession:f.session('act_child'),readBindings:()=>({schema:'DATA02_BINDINGS_V1',project_id:'prj_alpha',task_id:'task_memory',revision:1,spec_ref,required_refs:[r.ref],child_record_ids:['mem_goal'],purpose:'BUILD',context_bytes:1024})});
  no(ports.host.restoreView(),'BINDINGS_STALE');spec_ref=f.world.projects.prj_alpha.spec.content_hash;yes(ports.child.pack());
  const next=f.register({version:2,text:'Новая цель.'});yes(f.persist(next));no(ports.child.pack(),'BINDINGS_STALE');
});
