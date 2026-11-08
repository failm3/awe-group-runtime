import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fixture,json} from './fixture.mjs';
const [action,directory,stage]=process.argv.slice(2),stateFile=path.join(directory,'TEST-ONLY-authority.json');
const yes=r=>{assert.equal(r.ok,true,json(r));return r.value;};
if(action==='seed'){
  const f=fixture({directory}),goal=f.register(),v1=f.register({record_id:'mem_spec',kind:'SPEC',text:'ТЗ v1: offline.'});
  yes(f.persist(goal));yes(f.persist(v1));
  const v2=f.register({record_id:'mem_spec',kind:'SPEC',version:2,text:'ТЗ v2: offline. НЕ публиковать. Лимит 17.'});yes(f.persist(v2));
  fs.writeFileSync(stateFile,json({fixture:f.save(),refs:[goal.ref,v2.ref]}));
  console.log(json({status:'SEEDED',pid:process.pid}));
}else if(action==='read'){
  const saved=JSON.parse(fs.readFileSync(stateFile)),f=fixture({directory,saved:saved.fixture});
  const out=yes(f.memory.recover(f.session(),json({refs:saved.refs})));
  assert.equal(out.resume,false);assert.equal(yes(f.memory.history(f.session(),json({record_id:'mem_spec',limit:2}))).versions.length,2);
  console.log(json({status:'RESTORED',pid:process.pid,refs:out.recovered.length}));
}else if(action==='crash'){
  const f=fixture({directory,storeOptions:{primary:{fault:point=>{if(point===stage)process.exit(73);}}}}),r=f.register();
  fs.writeFileSync(stateFile,json({fixture:f.save(),refs:[r.ref]}));f.persist(r);throw Error('CRASH_NOT_TRIGGERED');
}else if(action==='after-crash'){
  const saved=JSON.parse(fs.readFileSync(stateFile)),f=fixture({directory,saved:saved.fixture});
  const out=f.memory.recover(f.session(),json({refs:saved.refs}));
  if(stage==='after_stage'){assert.equal(out.ok,false);assert.equal(out.code,'INTEGRITY_FAILURE');}
  else{assert.equal(out.ok,true,json(out));assert.equal(out.value.recovered[0].degraded,true);assert.equal(out.value.resume,false);}
  const locked=f.memory.persist(f.session(),json(f.register({record_id:'mem_later'}).record));
  assert.equal(locked.ok,false);assert.equal(locked.code,'WRITER_HOLD');
  console.log(json({status:'CRASH_RECONCILED_WITHOUT_REARM',pid:process.pid,stage}));
}else throw Error('UNKNOWN_TEST_ACTION');
