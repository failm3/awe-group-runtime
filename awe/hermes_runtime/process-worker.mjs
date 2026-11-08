import {createHash} from 'node:crypto';
import {boundedFrames} from './bounded-frames.mjs';
import {exact,digest,need} from './protocol.mjs';
// Fixed local synthetic worker. The preloaded offline guard denies network and
// all subprocess APIs. No Hermes import, tool backend, credentials or model API.
let started=null,collecting=false,usageTimer,allocationTimer;const allocations=[];
const write=value=>process.stdout.write(JSON.stringify(value)+'\n');
const finish=value=>{clearInterval(usageTimer);clearInterval(allocationTimer);process.stdout.write(JSON.stringify(value)+'\n',()=>process.exit(0));};
const frame=(type,payload={})=>({version:'rt01.process.ipc/1',instance:started.instance,binding:started.binding,type,payload});
const usage=()=>write(frame('USAGE',{rss_bytes:process.memoryUsage().rss,cpu_micros:process.cpuUsage().user+process.cpuUsage().system}));
function collect(){
 if(collecting)return;collecting=true;
 const mode=started.behavior;
 if(mode==='crash')process.exit(71);
 if(mode==='hang'||mode==='ignore_cancel'||mode==='late_result')return;
 if(mode==='malformed'){process.stdout.write('{bad\n');return;}
 if(mode==='flood'){process.stdout.write('x'.repeat(65536));return;}
 if(mode==='stderr_flood'){process.stderr.write('x'.repeat(65536));return;}
 if(mode==='memory'){allocationTimer=setInterval(()=>allocations.push(Buffer.alloc(4*1024*1024,1)),15);return;}
 if(mode==='cpu'){const spin=()=>{const until=performance.now()+10;while(performance.now()<until){}setImmediate(spin);};spin();return;}
 if(mode==='error'){finish(frame('ERROR',{code:'synthetic_failure'}));return;}
 const bytes=Buffer.from(started.context,'utf8'),output={schema:'rt01.process.result/1',input_hash:'sha256:'+createHash('sha256').update(bytes).digest('hex'),utf8_bytes:bytes.length};
 const message=frame('RESULT',{output});
 if(mode==='binding_spoof')message.binding=digest({foreign:true});
 if(mode==='history')message.payload.history=['forbidden dialog'];
 if(mode==='duplicate'){write(message);finish(message);return;}
 if(mode==='nonzero_exit'){write(message);process.stdout.write('',()=>process.exit(72));return;}
 finish(message);
}
const decoder=boundedFrames({limit:49152,onError:()=>process.exit(73),onFrame:m=>{
 exact(m,['version','instance','binding','type','payload']);need(m.version==='rt01.process.ipc/1','VERSION');
 if(m.type==='START'){
  need(started===null,'REPLAY');exact(m.payload,['scope','actor_id','run_id','child_id','parent_run_id','model','tools','permissions','context','behavior']);
  started={...m.payload,instance:m.instance,binding:m.binding};
  need(started.permissions.physical_decision==='DENY'&&started.permissions.context_readonly===true,'DENIED');
  write(frame('STARTED',{pid:process.pid}));usageTimer=setInterval(usage,40);return;
 }
 need(started&&m.instance===started.instance&&m.binding===started.binding,'BINDING');exact(m.payload,[]);
 if(m.type==='COLLECT')collect();
 else if(m.type==='CANCEL'){
  if(started.behavior==='ignore_cancel')return;
  if(started.behavior==='late_result'){collecting=false;started.behavior='digest';collect();return;}
  finish(frame('CANCELLED',{}));
 }else if(m.type==='CHECKPOINT')write(frame('CHECKPOINT',{context_hash:started.permissions.context_hash}));
 else throw Error('METHOD');
}});
process.stdin.on('data',chunk=>{try{decoder.push(chunk);}catch{process.exit(73);}});
// Parent controller death closes stdin. Fixed workers cannot spawn descendants.
process.stdin.on('end',()=>process.exit(0));process.stdin.on('error',()=>process.exit(0));
