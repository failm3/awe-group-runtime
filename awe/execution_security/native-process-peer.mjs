// Read-only Linux observer for a parent-owned Node IPC TEST process. Not native
// enrollment, human AuthN, sandbox isolation or an independent boot witness.
import fs from 'node:fs';import {ChildProcess} from 'node:child_process';
import {need,id,hash,integer,freeze,copy} from './native-identity-contract.mjs';
export function createLinuxNodeTestPeer(child,{host_id,generation,channel_binding_hash}){
 need(process.platform==='linux'&&process.getuid()!==0&&child instanceof ChildProcess&&Number.isSafeInteger(child.pid)&&child.pid>0,'G101_OWN_CHILD_REQUIRED');id(host_id);integer(generation,1);hash(channel_binding_hash);
 const pid=child.pid,exe=fs.realpathSync(process.execPath),boot=fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim();
 function read(){try{need(child.pid===pid&&child.connected===true&&child.exitCode===null&&child.signalCode===null,'G101_PROCESS_DEAD');const dir='/proc/'+pid;need(fs.statSync(dir).uid===process.getuid()&&fs.realpathSync(dir+'/exe')===exe,'G101_PROCESS_OWNER');const stat=fs.readFileSync(dir+'/stat','utf8'),tail=stat.slice(stat.lastIndexOf(')')+2).trim().split(/\s+/);const start=tail[19];need(/^[1-9][0-9]*$/.test(start),'G101_PROCESS_START');need(fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim()===boot,'G101_BOOT_CHANGED');return freeze({profile:'OS_OBSERVED_TEST_PROCESS',process_binding:{host_id,boot_id:boot,pid,start_ticks:start,uid:process.getuid(),generation,channel_binding_hash}});}catch{need(false,'G101_PEER_UNAVAILABLE');}}
 const initial=read();return Object.freeze({read(){const current=read();need(current.process_binding.start_ticks===initial.process_binding.start_ticks,'G101_PROCESS_REUSED');return current;},inspect:()=>freeze({pid,initial:copy(initial),assurance:'OS_OBSERVED_TEMPORARY_NODE_ONLY',native_authn:false,physical_decision:'DENY'})});
}
