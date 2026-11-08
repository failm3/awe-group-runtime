import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createFuseCandidate} from '../../FUSE-01/host.mjs';
import {digest} from './fixtures.mjs';
const out=path.resolve(import.meta.dirname,'../../MASTER-INTEGRATION-01/evidence/owner02-'+Date.now());fs.mkdirSync(out,{recursive:true});
test('three runtime-generated FUSE goals reach reviewed registry and genuine D09 block without fixture ALLOW',async()=>{
 const nonce=randomUUID(),goals=[`Посчитай статистику текста ${nonce}. Без сети. Готово, когда: локальная таблица.`,`Проанализируй текст ${nonce}; сравни строки; составь отчёт. Без сети. Готово, когда: три результата.`,`Подготовь отчёт об ошибке исполнителя ${nonce}; исправь и перепроверь с максимум двумя доработками. Без сети.`],evidence=[];
 for(let i=0;i<goals.length;i++){const f=await createFuseCandidate({sessionId:'owner02_'+i,ownerContracts:true});await f.converse(goals[i]);const s=f.snapshot(),p=f.preflights[0];assert.equal(s.effects,0);assert.equal(p.sec_registry,'REGISTERED_E0_LOCAL_REVIEWED_ONLY');assert.equal(p.local_admission.code,'D09_LOCAL_AUTHORITY_UNAVAILABLE',JSON.stringify(p));assert.equal(s.accepted,false);assert.ok(Object.values(s.tasks).every(t=>t.state!=='COMPLETE'));evidence.push({goal:goals[i],goal_hash:digest(goals[i]),plan_hash:digest(s.plan),node_count:s.plan.content.nodes.length,preflight:p,snapshot:s,chain:{user_goal:'PASS',auto01_spec:'PASS_DYNAMIC_LEXICAL_OFFLINE',dynamic_dag:'PASS',d03_task:'PASS',sec_registry:'PASS_REVIEWED_CANDIDATE',d09_local_admission:'BLOCKED',local_artifact:'NOT_RUN',d07_readback:'NOT_RUN',qa02:'NOT_RUN',d08:'NOT_RUN',owner_acceptance:'NOT_RUN',d03_complete:'NOT_RUN'},real_bounded_executor_rework:'NOT_RUN_D09_BLOCKED'});}
 assert.equal(new Set(evidence.map(x=>x.plan_hash)).size,3);fs.writeFileSync(path.join(out,'fuse-goals.json'),JSON.stringify(evidence,null,2)+'\n');
});
test('FUSE cancel during preflight prevents even registry/admission call',async()=>{let release,entered;const pause=new Promise(r=>release=r),started=new Promise(r=>entered=r);const f=await createFuseCandidate({sessionId:'o02cancel',ownerContracts:true,beforePreflight:async()=>{entered();await pause;}});const run=f.converse('Подготовь отчёт');await started;await f.host.cancel();release();await run;assert.equal(f.preflights.length,0);assert.equal(f.snapshot().effects,0);});
