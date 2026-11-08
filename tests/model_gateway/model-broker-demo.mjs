import {writeFileSync} from 'node:fs';
import {brokerFixture,query,config,approvePlan} from './model-broker-fixtures.mjs';
import {success,notSent} from '../budget/fixtures.mjs';
const f=brokerFixture({config:config({allowFallback:true}),scripts:[[notSent(),success()],[success()]]});
const main=f.broker.plan('main',query('one',{maxAttempts:2})),approval=approvePlan(f,main);
const first=await f.broker.run(main.handle,approval);f.ledger.advanceClock(first.retryAt);
const completed=await f.broker.run(main.handle,approval);
const child=f.broker.plan('child',query('two')),childResult=await f.broker.run(child.handle,approvePlan(f,child));
const result={mode:'MOCK_ONLY',physicalDecision:'DENY',realModelCalls:0,reservationOwner:f.broker.owners(),
 first,completed,childResult,runtimePin:f.broker.runtimeModelPin(main.handle),usage:f.broker.usageByAgent('main'),
 totals:f.ledger.inspect().totals,accepted:false,qa:'NOT_RUN'};
writeFileSync('LLM-01/model-broker-2026-11-06/EXECUTION-EVIDENCE.json',JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify({main:completed.status,mainAttempts:completed.execution.attempts.length,child:childResult.status,usage:result.usage.groups,realModelCalls:0}));
