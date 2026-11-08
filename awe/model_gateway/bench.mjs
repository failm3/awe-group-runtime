import {copy,hash} from './profiles.mjs';
import {requireThat as need,money,integer,ceilDiv} from '../budget/money.mjs';
const categories=['code','agent','tools','long_context','structured','extraction','errors','recovery'];
// 40 versioned, inspectable cases, fixed settings; code is scored by an external test sandbox in the live runbook.
export function benchmarkCases() {
  return categories.flatMap((category,ci)=>Array.from({length:5},(_,n)=>{
    const id=`${category}-${n+1}`,seed=ci*100+n+17;
    const specs={
      code:{prompt:[
        'Implement export function stableUnique(values) with SameValueZero semantics, preserving first occurrence. Return JavaScript source only.',
        'Implement export function parseCsv(text), RFC4180 subset: quoted comma, doubled quote, CRLF, empty fields; reject unterminated quote. Return JavaScript source only.',
        'Implement export function addMicros(a,b) for canonical nonnegative decimal strings of at most 30 digits. Reject overflow and malformed values. Never use floating point. Return JavaScript source only.',
        'Implement export function topo(nodes,edges): stable lexicographic topological order; reject cycles and unknown node edges. Return JavaScript source only.',
        'Implement export async function mapLimit(items,limit,fn): at most limit concurrent tasks, preserve input ordering, reject invalid limit. Return JavaScript source only.'
      ][n],oracle:{kind:'sandbox_tests',tests:[['empty','duplicates','NaN','object_identity','insertion_order','zero'],['quoted_comma','double_quote','CRLF','empty','unterminated'],['zero','30_digits','carry','overflow','leading_zero'],['DAG','stable_order','cycle','unknown_node','empty'],['concurrency','ordering','empty','invalid_limit','rejection']][n],variant:seed}},
      agent:{prompt:`In the provided read-only virtual repository, diagnose failure ${seed}, propose minimal patch, request tests via tool, read result, and report evidence. Never claim tests passed before tool reply.`,oracle:{kind:'trace',requires:['read','patch_proposal','test_request','test_readback','evidence'],forbids:['ungranted_write','fabricated_pass']}},
      tools:{prompt:`Call lookup with {key:"record-${seed}"}; after result call verify with {key:"record-${seed}",revision:${n+1}}. Do not execute other tools.`,oracle:{kind:'tools',expected:[{name:'lookup',arguments:{key:`record-${seed}`}},{name:'verify',arguments:{key:`record-${seed}`,revision:n+1}}]}},
      long_context:{prompt:`Find the single canonical record ${seed} in the deterministic corpus; ignore conflicting obsolete records. Return record value and offset.`,oracle:{kind:'corpus',seed,bytes:32768*(n+1),placement:['start','quarter','middle','three_quarters','end'][n],canonical:`VALUE_${seed}`}},
      structured:{prompt:`Return JSON only: {"record":"r${seed}","count":${n},"valid":true}. No additional properties.`,oracle:{kind:'exact',expected:{record:`r${seed}`,count:n,valid:true}}},
      extraction:{prompt:`Extract the current integer: superseded=${seed+1}; current=${seed}; future=${seed+2}. Return JSON {"value":...} only.`,oracle:{kind:'exact',expected:{value:seed}}},
      errors:{prompt:`Controller fixture ${seed}: inject auth failure, 429 without proof of non-delivery, timeout after acceptance, truncated SSE, or missing usage (variant ${n}). Return typed denial/unknown and never auto-fallback.`,oracle:{kind:'controller_fault',fault:['auth','429_unknown','timeout_after_accept','truncated_sse','missing_usage'][n]}},
      recovery:{prompt:`Controller fixture ${seed}: replay same IDs after ${['duplicate reply','lost COMMIT acknowledgement','cancellation after send intent','stale auth epoch','restore fence'][n]}; retain liability when uncertain.`,oracle:{kind:'controller_fault',fault:['duplicate','commit_unknown','cancel_sent','auth_stale','restore_fence'][n]}}
    };
    const c={version:'LLM01_BENCH_V1',id,category,seed,...specs[category],settings:{samples:3,maxOutput:2048,reasoning:'PIN_PER_MODEL',temperature:'ONLY_IF_SUPPORTED'},evidence:'DESIGN_NOT_MEASUREMENT'};
    return {...c,caseHash:hash(c)};
  }));
}
export function materializeCorpus(test) {
  need(test.oracle.kind==='corpus','CORPUS_REQUIRED');const {bytes,canonical,placement}=test.oracle;
  const padding='obsolete=IGNORE; '.repeat(Math.ceil(bytes/17)).slice(0,bytes);
  const offset=Math.floor(bytes*({start:0,quarter:0.25,middle:0.5,three_quarters:0.75,end:1}[placement]));
  const marker=`\nCANONICAL:${canonical}\n`;return {text:padding.slice(0,offset)+marker+padding.slice(offset),offset,canonical};
}
// Exact-case oracle only. Code, agent and faults require independently authenticated external scorers, never a worker PASS flag.
export function scoreExact(test,answer) {
  need(test.oracle.kind==='exact','INDEPENDENT_SCORER_REQUIRED');return hash(answer)===hash(test.oracle.expected);
}
export function wilson(successes,total) {
  integer(successes);integer(total);need(successes<=total && total>0,'SAMPLE_COUNT_INVALID');
  const z=1.959963984540054,p=successes/total,d=1+z*z/total,c=(p+z*z/(2*total))/d,h=z*Math.sqrt(p*(1-p)/total+z*z/(4*total*total))/d;
  return {low:Math.max(0,c-h),high:Math.min(1,c+h)};
}
// Money pooled across ALL attempts, repairs, failures and independent scoring; duplicate receipts rejected.
export function acceptedResultCost(records) {
  const rows=copy(records);need(Array.isArray(rows)&&rows.length>0,'RESULTS_REQUIRED');let spent=0n,unknown=false;const accepted=new Set(),receipts=new Set();
  for(const r of rows) {
    need(typeof r.taskId==='string' && typeof r.receiptId==='string' && !receipts.has(r.receiptId),'DUPLICATE_RECEIPT');receipts.add(r.receiptId);
    need(typeof r.accepted==='boolean' && ['INDEPENDENT_QA','NOT_ACCEPTED'].includes(r.acceptanceSource),'ACCEPTANCE_SOURCE_INVALID');
    if(r.costMicros===null)unknown=true;else spent+=money(r.costMicros);
    if(r.accepted){need(r.acceptanceSource==='INDEPENDENT_QA','WORKER_SELF_ACCEPTANCE_DENIED');accepted.add(r.taskId);}
  }
  return {spentMicros:String(spent),accepted:accepted.size,costPerAcceptedMicros:unknown||!accepted.size?null:String(ceilDiv(spent,BigInt(accepted.size))),
    status:unknown?'COST_UNKNOWN':accepted.size?'COMPUTED':'NO_ACCEPTED_RESULTS'};
}
