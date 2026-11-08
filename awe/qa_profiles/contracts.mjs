import {bytesHash,copy,digest,fields,frozen,need} from '../qa/common.mjs';
export {bytesHash,copy,digest,fields,frozen,need};
export const VERSION='qa02/1';
export const MAP={PASS:'QA_PASS',FAIL:'QA_FAIL',UNCLEAR:'QA_INCONCLUSIVE',BLOCKED:'QA_INCONCLUSIVE'};
const kinds={web:['web-text','web-action','web-responsive'],code:['code-case'],research:['claim'],document:['contains','markdown-sections','json-field','no-placeholder','exact-text','bytes-sha256']};
const shapes={
 'web-text':['kind','selector','expected'],
 'web-action':['kind','input','value','click','result','expected'],
 'web-responsive':['kind','widths'],
 'code-case':['kind','export_name','args','expected'],
 claim:['kind','claim_id','source_id','expected_claim','quote','max_age_ms'],
 contains:['kind','text'],'markdown-sections':['kind','headings'],
 'json-field':['kind','path','expected'],'no-placeholder':['kind'],'exact-text':['kind','text'],'bytes-sha256':['kind','expected']
};
export function validateProfile(p){
 fields(p,['version','profile','scope','spec','criteria','local_ids']);
 need(p.version===VERSION&&Object.hasOwn(kinds,p.profile),'PROFILE_VERSION');
 need(Array.isArray(p.criteria)&&p.criteria.length>0&&p.criteria.length<=32,'CRITERIA_REQUIRED');
 const ids=new Set();
 for(const c of p.criteria){
  fields(c,['id','requirement_id','check']);need(/^Q[0-9]{2}$/.test(c.id)&&!ids.has(c.id),'CRITERION_ID');ids.add(c.id);
  need(typeof c.requirement_id==='string'&&c.requirement_id.length>0,'REQUIREMENT_ID');
  need(kinds[p.profile].includes(c.check.kind),'CHECK_PROFILE');fields(c.check,shapes[c.check.kind]);
  if(c.check.kind==='code-case')need(/^[a-zA-Z_$][\w$]{0,63}$/.test(c.check.export_name)&&Array.isArray(c.check.args),'CODE_CASE');
  if(c.check.kind==='web-responsive')need(Array.isArray(c.check.widths)&&c.check.widths.length>0&&c.check.widths.length<=8&&c.check.widths.every(w=>Number.isInteger(w)&&w>=240&&w<=2560),'VIEWPORTS');
  if(c.check.kind==='claim')need(Number.isSafeInteger(c.check.max_age_ms)&&c.check.max_age_ms>0&&c.check.quote.length>0,'SOURCE_POLICY');
  if(c.check.kind==='exact-text')need(typeof c.check.text==='string'&&c.check.text.isWellFormed()&&Buffer.byteLength(c.check.text)<=4096,'EXACT_TEXT_LIMIT');
  if(c.check.kind==='bytes-sha256')need(/^sha256:[a-f0-9]{64}$/.test(c.check.expected),'EXACT_BYTES_HASH');
 }
 need(Array.isArray(p.local_ids)&&new Set(p.local_ids).size===p.local_ids.length&&p.local_ids.every(id=>ids.has(id)),'LOCAL_CRITERIA');
 need(Buffer.byteLength(JSON.stringify(p))<=32768,'PROFILE_SIZE');return frozen(copy(p));
}
export function verdict(rows){return rows.some(r=>r.status==='FAIL')?'FAIL':rows.some(r=>r.status==='BLOCKED')?'BLOCKED':rows.some(r=>r.status!=='PASS')?'UNCLEAR':rows.length?'PASS':'UNCLEAR';}
