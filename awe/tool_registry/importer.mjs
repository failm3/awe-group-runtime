import {bounded,sha,digest,urlKey} from './common.mjs';
import {classify} from './taxonomy.mjs';
export function reviewRows(rows,{snapshotId,observedAt}){
 const seen=new Set(),records=[],failures=[];
 for(let index=0;index<rows.length;index++){
  const raw=rows[index],locator={snapshot_id:snapshotId,pointer:'$['+index+']',index};
  try{
   const r=bounded(raw);if(typeof r.id!=='string'||!r.id||seen.has(r.id))throw Error('INVALID_OR_DUPLICATE_ROW_ID');seen.add(r.id);
   if(typeof r.description!=='string'||!r.description.trim()||!Number.isSafeInteger(r.source_row)||r.source_row<1||typeof r.source!=='string')throw Error('MALFORMED_RECORD');
   const key=urlKey(r.url),classification=classify(r);
   records.push({original_id:r.id,tool_id:'tool_'+sha(key).slice(0,40),source:r.source,source_row:r.source_row,
    locator,raw_digest:digest(r),url:r.url,canonical_url:key,duplicate_group:'dup_'+sha(key).slice(0,32),
    address_hint:new URL(r.url).hostname.toLowerCase().replace(/^www\./,'')+new URL(r.url).pathname.replace(/\/+$/,''),
    title:typeof r.title==='string'?r.title:r.id,description:r.description,description_trust:'UNTRUSTED_SOURCE_CLAIM',
    category:r.category??'UNKNOWN',secondary_categories:r.secondary_categories??'',type:r.resource_type??'UNKNOWN',
    purpose:{claim:r.description,certainty:'SOURCE_CLAIM'},...classification,
    source_confidence:r.confidence??'UNKNOWN',source_flags:r.flags??'',source_claims:r.claims??null,
    last_seen:observedAt,last_seen_scope:'LOCAL_CATALOG_SNAPSHOT',evidence_url:r.url,source_checked_at:null,
    vendor:'UNKNOWN',license:{value:'UNKNOWN',evidence:null},version:'UNKNOWN',entry_type:'UNKNOWN',
    platform:[],dependencies:[],auth_requirement:'UNKNOWN',cost:{amount_micros:null,currency:null,basis:'UNKNOWN',checked_at:null},
    compatibility:'NOT_TESTED',installed:'UNKNOWN',security:'NOT_TESTED',
    lifecycle:{found:true,studied:'METADATA_REVIEWED',verified:'NOT_RUN',permitted:false,available:'UNKNOWN',disabled:false,compromised:false},
    physical_decision:'DENY',review_required:true});
  }catch(e){failures.push({...locator,original_id:raw?.id??null,error:e.message,raw});}
 }
 const groups=new Map();for(const r of records){const g=groups.get(r.duplicate_group)??[];g.push(r.original_id);groups.set(r.duplicate_group,g);}
 for(const r of records)r.duplicate_ids=groups.get(r.duplicate_group);
 return {records,failures,coverage:{original:rows.length,reviewed:records.length,rejected:failures.length,
  externally_verified:0,runtime_verified:0,unresolved_external:records.length,unique_url_groups:groups.size,
  duplicate_extra_rows:records.length-groups.size,duplicate_rows:records.filter(r=>r.duplicate_ids.length>1).length,
  capability_unresolved:records.filter(r=>!r.capabilities.length).length,
  hazardous_review:records.filter(r=>r.hazards.length).length,unsupported_type:records.filter(r=>r.type==='UNKNOWN').length,
  costs_unknown:records.length,licenses_unknown:records.length,installed_unknown:records.length}};
}
