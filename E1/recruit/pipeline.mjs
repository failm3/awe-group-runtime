import {createHash} from 'node:crypto';
import {digest,need,immutable} from '../contracts/index.mjs';

const listingFields=['listing_id','canonical_id','revision','title','employer','skills','status','published_at','expires_at','apply_path','description'].sort();
const id=/^job-\d{3}$/;
export function validateListing(x){
 return Boolean(x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).sort().join()===listingFields.join()&&typeof x.listing_id==='string'&&x.listing_id.length<=80&&id.test(x.canonical_id)&&Number.isSafeInteger(x.revision)&&x.revision>=1&&x.revision<=100&&['OPEN','CLOSED'].includes(x.status)&&['title','employer','description','apply_path','published_at','expires_at'].every(k=>typeof x[k]==='string'&&x[k].length<=2048)&&Array.isArray(x.skills)&&x.skills.length<=16&&x.skills.every(s=>typeof s==='string'&&s.length<=40)&&Number.isFinite(Date.parse(x.published_at))&&Number.isFinite(Date.parse(x.expires_at)));
}
const rawDigest=b=>'sha256:'+createHash('sha256').update(b).digest('hex');
export async function readFixtureSource({url,source_id,fixture_id,now=new Date().toISOString()}){
 const endpoint=new URL(url);need(endpoint.protocol==='http:'&&endpoint.hostname==='127.0.0.1'&&endpoint.pathname==='/vacancies'&&!endpoint.username&&!endpoint.password&&!endpoint.search&&!endpoint.hash&&Number(endpoint.port)>1024,'RECRUIT_FIXTURE_ORIGIN');
 need(['fixture_alpha','fixture_beta'].includes(source_id)&&/^[a-z0-9_-]{8,80}$/.test(fixture_id),'RECRUIT_FIXTURE_BINDING');
 const attempts=[];let feed;
 for(let i=0;i<3;i++){
  const response=await fetch(endpoint,{method:'GET',redirect:'error',headers:{'X-AWE-Fixture':fixture_id},signal:AbortSignal.timeout(5000)});
  need(!response.redirected&&response.url===endpoint.href&&response.headers.get('x-awe-fixture')===fixture_id,'RECRUIT_HTTP_IDENTITY');
  const reader=response.body.getReader();let size=0;const chunks=[];
  while(true){const part=await reader.read();if(part.done)break;size+=part.value.byteLength;if(size>49152){await reader.cancel();throw Error('RECRUIT_SOURCE_BOUND');}chunks.push(Buffer.from(part.value));}
  const bytes=Buffer.concat(chunks);attempts.push({method:'GET',status:response.status,response_digest:rawDigest(bytes)});
  if(response.status===429||response.status===503){if(i<2){await new Promise(r=>setTimeout(r,50));continue;}throw Error('RECRUIT_SOURCE_INCOMPLETE');}
  need(response.status===200&&/application\/json/.test(response.headers.get('content-type')??''),'RECRUIT_SOURCE_HTTP');
  feed=JSON.parse(bytes.toString('utf8'));break;
 }
 need(feed?.schema==='awe.qa4.vacancy-feed/1'&&feed.source_id===source_id&&Array.isArray(feed.listings)&&feed.listings.length<=40,'RECRUIT_FEED_SCHEMA');
 return immutable({schema:'awe.recruit.source/1',source_id,source_url:url,records:feed.listings,attempts,content_digest:digest(feed.listings),observed_at:now});
}

export function rankListings(sources,{now=new Date().toISOString(),scoreByEvidence=null}={}){
 need(Array.isArray(sources)&&sources.length===2&&new Set(sources.map(s=>s.source_id)).size===2,'RECRUIT_TWO_SOURCES');
 const groups=new Map(),invalidRevisions=new Map(),rejections=[];
 for(const source of sources){need(source.content_digest===digest(source.records),'RECRUIT_SOURCE_DIGEST');for(const record of source.records){
  if(!validateListing(record)){
   rejections.push({listing_id:typeof record?.listing_id==='string'?record.listing_id:'invalid',reason:'SCHEMA_INVALID'});
   // Invalid current evidence must not resurrect an older valid vacancy.
   if(id.test(record?.canonical_id??'')){const revision=Number.isSafeInteger(record.revision)&&record.revision>=1?record.revision:Infinity;invalidRevisions.set(record.canonical_id,Math.max(invalidRevisions.get(record.canonical_id)??0,revision));}
   continue;
  }
  const entries=groups.get(record.canonical_id)??[];entries.push({record,source_id:source.source_id});groups.set(record.canonical_id,entries);
 }}
 const eligible=[];
 for(const [canonical_id,all] of groups){
  const revision=Math.max(...all.map(x=>x.record.revision)),latest=all.filter(x=>x.record.revision===revision),record=latest[0].record;
  // Source-local listing IDs differ on true duplicates; all business content must agree.
  const business=x=>{const {listing_id,...body}=x;return digest(body);};
  let reason=(invalidRevisions.get(canonical_id)??0)>=revision?'INVALID_CURRENT_REVISION':latest.some(x=>business(x.record)!==business(record))?'REVISION_CONFLICT':null;
  if(!reason&&record.status!=='OPEN')reason='INACTIVE';
  if(!reason&&(Date.parse(record.expires_at)<=Date.parse(now)||Date.parse(record.published_at)>Date.parse(now)))reason='STALE';
  if(!reason&&(record.apply_path!=='/apply/'+canonical_id||/(?:ignore.{0,40}(?:previous|instruction)|system\s*(?:message|prompt)|override|exfiltrat|https?:\/\/)/i.test(record.description)))reason='INJECTION';
  if(reason){for(const item of latest)rejections.push({listing_id:item.record.listing_id,reason});continue;}
  const skills=new Set(record.skills.map(s=>s.toLowerCase())),reference=`${latest[0].source_id}:${record.listing_id}:r${revision}`;
  const score=scoreByEvidence===null?5*skills.has('javascript')+3*skills.has('sql')+2*skills.has('testing'):scoreByEvidence[reference];
  need(Number.isSafeInteger(score)&&score>=0&&score<=10,'RECRUIT_SCORE_PROVIDER_RESULT');
  const fact_refs=[...(skills.has('javascript')?['F1']:[]),...(skills.has('sql')?['F2']:[]),...(skills.has('testing')?['F3']:[])];
  eligible.push({canonical_id,listing_id:record.listing_id,revision,rank:0,score,evidence_refs:latest.map(x=>`${x.source_id}:${x.record.listing_id}:r${revision}`).sort(),fact_refs});
 }
 eligible.sort((a,b)=>b.score-a.score||a.canonical_id.localeCompare(b.canonical_id,'en'));
 need(eligible.length>=5,'RECRUIT_INSUFFICIENT_ELIGIBLE');
 return immutable({schema:'awe.recruit.ranking/1',selected:eligible.slice(0,5).map((x,i)=>({...x,rank:i+1})),rejections,eligible_ids:eligible.map(x=>x.canonical_id).sort(),deduplicated_count:eligible.length,source_digests:sources.map(s=>s.content_digest)});
}

export function draftApplications(ranking,facts){
 need(ranking.schema==='awe.recruit.ranking/1'&&ranking.selected.length===5,'RECRUIT_RANKING');
 need(Array.isArray(facts)&&facts.length===3&&new Set(facts.map(f=>f.id)).size===3,'RECRUIT_FACTS');
 const byId=new Map(facts.map(f=>[f.id,f.claim]));
 const drafts=ranking.selected.map(item=>{
  need(item.fact_refs.length>0&&item.fact_refs.every(f=>byId.has(f)),'RECRUIT_UNSUPPORTED_FACT');
  const text=`SYNTHETIC DRAFT ONLY. Fixture Applicant 4101 for ${item.canonical_id} revision ${item.revision}. ${item.fact_refs.map(f=>byId.get(f)).join(' ')} Delivery status: NOT_SENT.`;
  const body={canonical_id:item.canonical_id,revision:item.revision,text,fact_refs:item.fact_refs};return {...body,content_digest:digest(body)};
 });
 return immutable({schema:'awe.recruit.drafts/1',drafts,send_attempts:0});
}
