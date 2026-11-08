import https from 'node:https';
import dns from 'node:dns';
import {isIP} from 'node:net';
import {bounded,copy,digest,ensure,httpsUrl,sha} from './common.mjs';
const DOCS=new Set(['https://playwright.dev/docs/screenshots','https://docs.pytest.org/en/stable/','https://pandoc.org/MANUAL.html']);
export function publicAddress(ip){
 if(isIP(ip)===4){const a=ip.split('.').map(Number);return !(a[0]===0||a[0]===10||a[0]===127||a[0]>=224||(a[0]===169&&a[1]===254)||(a[0]===172&&a[1]>=16&&a[1]<=31)||(a[0]===192&&(a[1]===168||a[1]===0||a[1]===2))||(a[0]===100&&a[1]>=64&&a[1]<=127)||(a[0]===198&&(a[1]===18||a[1]===19||a[1]===51))||(a[0]===203&&a[1]===0&&a[2]===113));}
 if(isIP(ip)===6)return /^2[0-9a-f]{3}:/i.test(ip)&&!/^2001:(?:db8|0*:)/i.test(ip)&&!/^2002:/i.test(ip);
 return false;
}
export function endpoint(spec){
 const s=bounded(spec,8192);let url;
 if(s.kind==='MCP'){ensure(s.limit===undefined||(Number.isInteger(s.limit)&&s.limit>0&&s.limit<=100),'TR_SOURCE_LIMIT');url=new URL('https://registry.modelcontextprotocol.io/v0.1/servers');url.searchParams.set('limit',String(s.limit??20));if(s.cursor){ensure(typeof s.cursor==='string'&&s.cursor.length<=2048,'TR_CURSOR');url.searchParams.set('cursor',s.cursor);}if(s.query){ensure(typeof s.query==='string'&&s.query.length<=100,'TR_QUERY');url.searchParams.set('search',s.query);}}
 else if(s.kind==='GITHUB'){ensure(typeof s.repo==='string'&&/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(s.repo),'TR_REPO');ensure(s.page===undefined||(Number.isInteger(s.page)&&s.page>=1&&s.page<=100),'TR_PAGE');url=new URL('https://api.github.com/repos/'+s.repo+'/releases?per_page=20&page='+(s.page??1));}
 else if(s.kind==='NPM'){ensure(typeof s.name==='string'&&/^(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+$/.test(s.name)&&s.name.length<=160,'TR_PACKAGE');url=new URL('https://registry.npmjs.org/'+encodeURIComponent(s.name)+'/latest');}
 else if(s.kind==='PYPI'){ensure(typeof s.name==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$/.test(s.name),'TR_PACKAGE');url=new URL('https://pypi.org/pypi/'+encodeURIComponent(s.name)+'/json');}
 else if(s.kind==='DOCS'){ensure(DOCS.has(s.url),'TR_DOCS_NOT_PINNED');url=new URL(s.url);}
 else throw Error('TR_SOURCE_KIND');
 httpsUrl(url.href);return url.href;
}
// TLS validation stays on. Resolve once for the socket, reject every nonpublic answer;
// descriptions cannot add endpoints. Redirects are returned as failures, never followed.
export function safeGet(url,headers={}){
 const u=httpsUrl(url);return new Promise((resolve,reject)=>{
  const req=https.request(u,{method:'GET',headers:{'user-agent':'AWE-TR01-metadata-review/1.0','accept':'application/json,text/html;q=0.5',...headers},
   lookup:(host,opts,cb)=>dns.lookup(host,{all:true},(err,addresses)=>{
    if(err)return cb(err);if(!addresses.length||!addresses.every(a=>publicAddress(a.address)))return cb(Error('TR_PRIVATE_ADDRESS'));
    cb(null,opts.all?addresses:addresses[0].address,addresses[0].family);
   })},res=>{const chunks=[];let size=0;res.on('data',c=>{size+=c.length;if(size>4*1024*1024)req.destroy(Error('TR_RESPONSE_SIZE'));else chunks.push(c);});
    res.on('error',reject);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks).toString('utf8'),url:u.href}));});
  req.setTimeout(10000,()=>req.destroy(Error('TR_TIMEOUT')));req.on('error',reject);req.end();
 });
}
function normalizePayload(spec,payload,url){
 const r=[],quarantine=[];const add=(key,title,description,canonical,claims={})=>{
  try{ensure(typeof key==='string'&&key.length<=250&&typeof title==='string'&&typeof description==='string','TR_SOURCE_SHAPE');
   const u=httpsUrl(canonical);r.push({id:'new-'+sha(spec.kind+':'+key).slice(0,24),source:spec.kind,source_row:r.length+1,url:u.href,title,description:description.slice(0,180000),category:'SOURCE_UNCLASSIFIED',resource_type:spec.kind==='MCP'?'mcp_server':spec.kind==='DOCS'?'documentation':'package_or_repository',confidence:'low',claims:{...claims,source_url:url,certainty:'PUBLISHER_METADATA_NOT_RUNTIME_TEST'}});
  }catch(e){quarantine.push({key,error:e.message});}
 };
 if(spec.kind==='MCP'){
  ensure(Array.isArray(payload.servers)&&payload.servers.length<=100,'TR_MCP_SHAPE');
  for(const item of payload.servers){const s=item.server??{};const status=item._meta?.['io.modelcontextprotocol.registry/official']?.status??'unknown';
   add(s.name+'@'+s.version,s.title??s.name,s.description,'https://registry.modelcontextprotocol.io/v0.1/servers/'+encodeURIComponent(s.name),{version:s.version??'UNKNOWN',publisher:s.name,status,repository:s.repository?.url??null});}
 }else if(spec.kind==='GITHUB'){
  ensure(Array.isArray(payload)&&payload.length<=100,'TR_GITHUB_SHAPE');
  for(const s of payload){ensure(typeof s.html_url==='string'&&s.html_url.startsWith('https://github.com/'+spec.repo+'/releases/'),'TR_RELEASE_ORIGIN');
   add(String(s.id),s.name??s.tag_name,s.body??'GitHub release metadata','https://github.com/'+spec.repo,{version:s.tag_name,published_at:s.published_at,release_url:s.html_url,prerelease:s.prerelease,draft:s.draft,license:'UNKNOWN'});}
 }else if(spec.kind==='NPM'){
  ensure(payload.name===spec.name,'TR_PACKAGE_IDENTITY');add(payload.name,payload.name,payload.description??'npm metadata','https://www.npmjs.com/package/'+spec.name,{version:payload.version,license:payload.license??'UNKNOWN',dependencies:payload.dependencies??{},integrity:payload.dist?.integrity??null});
 }else if(spec.kind==='PYPI'){
  const s=payload.info??{};ensure(typeof s.name==='string'&&s.name.toLowerCase().replace(/[-_.]+/g,'-')===spec.name.toLowerCase().replace(/[-_.]+/g,'-'),'TR_PACKAGE_IDENTITY');
  add(s.name,s.name,s.summary??'PyPI metadata','https://pypi.org/project/'+s.name+'/',{version:s.version,license:s.license_expression??s.license??'UNKNOWN',dependencies:s.requires_dist??[],yanked:payload.urls?.every(x=>x.yanked)??false});
 }else{add(url,new URL(url).hostname,'Official documentation snapshot: '+url,url,{body_digest:digest(payload),content:'QUARANTINED_NOT_PROMPTED'});}
 return {records:r,quarantine};
}
export function createSourceSync({transport=safeGet,clock=()=>Date.now(),state={},minIntervalMs=1000}={}){
 ensure(minIntervalMs>=0&&Number.isFinite(minIntervalMs),'TR_INTERVAL');const current=bounded(state,16*1024*1024),inflight=new Set();
 return Object.freeze({
  async refresh(spec,{optIn=false}={}){
   ensure(optIn===true,'TR_REFRESH_OPT_IN_REQUIRED');const url=endpoint(spec),key=spec.kind+':'+new URL(url).host;
   ensure(!inflight.has(key),'TR_SOURCE_BUSY');const prev=current[url]??{},rate=current['rate:'+key]??{};
   ensure(clock()>=(rate.next_at??0)&&clock()>=(prev.next_at??0),'TR_RATE_LIMIT');inflight.add(key);current['rate:'+key]={next_at:clock()+minIntervalMs};
   const checked_at=new Date(clock()).toISOString();
   try{
    const response=await transport(url,prev.etag?{'if-none-match':prev.etag}:{});ensure(response.url===url,'TR_REDIRECT_DENIED');
    if(response.status===304){ensure(prev.body_digest,'TR_CACHE_MISS');return {status:'NOT_MODIFIED',url,checked_at,body_digest:prev.body_digest,records:[],quarantine:[],next_cursor:prev.next_cursor??null};}
    if(response.status===429||response.status===503){const retry=Number(response.headers['retry-after']);const attempts=Math.min((prev.failures??0)+1,10);const delay=Number.isFinite(retry)&&retry>0?Math.min(retry*1000,86400000):Math.min(1000*2**attempts,3600000);current[url]={...prev,next_at:clock()+delay,failures:attempts};return {status:'RATE_LIMITED',url,checked_at,retry_at:current[url].next_at,records:[],quarantine:[]};}
    if(response.status===404||response.status===410){current[url]={...prev,availability:'UNAVAILABLE',last_checked:checked_at};return {status:'UNAVAILABLE',url,checked_at,records:[],quarantine:[],availability_scope:'SOURCE_ENDPOINT_ONLY'};}
    ensure(response.status===200,'TR_HTTP_FAILURE');ensure(Buffer.byteLength(response.body)<=4*1024*1024,'TR_RESPONSE_SIZE');
    const contentType=response.headers['content-type']??'';ensure(spec.kind==='DOCS'?/text\/(?:html|plain)/i.test(contentType):/application\/(?:[a-z.+-]*\+)?json/i.test(contentType),'TR_CONTENT_TYPE');
    const payload=spec.kind==='DOCS'?response.body:bounded(JSON.parse(response.body),4*1024*1024);
    const normalized=normalizePayload(spec,payload,url),body_digest=digest(payload);
    const cursor=payload?.metadata?.nextCursor??null;ensure(cursor===null||(typeof cursor==='string'&&cursor.length<=2048),'TR_CURSOR');
    current[url]={etag:response.headers.etag??null,body_digest,next_cursor:cursor,last_checked:checked_at,availability:'AVAILABLE',failures:0};
    return {status:'FETCHED',url,checked_at,body_digest,raw_body:response.body,...normalized,next_cursor:cursor,
     trust:{rank:spec.kind==='MCP'?90:spec.kind==='DOCS'?85:80,scope:'REGISTRY_ORIGIN_ONLY',safety_verified:false},physical_decision:'DENY'};
   }catch(e){current[url]={...prev,last_checked:checked_at,error:e.code??e.message,next_at:clock()+Math.min(1000*2**Math.min((prev.failures??0)+1,10),3600000),failures:(prev.failures??0)+1};return {status:'FAILED',url,checked_at,error:e.code??e.message,records:[],quarantine:[],physical_decision:'DENY'};}
   finally{inflight.delete(key);}
  },checkpoint:()=>copy(current)
 });
}
