import http from 'node:http';
import {need} from '../contracts/index.mjs';

/** Disposable, read-only synthetic fixture. It has no forwarding or send adapter. */
export async function startFixtureHttp({feed,fixture_id,port=0,transient=false}){
 need(feed.schema==='awe.qa4.vacancy-feed/1'&&/^[a-z0-9_-]{8,80}$/.test(fixture_id),'RECRUIT_FIXTURE_CONFIG');
 const requests=[];let gets=0;
 const server=http.createServer((req,res)=>{
  if(req.method!=='GET'||req.url!=='/vacancies'||req.headers['x-awe-fixture']!==fixture_id){requests.push({method:req.method,status:403});res.writeHead(403);res.end();return;}
  gets++;const status=transient&&gets===1?429:200;requests.push({method:'GET',status});
  res.writeHead(status,{'Content-Type':'application/json','X-AWE-Fixture':fixture_id,'Cache-Control':'no-store'});res.end(JSON.stringify(status===200?feed:{error:'SYNTHETIC_INTERMITTENT_FAILURE'}));
 });
 server.requestTimeout=6000;server.headersTimeout=5000;
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});
 return {url:`http://127.0.0.1:${server.address().port}/vacancies`,port:server.address().port,requests,async close(){await new Promise((r,j)=>server.close(e=>e?j(e):r()));}};
}
