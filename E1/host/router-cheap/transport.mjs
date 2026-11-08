import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {need} from '../../contracts/index.mjs';
const hosts=new WeakSet();
export function isRouterCheapHostTransport(value){return Boolean(value&&hosts.has(value));}
function helperPath(){const p=fileURLToPath(new URL('./preflight.py',import.meta.url));need(/^[A-Z]:\\/.test(p),'CLOUD_WSL_HOST_PLATFORM');return '/mnt/'+p[0].toLowerCase()+p.slice(2).replaceAll('\\','/');}
export function createRouterCheapHostTransport(){
  const transport=Object.freeze({
    kind:'ROUTER_CHEAP_WSL_TRUSTED_HOST',
    async preflight(){
      const env={WSL_UTF8:'1'};for(const k of ['SystemRoot','WINDIR','PATH'])if(process.env[k])env[k]=process.env[k];
      return await new Promise((resolve,reject)=>{
        const child=spawn('wsl.exe',['--distribution','Ubuntu','--user','nox','--exec','/usr/bin/python3',helperPath(),'preflight'],{env,stdio:['ignore','pipe','pipe'],windowsHide:true});let output='',oversized=false;
        const timer=setTimeout(()=>{child.kill();reject(new Error('CLOUD_HOST_READ_TIMEOUT'));},160000);
        child.stdout.on('data',b=>{output+=b.toString('utf8');if(Buffer.byteLength(output)>1024*1024){oversized=true;child.kill();}});
        // WSL diagnostics and provider errors are not copied into caller logs.
        child.stderr.on('data',()=>{});
        child.once('error',()=>{clearTimeout(timer);reject(new Error('CLOUD_HOST_UNAVAILABLE'));});
        child.once('exit',code=>{clearTimeout(timer);try{need(code===0&&!oversized,'CLOUD_HOST_PREFLIGHT_FAILED');const data=JSON.parse(output);need(data.schema==='awe.e1.router-cheap.preflight/1'&&data.paid_generation_requests===0&&data.spending_enabled===false,'CLOUD_HOST_PREFLIGHT_SHAPE');resolve(data);}catch{reject(new Error('CLOUD_HOST_PREFLIGHT_FAILED'));}});
      });
    },
    verifyInputBound(){return false;},
    async send(){throw Object.assign(new Error('CLOUD_PAID_TRANSPORT_DISABLED'),{code:'CLOUD_PAID_TRANSPORT_DISABLED'});}
  });hosts.add(transport);return transport;
}
