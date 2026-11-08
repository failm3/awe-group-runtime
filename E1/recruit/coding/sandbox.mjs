import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {need} from '../../contracts/index.mjs';

export async function runScoreSandbox({code,inputs}){
 need(typeof code==='string'&&Buffer.byteLength(code)<=4096&&Array.isArray(inputs)&&inputs.length<=64,'SCORE_SANDBOX_INPUT');
 const filename=fileURLToPath(new URL('./sandbox.py',import.meta.url)),helper='/mnt/'+filename[0].toLowerCase()+filename.slice(2).replaceAll('\\','/');
 const expected='sha256:'+createHash('sha256').update(code).digest('hex'),env=Object.fromEntries(['SystemRoot','WINDIR','PATH'].filter(k=>process.env[k]).map(k=>[k,process.env[k]]));env.WSL_UTF8='1';
 return new Promise((resolve,reject)=>{
  const child=spawn('wsl.exe',['-d','Ubuntu','-u','nox','--exec','/usr/bin/python3',helper],{env,stdio:['pipe','pipe','pipe'],windowsHide:true});let stdout='',settled=false;
  const finish=(e,v)=>{if(settled)return;settled=true;clearTimeout(timer);e?reject(e):resolve(v);};
  const timer=setTimeout(()=>{child.kill();finish(Error('SCORE_SANDBOX_TIMEOUT'));},12000);
  child.stdout.on('data',b=>{stdout+=b.toString('utf8');if(Buffer.byteLength(stdout)>65536){child.kill();finish(Error('SCORE_SANDBOX_OUTPUT_BOUND'));}});child.stderr.on('data',()=>{});
  child.once('error',()=>finish(Error('SCORE_SANDBOX_SPAWN')));child.once('exit',status=>{try{const result=JSON.parse(stdout);need(status===0&&result.status==='EXECUTED'&&result.source_digest===expected&&result.sandbox_enforced===true&&result.network==='DENY'&&result.scores.length===inputs.length,'SCORE_SANDBOX_DENIED');finish(null,result);}catch{finish(Error('SCORE_SANDBOX_DENIED'));}});
  child.stdin.on('error',()=>finish(Error('SCORE_SANDBOX_INPUT_FAILED')));child.stdin.end(JSON.stringify({code,inputs}));
 });
}
