import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {canonicalize,digest,need} from '../../contracts/index.mjs';
import {validateAuthorizationDocument,validateCanaryGateDocument,verifyCloud4Receipt} from '../../cloud4/authority.mjs';

/** Calls only the root-provisioned nox signing helper. The signing key stays in
 * its protected WSL file; neither the provider key nor a private value crosses
 * this process boundary. Root pins the exported public-key digest beforehand.
 */
export function createCloud4HostSigner({trusted_public_key_digest}){
  need(/^sha256:[a-f0-9]{64}$/.test(trusted_public_key_digest),'CLOUD4_SIGNER_NOT_TRUSTED');
  return Object.freeze({async sign(document){
    const canary=document.schema==='awe.e1.cloud4.canary-gate/1';canary?validateCanaryGateDocument(document):validateAuthorizationDocument(document);const path=fileURLToPath(new URL('./authority4.py',import.meta.url));need(/^[A-Z]:\\/.test(path),'CLOUD4_WSL_PLATFORM');
    const helper='/mnt/'+path[0].toLowerCase()+path.slice(2).replaceAll('\\','/'),payload=canonicalize({operation:canary?'sign-canary-acceptance':'sign-owner-authorization',document,document_digest:digest(document)});need(Buffer.byteLength(payload)<=16384,'CLOUD4_SIGN_REQUEST_BOUND');
    const env={WSL_UTF8:'1'};for(const name of ['SystemRoot','WINDIR','PATH'])if(process.env[name])env[name]=process.env[name];
    return await new Promise((resolve,reject)=>{
      const child=spawn('wsl.exe',['--distribution','Ubuntu','--user','nox','--exec','/usr/bin/python3',helper],{env,stdio:['pipe','pipe','pipe'],windowsHide:true});let output='',done=false;
      const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);error?reject(error):resolve(value);};
      const timer=setTimeout(()=>{child.kill();finish(new Error('CLOUD4_SIGNER_TIMEOUT'));},20000);
      child.stdout.on('data',bytes=>{output+=bytes.toString('utf8');if(Buffer.byteLength(output)>32768){child.kill();finish(new Error('CLOUD4_SIGNER_OUTPUT_BOUND'));}});child.stderr.on('data',()=>{});
      child.once('error',()=>finish(new Error('CLOUD4_SIGNER_UNAVAILABLE')));child.once('exit',code=>{try{need(code===0,'CLOUD4_SIGNER_FAILED');finish(null,verifyCloud4Receipt(JSON.parse(output),{trusted_public_key_digest,schema:document.schema}));}catch{finish(new Error('CLOUD4_SIGNER_FAILED'));}});
      child.stdin.on('error',()=>finish(new Error('CLOUD4_SIGNER_WRITE_FAILED')));child.stdin.end(payload);
    });
  }});
}
