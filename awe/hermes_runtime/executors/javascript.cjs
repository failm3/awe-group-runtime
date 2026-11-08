'use strict';
const fs=require('node:fs');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const {program,values}=input;
let value;
if(program==='sum')value=values.reduce((a,b)=>a+b,0);
else if(program==='wait')setInterval(()=>{},100);
else if(program==='cpu'){for(;;)Math.sqrt(Math.random());}
else if(program==='memory'){const xs=[];for(;;)xs.push(Buffer.alloc(8*1024*1024,1));}
else if(program==='crash')process.exit(7);
else if(program==='flood'){for(let i=0;i<1000;i++)process.stdout.write('x'.repeat(4096));}
else if(program==='stderr'){for(let i=0;i<1000;i++)process.stderr.write('x'.repeat(4096));}
else if(program==='probe'){
 const denied=fn=>{try{fn();return false;}catch{return true;}};
 value={environment_clean:!process.env.RT02_SECRET_CANARY&&!process.env.NODE_OPTIONS&&!process.env.PATH,
  filesystem_denied:denied(()=>fs.readFileSync(process.execPath)),
  network_denied:denied(()=>require('node:net').connect(9,'127.0.0.1')),
  spawn_denied:denied(()=>require('node:child_process').spawn(process.execPath,['--version']))};
 fs.writeFileSync('local.txt','synthetic');
}
else throw Error('PROGRAM_DENIED');
if(value!==undefined)process.stdout.write(JSON.stringify({schema:'rt02.synthetic.result/1',value})+'\n');
