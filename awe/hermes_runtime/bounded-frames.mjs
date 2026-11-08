import {need,parseIntent} from './protocol.mjs';
// Reject before accumulating an unbounded line; UTF8 must decode losslessly.
export function boundedFrames({limit,onFrame,onError}) {
 let pending=Buffer.alloc(0),failed=false;
 const fail=()=>{if(!failed){failed=true;pending=Buffer.alloc(0);onError();}};
 return {push(chunk){
  if(failed)return;
  let start=0;
  for(let i=0;i<chunk.length;i++)if(chunk[i]===10){
   const piece=chunk.subarray(start,i);if(pending.length+piece.length>limit){fail();return;}
   try{const line=Buffer.concat([pending,piece]);pending=Buffer.alloc(0);const text=new TextDecoder('utf-8',{fatal:true}).decode(line);onFrame(parseIntent(text));}
   catch{fail();return;}start=i+1;
  }
  const rest=chunk.subarray(start);if(pending.length+rest.length>limit){fail();return;}pending=Buffer.concat([pending,rest]);
 },end(){if(pending.length)fail();},get failed(){return failed;}};
}
