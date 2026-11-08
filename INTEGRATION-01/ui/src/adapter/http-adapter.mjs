// Transport only. The server-side INT04/D03/D06/RT01/D07/D08 own every state.
export async function createOfflineAdapter(){
 let unresolved=null,token=null,cursor=0,timer=null,closed=false,reading=false;
 const listeners=new Set(),pendingKey='AWE_INT01_PENDING_COMMAND';
 async function read(url){const r=await fetch(url,{cache:'no-store',credentials:'same-origin'});if(!r.ok)throw Object.assign(new Error('Не удалось прочитать контур'),{code:'OFFLINE_READ_FAILED'});return r.json();}
 const session=await read('/api/session');token=session.csrfToken;
 async function getSnapshot(){if(unresolved){try{const r=await lookup(unresolved.idempotencyKey);if(r){unresolved=null;clearPending();}}catch{}}const s=await read('/api/snapshot');cursor=Math.max(cursor,s.revision);return {...s,commandHold:Boolean(unresolved),storageWarning:unresolved?'Команда с неизвестным ACK. Новые изменения закрыты до lookup.':s.storageWarning};}
 async function lookup(key){const r=await fetch('/api/commands/by-key?key='+encodeURIComponent(key),{cache:'no-store',credentials:'same-origin'});if(r.status===404)return null;if(!r.ok)throw new Error('COMMAND_LOOKUP_UNAVAILABLE');return r.json();}
 function savePending(command){try{sessionStorage.setItem(pendingKey,JSON.stringify(command));}catch{}}
 function clearPending(){unresolved=null;try{sessionStorage.removeItem(pendingKey);}catch{}}
 async function command(command){
  if(unresolved&&unresolved.idempotencyKey!==command.idempotencyKey)throw Object.assign(new Error('Предыдущий ACK неизвестен. Новый ключ не создаёт обход.'),{code:'COMMAND_ACK_UNKNOWN'});unresolved=command;savePending(command);
  try{
   const response=await fetch('/api/commands',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-Integration-CSRF':token},body:JSON.stringify(command)});
   const result=await response.json();if(!response.ok){clearPending();throw Object.assign(new Error(result.message??result.code),{code:result.code});}
   clearPending();return result;
  }catch(e){
   if(e.code)throw e;
   let receipt=null;try{receipt=await lookup(command.idempotencyKey);}catch{}
   if(receipt){clearPending();return receipt;}
   // Never issue another POST or new key after a missing ACK.
   throw Object.assign(new Error('ACK неизвестен. Команда сохранена локально; новый запуск закрыт до проверки исхода.'),{code:'COMMAND_ACK_UNKNOWN'});
  }
 }
 let recovered=null;try{recovered=JSON.parse(sessionStorage.getItem(pendingKey)||'null');}catch{}
 if(recovered){unresolved=recovered;const receipt=await lookup(recovered.idempotencyKey);if(receipt)clearPending();else throw Object.assign(new Error('Есть команда с неизвестным ACK. Продолжение закрыто; проверьте существующий inbox.'),{code:'COMMAND_ACK_UNKNOWN'});}
 function subscribe(listener){listeners.add(listener);if(!timer)timer=setInterval(async()=>{
  if(closed||reading)return;reading=true;try{const s=await read('/api/snapshot');if(s.revision>cursor){const event={id:'projection_'+s.revision,revision:s.revision,cursor:s.cursor,type:'PROJECTION_CHANGED'};cursor=s.revision;for(const fn of listeners)fn(event);}}catch{for(const fn of listeners)fn({revision:cursor+1,type:'TRANSPORT_DISCONNECTED'});}finally{reading=false;}
 },250);return ()=>{listeners.delete(listener);if(!listeners.size){clearInterval(timer);timer=null;}};}
 return {mode:'offline',contractVersion:'integration01.ui/1',getSnapshot,subscribe,command,dispose(){closed=true;clearInterval(timer);timer=null;listeners.clear();}};
}
