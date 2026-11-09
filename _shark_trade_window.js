
const fs = require('fs');
const http = require('http');
const port = Number(process.env.SHARK_TRADE_DEBUG_PORT || 0);
const tradeUrl = process.env.SHARK_TRADE_URL || '';
const rawCookies = JSON.parse(process.env.SHARK_TRADE_COOKIES || '[]');
function out(value){process.stdout.write(JSON.stringify(value)+'\n');}
function getJson(path){return new Promise((resolve,reject)=>{http.get({host:'127.0.0.1',port,path,timeout:1500},res=>{let body='';res.on('data',c=>body+=c);res.on('end',()=>{try{resolve(JSON.parse(body));}catch(e){reject(e);}});}).on('error',reject).on('timeout',function(){this.destroy(new Error('CDP timeout'));});});}
async function main(){
 let version=null;
 for(let i=0;i<80;i++){try{version=await getJson('/json/version');if(version&&version.webSocketDebuggerUrl)break;}catch(e){}await new Promise(r=>setTimeout(r,100));}
 if(!version)throw new Error('Browser debugging endpoint did not start');
 const ws=new WebSocket(version.webSocketDebuggerUrl);
 await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
 let nextId=0;const pending=new Map();
 ws.onmessage=event=>{try{const msg=JSON.parse(event.data);if(msg.id&&pending.has(msg.id)){const p=pending.get(msg.id);pending.delete(msg.id);clearTimeout(p.timer);if(msg.error)p.reject(new Error(msg.error.message||'CDP error'));else p.resolve(msg.result||{});}}catch(e){}};
 function call(method,params={},sessionId){return new Promise((resolve,reject)=>{const id=++nextId;const timer=setTimeout(()=>{pending.delete(id);reject(new Error('CDP command timeout: '+method));},10000);pending.set(id,{resolve,reject,timer});const msg={id,method,params};if(sessionId)msg.sessionId=sessionId;ws.send(JSON.stringify(msg));});}
 const wantedTitle=process.env.SHARK_TRADE_WINDOW_TITLE || '';
 let target=null;
 for(let i=0;i<60;i++){
  const targets=await getJson('/json/list');
  target=targets.find(t=>t.type==='page'&&t.title===wantedTitle)||targets.find(t=>t.type==='page'&&String(t.title||'').startsWith('Steam Trade'));
  if(target)break;
  await new Promise(r=>setTimeout(r,100));
 }
 if(!target)throw new Error('Trade dialog target not found');
 const attached=await call('Target.attachToTarget',{targetId:target.id,flatten:true});
 const sessionId=attached.sessionId;
 await call('Network.enable',{},sessionId);
 await call('Page.enable',{},sessionId);
 const cookies=[];
 for(const raw of rawCookies){
  const pair=String(raw).split(';',1)[0].trim();const at=pair.indexOf('=');if(at<=0)continue;
  const name=pair.slice(0,at).trim(),value=pair.slice(at+1);
  cookies.push({name,value,domain:'.steamcommunity.com',path:'/',secure:true,sameSite:'Lax'});
 }
 if(!cookies.some(c=>c.name==='steamLoginSecure'))throw new Error('steamLoginSecure cookie is missing');
 await call('Network.setCookies',{cookies},sessionId);
 const nav=await call('Page.navigate',{url:tradeUrl},sessionId);
 if(nav.errorText)throw new Error(nav.errorText);
 out({ok:true});ws.close();setTimeout(()=>process.exit(0),250);
}
main().catch(e=>{out({ok:false,error:String(e&&e.message||e)});process.exit(1);});
