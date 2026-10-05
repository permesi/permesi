// Compiled console against real PostgreSQL, OPAQUE and admission verification.
// Only static assets/proxy faults are simulated. No password/transcript/cookie is logged.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {spawn} from 'node:child_process';
import assert from 'node:assert/strict';
const api=process.env.PERMESI_DELETION_TEST_API;
const session=process.env.PERMESI_DELETION_TEST_SESSION;
const otherSession=process.env.PERMESI_DELETION_TEST_OTHER_SESSION;
const password=process.env.PERMESI_DELETION_TEST_PASSWORD;
assert(api&&session&&otherSession&&password,'Run through just web-test-browser');
const root=path.resolve(process.env.PERMESI_WEB_TEST_DIST||path.join(import.meta.dirname,'../dist'));
assert(fs.existsSync(path.join(root,'index.html')),'Build WASM first');
const endpoint='/v1/orgs/deletion-browser';
const route='/console/orgs/deletion-browser';
let fault=0;let deletes=0;let finishing=false;const statuses=[];
const server=http.createServer(async(req,res)=>{
 try {
  const p=new URL(req.url,'http://localhost').pathname;
  if(p==='/config.js') {res.writeHead(200,{'Content-Type':'application/javascript'});res.end("window.PERMESI_CONFIG={api_base_url:location.origin,token_base_url:location.origin,client_id:'00000000-0000-0000-0000-000000000000',opaque_server_id:'api.permesi.dev'};");return;}
  if(p.startsWith('/v1/')||p.startsWith('/test/')||p==='/token') {
   if(p===endpoint&&req.method==='DELETE')deletes++;
   if(p.endsWith('/reauth/start')&&fault) {const status=fault;fault=0;res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify({error:{code:status===429?'rate_limited':'unavailable',message:status===429?'Too many attempts. Please try again.':'Service unavailable. Please try again.'}}));return;}
   if(p.endsWith('/reauth/finish')){finishing=true;await new Promise(resolve=>setTimeout(resolve,350));}
   const chunks=[];for await(const chunk of req)chunks.push(chunk);
   const headers={...req.headers};delete headers.host;delete headers.connection;delete headers['content-length'];
   const response=await fetch(api+(p==='/token'?'/test/admission':req.url),{method:req.method,headers,body:['GET','HEAD'].includes(req.method)?undefined:Buffer.concat(chunks)});
   statuses.push({path:p,status:response.status});
   res.writeHead(response.status,Object.fromEntries(response.headers));res.end(Buffer.from(await response.arrayBuffer()));return;
  }
  const target=path.resolve(root,'.'+p);
  assert(target.startsWith(root+path.sep),'Static fixture path outside dist');
  const file=fs.existsSync(target)&&fs.statSync(target).isFile()?target:path.join(root,'index.html');
  res.writeHead(200,{'Content-Type':file.endsWith('.wasm')?'application/wasm':file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':file.endsWith('.svg')?'image/svg+xml':'text/html'});fs.createReadStream(file).pipe(res);
 } catch {res.writeHead(500);res.end('Fixture unavailable');}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin=`http://127.0.0.1:${server.address().port}`;
const profile=path.resolve(import.meta.dirname,'../../../.tmp',`tenant-deletion-browser-${process.pid}`);fs.mkdirSync(profile,{recursive:true});
const browser=spawn('chromium',['--headless','--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE ::1, EXCLUDE [::1]','--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'],{stdio:'ignore'});
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));let socket;
try {
 for(let i=0;i<100&&!fs.existsSync(`${profile}/DevToolsActivePort`);i++)await delay(100);
 const port=fs.readFileSync(`${profile}/DevToolsActivePort`,'utf8').split('\n')[0];
 const targets=await(await fetch(`http://127.0.0.1:${port}/json/list`)).json();
 socket=new WebSocket(targets.find(v=>v.type==='page').webSocketDebuggerUrl);
 await new Promise((resolve,reject)=>{socket.onopen=resolve;socket.onerror=reject;});
 let sequence=0;const pending=new Map();const exceptions=[];
 socket.onmessage=e=>{const v=JSON.parse(e.data);if(v.id){const cb=pending.get(v.id);pending.delete(v.id);v.error?cb.reject(v.error):cb.resolve(v.result);}if(v.method==='Runtime.exceptionThrown')exceptions.push(v.params.exceptionDetails.text);};
 const call=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});
 const evaluate=async expression=>{const r=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true,userGesture:true});if(r.exceptionDetails)throw Error('Browser evaluation failed');return r.result.value;};
 const wait=async expression=>{for(let i=0;i<120;i++){if(await evaluate(`(()=>{try{return Boolean(${expression});}catch{return false;}})()`))return;await delay(80);}throw Error('Browser state timed out: '+expression+' '+JSON.stringify(statuses)+' '+await evaluate('document.body.innerText'));};
 const control=text=>`(()=>{const scope=document.querySelector('dialog[open]')||document;return [...scope.querySelectorAll('button')].find(e=>{const c=e.cloneNode(true);c.querySelectorAll('[aria-hidden=true]').forEach(n=>n.remove());return e.getClientRects().length&&!e.disabled&&c.textContent.trim()===${JSON.stringify(text)};});})()`;
 const click=async text=>{await wait(control(text));await evaluate(`(${control(text)}).click()`);};
 const fill=async(id,value)=>evaluate(`(()=>{const e=document.getElementById(${JSON.stringify(id)});Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,${JSON.stringify(value)});e.dispatchEvent(new Event('input',{bubbles:true}));})()`);
 const fixture=async action=>{const r=await fetch(api+'/test/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})});assert.equal(r.status,200);return r.json();};
 const request=async(method,p,body)=>{const r=await fetch(api+p,{method,headers:{Cookie:`permesi_session=${session}`,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});return {status:r.status,body:r.status===204?null:await r.json()};};
 const cookie=async value=>call('Network.setCookie',{name:'permesi_session',value,url:origin,httpOnly:true,sameSite:'Lax'});
 const goto=async()=>{await call('Page.navigate',{url:origin+route});await wait("document.body.innerText.includes('Danger Zone')");};
 const open=async()=>{await click('Delete Organization');await wait("document.querySelector('#delete-resource').open && !document.querySelector('#resource-delete-confirmation').disabled");await fill('resource-delete-confirmation','deletion-browser');};
 const reauth=async()=>{await click('Delete Organization');await wait("document.querySelector('#resource-delete-password')");};
 const verify=async()=>{await fill('resource-delete-password',password);await click('Verify password');};
 await call('Runtime.enable');await call('Page.enable');await call('Network.enable');
 await call('Page.addScriptToEvaluateOnNewDocument',{source:"localStorage.setItem('permesi_logged_in','true');"});
 await cookie(session);await goto();await open();await reauth();
 const before=await fixture('status');const attempts=deletes;
 await fill('resource-delete-password','wrong-password');await click('Verify password');
 await wait("document.querySelector('#resource-delete-error').innerText.includes('Unable to verify password')");
 assert.equal(await evaluate("document.querySelector('#resource-delete-password').value"),'');assert.equal((await fixture('status')).auth_time,before.auth_time);assert.equal(deletes,attempts);
 for(const status of [429,503]) {fault=status;await verify();await wait("document.querySelector('#resource-delete-error').innerText.toLowerCase().includes('try again')");assert.equal(await evaluate("document.querySelector('#resource-delete-password').value"),'');assert.equal(deletes,attempts);}
 await call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:false});await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-color-scheme',value:'dark'}]});
 await verify();await wait("document.querySelector('#delete-resource button[type=submit]').disabled");await call('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape'});await call('Input.dispatchKeyEvent',{type:'keyUp',key:'Escape',code:'Escape'});assert(await evaluate("document.querySelector('#delete-resource').open"));
 await wait("document.querySelector('#resource-delete-confirmation') && !document.querySelector('#resource-delete-confirmation').disabled");
 assert.equal(await evaluate("document.querySelector('#resource-delete-confirmation').value"),'deletion-browser');assert.equal(deletes,attempts);assert((await fixture('status')).active);assert((await fixture('status')).auth_time>before.auth_time);
 assert.equal(await evaluate('document.activeElement.id'),'resource-delete-confirmation');assert(await evaluate('document.documentElement.scrollWidth<=390'));
 assert(!await evaluate("Object.values(localStorage).some(v=>v.includes("+JSON.stringify(password)+"))"));
 // A held Enter must not carry its auto-repeat into the destructive confirmation.
 await call('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,nativeVirtualKeyCode:13,text:'\r',unmodifiedText:'\r',autoRepeat:true});
 await call('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,nativeVirtualKeyCode:13});await delay(200);
 assert.equal(deletes,attempts,'Auto-repeated Enter must require a new explicit confirmation');assert((await fixture('status')).active);
 // A completed proof for an unmounted route cannot restore or submit its old confirmation.
 await fixture('stale');await reauth();finishing=false;await verify();
 for(let i=0;i<120&&!finishing;i++)await delay(80);assert(finishing,'Proof must reach the real finish handler');
 const routeAttempts=deletes;await call('Page.navigate',{url:origin+'/console/dashboard'});await wait("document.body.innerText.includes('Dashboard')");await delay(500);
 assert.equal(deletes,routeAttempts);assert(!await evaluate("document.querySelector('#resource-delete-password')"));await fixture('stale');await goto();await open();
 // A project appearing during real password verification blocks the returned confirmation.
 await fixture('stale');await reauth();await verify();
 assert.equal((await request('POST',endpoint+'/projects',{name:'Concurrent',slug:'concurrent'})).status,201);
 await wait("document.querySelector('#resource-delete-confirmation') && document.querySelector('#delete-resource button[type=submit]').disabled && document.querySelector('#resource-delete-blocker').innerText.includes('Delete all projects')");
 assert.equal(await evaluate("document.querySelector('#resource-delete-confirmation').value"),'deletion-browser');assert((await fixture('status')).active);
 assert.equal((await request('DELETE',endpoint+'/projects/concurrent')).status,204);await click('Cancel');await goto();await open();
 // Losing owner authority during proof closes the original confirmation and hides the action.
 await fixture('stale');await reauth();await verify();await fixture('role_lost');
 await wait("!document.querySelector('#delete-resource').open && !document.body.innerText.includes('Danger Zone') && document.querySelector('[role=alert]')?.innerText.includes('Your organization role no longer permits this deletion')");assert((await fixture('status')).active);
 await fixture('owner');await fixture('stale');await goto();await open();await reauth();
 // Cookie account change is checked before starting any password proof.
 const starts=statuses.filter(v=>v.path.endsWith('/reauth/start')).length;
 await cookie(otherSession);await verify();await wait("!document.querySelector('#delete-resource').open");assert.equal(statuses.filter(v=>v.path.endsWith('/reauth/start')).length,starts);assert((await fixture('status')).active);
 await cookie(session);await goto();await open();await reauth();
 // A renamed tenant's slug reused by another owned org invalidates the pinned confirmation.
 await verify();assert.equal((await request('PATCH',endpoint,{slug:'original-renamed'})).status,200);
 assert.equal((await request('POST','/v1/orgs',{name:'Replacement',slug:'deletion-browser'})).status,201);
 await wait("!document.querySelector('#delete-resource').open");assert((await fixture('status')).active);
 await goto();await click('Delete Organization');await wait("document.querySelector('#resource-delete-confirmation') && !document.querySelector('#resource-delete-confirmation').disabled");
 assert.equal(await evaluate("document.querySelector('#resource-delete-confirmation').value"),'','A new target requires a fresh draft');await fill('resource-delete-confirmation','deletion-browser');
 // Only this fresh explicit click deletes the replacement and navigates to the org list.
 await evaluate("document.querySelector('#resource-delete-confirmation').focus()");await call('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,nativeVirtualKeyCode:13,text:'\r',unmodifiedText:'\r',autoRepeat:false});await call('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,nativeVirtualKeyCode:13});await wait("location.pathname==='/console/orgs'");assert((await fixture('status')).active);
 assert.deepEqual(exceptions,[]);
 console.log('Real OPAQUE/PostgreSQL deletion browser passed: wrong password, throttle/network failures, secret clearing, busy Escape, dark/mobile/focus, refreshed child blockers, role loss, account switch, immutable target, explicit final deletion.');
} finally {socket?.close();browser.kill('SIGTERM');await delay(500);fs.rmSync(profile,{recursive:true,force:true});await new Promise(resolve=>server.close(resolve));}
