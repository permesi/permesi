// Compiled WASM against the production router and PostgreSQL. Only Vault step-up is a fixture.
// Profiles, cookies, Vault tokens and captured request/response bodies are never reported.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {spawn} from 'node:child_process';
import assert from 'node:assert/strict';

const api=process.env.PERMESI_INSPECTION_TEST_API;
const session=process.env.PERMESI_INSPECTION_TEST_SESSION;
const other=process.env.PERMESI_INSPECTION_TEST_OTHER_SESSION;
const application=process.env.PERMESI_INSPECTION_TEST_APP;
assert(api&&session&&other&&application,'Run through just web-test-browser');
const root=path.resolve(process.env.PERMESI_WEB_TEST_DIST||path.join(import.meta.dirname,'../dist'));
assert(fs.existsSync(path.join(root,'index.html')),'Build WASM first');
let inspectionWrites=0;const statuses=[];
const server=http.createServer(async(req,res)=>{
 try {
  const p=new URL(req.url,'http://localhost').pathname;
  if(p==='/config.js') {
   res.writeHead(200,{'Content-Type':'application/javascript'});
   res.end("window.PERMESI_CONFIG={api_base_url:location.origin,token_base_url:location.origin,client_id:'00000000-0000-0000-0000-000000000000',opaque_server_id:'api.permesi.dev'};");return;
  }
  if(p.startsWith('/v1/')) {
   if(p.startsWith('/v1/admin/orgs')&&!['GET','HEAD'].includes(req.method))inspectionWrites++;
   const chunks=[];for await(const chunk of req)chunks.push(chunk);
   const headers={...req.headers};delete headers.host;delete headers.connection;delete headers['content-length'];
   const response=await fetch(api+req.url,{method:req.method,headers,body:['GET','HEAD'].includes(req.method)?undefined:Buffer.concat(chunks)});
   statuses.push({path:p,status:response.status});
   res.writeHead(response.status,Object.fromEntries(response.headers));res.end(Buffer.from(await response.arrayBuffer()));return;
  }
  const target=path.resolve(root,'.'+p);assert(target.startsWith(root+path.sep),'Invalid asset path');
  const file=fs.existsSync(target)&&fs.statSync(target).isFile()?target:path.join(root,'index.html');
  res.writeHead(200,{'Content-Type':file.endsWith('.wasm')?'application/wasm':file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':file.endsWith('.svg')?'image/svg+xml':'text/html'});
  fs.createReadStream(file).pipe(res);
 } catch {res.writeHead(500);res.end('Fixture unavailable');}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin=`http://127.0.0.1:${server.address().port}`;
const profile=fs.mkdtempSync(path.resolve(import.meta.dirname,'../../../.tmp/admin-inspection-browser-'));
const browser=spawn('chromium',['--headless','--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE ::1, EXCLUDE [::1]','--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'],{stdio:'ignore'});
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
let socket;
try {
 for(let i=0;i<100&&!fs.existsSync(`${profile}/DevToolsActivePort`);i++)await delay(100);
 const port=fs.readFileSync(`${profile}/DevToolsActivePort`,'utf8').split('\n')[0];
 const targets=await(await fetch(`http://127.0.0.1:${port}/json/list`)).json();
 socket=new WebSocket(targets.find(value=>value.type==='page').webSocketDebuggerUrl);
 await new Promise((resolve,reject)=>{socket.onopen=resolve;socket.onerror=reject;});
 let sequence=0;const pending=new Map();const exceptions=[];
 socket.onmessage=event=>{const value=JSON.parse(event.data);if(value.id){const callback=pending.get(value.id);pending.delete(value.id);value.error?callback.reject(Error('DevTools request failed')):callback.resolve(value.result);}if(value.method==='Runtime.exceptionThrown')exceptions.push(value.params.exceptionDetails.text);};
 const call=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});
 const evaluate=async expression=>{const result=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true,userGesture:true});if(result.exceptionDetails)throw Error('Browser evaluation failed');return result.result.value;};
 const wait=async expression=>{for(let i=0;i<120;i++){if(await evaluate(`(()=>{try{return Boolean(${expression});}catch{return false;}})()`))return;await delay(80);}throw Error('Admin inspection browser state timed out: '+JSON.stringify(statuses));};
 const text=expression=>`document.body.innerText.includes(${JSON.stringify(expression)})`;
 const button=label=>`[...document.querySelectorAll('button')].find(e=>e.getClientRects().length&&!e.disabled&&e.textContent.trim().endsWith(${JSON.stringify(label)}))`;
 const clickButton=async label=>{await wait(button(label));await evaluate(`(${button(label)}).click()`);};
 const link=href=>`[...document.querySelectorAll('a')].find(e=>new URL(e.href).pathname===${JSON.stringify(href)}&&e.getClientRects().length)`;
 const clickLink=async href=>{await wait(link(href));await evaluate(`(${link(href)}).click()`);};
 const readonly=async()=>{assert(await evaluate(text('Read-only platform inspection')));assert.equal(await evaluate(`document.querySelectorAll('aside a[aria-current="page"]').length`),1,'Only the current admin section should be active');assert(!await evaluate("/Danger Zone|New Project|Create Project|Create Environment|Delete Organization|New application/.test(document.body.innerText)"),'Admin inspection must not mount tenant-management controls');};
 const cookie=value=>call('Network.setCookie',{name:'permesi_session',value,url:origin,httpOnly:true,sameSite:'Lax'});
 await call('Runtime.enable');await call('Page.enable');await call('Network.enable');
 await call('Page.addScriptToEvaluateOnNewDocument',{source:"localStorage.setItem('permesi_logged_in','true');"});
 await cookie(session);
 await call('Page.navigate',{url:origin+'/console/admin/claim'});
 await wait("document.querySelector('input[placeholder=\"s.xxxxx\"]')");
 await evaluate("(()=>{const e=document.querySelector('input[placeholder=\"s.xxxxx\"]');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,'inspection-fixture-step-up');e.dispatchEvent(new Event('input',{bubbles:true}));})()");
 await clickButton('Elevate');await wait(`${text('Admin token active until')}||${text('Claimed successfully')}`);await clickLink('/console/admin');await wait(text('Admin Dashboard'));
 const card="[...document.querySelectorAll('a')].find(e=>e.querySelector('h2')?.textContent==='Organizations')";
 await wait(card);
 assert.equal(await evaluate(`new URL((${card}).href).pathname`),'/console/admin/orgs','Dashboard must open the global admin directory');
 await evaluate(`(${card}).click()`);
 await wait(text('foreign-owned'));await readonly();
 assert(await evaluate(text('operator-owned')));
 await clickButton('Next');await wait(`!${text('foreign-owned')}&&${text('Page organization')}`);
 await clickButton('Previous');await wait(text('foreign-owned'));
 const org='/console/admin/orgs/foreign-owned';
 const project=org+'/projects/main';const environment=project+'/envs/test';
 for(const [href,label] of [[org,'Main project'],[project,'Test environment'],[environment,'Application'],[environment+'/apps/'+application,application]]) {
  await clickLink(href);await wait(text(label));await readonly();
 }
 await wait(text('Application <img'));
 assert.equal(await evaluate(`document.querySelectorAll('section[aria-label="Read-only platform inspection"] img').length`),0,'Metadata must remain text rather than interpreted HTML');
 assert(!await evaluate("window.__inspectionXss===true"),'Untrusted metadata must not execute before navigation');
 const ordinary=await fetch(api+'/v1/orgs',{headers:{Cookie:`permesi_session=${session}`}});
 assert.equal(ordinary.status,200);assert.deepEqual((await ordinary.json()).map(value=>value.slug),['operator-owned']);
 const foreign=await fetch(api+'/v1/orgs/foreign-owned/projects',{headers:{Cookie:`permesi_session=${session}`}});
 assert.equal(foreign.status,404,'Inspection must not grant ordinary tenant access');
 await clickLink('/console/orgs');await wait(text('operator-owned'));assert(!await evaluate(text('foreign-owned')));
 await clickLink('/console/orgs/operator-owned');await wait(text('New Project'));await wait(text('Danger Zone'));assert(await evaluate(text('Danger Zone')),'Existing owner controls must remain available');
 await clickLink('/console/admin/orgs');await wait(text('foreign-owned'));
 await cookie(other);await clickButton('Refresh');await wait(text('operation is not authorized'));assert(!await evaluate(text('foreign-owned')),'Rejected reads must retire the previous metadata');
 await call('Page.navigate',{url:origin+'/console/orgs'});await wait(text('foreign-owned'));assert(!await evaluate(text('operator-owned')));assert(!await evaluate(text('Global Organizations')));
 await call('Page.navigate',{url:origin+'/console/admin/orgs'});await wait(text('404'));assert(!await evaluate(text('foreign-owned')));
 assert(!await evaluate("window.__inspectionXss===true"),'Other users metadata must be rendered as escaped text');
 assert.equal(inspectionWrites,0);assert.equal(exceptions.length,0,'No browser runtime exceptions');
 console.log('admin inspection browser passed');
} finally {
 socket?.close();browser.kill('SIGTERM');await delay(150);if(browser.exitCode===null)browser.kill('SIGKILL');
 await new Promise(resolve=>browser.exitCode!==null?resolve():browser.once('exit',resolve));
 await new Promise(resolve=>server.close(resolve));fs.rmSync(profile,{recursive:true,force:true});
}
