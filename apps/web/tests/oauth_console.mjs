// Browser smoke tests for the compiled console against isolated API fixtures.
// This verifies UI behavior and request contracts; real tenant/security validation
// remains covered by the backend PostgreSQL integration tests. Requires Node 22+
// (built-in WebSocket) and Chromium. No dev sessions or database data are used.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {spawn} from 'node:child_process';
import assert from 'node:assert/strict';
const webRoot = path.resolve(import.meta.dirname, '..');
const root = process.env.PERMESI_WEB_TEST_DIST
  ? path.resolve(process.env.PERMESI_WEB_TEST_DIST)
  : path.join(webRoot, 'dist');
assert(fs.existsSync(path.join(root, 'index.html')), 'Run just web-build first');
const app='11111111-1111-4111-8111-111111111111';
const clientId='22222222-2222-4222-8222-222222222222';
const base=`/v1/orgs/crono/projects/jobs/envs/production/apps/${app}/oauth`;
const route=`/console/orgs/crono/projects/jobs/envs/production/apps/${app}`;
const time='2026-10-04T06:00:00Z';
let clients=[];
let registry=['openid','profile','email','address','phone','offline_access'].map((name,i)=>({id:`system-${i}`,application_id:app,name,description:`OIDC ${name} scope`,kind:'protocol',created_at:time,updated_at:time}));
let redirects=[], allowed=[];
let mutationForbidden=false;
let denyNextLifecycle=false;
const requests=[];
const fixtureFailures=[];
const server=http.createServer(async(req,res)=>{
 try {
 const url=new URL(req.url,'http://localhost');
 const p=url.pathname;
 let body=''; for await(const chunk of req)body+=chunk;
 let input=body?JSON.parse(body):null;
 const send=(status,value)=>{res.writeHead(status,{'Content-Type':typeof value==='string'?'text/plain':'application/json'});res.end(value===undefined?'':typeof value==='string'?value:JSON.stringify(value));};
 if(p.startsWith('/v1/')) {
  requests.push({method:req.method,path:p,input});
  if(mutationForbidden && req.method!=='GET')return send(404,'');
  if(p==='/v1/auth/session')return send(200,{user_id:'test-user',email:'ui@example.test',is_operator:false,session_kind:'full',totp_enabled:true,webauthn_enabled:false});
  if(p==='/v1/orgs')return send(200,[{id:'org',slug:'crono',name:'Crono',created_at:time}]);
  if(p==='/v1/orgs/crono/projects')return send(200,[{id:'project',slug:'jobs',name:'Jobs',created_at:time}]);
  if(p==='/v1/orgs/crono/projects/jobs/envs')return send(200,[{id:'env',slug:'production',name:'Production',tier:'production',created_at:time}]);
  if(p===`/v1/orgs/crono/projects/jobs/envs/production/apps`)return send(200,[{id:app,name:'Crono',created_at:time}]);
  if(p===`${base}/clients`) {
   if(req.method==='GET')return send(200,clients);
   assert.deepEqual(Object.keys(input).sort(),['client_type','name']);
   const value={id:'internal-row-id',application_id:app,client_id:clientId,name:input.name,client_type:input.client_type,created_at:time,updated_at:time,disabled_at:null};clients=[value];return send(201,value);
  }
  if(p===`${base}/clients/${clientId}`) {
   if(denyNextLifecycle && req.method==='PATCH' && input.disabled!==undefined){denyNextLifecycle=false;await new Promise(resolve=>setTimeout(resolve,1500));return send(404,'');}
   if(req.method==='GET')return send(200,clients[0]);
   if(req.method==='DELETE'){clients=[];return send(204);}
   if(input.name)clients[0].name=input.name;
   if('disabled' in input)clients[0].disabled_at=input.disabled?time:null;
   return send(200,clients[0]);
  }
  if(p===`${base}/clients/${clientId}/redirect-uris`) {
   if(req.method==='GET')return send(200,redirects);
   if(input.redirect_uris.some(value=>value.includes('#')))return send(400,'Redirect URI contains invalid characters or is too long.');
   redirects=input.redirect_uris;return send(200,redirects);
  }
  if(p===`${base}/clients/${clientId}/scopes`) {if(req.method==='GET')return send(200,allowed);allowed=input.scopes;return send(200,allowed);}
  if(p===`${base}/scopes`) {
   if(req.method==='GET')return send(200,registry);
   assert.deepEqual(Object.keys(input).sort(),['description','name']);
   if(['openid','profile','email','address','phone','offline_access'].includes(input.name))return send(400,'Scope name is reserved.');
   const value={id:'scope-api',application_id:app,name:input.name,description:input.description,kind:'application',created_at:time,updated_at:time};registry.push(value);return send(201,value);
  }
  if(p===`${base}/scopes/scope-api`) {
   if(req.method==='PATCH'){registry.find(value=>value.id==='scope-api').description=input.description;return send(200,registry.find(value=>value.id==='scope-api'));}
   registry=registry.filter(value=>value.id!=='scope-api');allowed=allowed.filter(value=>value!=='jobs:read');return send(204);
  }
  return send(404,'');
 }
 if(p==='/config.js'){res.writeHead(200,{'Content-Type':'application/javascript'});return res.end(`window.PERMESI_CONFIG={api_base_url:location.origin};`);}
 const target=path.join(root,p==='/'?'index.html':p);
 const file=fs.existsSync(target)&&fs.statSync(target).isFile()?target:path.join(root,'index.html');
 res.writeHead(200,{'Content-Type':file.endsWith('.wasm')?'application/wasm':file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':file.endsWith('.svg')?'image/svg+xml':'text/html'});
 fs.createReadStream(file).pipe(res);
 } catch(error) {
  fixtureFailures.push(error.message);
  if(!res.headersSent)res.writeHead(500, {'Content-Type':'text/plain'});
  res.end('Fixture rejected an unexpected request');
 }
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin=`http://127.0.0.1:${server.address().port}`;
const profile=`/tmp/permesi-oauth-ui-browser-${process.pid}`;
fs.mkdirSync(profile);
const browser=spawn('chromium',['--headless','--no-sandbox','--disable-dev-shm-usage','--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'],{stdio:'ignore'});
let socket;
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
try {
 for(let i=0;i<100&&!fs.existsSync(`${profile}/DevToolsActivePort`);i++)await delay(100);
 const port=fs.readFileSync(`${profile}/DevToolsActivePort`,'utf8').split('\n')[0];
 const targets=await(await fetch(`http://127.0.0.1:${port}/json/list`)).json();
 socket=new WebSocket(targets.find(value=>value.type==='page').webSocketDebuggerUrl);
 await new Promise((resolve,reject)=>{socket.onopen=resolve;socket.onerror=reject;});
 let sequence=0;const pending=new Map();const exceptions=[];
 socket.onmessage=event=>{const value=JSON.parse(event.data);if(value.id){const callback=pending.get(value.id);pending.delete(value.id);value.error?callback.reject(value.error):callback.resolve(value.result);}if(value.method==='Runtime.exceptionThrown')exceptions.push(value.params);};
 const call=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});
 const evaluate=async(expression)=>{const result=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true,userGesture:true});if(result.exceptionDetails)throw Error(JSON.stringify(result.exceptionDetails));return result.result.value;};
 const wait=async(expression)=>{for(let i=0;i<100;i++){if(await evaluate(`(()=>{try{return Boolean(${expression});}catch{return false;}})()`))return;await delay(150);}throw Error(`Timeout: ${expression}\n${await evaluate('document.body.innerText')}`);};
 const control=text=>`(()=>{const scope=document.querySelector('dialog[open]')||document;return [...scope.querySelectorAll('a,button,summary')].find(e=>e.getClientRects().length&&!e.disabled&&(e.getAttribute('aria-label')===${JSON.stringify(text)}||e.textContent.trim()===${JSON.stringify(text)}));})()`;
 const click=async(text)=>{await wait(control(text));return evaluate(`(()=>{const e=${control(text)};if(!e)throw Error('Missing enabled control '+${JSON.stringify(text)});e.click();})()`);};
 const fill=async(id,value)=>evaluate(`(()=>{const e=document.getElementById(${JSON.stringify(id)});if(!e)throw Error('Missing input');const proto=e.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;Object.getOwnPropertyDescriptor(proto,'value').set.call(e,${JSON.stringify(value)});e.dispatchEvent(new Event('input',{bubbles:true}));})()`);
 const goto=async(p)=>{await call('Page.navigate',{url:origin+p});};
 await call('Runtime.enable');await call('Page.enable');await call('Page.bringToFront');
 await call('Page.addScriptToEvaluateOnNewDocument',{source:"localStorage.setItem('permesi_logged_in','true');"});
 await call('Emulation.setDeviceMetricsOverride',{width:1280,height:950,deviceScaleFactor:1,mobile:false});
 await goto('/console/orgs');await wait("document.body.innerText.includes('Crono')");
 await evaluate("[...document.querySelectorAll('a')].find(e=>e.href.endsWith('/console/orgs/crono')).click()");await wait("document.body.innerText.includes('Jobs')");
 await evaluate("[...document.querySelectorAll('a')].find(e=>e.href.endsWith('/projects/jobs')).click()");await wait("document.body.innerText.includes('Manage applications')");
 await evaluate("[...document.querySelectorAll('a')].find(e=>e.href.endsWith('/envs/production')).click()");
 await wait("document.body.innerText.includes('Applications in this environment')");
 await evaluate(`[...document.querySelectorAll('a')].find(e=>e.href.endsWith('/apps/${app}')).click()`);
 await wait("document.body.innerText.includes('Application overview')");
 assert.equal(await evaluate("document.querySelector('nav[aria-label=Application] a[aria-current=page]').getAttribute('aria-label')"),'Overview');
 await click('OAuth Configuration');await wait("document.body.innerText.includes('Manage clients →')");
 const assertNavigation=async(subsection)=>{
  assert.equal(await evaluate("document.querySelector('nav[aria-label=Application] a[aria-current=page]').getAttribute('aria-label')"),'OAuth Configuration');
  assert.equal(await evaluate("document.querySelector('nav[aria-label=\"OAuth configuration\"] a[aria-current=page]').getAttribute('aria-label')"),subsection);
  assert(await evaluate("[...document.querySelectorAll('nav[aria-label=Application] a,nav[aria-label=\"OAuth configuration\"] a')].every(e=>e.querySelector('.material-symbols-outlined[aria-hidden=true]') && e.querySelector('span:last-child').textContent.trim())"),'Navigation must retain labels and decorative Material Symbols');
  assert(await evaluate("document.querySelector('nav[aria-label=Application]').classList.contains('border-b') && document.querySelector('nav[aria-label=\"OAuth configuration\"]').classList.contains('rounded-lg')"),'Primary tabs and secondary segmented navigation must differ');
 };
 await assertNavigation('Summary');
 await click('Manage clients →');await wait("document.body.innerText.includes('No OAuth clients')");
 await click('+ Create OAuth Client');await wait("document.querySelector('#create-oauth-client').open");
 assert.equal(await evaluate("document.activeElement.closest('dialog')?.id"),'create-oauth-client');
 await evaluate("(()=>{const dialog=document.querySelector('#create-oauth-client');dialog.close();dialog.showModal();})()");await delay(100);
 assert(await evaluate("document.querySelector('#create-oauth-client').open"),'A queued close from an earlier opening must not dismiss a reopened dialog');
 const bounds=await evaluate("(()=>{const r=document.querySelector('#create-oauth-client').getBoundingClientRect();return {left:r.left,top:r.top,width:r.width,height:r.height,viewport:window.innerWidth}})()");
 console.log('Dialog bounds:',bounds);
 assert(Math.abs(bounds.left-(bounds.viewport-bounds.width)/2)<2,'Dialog must be centered horizontally');
 await fill('oauth-client-name','crono-web');await click('Create Client');
 await wait("document.body.innerText.includes('Allowed Scopes')");
 await assertNavigation('Clients');
 assert(!await evaluate("document.body.innerText.includes('internal-row-id')"));
 await click('Copy');await wait("document.body.innerText.includes('Copied.')");
 await fill('redirect-uri-input','https://EXAMPLE:443/a/../callback?x=%2f#fragment');await click('Add URI');await click('Save Redirect URIs');
 await wait("document.querySelector('#redirect-error').innerText.includes('invalid characters')");
 assert.equal(redirects.length,0);
 assert(await evaluate("document.body.innerText.includes('https://EXAMPLE:443/a/../callback?x=%2f#fragment')"));
 await click('Remove');await fill('redirect-uri-input','https://EXAMPLE:443/a/../callback?x=%2f');await click('Add URI');await click('Save Redirect URIs');
 await wait("document.body.innerText.includes('Redirect URIs saved.')");assert.equal(redirects[0],'https://EXAMPLE:443/a/../callback?x=%2f');
 await evaluate("[...document.querySelectorAll('input[type=checkbox]')].find(e=>e.closest('label').textContent.startsWith('openid')).click()");await click('Save Allowed Scopes');await wait("document.body.innerText.includes('Allowed scopes saved.')");assert.deepEqual(allowed,['openid']);
 assert.equal(await evaluate("getComputedStyle([...document.querySelectorAll('button')].find(e=>e.textContent==='Save Redirect URIs')).cursor"),'not-allowed');
 await fill('redirect-uri-input','https://example/second');await click('Add URI');await click('Save Redirect URIs');await wait("document.body.innerText.includes('Redirect URIs saved.')");
 await evaluate("[...document.querySelectorAll('button')].find(e=>e.getAttribute('aria-label')==='Remove redirect URI https://EXAMPLE:443/a/../callback?x=%2f').click()");
 await fill('redirect-uri-input','https://EXAMPLE:443/a/../callback?x=%2f');await click('Add URI');
 assert(await evaluate("[...document.querySelectorAll('button')].find(e=>e.textContent==='Save Redirect URIs').disabled"),'Unchanged URI set must not be saved');
 await fill('client-edit-name','renamed-web');await click('Save Name');await wait("document.body.innerText.includes('Client name saved.')");
 const desktop=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});fs.writeFileSync('/tmp/permesi-oauth-ui-client-desktop.png',Buffer.from(desktop.data,'base64'));
 await call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:false});await delay(400);
 assert(await evaluate('document.documentElement.scrollWidth <= 390'), 'Mobile page overflows the configured 390px viewport');
 const mobile=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});fs.writeFileSync('/tmp/permesi-oauth-ui-client-mobile.png',Buffer.from(mobile.data,'base64'));
 denyNextLifecycle=true;await click('Disable Client');await wait("document.querySelector('#client-lifecycle').open");await click('Confirm');
 for(let i=0;i<2;i++){await call('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});await call('Input.dispatchKeyEvent',{type:'keyUp',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});}
 await evaluate("document.querySelector('#client-lifecycle').close()");await delay(150);
 assert(await evaluate("document.querySelector('#client-lifecycle').open"),'Busy dialog must reopen after a forced browser close');
 await wait("document.querySelector('#lifecycle-error').innerText.includes('organization role')");assert(await evaluate("document.querySelector('#client-lifecycle').open"),'Failed lifecycle request must remain visible');await click('Cancel');
 await click('Disable Client');await wait("document.querySelector('#client-lifecycle').open");await click('Confirm');await wait("document.body.innerText.includes('Enable Client')");assert(clients[0].disabled_at);
 await click('Enable Client');await wait("document.querySelector('#client-lifecycle').open");await click('Confirm');await wait("document.body.innerText.includes('Disable Client')");assert.equal(clients[0].disabled_at,null);
 const lightCardColor=await evaluate("getComputedStyle(document.querySelector('#client-settings-heading').closest('section')).backgroundColor");
 const lightTextColor=await evaluate("getComputedStyle(document.querySelector('#client-settings-heading')).color");
 await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-color-scheme',value:'dark'}]});
 await delay(100);
 assert(await evaluate("matchMedia('(prefers-color-scheme: dark)').matches"));
 assert.notEqual(await evaluate("getComputedStyle(document.querySelector('#client-settings-heading').closest('section')).backgroundColor"), lightCardColor, 'Cards must render the dark theme');
 assert.notEqual(await evaluate("getComputedStyle(document.querySelector('#client-settings-heading')).color"), lightTextColor, 'Headings must remain readable in dark mode');
 const dark=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});fs.writeFileSync('/tmp/permesi-oauth-ui-client-dark.png',Buffer.from(dark.data,'base64'));
 await call('Emulation.setEmulatedMedia',{features:[]});
 await click('Scopes');await wait("document.body.innerText.includes('No application scopes')");await assertNavigation('Scopes');
 assert.equal(await evaluate("[...document.querySelectorAll('button')].filter(e=>e.getClientRects().length&&e.textContent==='Edit').length"),0);
 await click('+ Create Scope');await wait("document.querySelector('#create-oauth-scope').open");
 await fill('scope-resource','users');await fill('scope-action','invite');await click('Create Scope');await wait("document.querySelector('#create-scope-error').innerText.includes('reserved')");assert.equal(await evaluate("document.getElementById('scope-resource').value"),'users');
 await fill('scope-resource','jobs');await fill('scope-action','read:all');await click('Create Scope');await wait("document.querySelector('#create-scope-error').innerText.includes('without colons')");
 assert.equal(requests.filter(value=>value.method==='POST'&&value.path===`${base}/scopes`).length,0);
 await fill('scope-action','read');assert.equal(await evaluate("document.querySelector('#create-scope-error').textContent"),'');assert.equal(await evaluate("document.querySelector('#scope-preview').textContent"),'OAuth scope: jobs:read');
 await fill('scope-description','Read scheduled jobs');
 const creation=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});fs.writeFileSync('/tmp/permesi-resource-action-create.png',Buffer.from(creation.data,'base64'));
 await click('Create Scope');await wait("document.body.innerText.includes('Read scheduled jobs')");
 assert.deepEqual(requests.find(value=>value.method==='POST'&&value.path===`${base}/scopes`).input,{name:'jobs:read',description:'Read scheduled jobs'});
 assert(await evaluate("[...document.querySelectorAll('dt')].some(e=>e.textContent==='Resource' && e.nextElementSibling.textContent==='jobs') && [...document.querySelectorAll('dt')].some(e=>e.textContent==='Action' && e.nextElementSibling.textContent==='read')"),'Scope registry must show derived resource and action');
 const scopeList=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});fs.writeFileSync('/tmp/permesi-resource-action-scopes.png',Buffer.from(scopeList.data,'base64'));
 await click('Edit');await wait("document.querySelector('#edit-scope-scope-api').open");await fill('scope-description-scope-api','Read jobs and execution history');await click('Save Description');await wait("document.body.innerText.includes('Read jobs and execution history')");
 await goto(`${route}/oauth/clients/${clientId}`);await wait("document.body.innerText.includes('Allowed Scopes')");
 assert(await evaluate("[...document.querySelectorAll('#allowed-scopes-heading + p + form fieldset legend')].some(e=>e.textContent==='jobs') && document.querySelector('input[value=\"jobs:read\"]').closest('label').textContent.startsWith('read')"),'Client scopes must group by resource and display their action');
 await evaluate("[...document.querySelectorAll('input[type=checkbox]')].find(e=>e.value==='jobs:read').click()");await click('Save Allowed Scopes');await wait("document.body.innerText.includes('Allowed scopes saved.')");assert(allowed.includes('jobs:read'));
 registry.push({id:'unsupported-scope',application_id:app,name:'old.opaque',description:'Previously configured',kind:'application',created_at:time,updated_at:time});allowed.push('old.opaque');
 await goto(`${route}/oauth/clients/${clientId}`);await wait("document.body.innerText.includes('These configured scopes are unavailable')");
 assert(!await evaluate("document.querySelector('input[value=\"old.opaque\"]')"));
 assert(await evaluate("[...document.querySelectorAll('button')].find(e=>e.textContent==='Save Allowed Scopes').disabled"));
 await click('Remove unavailable scope old.opaque');assert(allowed.includes('old.opaque'),'Removal must stay in the draft until explicit Save');
 await click('Save Allowed Scopes');await wait("document.body.innerText.includes('Allowed scopes saved.')");assert(!allowed.includes('old.opaque'));registry=registry.filter(scope=>scope.name!=='old.opaque');
 const assignment=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});fs.writeFileSync('/tmp/permesi-resource-action-assignment.png',Buffer.from(assignment.data,'base64'));
 mutationForbidden=true;await fill('client-edit-name','must-stay-draft');await click('Save Name');await wait("document.querySelector('#client-settings-error').innerText.includes('organization role')");assert.equal(await evaluate("document.getElementById('client-edit-name').value"),'must-stay-draft');mutationForbidden=false;
 await click('Scopes');await wait("document.body.innerText.includes('Read jobs and execution history')");await assertNavigation('Scopes');await click('Delete');await wait("document.querySelector('#delete-scope-scope-api').open");
 assert(await evaluate("[...document.querySelectorAll('#delete-scope-scope-api button')].find(e=>e.textContent==='Delete Scope').disabled"));await fill('scope-confirmation-scope-api','jobs:read');await click('Delete Scope');await wait("document.body.innerText.includes('No application scopes')");assert(!allowed.includes('jobs:read'));
 await goto(`${route}/oauth/clients/${clientId}`);await wait("document.body.innerText.includes('Allowed Scopes')");await click('Delete Client');await wait("document.querySelector('#client-delete').open");
 assert(await evaluate("[...document.querySelectorAll('#client-delete button')].find(e=>e.textContent==='Delete Client').disabled"));await fill('delete-client-confirmation',clientId);await click('Delete Client');await wait("document.body.innerText.includes('No OAuth clients')");
 assert(requests.filter(value=>value.method==='POST'&&value.path===`${base}/clients`).length===1);
 assert(!requests.some(value=>value.path.includes('internal-row-id')));
 assert.deepEqual(exceptions,[]);
 assert.deepEqual(fixtureFailures,[]);
 console.log('Browser smoke passed: hierarchy, empty states, creation, public ID/copy, exact redirect bytes, rejected drafts, scope assignment/system immutability, name edits, lifecycle, typed deletion, role rejection, fixed 390px layout, dark mode, busy Escape/forced-close protection, queued-close reopening, independent navigation/icon states, disabled cursor, unchanged redirect save, resource/action composition and grouped assignment, no JS exceptions.');
 fs.writeFileSync('/tmp/permesi-oauth-ui-browser-requests.json',JSON.stringify(requests,null,2));
} finally {socket?.close();browser.kill('SIGTERM');await delay(500);server.close();fs.rmSync(profile,{recursive:true,force:true});}
