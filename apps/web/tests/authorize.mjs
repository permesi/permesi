// Real authorization-handler/consent browser test. The Rust fixture owns isolated
// PostgreSQL and an HTTP loopback listener; production dispatch still requires HTTPS.
// No external site, plaintext code storage, token endpoint or TLS bypass is used.
import fs from 'node:fs';
import path from 'node:path';
import {spawn} from 'node:child_process';
import assert from 'node:assert/strict';
const origin=process.env.PERMESI_AUTHORIZE_TEST_ORIGIN;
const issuer=process.env.PERMESI_AUTHORIZE_TEST_ISSUER;
const callbackOrigin=process.env.PERMESI_AUTHORIZE_TEST_CALLBACK_ORIGIN;
const authorizationUrl=process.env.PERMESI_AUTHORIZE_TEST_URL;
const session=process.env.PERMESI_AUTHORIZE_TEST_SESSION;
assert(origin&&issuer&&callbackOrigin&&authorizationUrl&&session,'Run through just web-test-browser');
assert.notEqual(origin,callbackOrigin,'The registered client must use a distinct origin');
const profile=path.resolve(import.meta.dirname,'../../../.tmp',`authorize-browser-${process.pid}`);
fs.mkdirSync(profile,{recursive:true});
const browser=spawn('chromium',['--headless','--no-sandbox','--disable-dev-shm-usage','--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'],{stdio:'ignore'});
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
let socket;
try {
 for(let i=0;i<100&&!fs.existsSync(`${profile}/DevToolsActivePort`);i++)await delay(100);
 const port=fs.readFileSync(`${profile}/DevToolsActivePort`,'utf8').split('\n')[0];
 const targets=await(await fetch(`http://127.0.0.1:${port}/json/list`)).json();
 socket=new WebSocket(targets.find(value=>value.type==='page').webSocketDebuggerUrl);
 await new Promise((resolve,reject)=>{socket.onopen=resolve;socket.onerror=reject;});
 let sequence=0;const pending=new Map();const exceptions=[];const responses=[];const submissions=[];
 socket.onmessage=event=>{const value=JSON.parse(event.data);if(value.id){const callback=pending.get(value.id);pending.delete(value.id);value.error?callback.reject(value.error):callback.resolve(value.result);}if(value.method==='Runtime.exceptionThrown')exceptions.push(value.params);if(value.method==='Network.responseReceived')responses.push({path:new URL(value.params.response.url).pathname,status:value.params.response.status});if(value.method==='Network.requestWillBeSentExtraInfo')submissions.push({origin:value.params.headers.Origin,site:value.params.headers['Sec-Fetch-Site'],cookieNames:(value.params.headers.Cookie||'').split(';').map(pair=>pair.trim().split('=')[0])});};
 const call=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});
 const evaluate=async expression=>{const result=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true,userGesture:true});if(result.exceptionDetails)throw Error('Browser script failed');return result.result.value;};
 const wait=async expression=>{for(let i=0;i<100;i++){if(await evaluate(`(()=>{try{return Boolean(${expression});}catch{return false;}})()`))return;await delay(100);}throw Error('Browser did not reach expected authorization state: '+JSON.stringify({responses,submissions})+' '+await evaluate('location.pathname+" "+document.body.innerText'));};
 const navigate=async url=>{await call('Page.navigate',{url});};
 const consentPage=()=>wait("document.querySelector('form[action=\"/authorize/consent\"]')");
 const callback=()=>wait(`location.origin===${JSON.stringify(callbackOrigin)} && location.pathname==='/callback'`);
 await call('Runtime.enable');await call('Page.enable');await call('Network.enable');
 await call('Network.setCookie',{name:'permesi_session',value:session,url:origin,httpOnly:true,sameSite:'Lax'});
 await navigate(authorizationUrl);await consentPage();
 assert(await evaluate("document.body.innerText.includes('Read jobs') && document.body.innerText.includes('Read execution history')"));
 assert(!await evaluate("document.body.innerText.includes('platform:admin') || document.body.innerText.includes('users:write') || document.body.innerText.includes('jobs:write')"));
 assert.equal(await evaluate("getComputedStyle(document.querySelector('button[value=allow]')).cursor"),'pointer');
 const cookies=await call('Network.getCookies',{urls:[origin]});
 const binding=cookies.cookies.find(cookie=>cookie.name==='__Host-permesi_oauth');
 assert(binding&&binding.secure&&binding.httpOnly&&binding.sameSite==='Lax','OAuth browser binding must be Secure, HttpOnly and Lax');
 assert(!await evaluate("document.cookie.includes('__Host-permesi_oauth')"));
 // Browser-submitted extra authority is rejected by the actual form parser.
 await evaluate("(()=>{const extra=document.createElement('input');extra.name='scope';extra.value='jobs:write';document.querySelector('form').append(extra);document.querySelector('button[value=allow]').click();})()");
 await wait("document.body.innerText.includes('invalid_request')");
 assert.equal(await evaluate("location.pathname"),'/authorize/consent');
 await navigate(authorizationUrl);await consentPage();
 const form=await evaluate("new URLSearchParams(new FormData(document.querySelector('form'))).toString()+'&decision=allow'");
 const consentScreenshot=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});
 fs.writeFileSync(path.resolve(profile,'../authorize-consent.png'),Buffer.from(consentScreenshot.data,'base64'));
 await evaluate("document.querySelector('button[value=allow]').click()");await callback();
 assert.equal(await evaluate("new URLSearchParams(location.search).get('state')"),'opaque + / & = % ü');
 assert(await evaluate("/^[A-Za-z0-9_-]{43}$/.test(new URLSearchParams(location.search).get('code'))"));
 assert.deepEqual(await evaluate("[...new URLSearchParams(location.search).keys()]"),['existing','code','iss','state']);
 assert.equal(await evaluate("new URLSearchParams(location.search).get('iss')"), issuer);
 // Replaying the exact allowed browser form cannot issue a second code.
 await navigate(origin+'/callback');await wait(`location.origin===${JSON.stringify(origin)} && location.pathname==='/callback'`);
 const replay=await evaluate(`(async()=>{const response=await fetch('/authorize/consent',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:${JSON.stringify(form)},redirect:'manual'});return response.status;})()`);
 assert.equal(replay,400);
 // Saved consent covers a subset and does not need another Allow action.
 const subset=new URL(authorizationUrl);subset.searchParams.set('scope','jobs:read');
 await navigate(subset.href);await callback();
 assert(await evaluate("new URLSearchParams(location.search).has('code')"));
 const forced=new URL(authorizationUrl);forced.searchParams.set('prompt','consent');
 await navigate(forced.href);await consentPage();
 await evaluate("document.querySelector('button[value=cancel]').click()");await callback();
 assert.equal(await evaluate("new URLSearchParams(location.search).get('error')"),'access_denied');
 assert.equal(await evaluate("new URLSearchParams(location.search).get('state')"),'opaque + / & = % ü');
 assert(!await evaluate("new URLSearchParams(location.search).has('code')"));
 assert.deepEqual(exceptions,[]);
 console.log('Real PostgreSQL authorization browser passed: HttpOnly/Secure binding, read-only consent, scope injection rejection, cross-origin code/state redirect, form replay rejection, saved subset consent, cross-origin Cancel.');
} finally {
 socket?.close();browser.kill('SIGTERM');await delay(500);fs.rmSync(profile,{recursive:true,force:true});
}
