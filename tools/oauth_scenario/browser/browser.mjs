// Private JSON-line control channel. Never log evaluated expressions, URLs, cookies,
// OPAQUE material, callback parameters, exception stacks or browser stderr.
import {spawn} from 'node:child_process';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createInterface} from 'node:readline';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const directory = await mkdtemp(join(tmpdir(), 'scenario-browser-'));
const chromium = spawn('/usr/bin/chromium', ['--headless=new', '--no-sandbox', '--disable-dev-shm-usage',
  '--disable-background-networking', '--disable-extensions', '--no-first-run', '--no-default-browser-check',
  '--remote-debugging-pipe', `--user-data-dir=${directory}`, 'about:blank'],
  {stdio: ['ignore','ignore','ignore','pipe','pipe']});
let sequence = 0;
const pending = new Map();
let incoming = Buffer.alloc(0);
const contexts = new Map();

async function wait(check, seconds = 15) {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) { const value = await check(); if (value) return value; await sleep(100); }
  throw new Error('deadline');
}

function call(method, params = {}, sessionId) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('cdp_deadline')); }, 15000);
    pending.set(id, {resolve, reject, timer});
    chromium.stdio[3].write(JSON.stringify({id, method, params, ...(sessionId ? {sessionId} : {})}) + '\0');
  });
}

async function initialize() {
  const closed = () => { for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(new Error('browser_closed')); } pending.clear(); };
  chromium.on('error', closed); chromium.on('exit', closed);
  chromium.stdio[3].on('error', closed); chromium.stdio[4].on('error', closed);
  chromium.stdio[4].on('data', chunk => {
    incoming = Buffer.concat([incoming, chunk]);
    if (incoming.length > 4 * 1024 * 1024) { chromium.kill('SIGKILL'); closed(); return; }
    let boundary;
    while ((boundary = incoming.indexOf(0)) !== -1) {
      const bytes = incoming.subarray(0, boundary); incoming = incoming.subarray(boundary + 1);
      let response;
      try { response = JSON.parse(bytes.toString('utf8')); } catch { chromium.kill('SIGKILL'); closed(); return; }
      if (response.method === 'Network.requestWillBeSent' && response.params.type === 'Document' && response.params.redirectResponse) {
        for (const page of contexts.values()) if (page.session === response.sessionId) page.hadRedirect = true;
      }
      if (response.method === 'Network.responseReceived' && response.params.type === 'Document') {
        for (const page of contexts.values()) if (page.session === response.sessionId) {
          page.status = response.params.response.status;
          page.hasLocation = Object.keys(response.params.response.headers).some(name => name.toLowerCase() === 'location');
        }
      }
      const entry = pending.get(response.id); if (!entry) continue;
      pending.delete(response.id); clearTimeout(entry.timer);
      if (response.error) entry.reject(new Error('browser_protocol')); else entry.resolve(response.result);
    }
  });
  await call('Browser.getVersion');
}

async function evaluate(page, expression) {
  const response = await call('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true, userGesture:true}, page.session);
  if (response.exceptionDetails) throw new Error('browser_evaluation');
  return response.result?.value;
}

async function navigate(page, url, seconds) {
  page.status = null; page.hasLocation = null; page.hadRedirect = false;
  const previous = await evaluate(page, 'performance.timeOrigin');
  await call('Page.navigate', {url}, page.session);
  await wait(() => evaluate(page, `performance.timeOrigin !== ${JSON.stringify(previous)} && document.readyState === 'complete'`), seconds);
}

async function newPage(input) {
  if (contexts.has(input.actor)) { const old = contexts.get(input.actor); await call('Target.disposeBrowserContext', {browserContextId: old.context}); }
  const {browserContextId: context} = await call('Target.createBrowserContext');
  const {targetId} = await call('Target.createTarget', {url: 'about:blank', browserContextId: context});
  const {sessionId: session} = await call('Target.attachToTarget', {targetId, flatten: true});
  const page = {context, session, origin: input.origin, callback: input.callback}; contexts.set(input.actor, page);
  await call('Page.enable', {}, session); await call('Runtime.enable', {}, session); await call('Network.enable', {}, session);
  await call('Network.setBlockedURLs', {urls: ['https://fonts.googleapis.com/*', 'https://fonts.gstatic.com/*']}, session);
  return {stage: 'created'};
}

async function stage(page) {
  const result = await evaluate(page, `(() => {
    if (location.origin === ${JSON.stringify(new URL(page.callback).origin)} && location.pathname === '/callback') return {stage:'callback',url:location.href};
    if (location.origin === ${JSON.stringify(page.origin)} && location.pathname === '/client-callback') return {stage:'callback',url:location.href};
    if (location.origin !== ${JSON.stringify(page.origin)}) return {stage:'unexpected_origin'};
    if (document.querySelector('form[action="/authorize/consent"]')) return {stage:'consent', items:[...document.querySelectorAll('li')].map(li=>li.textContent)};
    if (location.pathname === '/login' && document.querySelector('#email')) return {stage:'login'};
    if (document.contentType === 'application/json') return {stage:'protocol_error',url:location.href};
    return null;
  })()`);
  return result ? {...result, status:page.status} : null;
}

async function login(page, input) {
  if (input.navigate) await navigate(page, `${page.origin}/login`, input.seconds);
  await wait(() => evaluate(page, `!!document.querySelector('#email')`), input.seconds);
  const fill = (selector, value) => evaluate(page, `(() => {
    const field = document.querySelector(${JSON.stringify(selector)}); if (!field) return false;
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(field,${JSON.stringify(value)});
    field.dispatchEvent(new Event('input',{bubbles:true})); field.dispatchEvent(new Event('change',{bubbles:true})); return true;
  })()`);
  await fill('#email', input.email);
  await evaluate(page, `(() => { const button=[...document.querySelectorAll('button')].find(b=>b.textContent.includes('Use password instead')); button?.click(); })()`);
  await wait(() => evaluate(page, `!!document.querySelector('#password')`), input.seconds);
  await fill('#password', input.password);
  await evaluate(page, `(() => { const button=[...document.querySelectorAll('button')].find(b=>b.textContent.includes('Continue with password')); if (!button || button.disabled) throw new Error('login_button'); button.click(); })()`);
  await wait(() => evaluate(page, `location.pathname.startsWith('/console') || !!document.querySelector('form[action="/authorize/consent"]')`), input.seconds);
  const {cookies} = await call('Network.getCookies', {urls:[page.origin]}, page.session);
  return {cookies: cookies.map(({name,value})=>({name,value}))};
}

async function action(input) {
  if (input.action === 'new') return newPage(input);
  const page = contexts.get(input.actor); if (!page) throw new Error('unknown_actor');
  if (input.action === 'login') return login(page, input);
  if (input.action === 'authorize') {
    const url = new URL(input.url); if (url.origin !== page.origin || url.pathname !== '/authorize') throw new Error('issuer_mismatch');
    await navigate(page, input.url, input.seconds); return wait(() => stage(page), input.seconds);
  }
  if (input.action === 'decision') {
    if (!['allow','cancel'].includes(input.decision)) throw new Error('decision');
    page.status = null; page.hasLocation = null; page.hadRedirect = false;
    await evaluate(page, `document.querySelector('button[name="decision"][value="${input.decision}"]').click()`);
    try { return await wait(async () => {
      const value = await stage(page);
      if (value?.stage === 'callback') return value;
      if (value?.stage === 'protocol_error' && page.status !== null && page.hasLocation !== null) return {...value,status:page.status,has_location_header:page.hasLocation,had_redirect:page.hadRedirect};
      return false;
    }, input.seconds); }
    catch { return {stage:'consent_incomplete',status:page.status,protocol_error:(await stage(page))?.stage==='protocol_error'}; }
  }
  if (input.action === 'tamper') {
    await evaluate(page, `(() => {
      const form=document.querySelector('form[action="/authorize/consent"]');
      const field=document.createElement('input'); field.name='scope'; field.value='platform:admin jobs:write'; form.append(field);
      form.querySelector('button[value="allow"]').click();
    })()`);
    await wait(async()=> (await stage(page))?.stage==='protocol_error',input.seconds);
    return {status:page.status};
  }
  if (input.action === 'inspect') {
    if (!input.path.startsWith('/console/') || input.path.includes('..')) throw new Error('console_path');
    await navigate(page, page.origin + input.path, input.seconds);
    await wait(() => evaluate(page, `${JSON.stringify(input.labels)}.every(label=>document.body.textContent.includes(label))`), input.seconds);
    return {stage:'console'};
  }
  if (input.action === 'resume') {
    await navigate(page, page.origin + '/authorize/resume?request_id=' + encodeURIComponent(input.request_id), input.seconds);
    return wait(() => stage(page), input.seconds);
  }
  throw new Error('unsupported_action');
}

try {
  await initialize(); process.stdout.write(JSON.stringify({ok:true,result:{stage:'ready'}})+'\n');
  const lines = createInterface({input:process.stdin, crlfDelay:Infinity});
  for await (const line of lines) {
    try { const input = JSON.parse(line); process.stdout.write(JSON.stringify({ok:true,result:await action(input)})+'\n'); }
    catch { process.stdout.write(JSON.stringify({ok:false,error:'browser_action_failed'})+'\n'); }
  }
} catch { process.stdout.write(JSON.stringify({ok:false,error:'browser_startup_failed'})+'\n'); process.exitCode=1; }
finally { chromium.kill('SIGKILL'); await rm(directory,{recursive:true,force:true}); }
