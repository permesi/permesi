import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {createBrowserWorkspace,devToolsListUrl} from './browser_files.mjs';

test('browser files are private and refuse symlinks and traversal',()=>{
 const workspace=createBrowserWorkspace('permesi-browser-files-test-');
 const second=createBrowserWorkspace('permesi-browser-files-test-');
 try {
  assert.notEqual(workspace.directory,second.directory);
  for(const directory of [workspace.directory,workspace.profile])assert.equal(fs.statSync(directory).mode&0o777,0o700);
  const target=path.join(second.directory,'protected');
  fs.writeFileSync(target,'unchanged');
  fs.symlinkSync(target,path.join(workspace.directory,'linked.png'));
  assert.throws(()=>workspace.writeScreenshot('linked.png','overwrite'),{code:'EEXIST'});
  assert.equal(fs.readFileSync(target,'utf8'),'unchanged');
  for(const name of ['../escaped.png','/tmp/escaped.png','nested/image.png'])assert.throws(()=>workspace.writeScreenshot(name,'overwrite'),/Invalid screenshot name/);
  workspace.writeScreenshot('safe.png','image');
  assert.equal(fs.readFileSync(path.join(workspace.directory,'safe.png'),'utf8'),'image');
  assert.equal(fs.statSync(path.join(workspace.directory,'safe.png')).mode&0o777,0o600);
  assert.throws(()=>workspace.writeScreenshot('safe.png','overwrite'),{code:'EEXIST'});
 } finally {
  fs.rmSync(workspace.directory,{recursive:true,force:true});
  fs.rmSync(second.directory,{recursive:true,force:true});
 }
});

test('debugging discovery accepts only a loopback numeric port',()=>{
 const workspace=createBrowserWorkspace('permesi-browser-port-test-');
 try {
  const portFile=path.join(workspace.profile,'DevToolsActivePort');
  for(const raw of ['9222\n/devtools/browser/id','1','65535']) {
   fs.writeFileSync(portFile,raw);
   const url=devToolsListUrl(workspace.profile);
   assert.equal(url.hostname,'127.0.0.1');assert.equal(url.pathname,'/json/list');
   assert.equal(url.port,raw.split('\n')[0]);assert.equal(url.username,'');
  }
  for(const raw of ['','0','65536','-1','1.5','80@attacker.test','80/path','80?query','80#fragment',' 80','80\r']) {
   fs.writeFileSync(portFile,raw);
   assert.throws(()=>devToolsListUrl(workspace.profile),/Invalid Chromium debugging port/);
  }
 } finally {fs.rmSync(workspace.directory,{recursive:true,force:true});}
});
