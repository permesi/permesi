// Browser profiles and screenshots belong to a private, unpredictable directory.
// Screenshots are retained for inspection; callers remove the profile after Chromium exits.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** Allocate a private browser profile and exclusively created screenshot files. */
export function createBrowserWorkspace(prefix) {
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),prefix));
 const profile=path.join(directory,'profile');
 fs.mkdirSync(profile,{mode:0o700});
 return {
  directory,profile,
  /** Reject paths and existing files, including symlinks, before writing an artifact. */
  writeScreenshot(name,data) {
   if(!/^[a-z0-9][a-z0-9-]*\.png$/.test(name))throw Error('Invalid screenshot name');
   fs.writeFileSync(path.join(directory,name),data,{flag:'wx',mode:0o600});
  },
 };
}

/** Read Chromium's local port without allowing file contents to change the host or path. */
export function devToolsListUrl(profile) {
 const raw=fs.readFileSync(path.join(profile,'DevToolsActivePort'),'utf8').split('\n')[0];
 if(!/^[0-9]{1,5}$/.test(raw))throw Error('Invalid Chromium debugging port');
 const port=Number(raw);
 if(port<1||port>65535)throw Error('Invalid Chromium debugging port');
 const url=new URL('http://127.0.0.1/json/list');
 url.port=String(port);
 return url;
}
