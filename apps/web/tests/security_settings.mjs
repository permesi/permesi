// Focused regressions for the composed security settings against owned fixtures.
// Rejected password proof must leave every factor/password mutation undispatched.
import assert from 'node:assert/strict';

export async function checkSecuritySettings({goto,wait,click,fill,evaluate,call,requests}) {
 await goto('/console/me/security');
 await wait("document.body.innerText.includes('Fixture passkey') && document.body.innerText.includes('Fixture hardware key')");
 for (const label of ['Password','Passkeys','Authenticator app','Recovery codes','Security keys']) {
  assert(await evaluate(`document.body.innerText.includes(${JSON.stringify(label)})`),`Missing security section: ${label}`);
 }
 const before=requests.length;
 await click('Change password');
 await fill('current_password','fixture-current-password');
 await fill('new_password','short');await fill('confirm_password','different');
 await click('Update password');await wait("document.body.innerText.includes('New passwords do not match.')");
 await fill('confirm_password','short');await click('Update password');
 await wait("document.body.innerText.includes('New password must be at least 12 characters.')");
 assert(!requests.slice(before).some(value=>value.path==='/v1/auth/opaque/reauth/start'),'Invalid local input must not start a password proof');
 await fill('new_password','fixture-replacement-password');await fill('confirm_password','fixture-replacement-password');
 await click('Update password');await wait("document.body.innerText.includes('Fixture password proof rejected.')");
 await click('Cancel');

 // Keyboard activation must still reach the extracted authenticator menu/form.
 await evaluate("document.querySelector('[aria-label=\"Authenticator settings\"]').focus()");
 await call('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
 await call('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
 await click('Delete');await fill('delete_password','fixture-current-password');
 await click('Remove method');await wait("document.querySelector('#delete_password').closest('form').innerText.includes('Fixture password proof rejected.')");
 await click('Cancel');
 await click('Regenerate');await fill('recovery_password','fixture-current-password');
 await evaluate("document.querySelector('#recovery_password').closest('form').requestSubmit()");
 await wait("document.querySelector('#recovery_password').closest('form').innerText.includes('Fixture password proof rejected.')");
 await click('Cancel');

 for (const [label,input,submit] of [
  ['Remove passkey','delete_passkey_password','Remove passkey'],
  ['Remove security key','delete_key_password','Remove key'],
 ]) {
  await evaluate(`document.querySelector('[aria-label="${label}"]').click()`);
  await fill(input,'fixture-current-password');
  // Both row forms submit through their original password-proof action.
  await evaluate(`document.getElementById(${JSON.stringify(input)}).closest('form').requestSubmit()`);
  await wait(`document.getElementById(${JSON.stringify(input)}).closest('form').innerText.includes('Fixture password proof rejected.')`);
  assert(await evaluate(`document.getElementById(${JSON.stringify(input)}).closest('form').innerText.includes(${JSON.stringify(submit)})`));
  await click('Cancel');
 }
 const proofs=requests.slice(before).filter(value=>value.path==='/v1/auth/opaque/reauth/start');
 assert.equal(proofs.length,5,'Each extracted mutation form must prove its password exactly once');
 assert(proofs.every(value=>!JSON.stringify(value.input).includes('fixture-current-password')),'Password proof must not transmit plaintext');
 assert(!requests.slice(before).some(value=>value.method==='DELETE'||[
  '/v1/auth/opaque/password/start','/v1/auth/opaque/password/finish',
  '/v1/me/mfa/totp','/v1/me/mfa/recovery-codes',
 ].includes(value.path)),'Rejected password proof must not reach a protected mutation');
 assert(await evaluate("document.body.innerText.includes('Fixture passkey') && document.body.innerText.includes('Fixture hardware key')"));

 await call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:false});
 await evaluate("document.documentElement.classList.add('dark')");
 assert(await evaluate('document.documentElement.scrollWidth <= 390'),'Security settings overflow the mobile viewport');
 await evaluate("document.documentElement.classList.remove('dark')");
 await call('Emulation.setDeviceMetricsOverride',{width:1280,height:900,deviceScaleFactor:1,mobile:false});
}
