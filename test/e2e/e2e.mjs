// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview End-to-end test: unmodified Secure Shell, using this agent
 * via --ssh-agent=<id>, logs in to a real sshd with keys on a CDP virtual
 * FIDO authenticator.  Driven by run.sh.
 *
 * Usage: node e2e.mjs <agent dir> <secure shell dir> <profile dir>
 *            <authorized_keys path> <port> <user> <sshd host key fingerprint>
 */

import fs from 'node:fs';
import {createRequire} from 'node:module';

const require = createRequire(process.env.PLAYWRIGHT_DIR ?? import.meta.url);
const {chromium} = require('playwright');

const [, , agentDir, sshDir, profileDir, authKeys, port, user, hostKeyFp] =
    process.argv;
const outsiderDir = new URL('./outsider', import.meta.url).pathname;

const ctx = await chromium.launchPersistentContext(profileDir, {
  headless: true,
  channel: 'chromium',
  args: [
    '--no-sandbox',
    `--disable-extensions-except=${agentDir},${sshDir},${outsiderDir}`,
    `--load-extension=${agentDir},${sshDir},${outsiderDir}`,
  ],
});

/**
 * @param {string} name The extension's name in its manifest.
 * @return {!Promise<string>} Its ID.
 */
async function extensionId(name) {
  for (let i = 0; i < 60; ++i) {
    for (const sw of ctx.serviceWorkers()) {
      const id = new URL(sw.url()).host;
      const manifestName = await sw.evaluate(
          () => globalThis.chrome?.runtime?.getManifest?.().name).catch(
          () => null);
      if (manifestName === name) {
        return id;
      }
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`extension ${name} not found`);
}
const agentId = await extensionId('WebAuthn SSH Agent');
// Secure Shell's dev ID: build-secure-shell.sh keeps upstream's dev key.
const sshId = 'algkcnfjnajfhgimadimbjhmpaeohhln';
console.log('agent', agentId, 'secure shell', sshId);

const AUTHENTICATOR = {
  protocol: 'ctap2', transport: 'usb', hasResidentKey: true,
  hasUserVerification: true, isUserVerified: true,
  automaticPresenceSimulation: true,
};

// Virtual authenticators are per page, so copy the credentials created in the
// "Manage keys and settings" page into each touch window's authenticator.
let credentials = [];

// Every touch window: give it the authenticator & record what it showed.
const signWindows = [];
// Details windows, shown beside touch windows that skip the confirmation.
const detailsWindows = [];
ctx.on('page', async (page) => {
  if (!page.url().includes('/src/details.html')) {
    return;
  }
  const shown = {facts: null};
  detailsWindows.push(shown);
  while (!shown.facts && !page.isClosed()) {
    shown.facts = await page.evaluate(() => {
      const dts = [...document.querySelectorAll('#facts dt')];
      return dts.length ? Object.fromEntries(dts.map(
          (dt) => [dt.textContent, dt.nextElementSibling.textContent])) :
          null;
    }).catch(() => null);
    await new Promise((r) => setTimeout(r, 10));
  }
});

ctx.on('page', async (page) => {
  if (!page.url().includes('/src/sign.html')) {
    return;
  }
  const shown = {facts: null};
  const first = signWindows.push(shown) === 1;
  // Record what it shows (it closes soon after signing): the labelled facts,
  // any warning, & whether the user had to click Continue.
  (async () => {
    while (!shown.facts && !page.isClosed()) {
      Object.assign(shown, await page.evaluate(() => {
        const dts = [...document.querySelectorAll('#facts dt')];
        if (!dts.length) {
          return {};
        }
        const button = document.getElementById('continue');
        return {
          facts: Object.fromEntries(dts.map(
              (dt) => [dt.textContent, dt.nextElementSibling.textContent])),
          warning: document.getElementById('warning').textContent,
          title: document.title,
          mustContinue: !button.classList.contains('hidden') &&
              button.textContent === 'Continue',
        };
      }).catch(() => ({})));
      await new Promise((r) => setTimeout(r, 10));
    }
  })();

  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const {authenticatorId} = await cdp.send(
      'WebAuthn.addVirtualAuthenticator', {options: AUTHENTICATOR});
  for (const credential of credentials) {
    await cdp.send('WebAuthn.addCredential', {authenticatorId, credential});
  }
  try {
    if (first) {
      // Skip the confirmation from now on, from the window itself.
      await page.check('#skip');
    }
    // Click Continue once it's enabled (by then the authenticator is there).
    await page.locator('#continue:not(.hidden)').click({timeout: 5000});
  } catch (e) {
    // Fine if it signed without Continue (the confirmation was skipped).
    if (!page.isClosed()) {
      console.log('could not click Continue:', e.message);
    }
  }
});

// Create keys in "Manage keys and settings".
const options = await ctx.newPage();
const optionsCdp = await ctx.newCDPSession(options);
await optionsCdp.send('WebAuthn.enable');
const {authenticatorId} = await optionsCdp.send(
    'WebAuthn.addVirtualAuthenticator', {options: AUTHENTICATOR});
await options.goto(`chrome-extension://${agentId}/src/manage.html`);
const status = options.locator('#status');

// The test uses Secure Shell's dev build, which needs the user's opt in.
await options.check('#allowDevSecureShell');
await options.waitForFunction(async () =>
  (await chrome.storage.local.get('settings')).settings
      ?.allowDevSecureShell === true);

await options.fill('#name', 'touch-key');
await options.click('#create');
await status.getByText('"touch-key" is ready').waitFor();

await options.fill('#name', 'pin-key');
await options.check('#verify');
await options.click('#create');
await status.getByText('"pin-key" is ready').waitFor();
await options.locator('#keys').getByText('PIN required').waitFor();
// The virtual authenticator is a USB security key, & the list says so.
await options.locator('#keys li', {hasText: 'touch-key'})
    .getByText(/^security key ·/).waitFor();
console.log('created keys in "Manage keys and settings"');

({credentials} = await optionsCdp.send(
    'WebAuthn.getCredentials', {authenticatorId}));

const lines = await options.evaluate(async () => {
  const keys = await import('./keys.js');
  return Object.fromEntries((await keys.loadKeys()).map(
      (key) => [key.comment, keys.keyAuthorizedKeysLine(key)]));
});
if (!lines['pin-key'].startsWith('verify-required ')) {
  throw new Error(`pin-key lacks verify-required: ${lines['pin-key']}`);
}

/**
 * Log in from Secure Shell & run a command.
 *
 * @param {string} marker Printed by the remote command.
 * @param {{sshArgs: (string|undefined), command: (string|undefined)}=} options
 *     Extra ssh arguments, & a command printing the marker.
 */
async function login(marker, {sshArgs = '', command} = {}) {
  const page = await ctx.newPage();
  const screen = async () => {
    const texts = [];
    for (const f of page.frames()) {
      try {
        texts.push(await f.evaluate(() => document.body?.innerText ?? ''));
      } catch (e) {
        // Frame went away.
      }
    }
    return texts.join('\n');
  };
  const waitFor = async (re, ms = 60000) => {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      if (re.test(await screen())) {
        return;
      }
      await page.waitForTimeout(250);
    }
    console.log('---- screen ----\n' + await screen());
    throw new Error(`timeout waiting for ${re}`);
  };

  const uri = `ssh://${user};-nassh-args=--ssh-agent%3D${agentId}` +
      (sshArgs ? `;-nassh-ssh-args=${encodeURIComponent(sshArgs)}` : '') +
      `@127.0.0.1:${port}`;
  await page.goto(`chrome-extension://${sshId}/html/nassh.html#uri:${uri}`);
  await waitFor(/continue connecting|[#$] $/m);
  if (/continue connecting/.test(await screen())) {
    await page.keyboard.type('yes\n');
  }
  await waitFor(/[#$] $/m);
  await page.keyboard.type(`${command ?? 'echo'} ${marker}_$((6*7))\n`);
  await waitFor(new RegExp(`${marker}_42`));
  await page.close();
}

fs.writeFileSync(authKeys, lines['touch-key'] + '\n');
await login('TOUCH_KEY');
console.log('logged in with touch-key');

// The first touch window turned on skipping the confirmation.
if (!await options.evaluate(async () =>
  (await chrome.storage.local.get('settings')).settings?.skipConfirmation)) {
  throw new Error('skipping the confirmation was not saved');
}

fs.writeFileSync(authKeys, lines['pin-key'] + '\n');
await login('PIN_KEY');
console.log('logged in with pin-key (verify-required)');

// Through a forwarded agent: log in again from the server.  OpenSSH clients
// before 10.3 refuse webauthn signatures from an agent ("returned incorrect
// signature type"), so the login itself may fail: what's tested is the touch
// window.
fs.writeFileSync(authKeys, lines['touch-key'] + '\n');
await login('FORWARDED', {
  sshArgs: '-A',
  command: `ssh -o BatchMode=yes -o StrictHostKeyChecking=no ` +
      `-o UserKnownHostsFile=/dev/null -p ${port} ${user}@127.0.0.1 true; ` +
      'echo',
});
console.log('signed a login through a forwarded agent');

// Direct logins named the user & the verified server, without a warning.
const check = (ok, shown) => {
  if (!ok) {
    throw new Error(`touch window showed: ${JSON.stringify(shown)}`);
  }
};
// (Older OpenSSH retries the forwarded login once after refusing it.)
if (signWindows.length < 4) {
  throw new Error(`expected 4+ touch windows, got ${signWindows.length}`);
}
for (const [i, shown] of signWindows.slice(0, 3).entries()) {
  const {facts} = shown;
  check(facts?.['Requested by'] === 'Secure Shell (dev)' &&
        facts['Action'] === 'Log in' && facts['As user'] === user &&
        facts['Server'] === `${hostKeyFp} (verified)` &&
        facts['Route'] === 'Direct connection' &&
        // Only the first came before skipping the confirmation.
        shown.mustContinue === (i === 0) && !shown.warning &&
        shown.title === `Log in as ${user} · ${hostKeyFp} (verified)`, shown);
}
console.log('direct login touch windows:', JSON.stringify(signWindows[0]));
// The two that skipped the confirmation showed the request beside them.
if (detailsWindows.length !== 2 || !detailsWindows.every(({facts}) =>
  facts?.['As user'] === user &&
    facts['Server'] === `${hostKeyFp} (verified)`)) {
  throw new Error(`details windows: ${JSON.stringify(detailsWindows)}`);
}
console.log('details windows:', JSON.stringify(detailsWindows[0]));
// The forwarded ones said so, warned, & still needed Continue.
for (const forwarded of signWindows.slice(3)) {
  check(forwarded.facts?.['Server'] === `${hostKeyFp} (verified)` &&
        forwarded.facts['Route'] ===
            `Through a forwarded agent, on the server with host key ` +
            hostKeyFp &&
        /forwarded your agent/.test(forwarded.warning) &&
        forwarded.mustContinue, forwarded);
}
console.log('forwarded login touch window:', JSON.stringify(signWindows[3]));

// Other extensions can't use the agent at all.
const outsider = ctx.serviceWorkers().find(
    (sw) => !sw.url().includes(agentId) && !sw.url().includes(sshId));
const outsiderResult =
    await outsider.evaluate((id) => globalThis.tryAgent(id), agentId);
if (outsiderResult !== 'refused') {
  throw new Error(`another extension used the agent: ${outsiderResult}`);
}
console.log('another extension was refused');

await ctx.close();
console.log('PASS');
