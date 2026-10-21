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
// Details windows, shown beside touch windows with the Show level.
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

/** Whether the next touch window's prompt should fail, as if cancelled. */
let failNextPrompt = false;

ctx.on('page', async (page) => {
  if (!page.url().includes('/src/sign.html')) {
    return;
  }
  const fail = failNextPrompt;
  failNextPrompt = false;
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
  // Without the credential, the prompt fails like a cancelled one.
  for (const credential of fail ? [] : credentials) {
    await cdp.send('WebAuthn.addCredential', {authenticatorId, credential});
  }
  try {
    if (first) {
      // Switch this key to the Show level, from the window itself.
      await page.selectOption('#level', 'show');
    }
    // Click Continue (by then the authenticator is there).
    await page.locator('#continue:not(.hidden)').click({timeout: 5000});
  } catch (e) {
    // Fine if it signed without Continue (Show & Silent levels).
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
// pin-key's PIN column is marked (the virtual authenticator doesn't
// enforce the PIN itself, so "by servers only").
await options.locator('#keys tr', {hasText: 'pin-key'})
    .locator('[data-tip^="Required, enforced by servers only"]').waitFor();
// The virtual authenticator is a USB security key, & the list says so.
await options.locator('#keys tr', {hasText: 'touch-key'})
    .getByText('Cross-platform', {exact: true}).waitFor();
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

// The first touch window switched touch-key (only) to the Show level.
const levels = await options.evaluate(async () => {
  const keys = await (await import('./keys.js')).loadKeys();
  const {settings} = await chrome.storage.local.get('settings');
  return {
    keys: Object.fromEntries(
        keys.map((key) => [key.comment, key.confirmation ?? null])),
    default: settings?.confirmation ?? 'review',
  };
});
if (levels.keys['touch-key'] !== 'show' || levels.keys['pin-key'] !== null ||
    levels.default !== 'review') {
  throw new Error(`confirmation levels: ${JSON.stringify(levels)}`);
}

// The default for other keys: Silent, from Manage keys and settings.
await options.selectOption('#confirmation', 'silent');
await options.waitForFunction(async () =>
  (await chrome.storage.local.get('settings')).settings?.confirmation ===
      'silent');

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
// touch-key: Review, then (the forwarded run's own login) Show.
for (const [i, shown] of [[0, signWindows[0]], [2, signWindows[2]]]) {
  const {facts} = shown;
  check(facts?.['Requested by'] === 'Secure Shell (dev)' &&
        facts['Action'] === 'Log in' && facts['As user'] === user &&
        facts['Server'] === `${hostKeyFp} (verified)` &&
        facts['Route'] === 'Direct connection' &&
        facts['With key'] === 'touch-key' &&
        shown.mustContinue === (i === 0) && !shown.warning &&
        shown.title === `Log in as ${user} · ${hostKeyFp} (verified)`, shown);
}
console.log('direct login touch windows:', JSON.stringify(signWindows[0]));
// pin-key, with the default level: Silent, no Continue.
check(!signWindows[1].mustContinue, signWindows[1]);
// Only Show showed the request beside the prompt.
if (detailsWindows.length !== 1 || !detailsWindows.every(({facts}) =>
  facts?.['As user'] === user && facts['With key'] === 'touch-key' &&
    facts['Server'] === `${hostKeyFp} (verified)`)) {
  throw new Error(`details windows: ${JSON.stringify(detailsWindows)}`);
}
console.log('details windows:', JSON.stringify(detailsWindows[0]));
// The forwarded ones said so, warned, & still needed Continue.
for (const forwarded of signWindows.slice(3)) {
  check(forwarded.facts?.['Server'] === `${hostKeyFp} (verified)` &&
        forwarded.facts['Route'] ===
            `Through a forwarded agent, on server ` +
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

// Cancelling Chrome's prompt skips that key, without another click: ssh
// tries the next one (touch-key is offered first).
fs.writeFileSync(authKeys, lines['touch-key'] + '\n' + lines['pin-key'] + '\n');
failNextPrompt = true;
await login('SKIPPED');
if (failNextPrompt) {
  throw new Error('no touch window to cancel');
}
console.log('a cancelled prompt skipped to the next key');

await ctx.close();
console.log('PASS');
