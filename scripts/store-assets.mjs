// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Render the Chrome Web Store images into store/: plain
 * screenshots of the real UI (1280x800) & the small promo tile (440x280).
 *
 * Usage: node scripts/store-assets.mjs
 * Needs Playwright with its "chromium" browser (set PLAYWRIGHT_DIR to its
 * node_modules if it isn't resolvable from here).
 */

import fs from 'node:fs';
import http from 'node:http';
import {createRequire} from 'node:module';
import os from 'node:os';
import path from 'node:path';

const require = createRequire(process.env.PLAYWRIGHT_DIR ?? import.meta.url);
const {chromium} = require('playwright');

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname),
                          '..');
const outDir = path.join(root, 'store');
fs.mkdirSync(outDir, {recursive: true});

/** @param {string} file @return {string} A data: URL for an image. */
const dataUrl = (file) =>
  `data:image/png;base64,${fs.readFileSync(file).toString('base64')}`;

const iconUrl = dataUrl(path.join(root, 'icons/icon-128.png'));

const STYLE = `
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: system-ui, sans-serif;
    color: #e8ecff;
    background:
      linear-gradient(#2a3a7a55 1px, transparent 1px) 0 0 / 32px 32px,
      linear-gradient(90deg, #2a3a7a55 1px, transparent 1px) 0 0 / 32px 32px,
      radial-gradient(circle at 30% 30%, #1b1f45, #05060f 75%);
    overflow: hidden;
  }
  .glow-cyan { color: #22e6ff; text-shadow: 0 0 12px #22e6ff99; }
  .glow-pink { color: #ff2fd6; text-shadow: 0 0 12px #ff2fd699; }
  .shot {
    border-radius: 12px;
    border: 1px solid #3a4bb0;
    box-shadow: 0 0 40px #22e6ff33, 0 20px 50px #000a;
  }
`;

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'store-assets-'));
const ctx = await chromium.launchPersistentContext(path.join(tmp, 'profile'), {
  headless: true,
  channel: 'chromium',
  colorScheme: 'dark',
  // 1024x640 pages at 1.25x: 1280x800 screenshots, at a readable size.
  deviceScaleFactor: 1.25,
  args: ['--no-sandbox', `--disable-extensions-except=${root}`,
         `--load-extension=${root}`],
});

// --- "Manage keys and settings", with two keys made on a virtual security
// key.
let [sw] = ctx.serviceWorkers();
if (!sw) {
  sw = await ctx.waitForEvent('serviceworker');
}
const extensionId = new URL(sw.url()).host;
const options = await ctx.newPage();
await options.setViewportSize({width: 1024, height: 640});
const cdp = await ctx.newCDPSession(options);
await cdp.send('WebAuthn.enable');
await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {
  protocol: 'ctap2', transport: 'usb', hasResidentKey: true,
  hasUserVerification: true, isUserVerified: true,
  automaticPresenceSimulation: true,
}});
await options.goto(`chrome-extension://${extensionId}/src/manage.html`);
// Not the version: it would date the images.
await options.evaluate(() => document.getElementById('version').remove());
for (const [name, verify] of [['yubikey-5c', false], ['backup-key', true]]) {
  await options.fill('#name', name);
  if (verify) {
    await options.check('#verify');
  }
  await options.click('#create');
  await options.locator('#status').getByText(`"${name}" is ready`).waitFor();
}
await options.locator('#keys li', {hasText: 'yubikey-5c'})
    .getByRole('button', {name: 'Copy public key'}).click();
await options.evaluate(() => scrollTo(0, 0));
await options.screenshot({path: path.join(outDir, 'screenshot-1-keys.png')});
console.log('store/screenshot-1-keys.png');

// --- The touch window, served over HTTP with a stubbed chrome.runtime that
// hands it a sample login request.
const server = http.createServer((req, res) => {
  const file = path.join(root, decodeURIComponent(new URL(req.url,
      'http://x').pathname));
  if (!file.startsWith(root) || !fs.existsSync(file)) {
    res.writeHead(404).end();
    return;
  }
  const type = {'.js': 'text/javascript', '.css': 'text/css',
                '.html': 'text/html', '.png': 'image/png'}[path.extname(file)];
  res.writeHead(200, {'Content-Type': type}).end(fs.readFileSync(file));
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const sign = await ctx.newPage();
await sign.setViewportSize({width: 1024, height: 640});
await sign.addInitScript(() => {
  // A login as "alice" (SSH_MSG_USERAUTH_REQUEST, hostbound) to a server
  // whose host key blob is 32 bytes of 0x2a.
  const enc = (bytes) => [0, 0, 0, bytes.length, ...bytes];
  const str = (s) => enc([...new TextEncoder().encode(s)]);
  const data = [
    ...enc(new Array(32).fill(1)), 50, ...str('alice'),
    ...str('ssh-connection'), ...str('publickey-hostbound-v00@openssh.com'), 1,
    ...str('sk-ecdsa-sha2-nistp256@openssh.com'), ...enc([1, 2, 3]),
    ...enc(new Array(32).fill(0x2a)),
  ];
  globalThis.chrome = {storage: {local: {get: async () => ({})}},
    runtime: {sendMessage: async (msg) =>
    msg.type === 'get-sign-request' ? {
      key: {comment: 'yubikey-5c', credentialId: 'AA', verify: false,
            kind: 'security-key', resident: false},
      data,
      caller: 'Secure Shell',
      decision: 'ask',
      fields: {
        action: 'Log in',
        user: 'alice',
        server: 'SHA256:v7NmrHuQyNNMI7bdsaqwbdqRMCO6TCqFRb/qREpBMTs (verified)',
        route: 'Direct connection',
      },
    } : null}};
  // Leave WebAuthn pending, as while waiting for a touch.
  navigator.credentials.get = () => new Promise(() => {});
});
await sign.goto(`http://127.0.0.1:${server.address().port}/src/sign.html#x`);
await sign.locator('#facts').getByText('alice').waitFor();
await sign.locator('#continue:enabled').waitFor();
await sign.screenshot({path: path.join(outDir, 'screenshot-2-touch.png')});
console.log('store/screenshot-2-touch.png');
server.close();

// --- The promo tile.
const page = await ctx.newPage();

/**
 * @param {string} name Output file name.
 * @param {number} width
 * @param {number} height
 * @param {string} body HTML.
 */
async function render(name, width, height, body) {
  await page.setViewportSize({width, height});
  await page.setContent(`<style>${STYLE}</style>${body}`);
  await page.waitForLoadState('load');
  await page.screenshot({path: path.join(outDir, name), scale: 'css'});
  console.log(path.join('store', name));
}

await render('promo-small-440x280.png', 440, 280, `
  <div style="display:flex; align-items:center; height:280px; padding:0 28px;
              gap:22px">
    <img src="${iconUrl}" width="112"
         style="filter:drop-shadow(0 0 14px #22e6ff77)">
    <div>
      <div style="font-size:30px; font-weight:700; line-height:1.1">
        WebAuthn<br><span class="glow-cyan">SSH Agent</span></div>
      <div style="font-size:16px; color:#b8c2ff; margin-top:12px">
        SSH keys on your <span class="glow-pink">security key</span></div>
    </div>
  </div>`);

await ctx.close();
fs.rmSync(tmp, {recursive: true, force: true});
