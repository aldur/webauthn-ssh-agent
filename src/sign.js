// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview The window that asks the user to approve one signature.
 *
 * The background page decides what to ask & prepares display-safe, labelled
 * facts (see policy.js); this page only shows them, as text.
 */

import {describeKey, sign} from './keys.js';

/**
 * How long Continue stays disabled, so a click or key press meant for
 * something else (the window takes focus) can't approve the request: longer
 * for requests that come with a warning.
 */
const CONTINUE_DELAY_MS = {ask: 500, confirm: 1000};

const id = location.hash.slice(1);
const $ = (elementId) => document.getElementById(elementId);

/**
 * Report the result to the background page, which closes this window.
 *
 * @param {!Object} result {signature: !Array<number>} or {error: string}.
 */
function finish(result) {
  chrome.runtime.sendMessage({type: 'sign-result', id, ...result});
}

/**
 * @param {string} label
 * @param {string} value
 */
function addFact(label, value) {
  const dt = document.createElement('dt');
  dt.textContent = label;
  const dd = document.createElement('dd');
  dd.textContent = value;
  $('facts').append(dt, dd);
}

/**
 * @param {!Object} request From the background page.
 */
async function trySign(request) {
  $('continue').classList.add('hidden');
  const device = request.key.kind === 'passkey' ? 'passkey' : 'security key';
  $('status').textContent = request.key.verify ?
      `Confirm with your ${device} (touch & PIN or fingerprint)…` :
      `Confirm with your ${device}…`;
  try {
    const signature =
        await sign(request.key, Uint8Array.from(request.data));
    $('status').textContent = 'Done.';
    finish({signature: Array.from(signature)});
  } catch (e) {
    // E.g. the user dismissed Chrome's dialog, or it timed out.
    $('status').textContent = `Not signed: ${e.message}`;
    $('continue').textContent = 'Try again';
    $('continue').classList.remove('hidden');
  }
}

$('cancel').onclick = () => finish({error: 'cancelled by the user'});
$('deny').onclick = () =>
  chrome.runtime.sendMessage({type: 'deny-connection', id});

const request =
    await chrome.runtime.sendMessage({type: 'get-sign-request', id});
if (!request) {
  $('status').textContent = 'This request is no longer pending.';
} else {
  const {fields, key} = request;
  addFact('Requested by', request.caller);
  addFact('Action', fields.action);
  if (fields.user !== undefined) {
    addFact('As user', fields.user);
  }
  if (fields.namespace !== undefined) {
    addFact('Namespace', fields.namespace);
  }
  addFact('Server', fields.server);
  addFact('Route', fields.route);
  addFact('With key', `${key.comment} (${describeKey(key)})`);
  if (fields.warning) {
    $('warning').textContent = fields.warning;
    $('warning').classList.remove('hidden');
  }

  // Only start WebAuthn when the user has read the request: Chrome's
  // security key & passkey dialogs cover this window.
  $('continue').onclick = () => trySign(request);
  $('continue').disabled = true;
  $('continue').classList.remove('hidden');
  $('status').textContent = 'Check the request, then click Continue.';
  setTimeout(() => {
    $('continue').disabled = false;
    $('continue').focus();  // Enter continues.
  }, CONTINUE_DELAY_MS[request.decision] ?? CONTINUE_DELAY_MS.confirm);
}
