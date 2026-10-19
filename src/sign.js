// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview The window that asks the user to approve one signature.
 *
 * Normally the user reads the request, then clicks Continue to open
 * Chrome's security key or passkey prompt, which covers this window.  With
 * the confirmation skipped, the prompt opens right away: then this window
 * shows nothing behind it, and a details window beside it shows the request.
 */

import {sign} from './keys.js';
import {showRequest} from './request-view.js';
import {saveSetting} from './settings.js';

/** Size of the details window, in pixels. */
const DETAILS_WIDTH = 440;
const DETAILS_MIN_HEIGHT = 420;

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
 * @return {{left: number, top: number, width: number, height: number}}
 *     Where to put the details window: beside this one, on the screen.
 */
function detailsBounds() {
  const gap = 8;
  const screenRight = screen.availLeft + screen.availWidth;
  let left = window.screenX + window.outerWidth + gap;
  if (left + DETAILS_WIDTH > screenRight) {
    left = Math.max(screen.availLeft, window.screenX - DETAILS_WIDTH - gap);
  }
  return {
    left,
    top: window.screenY,
    width: DETAILS_WIDTH,
    height: Math.max(window.outerHeight, DETAILS_MIN_HEIGHT),
  };
}

/**
 * @param {!Object} request From the background page.
 */
async function trySign(request) {
  $('continue').classList.add('hidden');
  if (request.decision === 'sign') {
    // The prompt is about to cover this window, unread: show nothing here,
    // and the request beside it instead.
    document.body.classList.add('prompting');
    await chrome.runtime.sendMessage(
        {type: 'show-details', id, bounds: detailsBounds()});
  } else {
    const device =
        request.key.kind === 'passkey' ? 'passkey' : 'security key';
    $('status').textContent = request.key.verify ?
        `Confirm with your ${device} (touch & PIN or fingerprint)…` :
        `Confirm with your ${device}…`;
  }
  try {
    const signature =
        await sign(request.key, Uint8Array.from(request.data));
    document.body.classList.remove('prompting');
    $('status').textContent = 'Done.';
    finish({signature: Array.from(signature)});
  } catch (e) {
    // E.g. the user dismissed Chrome's dialog, or it timed out.
    document.body.classList.remove('prompting');
    $('status').textContent = `Not signed: ${e.message}`;
    $('continue').textContent = 'Try again';
    $('continue').classList.remove('hidden');
  }
}

/**
 * Only start WebAuthn when the user has read the request: Chrome's security
 * key & passkey dialogs cover this window.
 *
 */
function showContinue() {
  $('continue').classList.remove('hidden');
  $('status').textContent = 'Check the request, then click Continue.';
  $('continue').focus();  // Enter continues.
}

$('cancel').onclick = () => finish({error: 'cancelled by the user'});
$('deny').onclick = () =>
  chrome.runtime.sendMessage({type: 'deny-connection', id});

const request =
    await chrome.runtime.sendMessage({type: 'get-sign-request', id});
if (!request) {
  $('status').textContent = 'This request is no longer pending.';
} else {
  showRequest(request);

  $('continue').onclick = () => trySign(request);
  if (request.decision === 'sign') {
    // The user chose to skip the confirmation for such requests.
    trySign(request);
  } else {
    if (request.decision === 'ask') {
      // The kind of request the setting applies to: offer it here.
      $('skip-label').classList.remove('hidden');
      $('skip').onchange = () =>
        saveSetting('skipConfirmation', $('skip').checked);
    }
    showContinue();
  }
}
