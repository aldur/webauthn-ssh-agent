// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Service worker: serves the SSH agent protocol to Secure Shell
 * (`--ssh-agent=<this extension's id>`) and opens a small window to have the
 * user touch their security key for each signature, since service workers
 * can't use WebAuthn.
 */

import {handleRequest} from './agent.js';
import {SessionBindings} from './binding.js';
import {callerName} from './callers.js';
import {WEBAUTHN_TIMEOUT_MS, keyBlob, loadKeys} from './keys.js';
import {Decision, assess} from './policy.js';
import {loadSettings} from './settings.js';

/** Limit on the size of an agent request; real ones are a few KiB at most. */
const MAX_REQUEST_BYTES = 256 * 1024;

/** How long the touch window shows "Done." after signing. */
const SUCCESS_DISPLAY_MS = 800;

/**
 * Signature requests one connection may have waiting; more are refused, so a
 * client can't flood the user with prompts.
 */
const MAX_PENDING_PER_CONNECTION = 2;

/** The message type Secure Shell's agent relay uses. */
const AGENT_MESSAGE_TYPE = 'auth-agent@openssh.com';

/**
 * Signature requests waiting for the user, by random ID.
 *
 * @type {!Map<string, {
 *   key: !Object,
 *   data: !Uint8Array,
 *   caller: string,
 *   decision: string,
 *   fields: !Object,
 *   connection: !Connection,
 *   windowId: (number|undefined),
 *   resolve: function(!Uint8Array),
 *   reject: function(!Error),
 * }>}
 */
const pending = new Map();

/**
 * State of one agent connection (one Secure Shell agent socket).
 *
 * @typedef {{
 *   caller: string,
 *   bindings: !SessionBindings,
 *   pending: number,
 *   denied: boolean,
 * }}
 */
let Connection;

/** Serializes signature requests: one touch window at a time. */
let signQueue = Promise.resolve();

/** Whether we already opened "Manage keys and settings" as no keys exist. */
let openedManagePage = false;

/**
 * Ask the user to sign in a window.
 *
 * @param {!Object} key The StoredKey to use.
 * @param {!Uint8Array} data The SSH data to sign.
 * @param {!Connection} connection Where the request came from.
 * @param {string} decision A policy Decision: ask or confirm.
 * @param {!Object} fields What to show the user (policy Fields).
 * @return {!Promise<!Uint8Array>} The SSH signature.
 */
function signInWindow(key, data, connection, decision, fields) {
  if (connection.pending >= MAX_PENDING_PER_CONNECTION) {
    return Promise.reject(new Error('too many pending requests'));
  }
  ++connection.pending;
  const run = () => new Promise((resolve, reject) => {
    if (connection.denied) {
      reject(new Error('denied for this connection'));
      return;
    }
    const id = crypto.randomUUID();
    const request = {key, data, caller: connection.caller, decision, fields,
                     connection, resolve, reject};
    pending.set(id, request);
    /** @param {number} delay How long to leave the window up. */
    const finish = (delay) => {
      clearTimeout(timer);
      pending.delete(id);
      if (request.windowId !== undefined) {
        const windowId = request.windowId;
        setTimeout(
            () => chrome.windows.remove(windowId).catch(() => {}), delay);
      }
    };
    request.resolve = (signature) => {
      // Leave "Done." up briefly so the user sees it worked.
      finish(SUCCESS_DISPLAY_MS);
      resolve(signature);
    };
    request.reject = (error) => {
      finish(0);
      reject(error);
    };
    const timer = setTimeout(
        () => request.reject(new Error('timed out')),
        WEBAUTHN_TIMEOUT_MS + 30 * 1000);
    chrome.windows.create({
      url: chrome.runtime.getURL(`src/sign.html#${id}`),
      type: 'popup',
      width: 640,
      height: 560,
      focused: true,
    }).then((win) => {
      if (pending.has(id)) {
        request.windowId = win.id;
      } else {
        chrome.windows.remove(win.id).catch(() => {});
      }
    }, request.reject);
  });
  const result = signQueue.then(run, run)
      .finally(() => --connection.pending);
  signQueue = result.catch(() => {});
  return result;
}

// Closing the window cancels its request.
chrome.windows.onRemoved.addListener((windowId) => {
  for (const request of pending.values()) {
    if (request.windowId === windowId) {
      request.reject(new Error('cancelled'));
    }
  }
});

// Messages from our sign window.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id ||
      !sender.url?.startsWith(chrome.runtime.getURL('src/sign.html'))) {
    return;
  }
  const request = pending.get(msg?.id);
  if (!request) {
    sendResponse(null);
    return;
  }
  switch (msg.type) {
    case 'get-sign-request':
      sendResponse({
        key: request.key,
        data: Array.from(request.data),
        caller: request.caller,
        decision: request.decision,
        fields: request.fields,
      });
      break;
    case 'deny-connection':
      // Refuse this & everything else from the same connection.
      request.connection.denied = true;
      request.reject(new Error('denied for this connection'));
      sendResponse(null);
      break;
    case 'sign-result':
      if (Array.isArray(msg.signature)) {
        request.resolve(Uint8Array.from(msg.signature));
      } else {
        request.reject(new Error(String(msg.error)));
      }
      sendResponse(null);
      break;
  }
});

/**
 * @param {*} msg
 * @return {?Uint8Array} The agent request, if msg is well formed.
 */
function parseAgentMessage(msg) {
  if (msg?.type !== AGENT_MESSAGE_TYPE || !Array.isArray(msg.data) ||
      msg.data.length === 0 || msg.data.length > MAX_REQUEST_BYTES ||
      !msg.data.every((b) => Number.isInteger(b) && b >= 0 && b <= 255)) {
    return null;
  }
  return Uint8Array.from(msg.data);
}

// Secure Shell connects here when --ssh-agent=<our id> is set; each agent
// socket is a separate connection.  Only Secure Shell can connect at all (see
// manifest.json's externally_connectable); check again, as the dev channel
// is opt-in.
chrome.runtime.onConnectExternal.addListener((port) => {
  // Hold messages until we know whether to serve this connection.
  const early = [];
  const hold = (msg) => early.push(msg);
  port.onMessage.addListener(hold);
  loadSettings().then((settings) => {
    port.onMessage.removeListener(hold);
    const caller = callerName(port.sender?.id ?? '', settings);
    if (!caller) {
      console.warn('rejected connection from', port.sender);
      port.disconnect();
      return;
    }
    serve(port, caller, settings, early);
  }).catch((e) => {
    console.warn('rejected connection:', e);
    port.disconnect();
  });
});

/**
 * Serve the agent protocol on a connection.
 *
 * @param {!chrome.runtime.Port} port
 * @param {string} caller The client's name, for the user.
 * @param {!Object} settings The Settings.
 * @param {!Array<*>} early Messages that arrived before we were ready.
 */
function serve(port, caller, settings, early) {
  /** @type {!Connection} */
  const connection = {
    caller,
    bindings: new SessionBindings(),
    pending: 0,
    denied: false,
  };

  const identities = async () => {
    const keys = await loadKeys();
    if (keys.length === 0 && !openedManagePage) {
      // Help first-time users find where keys are created.
      openedManagePage = true;
      chrome.runtime.openOptionsPage();
    }
    return keys.map((key) => ({key, blob: keyBlob(key), comment: key.comment}));
  };
  const backend = {
    identities,
    sign: async (identity, data) => {
      const {decision, reason, fields} =
          await assess(data, connection.bindings, settings);
      if (decision === Decision.REFUSE) {
        throw new Error(`refused: ${reason}`);
      }
      return signInWindow(identity.key, data, connection, decision, fields);
    },
    bind: (hostKey, sessionId, signature, forwarded) =>
      connection.bindings.bind(hostKey, sessionId, signature, forwarded),
  };

  // Handle requests in order: the protocol has no request IDs.
  let queue = Promise.resolve();
  const onMessage = (msg) => {
    queue = queue.then(async () => {
      const request = parseAgentMessage(msg);
      if (request === null) {
        port.disconnect();
        return;
      }
      const response = await handleRequest(request, backend);
      try {
        port.postMessage({type: AGENT_MESSAGE_TYPE, data: Array.from(response)});
      } catch (e) {
        // The client went away.
      }
    });
  };
  port.onMessage.addListener(onMessage);
  early.forEach(onMessage);
}

// The toolbar button opens "Manage keys and settings".
chrome.action.onClicked.addListener(() => chrome.runtime.openOptionsPage());
