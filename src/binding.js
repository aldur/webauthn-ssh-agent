// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Session binding (session-bind@openssh.com) for one agent
 * connection, as OpenSSH's ssh-agent does it.
 *
 * OpenSSH clients (8.9+) tell the agent which server each connection is for:
 * the server's host key, the session ID, the server's signature over it (so
 * it can't be faked), and whether the connection is a forwarded agent.  That
 * lets the agent tell a direct login from one through a forwarded agent, and
 * refuse to sign a login for a different session than the one bound.
 *
 * @see https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent
 */

import {equalBytes} from './ssh.js';
import {verifyHostKeySignature} from './hostkey.js';

/** Bindings per connection, like ssh-agent's AGENT_MAX_SESSION_IDS. */
const MAX_BINDINGS = 16;

/**
 * @typedef {{hostKey: !Uint8Array, sessionId: !Uint8Array,
 *            forwarded: boolean}}
 */
export let Binding;

/** The bindings of one agent connection. */
export class SessionBindings {
  constructor() {
    /** @type {!Array<!Binding>} Oldest first. */
    this.bindings = [];
  }

  /**
   * Handle a session-bind request.
   *
   * @param {!Uint8Array} hostKey The server's host key blob.
   * @param {!Uint8Array} sessionId
   * @param {!Uint8Array} signature The server's signature over sessionId.
   * @param {boolean} forwarded Whether this connection is a forwarded agent.
   * @return {!Promise<boolean>} Whether the binding was accepted.
   */
  async bind(hostKey, sessionId, signature, forwarded) {
    // Same checks, in the same order, as ssh-agent's process_ext_session_bind.
    if (!await verifyHostKeySignature(hostKey, signature, sessionId)) {
      return false;
    }
    for (const b of this.bindings) {
      // A connection bound for a direct login can't be bound again.
      if (!b.forwarded) {
        return false;
      }
      if (equalBytes(b.sessionId, sessionId)) {
        // Already recorded; but a session belongs to one host only.
        return equalBytes(b.hostKey, hostKey);
      }
    }
    if (this.bindings.length >= MAX_BINDINGS) {
      return false;
    }
    this.bindings.push({hostKey, sessionId, forwarded});
    return true;
  }

  /** @return {boolean} Whether any hop was a forwarded agent. */
  get forwarded() {
    return this.bindings.some((b) => b.forwarded);
  }

  /** @return {?Binding} The first binding: the server our client reached. */
  get first() {
    return this.bindings[0] ?? null;
  }

  /** @return {?Binding} The most recent binding. */
  get last() {
    return this.bindings.at(-1) ?? null;
  }
}
