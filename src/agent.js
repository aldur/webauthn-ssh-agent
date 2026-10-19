// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview The SSH agent protocol: requests in, responses out.
 *
 * Messages exclude the 4 byte length prefix (Secure Shell's relay strips &
 * adds it).
 *
 * @see https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
 */

import {Reader, concat, encodeString, encodeUint32, equalBytes} from './ssh.js';

export const AGENT_FAILURE = 5;
export const AGENT_SUCCESS = 6;
export const AGENTC_REQUEST_IDENTITIES = 11;
export const AGENT_IDENTITIES_ANSWER = 12;
export const AGENTC_SIGN_REQUEST = 13;
export const AGENT_SIGN_RESPONSE = 14;
export const AGENTC_EXTENSION = 27;

const FAILURE = new Uint8Array([AGENT_FAILURE]);
const SUCCESS = new Uint8Array([AGENT_SUCCESS]);

/**
 * @typedef {{
 *   blob: !Uint8Array,
 *   comment: string,
 * }}
 */
export let Identity;

/**
 * Handle one agent request.
 *
 * Anything we don't support (other requests & extensions, malformed
 * messages) gets AGENT_FAILURE, as the protocol requires.
 *
 * @param {!Uint8Array} request
 * @param {{
 *   identities: function(): !Promise<!Array<!Identity>>,
 *   sign: function(!Identity, !Uint8Array): !Promise<!Uint8Array>,
 *   bind: function(!Uint8Array, !Uint8Array, !Uint8Array, boolean):
 *       !Promise<boolean>,
 * }} backend sign gets the identity & data to sign, and returns the SSH
 *     signature (or throws).  bind handles session-bind@openssh.com: host
 *     key, session ID, signature, forwarded; it returns whether it accepted
 *     the binding.
 * @return {!Promise<!Uint8Array>}
 */
export async function handleRequest(request, backend) {
  try {
    const r = new Reader(request);
    switch (r.byte()) {
      case AGENTC_REQUEST_IDENTITIES: {
        if (!r.eom()) {
          return FAILURE;
        }
        const identities = await backend.identities();
        return concat(
            new Uint8Array([AGENT_IDENTITIES_ANSWER]),
            encodeUint32(identities.length),
            ...identities.flatMap(
                (id) => [encodeString(id.blob), encodeString(id.comment)]));
      }

      case AGENTC_SIGN_REQUEST: {
        const blob = r.string();
        const data = r.string();
        r.uint32();  // Flags: sk-ecdsa signatures have no variants.
        if (!r.eom()) {
          return FAILURE;
        }
        const identity = (await backend.identities())
            .find((id) => equalBytes(id.blob, blob));
        if (!identity) {
          return FAILURE;
        }
        const signature = await backend.sign(identity, data);
        return concat(
            new Uint8Array([AGENT_SIGN_RESPONSE]), encodeString(signature));
      }

      case AGENTC_EXTENSION: {
        if (r.text() !== 'session-bind@openssh.com') {
          return FAILURE;
        }
        const hostKey = r.string();
        const sessionId = r.string();
        const signature = r.string();
        const forwarded = r.byte() !== 0;
        if (!r.eom()) {
          return FAILURE;
        }
        return await backend.bind(hostKey, sessionId, signature, forwarded) ?
            SUCCESS : FAILURE;
      }
    }
  } catch (e) {
    console.warn('agent request failed:', e);
  }
  return FAILURE;
}
