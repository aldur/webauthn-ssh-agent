// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview SSH host keys made with WebCrypto, for tests.
 */

import {
  concat, encodeMpint, encodeString, fromBase64Url,
} from '../src/ssh.js';

/**
 * @param {string} type 'ed25519', 'nistp256' or 'rsa'.
 * @return {!Promise<{blob: !Uint8Array,
 *                    sign: function(!Uint8Array): !Promise<!Uint8Array>}>}
 *     The SSH public key blob, and a function returning SSH signatures.
 */
export async function makeHostKey(type) {
  if (type === 'ed25519') {
    const {publicKey, privateKey} = await crypto.subtle.generateKey(
        {name: 'Ed25519'}, true, ['sign', 'verify']);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
    return {
      blob: concat(encodeString('ssh-ed25519'), encodeString(raw)),
      sign: async (data) => concat(
          encodeString('ssh-ed25519'),
          encodeString(new Uint8Array(await crypto.subtle.sign(
              {name: 'Ed25519'}, privateKey, data)))),
    };
  }
  if (type === 'nistp256') {
    const {publicKey, privateKey} = await crypto.subtle.generateKey(
        {name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify']);
    const point =
        new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
    const name = 'ecdsa-sha2-nistp256';
    return {
      blob: concat(encodeString(name), encodeString('nistp256'),
                   encodeString(point)),
      sign: async (data) => {
        const rs = new Uint8Array(await crypto.subtle.sign(
            {name: 'ECDSA', hash: 'SHA-256'}, privateKey, data));
        return concat(encodeString(name), encodeString(concat(
            encodeMpint(rs.subarray(0, 32)), encodeMpint(rs.subarray(32)))));
      },
    };
  }
  const {publicKey, privateKey} = await crypto.subtle.generateKey(
      {name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
       publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-512'},
      true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);
  return {
    blob: concat(encodeString('ssh-rsa'), encodeMpint(fromBase64Url(jwk.e)),
                 encodeMpint(fromBase64Url(jwk.n))),
    sign: async (data) => concat(
        encodeString('rsa-sha2-512'),
        encodeString(new Uint8Array(await crypto.subtle.sign(
            {name: 'RSASSA-PKCS1-v1_5'}, privateKey, data)))),
  };
}
