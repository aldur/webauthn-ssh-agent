// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Test data: SSH host keys made with WebCrypto, WebAuthn
 * authenticator data & SSH certificates.
 */

import {concat, fromBase64Url} from '../src/bytes.js';
import {
  SK_ECDSA_CERT_TYPE, encodeMpint, encodeString, encodeUint32,
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

// WebAuthn authenticator data, as authenticators make it: the RP ID hash,
// flags & counter, ...
export const authDataHeader = (flags, rpIdHash = new Uint8Array(32)) =>
  [...rpIdHash, flags, 0, 0, 0, 1];
// A COSE P-256 key: {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
const coseKey = [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01,
                 0x21, 0x58, 32, ...new Uint8Array(32).fill(1),
                 0x22, 0x58, 32, ...new Uint8Array(32).fill(2)];
// AAGUID, credential ID 09090909, public key.
export const attested = [...new Uint8Array(16), 0, 4, 9, 9, 9, 9, ...coseKey];
// {"credProtect": 3}
export const credProtect =
    [0xa1, 0x6b, ...new TextEncoder().encode('credProtect'), 0x03];

/**
 * An sk-ecdsa user certificate, with a dummy CA signature.
 *
 * @param {!Uint8Array} point The key's public key.
 * @param {string} application
 * @param {{principals: (!Array<string>|undefined),
 *          validBefore: (bigint|undefined),
 *          options: (!Array<string>|undefined)}=} options validBefore in
 *     seconds; options are critical options' names.
 * @return {!Uint8Array}
 */
export function certificate(point, application,
                            {principals = ['alice'],
                             validBefore = 0xffffffffffffffffn,
                             options = []} = {}) {
  const uint64 = (n) => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, n);
    return bytes;
  };
  return concat(
      encodeString(SK_ECDSA_CERT_TYPE), encodeString(new Uint8Array(32)),
      encodeString('nistp256'), encodeString(point),
      encodeString(application), uint64(7n), encodeUint32(1),
      encodeString('id'),
      encodeString(concat(...principals.map((p) => encodeString(p)))),
      uint64(1000n), uint64(validBefore),
      encodeString(concat(...options.flatMap(
          (o) => [encodeString(o), encodeString('')]))),
      encodeString(''),
      encodeString(''), encodeString('ca key'), encodeString('signature'));
}
