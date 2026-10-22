// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Verifying signatures made by SSH host keys, with WebCrypto.
 *
 * Used for session-bind@openssh.com: the client proves which server it's
 * talking to by forwarding the server's signature over the session ID.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8709 (Ed25519)
 * @see https://www.rfc-editor.org/rfc/rfc5656 (ECDSA)
 * @see https://www.rfc-editor.org/rfc/rfc8332 (RSA with SHA-2)
 */

import {concat, toBase64Url} from './bytes.js';
import {Reader} from './ssh.js';

/** ECDSA curves: SSH name -> WebCrypto curve, hash & coordinate size. */
const ECDSA = {
  'nistp256': {curve: 'P-256', hash: 'SHA-256', size: 32},
  'nistp384': {curve: 'P-384', hash: 'SHA-384', size: 48},
  'nistp521': {curve: 'P-521', hash: 'SHA-512', size: 66},
};

/** RSA signature algorithms we accept (no SHA-1 "ssh-rsa"). */
const RSA_HASHES = {
  'rsa-sha2-256': 'SHA-256',
  'rsa-sha2-512': 'SHA-512',
};

/**
 * Strip leading zeros from an SSH mpint (unsigned).
 *
 * @param {!Uint8Array} bytes
 * @return {!Uint8Array}
 */
function unsigned(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) {
    ++i;
  }
  return bytes.subarray(i);
}

/**
 * Left-pad an unsigned integer to a fixed size.
 *
 * @param {!Uint8Array} bytes
 * @param {number} size
 * @return {!Uint8Array}
 */
function pad(bytes, size) {
  bytes = unsigned(bytes);
  if (bytes.length > size) {
    throw new Error('integer too large');
  }
  return concat(new Uint8Array(size - bytes.length), bytes);
}

/**
 * Verify a host key's signature.
 *
 * @param {!Uint8Array} keyBlob The SSH public key blob.
 * @param {!Uint8Array} signatureBlob The SSH signature blob.
 * @param {!Uint8Array} data The signed data.
 * @return {!Promise<boolean>} False for bad signatures, malformed input, or
 *     key types we don't support.
 */
export async function verifyHostKeySignature(keyBlob, signatureBlob, data) {
  try {
    const key = new Reader(keyBlob);
    const keyType = key.text();
    const sig = new Reader(signatureBlob);
    const sigType = sig.text();
    const sigBytes = sig.string();
    if (!sig.eom()) {
      return false;
    }

    if (keyType === 'ssh-ed25519') {
      const publicKey = key.string();
      if (!key.eom() || sigType !== keyType || publicKey.length !== 32 ||
          sigBytes.length !== 64) {
        return false;
      }
      const cryptoKey = await crypto.subtle.importKey(
          'raw', publicKey, {name: 'Ed25519'}, false, ['verify']);
      return await crypto.subtle.verify(
          {name: 'Ed25519'}, cryptoKey, sigBytes, data);
    }

    if (keyType.startsWith('ecdsa-sha2-')) {
      const curveName = key.text();
      const params = ECDSA[curveName];
      const point = key.string();
      if (!params || !key.eom() || keyType !== `ecdsa-sha2-${curveName}` ||
          sigType !== keyType) {
        return false;
      }
      const rs = new Reader(sigBytes);
      const raw = concat(pad(rs.string(), params.size),
                         pad(rs.string(), params.size));
      if (!rs.eom()) {
        return false;
      }
      const cryptoKey = await crypto.subtle.importKey(
          'raw', point, {name: 'ECDSA', namedCurve: params.curve}, false,
          ['verify']);
      return await crypto.subtle.verify(
          {name: 'ECDSA', hash: params.hash}, cryptoKey, raw, data);
    }

    if (keyType === 'ssh-rsa') {
      const hash = RSA_HASHES[sigType];
      const e = unsigned(key.string());
      const n = unsigned(key.string());
      if (!hash || !key.eom()) {
        return false;
      }
      const cryptoKey = await crypto.subtle.importKey(
          'jwk', {kty: 'RSA', n: toBase64Url(n), e: toBase64Url(e)},
          {name: 'RSASSA-PKCS1-v1_5', hash}, false, ['verify']);
      return await crypto.subtle.verify(
          {name: 'RSASSA-PKCS1-v1_5'}, cryptoKey, sigBytes, data);
    }
  } catch (e) {
    // Malformed input.
  }
  return false;
}
