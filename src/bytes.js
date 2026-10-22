// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Byte arrays: joining, comparing, base64 & hashing.
 */

/**
 * @param {...!Uint8Array} arrays
 * @return {!Uint8Array}
 */
export function concat(...arrays) {
  const ret = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let pos = 0;
  for (const a of arrays) {
    ret.set(a, pos);
    pos += a.length;
  }
  return ret;
}

/**
 * @param {!Uint8Array} a
 * @param {!Uint8Array} b
 * @return {boolean}
 */
export function equalBytes(a, b) {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

/**
 * @param {!Uint8Array|!ArrayBuffer} bytes
 * @return {string}
 */
export function toBase64(bytes) {
  let str = '';
  for (const byte of new Uint8Array(bytes)) {
    str += String.fromCharCode(byte);
  }
  return btoa(str);
}

/**
 * @param {string} str
 * @return {!Uint8Array}
 */
export function fromBase64(str) {
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}

/**
 * @param {!Uint8Array|!ArrayBuffer} bytes
 * @return {string} Unpadded base64url.
 */
export function toBase64Url(bytes) {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_')
      .replace(/=+$/, '');
}

/**
 * @param {string} str Base64url, with or without padding.
 * @return {!Uint8Array}
 */
export function fromBase64Url(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  return fromBase64(b64 + '='.repeat((4 - b64.length % 4) % 4));
}

/**
 * @param {!Uint8Array|string} data Strings are UTF-8 encoded.
 * @return {!Promise<!Uint8Array>}
 */
export async function sha256(data) {
  if (typeof data === 'string') {
    data = new TextEncoder().encode(data);
  }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}
