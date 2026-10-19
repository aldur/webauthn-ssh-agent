// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Just enough NIST P-256 arithmetic to recover the public key
 * from an ECDSA signature.
 *
 * WebAuthn never returns the public key of an existing credential, which we
 * need when importing a key stored on a security key.  Each signature yields
 * up to two candidate keys; verifying a second signature picks the right one.
 */

import {concat} from './ssh.js';

/**
 * @see https://www.secg.org/sec2-v2.pdf (secp256r1)
 */
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const G = {
  x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
};

/**
 * @param {bigint} a
 * @param {bigint} m
 * @return {bigint} a mod m in [0, m).
 */
function mod(a, m) {
  const r = a % m;
  return r < 0n ? r + m : r;
}

/**
 * @param {bigint} base
 * @param {bigint} exp
 * @param {bigint} m
 * @return {bigint}
 */
function modPow(base, exp, m) {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * base) % m;
    }
    base = (base * base) % m;
    exp >>= 1n;
  }
  return result;
}

/**
 * @param {bigint} a
 * @param {bigint} m A prime.
 * @return {bigint}
 */
function modInv(a, m) {
  return modPow(a, m - 2n, m);
}

/**
 * Add two points; null is the point at infinity.
 *
 * @param {?{x: bigint, y: bigint}} p1
 * @param {?{x: bigint, y: bigint}} p2
 * @return {?{x: bigint, y: bigint}}
 */
function add(p1, p2) {
  if (p1 === null) {
    return p2;
  }
  if (p2 === null) {
    return p1;
  }
  let lambda;
  if (p1.x === p2.x) {
    if (mod(p1.y + p2.y, P) === 0n) {
      return null;
    }
    // Doubling; the curve's a coefficient is -3.
    lambda = mod((3n * p1.x * p1.x - 3n) * modInv(2n * p1.y, P), P);
  } else {
    lambda = mod((p2.y - p1.y) * modInv(p2.x - p1.x, P), P);
  }
  const x = mod(lambda * lambda - p1.x - p2.x, P);
  return {x, y: mod(lambda * (p1.x - x) - p1.y, P)};
}

/**
 * @param {bigint} k
 * @param {?{x: bigint, y: bigint}} point
 * @return {?{x: bigint, y: bigint}} k * point.
 */
function multiply(k, point) {
  let result = null;
  while (k > 0n) {
    if (k & 1n) {
      result = add(result, point);
    }
    point = add(point, point);
    k >>= 1n;
  }
  return result;
}

/**
 * @param {!Uint8Array} bytes Big endian.
 * @return {bigint}
 */
function toBigInt(bytes) {
  let ret = 0n;
  for (const byte of bytes) {
    ret = (ret << 8n) | BigInt(byte);
  }
  return ret;
}

/**
 * @param {bigint} value
 * @param {number} length
 * @return {!Uint8Array} Big endian, zero padded.
 */
function toBytes(value, length) {
  const ret = new Uint8Array(length);
  for (let i = length - 1; i >= 0; --i) {
    ret[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return ret;
}

/**
 * Recover the possible public keys that made an ECDSA P-256 signature.
 *
 * @see https://www.secg.org/sec1-v2.pdf section 4.1.6
 * @param {!Uint8Array} hash SHA-256 of the signed message.
 * @param {!Uint8Array} r
 * @param {!Uint8Array} s
 * @return {!Array<!Uint8Array>} Uncompressed points (0x04 || X || Y).
 */
export function recoverPublicKeys(hash, r, s) {
  const rn = toBigInt(r);
  const sn = toBigInt(s);
  if (rn <= 0n || rn >= N || sn <= 0n || sn >= N) {
    return [];
  }
  const rInv = modInv(rn, N);
  const u1 = mod(-toBigInt(hash) * rInv, N);
  const u2 = mod(sn * rInv, N);

  // R.x == r (R.x == r + n is possible in theory, but astronomically rare).
  const x = rn;
  const ySquared = mod(x * x * x - 3n * x + B, P);
  // P = 3 mod 4, so the square root is a simple exponentiation.
  const y = modPow(ySquared, (P + 1n) / 4n, P);
  if (mod(y * y, P) !== ySquared) {
    return [];
  }

  const keys = [];
  for (const ry of [y, P - y]) {
    const q = add(multiply(u1, G), multiply(u2, {x, y: ry}));
    if (q !== null) {
      keys.push(concat(new Uint8Array([4]), toBytes(q.x, 32),
                       toBytes(q.y, 32)));
    }
  }
  return keys;
}

/**
 * Verify an ECDSA P-256/SHA-256 signature with WebCrypto.
 *
 * @param {!Uint8Array} publicKey Uncompressed point.
 * @param {!Uint8Array} message The signed data (hashed by WebCrypto).
 * @param {{r: !Uint8Array, s: !Uint8Array}} signature
 * @return {!Promise<boolean>}
 */
export async function verifySignature(publicKey, message, {r, s}) {
  const key = await crypto.subtle.importKey(
      'raw', publicKey, {name: 'ECDSA', namedCurve: 'P-256'}, false,
      ['verify']);
  const raw = concat(toBytes(toBigInt(r), 32), toBytes(toBigInt(s), 32));
  return crypto.subtle.verify(
      {name: 'ECDSA', hash: 'SHA-256'}, key, raw, message);
}
