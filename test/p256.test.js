// SPDX-License-Identifier: BSD-3-Clause

import assert from 'node:assert/strict';
import {test} from 'node:test';

import {recoverPublicKeys, verifySignature} from '../src/p256.js';

test('recoverPublicKeys finds the key that made a signature', async () => {
  for (let i = 0; i < 5; ++i) {
    const {publicKey, privateKey} = await crypto.subtle.generateKey(
        {name: 'ECDSA', namedCurve: 'P-256'}, false, ['sign', 'verify']);
    const point =
        new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
    const sign = async (message) => {
      // WebCrypto signatures are r || s.
      const raw = new Uint8Array(await crypto.subtle.sign(
          {name: 'ECDSA', hash: 'SHA-256'}, privateKey, message));
      return {r: raw.subarray(0, 32), s: raw.subarray(32)};
    };

    const message1 = crypto.getRandomValues(new Uint8Array(100));
    const sig1 = await sign(message1);
    const hash1 =
        new Uint8Array(await crypto.subtle.digest('SHA-256', message1));
    const candidates = recoverPublicKeys(hash1, sig1.r, sig1.s);
    assert.equal(candidates.length, 2);
    assert.ok(candidates.some((c) => c.every((b, j) => b === point[j])));

    // Only the real key verifies another signature.
    const message2 = crypto.getRandomValues(new Uint8Array(100));
    const sig2 = await sign(message2);
    const verified = [];
    for (const candidate of candidates) {
      if (await verifySignature(candidate, message2, sig2)) {
        verified.push(candidate);
      }
    }
    assert.deepEqual(verified, [point]);
  }
});

test('recoverPublicKeys rejects out of range signatures', () => {
  const hash = new Uint8Array(32);
  assert.deepEqual(
      recoverPublicKeys(hash, new Uint8Array(32), new Uint8Array([1])), []);
  assert.deepEqual(
      recoverPublicKeys(hash, new Uint8Array([1]), new Uint8Array(32)), []);
});
