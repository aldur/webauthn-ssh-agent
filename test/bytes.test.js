// SPDX-License-Identifier: BSD-3-Clause

import assert from 'node:assert/strict';
import {test} from 'node:test';

import {
  concat, equalBytes, fromBase64Url, sha256, toBase64Url,
} from '../src/bytes.js';

test('base64url round trip', () => {
  for (let len = 0; len < 40; ++len) {
    const bytes = crypto.getRandomValues(new Uint8Array(len));
    const encoded = toBase64Url(bytes);
    assert.match(encoded, /^[A-Za-z0-9_-]*$/);
    assert.deepEqual(fromBase64Url(encoded), bytes);
  }
});

test('concat & equalBytes', () => {
  const bytes = (...b) => new Uint8Array(b);
  assert.deepEqual(concat(bytes(1), bytes(), bytes(2, 3)), bytes(1, 2, 3));
  assert.ok(equalBytes(bytes(1, 2), bytes(1, 2)));
  assert.ok(!equalBytes(bytes(1, 2), bytes(1, 3)));
  assert.ok(!equalBytes(bytes(1), bytes(1, 0)));
});

test('sha256', async () => {
  assert.equal(toBase64Url(await sha256('abc')),
               'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0');
  assert.deepEqual(await sha256('abc'),
                   await sha256(new TextEncoder().encode('abc')));
});
