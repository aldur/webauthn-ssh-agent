// SPDX-License-Identifier: BSD-3-Clause

import assert from 'node:assert/strict';
import {test} from 'node:test';

import {concat} from '../src/bytes.js';
import {verifyHostKeySignature} from '../src/hostkey.js';
import {encodeString} from '../src/ssh.js';
import {makeHostKey} from './helpers.js';

for (const type of ['ed25519', 'nistp256', 'rsa']) {
  test(`verifyHostKeySignature: ${type}`, async () => {
    const key = await makeHostKey(type);
    const other = await makeHostKey(type);
    const data = crypto.getRandomValues(new Uint8Array(32));
    const signature = await key.sign(data);

    assert.equal(await verifyHostKeySignature(key.blob, signature, data), true);
    assert.equal(await verifyHostKeySignature(
        key.blob, signature, new Uint8Array(32)), false);
    assert.equal(
        await verifyHostKeySignature(other.blob, signature, data), false);
    assert.equal(await verifyHostKeySignature(
        key.blob, concat(signature, new Uint8Array(1)), data), false);
    assert.equal(await verifyHostKeySignature(
        key.blob, signature.subarray(0, signature.length - 1), data), false);
  });
}

test('verifyHostKeySignature: no SHA-1 RSA, no unknown types', async () => {
  const key = await makeHostKey('rsa');
  const data = new Uint8Array(32);
  const signature = await key.sign(data);
  // Same bytes, but claiming to be a SHA-1 "ssh-rsa" signature.
  const sha1 = concat(encodeString('ssh-rsa'),
                      signature.subarray(4 + 'rsa-sha2-512'.length));
  assert.equal(await verifyHostKeySignature(key.blob, sha1, data), false);
  assert.equal(await verifyHostKeySignature(
      concat(encodeString('ssh-dss'), encodeString(new Uint8Array(8))),
      signature, data), false);
  assert.equal(await verifyHostKeySignature(
      new Uint8Array(), new Uint8Array(), data), false);
});
