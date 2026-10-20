// SPDX-License-Identifier: BSD-3-Clause

import assert from 'node:assert/strict';
import {test} from 'node:test';

import {decodeCbor} from '../src/cbor.js';

const bytes = (...b) => new Uint8Array(b);

test('decodeCbor', () => {
  assert.deepEqual(decodeCbor(bytes(0x17), 0), {value: 23, end: 1});
  assert.deepEqual(decodeCbor(bytes(0x19, 0x01, 0x00), 0),
                   {value: 256, end: 3});
  assert.deepEqual(decodeCbor(bytes(0x26), 0), {value: -7, end: 1});
  assert.deepEqual(decodeCbor(bytes(0x62, 0x68, 0x69), 0),
                   {value: 'hi', end: 3});
  assert.deepEqual(decodeCbor(bytes(0x42, 1, 2), 0).value, bytes(1, 2));
  assert.deepEqual(decodeCbor(bytes(0x82, 0xf5, 0xf6), 0).value, [true, null]);
  // {"a": 1, 2: -1}, starting after a byte to skip.
  assert.deepEqual(decodeCbor(bytes(0, 0xa2, 0x61, 0x61, 1, 2, 0x20), 1), {
    value: new Map([['a', 1], [2, -1]]),
    end: 7,
  });
  assert.throws(() => decodeCbor(bytes(0x62, 0x68), 0), /truncated/);
  assert.throws(() => decodeCbor(bytes(0x9f), 0), /unsupported/);
  assert.throws(() => decodeCbor(bytes(), 0), /truncated/);
});
