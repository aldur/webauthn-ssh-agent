// SPDX-License-Identifier: BSD-3-Clause

import assert from 'node:assert/strict';
import {test} from 'node:test';

import {aaguidOf, authDataExtensions} from '../src/authdata.js';
import {attested, authDataHeader, credProtect} from './helpers.js';

// Flags: UP 0x01, UV 0x04, AT 0x40 (attested credential data), ED 0x80
// (extensions).
const AT = 0x40;
const ED = 0x80;

test('authDataExtensions: what the authenticator reported', () => {
  const read = (...parts) => authDataExtensions(new Uint8Array(parts.flat()));
  // On creation: attested credential data (AT), then extensions (ED).
  assert.equal(read(authDataHeader(AT | ED | 0x05), attested, credProtect)
      .get('credProtect'), 3);
  // On use: just extensions.
  assert.equal(read(authDataHeader(ED | 0x01), credProtect).get('credProtect'),
               3);
  // None, or unreadable.
  assert.equal(read(authDataHeader(AT | 0x05), attested).size, 0);
  assert.equal(
      read(authDataHeader(AT | ED | 0x05), attested.slice(0, 30)).size, 0);
  assert.equal(read(new Array(10).fill(0)).size, 0);
});

test('aaguidOf: the model, unless it was hidden', () => {
  const aaguid = [0xee, 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13,
                  0x97, 0x75, 0x3d, 0xfc, 0xce, 0x97, 0x07, 0x2a];
  const withAaguid = (bytes) => new Uint8Array(
      [...authDataHeader(AT | 0x05), ...bytes, ...attested.slice(16)]);
  assert.equal(aaguidOf(withAaguid(aaguid)),
               'ee882879-721c-4913-9775-3dfcce97072a');
  // Browsers often zero it without attestation.
  assert.equal(aaguidOf(withAaguid(new Uint8Array(16))), undefined);
  // Only creating a credential reports one.
  assert.equal(aaguidOf(new Uint8Array(authDataHeader(0x05))), undefined);
});
