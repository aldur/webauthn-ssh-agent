// SPDX-License-Identifier: BSD-3-Clause

import assert from 'node:assert/strict';
import {test} from 'node:test';

import {cleanName, displayText, utf8Prefix} from '../src/text.js';

test('displayText makes disguising characters visible', () => {
  assert.equal(displayText('alice'), 'alice');
  assert.equal(displayText('a\nb'), 'a\\u{000a}b');
  assert.equal(displayText('root‮gnp.exe'), 'root\\u{202e}gnp.exe');
  assert.equal(displayText('x​y'), 'x\\u{200b}y');
  assert.equal(displayText('é😀'), 'é😀');
});

test('displayText cuts long text short', () => {
  assert.equal(displayText('a'.repeat(64)), 'a'.repeat(64));
  assert.equal(displayText('a'.repeat(65)), 'a'.repeat(63) + '…');
  assert.equal([...displayText('😀'.repeat(100))].length, 64);
});

test('cleanName', () => {
  assert.equal(cleanName('  my\r\nkey\t x  '), 'my key x');
  assert.equal(cleanName('‮\u0000'), '');
  assert.equal(cleanName('k'.repeat(100)).length, 64);
});

test('utf8Prefix never splits a character', () => {
  assert.deepEqual(utf8Prefix('abc', 10), new TextEncoder().encode('abc'));
  assert.deepEqual(utf8Prefix('aé', 2), new TextEncoder().encode('a'));
  assert.deepEqual(utf8Prefix('😀😀', 7), new TextEncoder().encode('😀'));
  assert.equal(new TextDecoder('utf-8', {fatal: true})
                   .decode(utf8Prefix('é'.repeat(40), 47)), 'é'.repeat(23));
});
