// SPDX-License-Identifier: BSD-3-Clause

import assert from 'node:assert/strict';
import {test} from 'node:test';

import {SessionBindings} from '../src/binding.js';
import {makeHostKey} from './helpers.js';

const sessionId = () => crypto.getRandomValues(new Uint8Array(32));

test('a direct binding is final', async () => {
  const host = await makeHostKey('ed25519');
  const bindings = new SessionBindings();
  const id = sessionId();
  assert.equal(await bindings.bind(
      host.blob, id, await host.sign(id), false), true);
  assert.equal(bindings.forwarded, false);
  assert.deepEqual(bindings.last.sessionId, id);

  const id2 = sessionId();
  assert.equal(await bindings.bind(
      host.blob, id2, await host.sign(id2), false), false);
  assert.equal(await bindings.bind(
      host.blob, id, await host.sign(id), false), false);
  assert.equal(bindings.bindings.length, 1);
});

test('bad signatures are refused', async () => {
  const host = await makeHostKey('nistp256');
  const bindings = new SessionBindings();
  const id = sessionId();
  assert.equal(await bindings.bind(
      host.blob, id, await host.sign(sessionId()), false), false);
  assert.equal(bindings.last, null);
});

test('forwarded hops, then a login', async () => {
  const first = await makeHostKey('ed25519');
  const second = await makeHostKey('ed25519');
  const bindings = new SessionBindings();
  const id1 = sessionId();
  const id2 = sessionId();
  assert.equal(await bindings.bind(
      first.blob, id1, await first.sign(id1), true), true);
  // The same session again is fine, but not for a different host.
  assert.equal(await bindings.bind(
      first.blob, id1, await first.sign(id1), true), true);
  assert.equal(await bindings.bind(
      second.blob, id1, await second.sign(id1), true), false);
  assert.equal(await bindings.bind(
      second.blob, id2, await second.sign(id2), false), true);
  assert.equal(bindings.forwarded, true);
  assert.deepEqual(bindings.first.hostKey, first.blob);
  assert.deepEqual(bindings.last.hostKey, second.blob);
});

test('at most 16 bindings', async () => {
  const host = await makeHostKey('ed25519');
  const bindings = new SessionBindings();
  for (let i = 0; i < 16; ++i) {
    const id = sessionId();
    assert.equal(await bindings.bind(
        host.blob, id, await host.sign(id), true), true);
  }
  const id = sessionId();
  assert.equal(await bindings.bind(
      host.blob, id, await host.sign(id), true), false);
});
