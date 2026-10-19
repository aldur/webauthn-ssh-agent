// SPDX-License-Identifier: BSD-3-Clause

import assert from 'node:assert/strict';
import {test} from 'node:test';

import {findApplication, sha256} from '../src/keys.js';
import {toBase64Url} from '../src/ssh.js';

test('findApplication', async () => {
  const hash = await sha256('chrome-extension://abcdef');
  assert.equal(
      await findApplication(hash, ['abcdef', 'chrome-extension://abcdef']),
      'chrome-extension://abcdef');
  assert.equal(await findApplication(hash, ['abcdef']), null);
});

test('kindOf', async () => {
  const {Kind, kindOf} = await import('../src/keys.js');
  assert.equal(kindOf('cross-platform', ['usb']), Kind.SECURITY_KEY);
  assert.equal(kindOf('cross-platform', ['nfc', 'usb']), Kind.SECURITY_KEY);
  assert.equal(kindOf(null, []), Kind.SECURITY_KEY);
  assert.equal(kindOf('platform', ['internal']), Kind.PASSKEY);
  assert.equal(kindOf('cross-platform', ['hybrid', 'internal']), Kind.PASSKEY);
});

test('describeKey', async () => {
  const {describeKey} = await import('../src/keys.js');
  assert.equal(describeKey({kind: 'security-key', resident: false}),
               'security key');
  assert.match(describeKey({kind: 'security-key', resident: true}),
               /discoverable credential/);
  // Keys from before "kind" existed were all on security keys.
  assert.equal(describeKey({resident: false}), 'security key');
  assert.match(describeKey({kind: 'passkey', resident: true}), /passkey/);
});

const ORIGIN = 'chrome-extension://test';
const POINT = toBase64Url(new Uint8Array([4, ...new Uint8Array(64).fill(1)]));
const storedKey = (id, created, extra = {}) => ({
  credentialId: id, publicKey: POINT, application: ORIGIN, comment: id,
  created, resident: false, verify: false, ...extra,
});

function fakeStorage() {
  const area = (store) => ({
    get: async (names) => names === null ? {...store} :
        Object.fromEntries([names].flat().filter((n) => n in store)
                               .map((n) => [n, store[n]])),
    set: async (items) => Object.assign(store, items),
    remove: async (names) => [names].flat().forEach((n) => delete store[n]),
  });
  const sync = {};
  const local = {};
  globalThis.chrome = {storage: {sync: area(sync), local: area(local)}};
  globalThis.location = {origin: ORIGIN, hostname: 'test'};
  return {sync, local};
}

test('key storage: one item per key, migrating the old format', async () => {
  const {deleteKey, loadKeys} = await import('../src/keys.js');
  const {sync: store} = fakeStorage();

  store.keys = [storedKey('b', 2), storedKey('a', 1)];
  store['key:c'] = storedKey('c', 3);

  assert.deepEqual((await loadKeys()).map((k) => k.credentialId),
                   ['a', 'b', 'c']);
  assert.deepEqual(Object.keys(store).sort(), ['key:a', 'key:b', 'key:c']);

  await deleteKey('b');
  assert.deepEqual((await loadKeys()).map((k) => k.credentialId), ['a', 'c']);
  delete globalThis.chrome;
  delete globalThis.location;
});

test('key storage: the old format is kept unless fully migrated', async () => {
  const {loadKeys} = await import('../src/keys.js');
  const {sync: store} = fakeStorage();
  const unreadable = {credentialId: 'x', comment: 'from the future'};
  store.keys = [storedKey('a', 1), unreadable];
  assert.deepEqual((await loadKeys()).map((k) => k.credentialId), ['a']);
  assert.deepEqual(store.keys, [storedKey('a', 1), unreadable]);
  assert.ok(store['key:a']);
  delete globalThis.chrome;
  delete globalThis.location;
});

test('validateKey refuses anything malformed', async () => {
  const {validateKey} = await import('../src/keys.js');
  assert.ok(validateKey(storedKey('a', 1), [ORIGIN, 'test']));
  // Browsers may use the extension's hostname as its RP ID.
  assert.ok(validateKey(storedKey('a', 1, {application: 'test'}),
                        [ORIGIN, 'test']));
  for (const bad of [
    null, 'x', {},
    storedKey('a', 1, {application: 'chrome-extension://other'}),
    storedKey('a', 1, {credentialId: 'not base64url!'}),
    storedKey('a', 1, {publicKey: toBase64Url(new Uint8Array(65))}),
    storedKey('a', 1, {publicKey: toBase64Url(new Uint8Array(33).fill(4))}),
    storedKey('a', 1, {comment: 7}),
    storedKey('a', 1, {created: Infinity}),
    storedKey('a', 1, {resident: 'yes'}),
    storedKey('a', 1, {verify: 1}),
    storedKey('a', 1, {kind: 'magic'}),
    storedKey('a', 1, {verifyEnforcedByKey: 'true'}),
  ]) {
    assert.equal(validateKey(bad, [ORIGIN, 'test']), null,
                 JSON.stringify(bad));
  }
  // Names are cleaned: nothing that could add a line to authorized_keys.
  assert.equal(
      validateKey(storedKey('a', 1, {comment: 'x\nssh-rsa AAAA'}), [ORIGIN])
          .comment,
      'x ssh-rsa AAAA');
});

test('a key\'s own confirmation level, for keys verified here', async () => {
  const {confirmationFor, loadKeys, setKeyConfirmation, validateKey} =
      await import('../src/keys.js');
  assert.equal(validateKey(storedKey('a', 1, {confirmation: 'loud'}),
                           [ORIGIN]), null);
  const {sync, local} = fakeStorage();
  sync['key:a'] = storedKey('a', 1);
  const settings = {confirmation: 'review'};

  let [key] = await loadKeys();
  await setKeyConfirmation(key, 'silent');
  [key] = await loadKeys();
  assert.equal(key.confirmation, 'silent');
  // Not verified on this computer (only synced): the default applies.
  assert.equal(await confirmationFor(key, settings), 'review');

  // Verified here: its own level applies.
  const {sha256} = await import('../src/keys.js');
  local['verified:a'] = toBase64Url(await sha256(JSON.stringify(
      [key.credentialId, key.publicKey, key.application, key.verify])));
  assert.equal(await confirmationFor(key, settings), 'silent');
  await setKeyConfirmation(key, null);
  [key] = await loadKeys();
  assert.equal(await confirmationFor(key, settings), 'review');
  delete globalThis.chrome;
  delete globalThis.location;
});

test('synced keys are unverified until checked on this computer', async () => {
  const {isVerified, loadKeys} = await import('../src/keys.js');
  const {sync, local} = fakeStorage();
  sync['key:a'] = storedKey('a', 1);
  const [key] = await loadKeys();
  assert.equal(await isVerified(key), false);
  // Unless the user trusts synced keys.
  local.settings = {trustSyncedKeys: true};
  assert.equal(await isVerified(key), true);
  delete globalThis.chrome;
  delete globalThis.location;
});
