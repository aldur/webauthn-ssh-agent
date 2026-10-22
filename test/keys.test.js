// SPDX-License-Identifier: BSD-3-Clause

import assert from 'node:assert/strict';
import {test} from 'node:test';

import {sha256, toBase64Url} from '../src/bytes.js';
import {findApplication} from '../src/keys.js';
import {attested, authDataHeader, credProtect} from './helpers.js';

test('findApplication', async () => {
  const hash = await sha256('chrome-extension://abcdef');
  assert.equal(
      await findApplication(hash, ['abcdef', 'chrome-extension://abcdef']),
      'chrome-extension://abcdef');
  assert.equal(await findApplication(hash, ['abcdef']), null);
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

test('createKey: PIN enforcement as the authenticator reports it', async () => {
  const {createKey} = await import('../src/keys.js');
  // What Chrome returns: credProtect's output only in the authenticator
  // data, never in getClientExtensionResults().
  const rpIdHash = await sha256(ORIGIN);
  const create = (extensions) => async () => ({
    rawId: new Uint8Array([9, 9, 9, 9]).buffer,
    authenticatorAttachment: 'cross-platform',
    getClientExtensionResults: () => ({credProps: {rk: false}}),
    response: {
      getPublicKeyAlgorithm: () => -7,
      getPublicKey: () => new Uint8Array(
          [...new Uint8Array(26), 4, ...new Uint8Array(64).fill(1)]).buffer,
      getTransports: () => ['usb'],
      getAuthenticatorData: () => new Uint8Array([
        ...authDataHeader(0x45 | (extensions.length ? 0x80 : 0), rpIdHash),
        ...attested, ...extensions]).buffer,
    },
  });
  const original = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  for (const [extensions, enforced] of [[credProtect, true], [[], false]]) {
    fakeStorage();
    Object.defineProperty(globalThis, 'navigator', {
      value: {credentials: {create: create(extensions)}},
      configurable: true,
    });
    const key = await createKey('k', {verify: true});
    assert.equal(key.verifyEnforcedByKey, enforced);
  }
  Object.defineProperty(globalThis, 'navigator', original);
  delete globalThis.chrome;
  delete globalThis.location;
});

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

test('isMismatched: a security key that turns out backup eligible', async () => {
  const {isMismatched} = await import('../src/keys.js');
  const key = (extra) => storedKey('a', 1, extra);
  assert.equal(isMismatched(key({})), false);
  assert.equal(isMismatched(key({requested: 'security-key'})), false);
  assert.equal(isMismatched(
      key({requested: 'security-key', backupEligible: false})), false);
  assert.equal(isMismatched(
      key({requested: 'security-key', backupEligible: true})), true);
  assert.equal(isMismatched(
      key({requested: 'passkey', backupEligible: true})), false);
});

test('key order: as the user set it, then by age', async () => {
  const {loadKeys, reorderKeys, validateKey} = await import('../src/keys.js');
  assert.equal(validateKey(storedKey('a', 1, {order: -1}), [ORIGIN]), null);
  assert.equal(validateKey(storedKey('a', 1, {order: 0.5}), [ORIGIN]), null);
  const {sync} = fakeStorage();
  const ids = async () => (await loadKeys()).map((k) => k.credentialId);
  // Without an order (older keys), by age.
  sync['key:a'] = storedKey('a', 1);
  sync['key:b'] = storedKey('b', 2);
  sync['key:c'] = storedKey('c', 3);
  assert.deepEqual(await ids(), ['a', 'b', 'c']);
  await reorderKeys(['c', 'a', 'b', 'gone']);
  assert.deepEqual(await ids(), ['c', 'a', 'b']);
  assert.deepEqual([sync['key:c'].order, sync['key:a'].order], [0, 1]);
  // A new key comes last; clashes (e.g. from two computers) go by age.
  sync['key:d'] = storedKey('d', 0);
  sync['key:b'].order = 0;
  assert.deepEqual(await ids(), ['b', 'c', 'a', 'd']);
  delete globalThis.chrome;
  delete globalThis.location;
});

test('renaming & other updates are validated', async () => {
  const {loadKeys, renameKey, setKeyConfirmation, validateKey} =
      await import('../src/keys.js');
  assert.equal(validateKey(storedKey('a', 1, {backedUp: 'yes'}), [ORIGIN]),
               null);
  assert.equal(validateKey(storedKey('a', 1, {requested: 'any'}), [ORIGIN]),
               null);
  assert.equal(validateKey(storedKey('a', 1, {imported: 1}), [ORIGIN]),
               null);
  assert.equal(validateKey(storedKey('a', 1, {attachment: 'usb'}), [ORIGIN]),
               null);
  assert.equal(validateKey(storedKey('a', 1, {aaguid: 'EE88'}), [ORIGIN]),
               null);
  assert.equal(validateKey(storedKey('a', 1, {transports: 'usb'}), [ORIGIN]),
               null);
  assert.equal(
      validateKey(storedKey('a', 1, {transports: ['<b>']}), [ORIGIN]), null);
  assert.deepEqual(validateKey(storedKey('a', 1, {
    attachment: 'cross-platform', transports: ['usb', 'nfc'],
  }), [ORIGIN]).transports, ['usb', 'nfc']);
  const {sync} = fakeStorage();
  sync['key:a'] = storedKey('a', 1);
  let [key] = await loadKeys();

  await renameKey(key, '  new\nname ');
  [key] = await loadKeys();
  assert.equal(key.comment, 'new name');
  await assert.rejects(renameKey(key, ' \n '), /needs a name/);
  await assert.rejects(setKeyConfirmation(key, 'loud'), /invalid change/);
  await assert.rejects(renameKey(storedKey('gone', 1), 'x'), /no such key/);
  delete globalThis.chrome;
  delete globalThis.location;
});
