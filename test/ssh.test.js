// SPDX-License-Identifier: BSD-3-Clause

import assert from 'node:assert/strict';
import {test} from 'node:test';

import {concat, fromBase64} from '../src/bytes.js';
import {
  Reader, WEBAUTHN_SK_ECDSA_SIG_TYPE, authorizedKeysLine,
  decodeDerEcdsaSignature, describeSignData, encodeMpint, encodeString,
  fingerprint, p256PointFromSpki, skEcdsaKeyBlob,
  webauthnAssertionToSshSignature,
} from '../src/ssh.js';

// A key sshd accepted in an end-to-end test against a WebAuthn virtual
// authenticator on http://localhost.
const POINT = fromBase64(
    'BFJXDZN53Fvox8rxBLHYxufhMiDjhQfhBf49/F+TUlycV8TgKS34PBi5mjf/YS69gcyxCebO' +
    'wrSPKiO6tIWgADs=');
const AUTHORIZED_KEY =
    'sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZA' +
    'b3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBFJXDZN53Fvox8rxBLHYxufhMiDjhQfhBf49' +
    '/F+TUlycV8TgKS34PBi5mjf/YS69gcyxCebOwrSPKiO6tIWgADsAAAAJbG9jYWxob3N0';

test('authorized_keys line', () => {
  const blob = skEcdsaKeyBlob(POINT, 'localhost');
  assert.equal(authorizedKeysLine(blob, 'my-key'), `${AUTHORIZED_KEY} my-key`);
  assert.equal(authorizedKeysLine(blob, 'my-key', {verifyRequired: true}),
               `verify-required ${AUTHORIZED_KEY} my-key`);
});

test('encodeMpint', () => {
  assert.deepEqual(encodeMpint(new Uint8Array([0, 0, 0x12])),
                   new Uint8Array([0, 0, 0, 1, 0x12]));
  assert.deepEqual(encodeMpint(new Uint8Array([0x80])),
                   new Uint8Array([0, 0, 0, 2, 0, 0x80]));
  assert.deepEqual(encodeMpint(new Uint8Array([0])),
                   new Uint8Array([0, 0, 0, 0]));
});

test('p256PointFromSpki', async () => {
  const {publicKey} = await crypto.subtle.generateKey(
      {name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
  assert.deepEqual(p256PointFromSpki(spki), raw);
  assert.throws(() => p256PointFromSpki(spki.subarray(1)));
});

test('decodeDerEcdsaSignature', () => {
  const der = new Uint8Array([
    0x30, 0x0a, 0x02, 0x03, 0x00, 0x80, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03,
  ]);
  const {r, s} = decodeDerEcdsaSignature(der);
  assert.deepEqual(r, new Uint8Array([0x00, 0x80, 0x01]));
  assert.deepEqual(s, new Uint8Array([0x01, 0x02, 0x03]));
  assert.throws(() => decodeDerEcdsaSignature(der.subarray(1)));
  assert.throws(() => decodeDerEcdsaSignature(concat(der, new Uint8Array(1))));

  const bad = [
    // Wrong tags.
    [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
    [0x30, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x01],
    // Negative, non-minimal, empty & oversized integers.
    [0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01],
    [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01],
    [0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01],
    [0x30, 0x26, 0x02, 0x22, 0x00, 0x80, ...new Array(32).fill(1),
     0x02, 0x01, 0x01],
    // Long form lengths that didn't need it.
    [0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
    [0x30, 0x06, 0x02, 0x81, 0x01, 0x01, 0x02, 0x01, 0x01],
    // Lengths running past the end.
    [0x30, 0x06, 0x02, 0x05, 0x01, 0x02, 0x01, 0x01],
    [0x30, 0x84, 0x00, 0x00, 0x00, 0x06],
    [],
  ];
  for (const bytes of bad) {
    assert.throws(() => decodeDerEcdsaSignature(new Uint8Array(bytes)),
                  undefined, bytes.join(','));
  }
});

test('webauthnAssertionToSshSignature', () => {
  const authenticatorData = new Uint8Array(40);
  authenticatorData.fill(0xaa, 0, 32);
  authenticatorData.set([0x81, 0, 0, 1, 2, 0xa0, 0xb0, 0xc0], 32);
  const clientDataJSON = new TextEncoder().encode(
      '{"type":"webauthn.get","challenge":"AAEC",' +
      '"origin":"chrome-extension://abc","crossOrigin":false}');
  const signature = new Uint8Array(
      [0x30, 0x08, 0x02, 0x02, 0x00, 0x90, 0x02, 0x02, 0x12, 0x34]);

  const r = new Reader(webauthnAssertionToSshSignature(
      {authenticatorData, clientDataJSON, signature}));
  assert.equal(r.text(), WEBAUTHN_SK_ECDSA_SIG_TYPE);
  const inner = new Reader(r.string());
  assert.deepEqual(inner.string(), new Uint8Array([0x00, 0x90]));
  assert.deepEqual(inner.string(), new Uint8Array([0x12, 0x34]));
  assert.ok(inner.eom());
  assert.equal(r.byte(), 0x81);
  assert.equal(r.uint32(), 258);
  assert.equal(r.text(), 'chrome-extension://abc');
  assert.deepEqual(r.string(), clientDataJSON);
  assert.deepEqual(r.string(), new Uint8Array([0xa0, 0xb0, 0xc0]));
  assert.ok(r.eom());

  assert.throws(() => webauthnAssertionToSshSignature({
    authenticatorData,
    clientDataJSON: new TextEncoder().encode(
        '{"type":"webauthn.create","challenge":"","origin":"x"}'),
    signature,
  }));
});

test('describeSignData', async () => {
  const userauth = (method, ...extra) => concat(
      encodeString(new Uint8Array(32)), new Uint8Array([50]),
      encodeString('alice'), encodeString('ssh-connection'),
      encodeString(method), new Uint8Array([1]),
      encodeString('sk-ecdsa-sha2-nistp256@openssh.com'),
      encodeString(new Uint8Array(10)), ...extra);

  const sessionId = new Uint8Array(32);
  assert.deepEqual(describeSignData(userauth('publickey')),
                   {kind: 'login', user: 'alice', sessionId});

  const hostKey = new Uint8Array([7, 7, 7]);
  assert.deepEqual(
      describeSignData(userauth('publickey-hostbound-v00@openssh.com',
                                encodeString(hostKey))),
      {kind: 'login', user: 'alice', sessionId, hostKey});
  // The host key is mandatory for hostbound requests.
  assert.equal(
      describeSignData(userauth('publickey-hostbound-v00@openssh.com')).kind,
      'unknown');
  // As is the exact layout.
  assert.equal(
      describeSignData(userauth('publickey', new Uint8Array(1))).kind,
      'unknown');
  assert.equal(describeSignData(userauth('password')).kind, 'unknown');

  const sshsig = concat(new TextEncoder().encode('SSHSIG'), encodeString('git'),
                        encodeString(''), encodeString('sha512'),
                        encodeString(new Uint8Array(64)));
  assert.deepEqual(describeSignData(sshsig), {kind: 'sshsig', namespace: 'git'});

  assert.deepEqual(describeSignData(new Uint8Array([1, 2, 3])),
                   {kind: 'unknown'});
});

test('fingerprint', async () => {
  // As printed by `ssh-keygen -lf` for this key.
  const blob = fromBase64(
      'AAAAC3NzaC1lZDI1NTE5AAAAIKsEa2RL2X0d3L3CA9uwTbqQvJfVjIEEJzH/i8lpWkNq');
  assert.equal(await fingerprint(blob),
               'SHA256:3tKJiO2GW25nKi0aDEkaGmsavQSwmE12+eZjrEfp0W4');
});
