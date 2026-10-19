// SPDX-License-Identifier: BSD-3-Clause

import assert from 'node:assert/strict';
import {test} from 'node:test';

import {SessionBindings} from '../src/binding.js';
import {Decision, assess} from '../src/policy.js';
import {concat, encodeString, fingerprint} from '../src/ssh.js';
import {makeHostKey} from './helpers.js';

const STRICT = {allowUnrecognized: false};

/** A login request, as ssh signs it. */
function login(sessionId, user = 'alice', hostKey = undefined) {
  return concat(
      encodeString(sessionId), new Uint8Array([50]), encodeString(user),
      encodeString('ssh-connection'),
      encodeString(hostKey ? 'publickey-hostbound-v00@openssh.com' :
                             'publickey'),
      new Uint8Array([1]), encodeString('sk-ecdsa-sha2-nistp256@openssh.com'),
      encodeString(new Uint8Array(10)),
      ...(hostKey ? [encodeString(hostKey)] : []));
}

async function bound(host, forwarded = false) {
  const bindings = new SessionBindings();
  const sessionId = crypto.getRandomValues(new Uint8Array(32));
  assert.ok(await bindings.bind(
      host.blob, sessionId, await host.sign(sessionId), forwarded));
  return {bindings, sessionId};
}

test('a direct login to the bound server', async () => {
  const host = await makeHostKey('ed25519');
  const {bindings, sessionId} = await bound(host);
  for (const data of [login(sessionId), login(sessionId, 'alice', host.blob)]) {
    const {decision, fields} = await assess(data, bindings, STRICT);
    assert.equal(decision, Decision.ASK);
    assert.equal(fields.user, 'alice');
    assert.equal(fields.server, `${await fingerprint(host.blob)} (verified)`);
    assert.equal(fields.route, 'Direct connection');
    assert.equal(fields.warning, undefined);
  }
});

test('confirmation levels, for direct logins only', async () => {
  const host = await makeHostKey('ed25519');
  const {bindings, sessionId} = await bound(host);
  for (const [confirmation, decision] of [
    ['review', Decision.ASK], ['show', Decision.SHOW],
    ['silent', Decision.SILENT]]) {
    assert.equal((await assess(login(sessionId), bindings,
                               {allowUnrecognized: false, confirmation}))
                     .decision, decision);
  }
  const skip = {allowUnrecognized: false, confirmation: 'silent'};
  const forwarded = await bound(host, true);
  assert.equal((await assess(login(new Uint8Array(32)), forwarded.bindings,
                             skip)).decision, Decision.CONFIRM);
  assert.equal((await assess(login(new Uint8Array(32)),
                             new SessionBindings(), skip)).decision,
               Decision.CONFIRM);
});

test('a login for another session or server is refused', async () => {
  const host = await makeHostKey('ed25519');
  const other = await makeHostKey('ed25519');
  const {bindings, sessionId} = await bound(host);
  assert.equal((await assess(login(new Uint8Array(32)), bindings, STRICT))
                   .decision, Decision.REFUSE);
  assert.equal((await assess(login(sessionId, 'alice', other.blob), bindings,
                             STRICT)).decision, Decision.REFUSE);
});

test('logins through a forwarded agent need Continue', async () => {
  const host = await makeHostKey('ed25519');
  const target = await makeHostKey('ed25519');
  const {bindings} = await bound(host, true);
  const {decision, fields} = await assess(
      login(new Uint8Array(32), 'bob', target.blob), bindings, STRICT);
  assert.equal(decision, Decision.CONFIRM);
  assert.match(fields.route, /forwarded agent/);
  assert.ok(fields.route.includes(await fingerprint(host.blob)));
  assert.match(fields.server, /not verified/);
  assert.match(fields.warning, /forwarded/);
});

test('unbound logins need Continue', async () => {
  const {decision, fields} = await assess(
      login(new Uint8Array(32)), new SessionBindings(), STRICT);
  assert.equal(decision, Decision.CONFIRM);
  assert.equal(fields.server, 'unknown');
  assert.match(fields.route, /didn't say/);
  assert.ok(fields.warning);
});

test('user names are shown safely', async () => {
  const {fields} = await assess(
      login(new Uint8Array(32), 'root\nServer: trusted.example'),
      new SessionBindings(), STRICT);
  assert.equal(fields.user, 'root\\u{000a}Server: trusted.example');
});

test('file signatures need Continue', async () => {
  const sshsig = concat(new TextEncoder().encode('SSHSIG'), encodeString('git'),
                        encodeString(''), encodeString('sha512'),
                        encodeString(new Uint8Array(64)));
  const {decision, fields} =
      await assess(sshsig, new SessionBindings(), STRICT);
  assert.equal(decision, Decision.CONFIRM);
  assert.equal(fields.namespace, 'git');
  assert.match(fields.action, /not a login/);
});

test('unrecognized data is refused unless allowed', async () => {
  const data = new Uint8Array([1, 2, 3]);
  assert.equal((await assess(data, new SessionBindings(), STRICT)).decision,
               Decision.REFUSE);
  const {decision, fields} = await assess(
      data, new SessionBindings(), {allowUnrecognized: true});
  assert.equal(decision, Decision.CONFIRM);
  assert.ok(fields.warning);
});
