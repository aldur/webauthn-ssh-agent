// SPDX-License-Identifier: BSD-3-Clause

import assert from 'node:assert/strict';
import {test} from 'node:test';

import {
  AGENTC_EXTENSION, AGENTC_REQUEST_IDENTITIES, AGENTC_SIGN_REQUEST,
  AGENT_FAILURE, AGENT_IDENTITIES_ANSWER, AGENT_SIGN_RESPONSE, AGENT_SUCCESS,
  handleRequest,
} from '../src/agent.js';
import {Reader, concat, encodeString, encodeUint32} from '../src/ssh.js';

const ID1 = {blob: new Uint8Array([1, 2, 3]), comment: 'one'};
const ID2 = {blob: new Uint8Array([4, 5]), comment: 'two'};

/** A backend recording sign calls. */
function backend() {
  const calls = [];
  return {
    calls,
    identities: async () => [ID1, ID2],
    sign: async (identity, data) => {
      calls.push({identity, data});
      return new Uint8Array([9, 9]);
    },
    bind: async (...args) => {
      calls.push({bind: args});
      return true;
    },
  };
}

test('identities', async () => {
  const r = new Reader(await handleRequest(
      new Uint8Array([AGENTC_REQUEST_IDENTITIES]), backend()));
  assert.equal(r.byte(), AGENT_IDENTITIES_ANSWER);
  assert.equal(r.uint32(), 2);
  assert.deepEqual(r.string(), ID1.blob);
  assert.equal(r.text(), 'one');
  assert.deepEqual(r.string(), ID2.blob);
  assert.equal(r.text(), 'two');
  assert.ok(r.eom());
});

test('sign', async () => {
  const b = backend();
  const request = concat(new Uint8Array([AGENTC_SIGN_REQUEST]),
                         encodeString(ID2.blob), encodeString('data'),
                         encodeUint32(0));
  const r = new Reader(await handleRequest(request, b));
  assert.equal(r.byte(), AGENT_SIGN_RESPONSE);
  assert.deepEqual(r.string(), new Uint8Array([9, 9]));
  assert.ok(r.eom());
  assert.equal(b.calls.length, 1);
  assert.equal(b.calls[0].identity, ID2);
  assert.equal(new TextDecoder().decode(b.calls[0].data), 'data');
});

test('failures', async () => {
  const failure = new Uint8Array([AGENT_FAILURE]);
  const b = backend();
  const sign = (blob) => concat(new Uint8Array([AGENTC_SIGN_REQUEST]),
                                encodeString(blob), encodeString('data'),
                                encodeUint32(0));
  // Unknown key.
  assert.deepEqual(await handleRequest(sign(new Uint8Array([7])), b), failure);
  // Truncated & trailing data.
  assert.deepEqual(await handleRequest(sign(ID1.blob).subarray(0, 8), b),
                   failure);
  assert.deepEqual(
      await handleRequest(concat(sign(ID1.blob), new Uint8Array(1)), b),
      failure);
  // Truncated session-bind, other extensions, unknown & empty requests.
  assert.deepEqual(
      await handleRequest(concat(new Uint8Array([AGENTC_EXTENSION]),
                                 encodeString('session-bind@openssh.com')), b),
      failure);
  assert.deepEqual(
      await handleRequest(concat(new Uint8Array([AGENTC_EXTENSION]),
                                 encodeString('query')), b),
      failure);
  assert.deepEqual(await handleRequest(new Uint8Array([0]), b), failure);
  assert.deepEqual(await handleRequest(new Uint8Array(0), b), failure);
  assert.equal(b.calls.length, 0);

  // The user declining (sign throws).
  b.sign = async () => {
    throw new Error('cancelled');
  };
  assert.deepEqual(await handleRequest(sign(ID1.blob), b), failure);
});

test('session-bind@openssh.com', async () => {
  const b = backend();
  const bind = (...extra) => concat(
      new Uint8Array([AGENTC_EXTENSION]),
      encodeString('session-bind@openssh.com'), encodeString('host key'),
      encodeString('session'), encodeString('signature'), ...extra);

  assert.deepEqual(await handleRequest(bind(new Uint8Array([1])), b),
                   new Uint8Array([AGENT_SUCCESS]));
  const text = (bytes) => new TextDecoder().decode(bytes);
  const [hostKey, sessionId, signature, forwarded] = b.calls[0].bind;
  assert.deepEqual([text(hostKey), text(sessionId), text(signature), forwarded],
                   ['host key', 'session', 'signature', true]);

  // Trailing data.
  assert.deepEqual(await handleRequest(bind(new Uint8Array([0, 0])), b),
                   new Uint8Array([AGENT_FAILURE]));
  // Refused by the backend.
  b.bind = async () => false;
  assert.deepEqual(await handleRequest(bind(new Uint8Array([0])), b),
                   new Uint8Array([AGENT_FAILURE]));
});
