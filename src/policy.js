// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview What to do with a signature request, and what to tell the
 * user about it.
 *
 * Mirrors ssh-agent: on a connection bound to a direct login, a login request
 * must be for that session & server, or it's refused.  Requests through a
 * forwarded agent, unbound connections & non-login data come with a warning.
 * Unrecognized data is refused unless the user allowed it.
 */

import {SessionBindings} from './binding.js';
import {equalBytes} from './bytes.js';
import {Confirmation} from './settings.js';
import {SignedData, describeSignData, fingerprint} from './ssh.js';
import {displayText} from './text.js';

/**
 * @enum {string}
 */
export const Decision = {
  /** Refuse without asking the user. */
  REFUSE: 'refuse',
  /** Ask, with a warning. */
  CONFIRM: 'confirm',
  /** Ask. */
  ASK: 'ask',
  /** Open the touch prompt right away, showing the request beside it. */
  SHOW: 'show',
  /** Only open the touch prompt. */
  SILENT: 'silent',
};

/**
 * Labelled, display-safe facts about a request.
 *
 * @typedef {{
 *   action: string,
 *   user: (string|undefined),
 *   server: string,
 *   route: string,
 *   namespace: (string|undefined),
 *   warning: (string|undefined),
 * }}
 */
export let Fields;

/**
 * @param {!SessionBindings} bindings
 * @return {!Promise<string>} Where the request comes from, for the user.
 */
async function describeRoute(bindings) {
  if (!bindings.last) {
    return 'Unknown (your SSH client didn\'t say)';
  }
  if (bindings.forwarded) {
    return 'Through a forwarded agent, on server ' +
        await fingerprint(bindings.first.hostKey);
  }
  return 'Direct connection';
}

/**
 * @param {{user: string, sessionId: !Uint8Array,
 *          hostKey: (!Uint8Array|undefined)}} login From describeSignData.
 * @param {!SessionBindings} bindings
 * @param {!Confirmation} confirmation For direct logins to a bound server.
 * @param {string} route
 * @return {!Promise<{decision: !Decision, reason: (string|undefined),
 *                    fields: (!Fields|undefined)}>}
 */
async function assessLogin(login, bindings, confirmation, route) {
  const last = bindings.last;
  let server = 'unknown';
  if (last && !last.forwarded) {
    // The bound session is the one being logged in to: it must match.
    if (!equalBytes(login.sessionId, last.sessionId) ||
        (login.hostKey && !equalBytes(login.hostKey, last.hostKey))) {
      return {decision: Decision.REFUSE, reason: 'session mismatch'};
    }
    server = `${await fingerprint(last.hostKey)} (verified)`;
  } else if (login.hostKey) {
    server = `${await fingerprint(login.hostKey)} (not verified)`;
  }
  const fields = {
    action: 'Log in',
    user: displayText(login.user),
    server,
    route,
  };

  // A direct login to a bound server: as the user chose.
  if (last && !bindings.forwarded) {
    const decision = {
      [Confirmation.SHOW]: Decision.SHOW,
      [Confirmation.SILENT]: Decision.SILENT,
    }[confirmation] ?? Decision.ASK;
    return {decision, fields};
  }
  fields.warning = bindings.forwarded ?
      'A server you forwarded your agent to wants to log in elsewhere ' +
          'with your key.  Only continue if you just ran ssh there.' :
      'Your SSH client didn\'t say which server this is for.  Only ' +
          'continue if you expected it.';
  return {decision: Decision.CONFIRM, fields};
}

/**
 * @param {!Uint8Array} data The data to sign.
 * @param {!SessionBindings} bindings The connection's session bindings.
 * @param {{allowUnrecognized: boolean, confirmation: !Confirmation}} settings
 * @return {!Promise<{decision: !Decision, reason: (string|undefined),
 *                    fields: (!Fields|undefined)}>}
 */
export async function assess(data, bindings, settings) {
  const what = describeSignData(data);
  if (what.kind === SignedData.UNKNOWN && !settings.allowUnrecognized) {
    return {decision: Decision.REFUSE, reason: 'unrecognized data'};
  }
  const route = await describeRoute(bindings);
  switch (what.kind) {
    case SignedData.LOGIN:
      return assessLogin(what, bindings, settings.confirmation, route);
    case SignedData.SSHSIG:
      return {decision: Decision.CONFIRM, fields: {
        action: 'Sign data (not a login)',
        namespace: displayText(what.namespace),
        server: 'not applicable',
        route,
        warning: 'This is not a login.  Only continue if you are signing ' +
            'something, e.g. a git commit.',
      }};
  }
  return {decision: Decision.CONFIRM, fields: {
    action: 'Sign unrecognized data',
    server: 'unknown',
    route,
    warning: 'This is neither an SSH login nor a file signature.  Only ' +
        'continue if you know what it is.',
  }};
}
