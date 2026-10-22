// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Reading WebAuthn authenticator data: the RP ID hash, flags,
 * & what follows them.
 *
 * Layout: RP ID hash (32 bytes), flags (1), signature counter (4), then, when
 * creating a credential, attested credential data (AAGUID, credential ID &
 * COSE public key), then any extension outputs (CBOR).
 *
 * @see https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
 */

import {decodeCbor} from './cbor.js';

// authenticatorData flags.
/** User verified (a PIN or biometric). */
const FLAG_UV = 0x04;
/** Backup eligible: the credential can be synced. */
const FLAG_BE = 0x08;
/** Backed up: the credential is synced. */
const FLAG_BS = 0x10;
/** Attested credential data follows the fixed fields. */
const FLAG_AT = 0x40;
/** Extension outputs follow (after any attested credential data). */
const FLAG_ED = 0x80;
/** CTAP credProtect: never used without user verification. */
export const CRED_PROTECT_UV_REQUIRED = 3;

/**
 * @param {!Uint8Array} authData
 * @return {!Uint8Array} The hash of the RP ID (application) it was made for.
 */
export function rpIdHash(authData) {
  return authData.subarray(0, 32);
}

/**
 * @param {!Uint8Array} authData
 * @return {boolean} Whether the authenticator verified the user (UV).
 */
export function isUserVerified(authData) {
  return !!(authData[32] & FLAG_UV);
}

/**
 * @param {!Uint8Array} authData
 * @return {{backupEligible: boolean, backedUp: boolean}} Its BE & BS flags.
 */
export function backupFlags(authData) {
  return {
    backupEligible: !!(authData[32] & FLAG_BE),
    backedUp: !!(authData[32] & FLAG_BS),
  };
}

/**
 * The authenticator's extension outputs, from its authenticator data:
 * browsers don't pass some on (e.g. credProtect).
 *
 * @param {!Uint8Array} authData
 * @return {!Map} Empty if there are none, or they can't be read.
 */
export function authDataExtensions(authData) {
  if (authData.length < 37 || !(authData[32] & FLAG_ED)) {
    return new Map();
  }
  try {
    let offset = 37;  // RP ID hash, flags, signature counter.
    if (authData[32] & FLAG_AT) {
      // AAGUID, credential ID length & ID, then the COSE public key.
      const idLength = (authData[offset + 16] << 8) | authData[offset + 17];
      offset = decodeCbor(authData, offset + 18 + idLength).end;
    }
    const {value} = decodeCbor(authData, offset);
    return value instanceof Map ? value : new Map();
  } catch (e) {
    return new Map();
  }
}

/**
 * @param {!Uint8Array} authData From creating a credential.
 * @return {(string|undefined)} The authenticator's AAGUID, as a lowercase
 *     UUID, unless it's all zeros (or missing).
 */
export function aaguidOf(authData) {
  if (authData.length < 53 || !(authData[32] & FLAG_AT)) {
    return undefined;
  }
  const bytes = authData.subarray(37, 53);
  if (bytes.every((b) => b === 0)) {
    return undefined;
  }
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0'))
      .join('');
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16),
          hex.slice(16, 20), hex.slice(20)].join('-');
}
