// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview SSH wire formats: keys, signatures & the data being signed.
 *
 * Keys are OpenSSH "sk-ecdsa-sha2-nistp256@openssh.com" keys.  Signatures use
 * the "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" format, which sshd (8.4+)
 * verifies against the browser-generated WebAuthn clientDataJSON.
 *
 * @see https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
 */

import {
  concat, equalBytes, fromBase64, fromBase64Url, sha256, toBase64,
  toBase64Url,
} from './bytes.js';
import {cleanName} from './text.js';

export const SK_ECDSA_KEY_TYPE = 'sk-ecdsa-sha2-nistp256@openssh.com';
export const SK_ECDSA_CERT_TYPE =
    'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com';
export const WEBAUTHN_SK_ECDSA_SIG_TYPE =
    'webauthn-sk-ecdsa-sha2-nistp256@openssh.com';

/** The message a login signs (RFC 4252). */
const SSH_MSG_USERAUTH_REQUEST = 50;

/**
 * What an SSH client asked us to sign.
 *
 * @enum {string}
 */
export const SignedData = {
  /** A login (SSH_MSG_USERAUTH_REQUEST). */
  LOGIN: 'login',
  /** A file or commit signature (ssh-keygen -Y sign). */
  SSHSIG: 'sshsig',
  /** Anything else. */
  UNKNOWN: 'unknown',
};

/**
 * @param {number} value
 * @return {!Uint8Array}
 */
export function encodeUint32(value) {
  const ret = new Uint8Array(4);
  new DataView(ret.buffer).setUint32(0, value);
  return ret;
}

/**
 * Encode an SSH "string".
 *
 * @param {!Uint8Array|string} data Strings are UTF-8 encoded.
 * @return {!Uint8Array}
 */
export function encodeString(data) {
  if (typeof data === 'string') {
    data = new TextEncoder().encode(data);
  }
  return concat(encodeUint32(data.length), data);
}

/**
 * Encode an unsigned big endian integer as an SSH "mpint".
 *
 * @param {!Uint8Array} bytes
 * @return {!Uint8Array}
 */
export function encodeMpint(bytes) {
  let pos = 0;
  while (pos < bytes.length && bytes[pos] === 0) {
    ++pos;
  }
  let mpint = bytes.subarray(pos);
  // Positive numbers with the high bit set need a leading zero.
  if (mpint.length && (mpint[0] & 0x80)) {
    mpint = concat(new Uint8Array([0]), mpint);
  }
  return encodeString(mpint);
}

/**
 * Reads SSH wire format data.
 */
export class Reader {
  /** @param {!Uint8Array} bytes */
  constructor(bytes) {
    this.bytes = bytes;
    this.pos = 0;
  }

  /** @return {boolean} Whether all data has been read. */
  eom() {
    return this.pos === this.bytes.length;
  }

  /**
   * @param {number} length
   * @return {!Uint8Array}
   */
  read(length) {
    if (this.pos + length > this.bytes.length) {
      throw new Error('SSH data truncated');
    }
    const ret = this.bytes.subarray(this.pos, this.pos + length);
    this.pos += length;
    return ret;
  }

  /** @return {number} */
  byte() {
    return this.read(1)[0];
  }

  /** @return {number} */
  uint32() {
    const bytes = this.read(4);
    return new DataView(bytes.buffer, bytes.byteOffset).getUint32(0);
  }

  /** @return {bigint} */
  uint64() {
    const bytes = this.read(8);
    return new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(0);
  }

  /** @return {!Uint8Array} */
  string() {
    return this.read(this.uint32());
  }

  /** @return {string} The string, decoded as UTF-8. */
  text() {
    return new TextDecoder().decode(this.string());
  }
}

/**
 * Generate the SSH public key blob for an sk-ecdsa key.
 *
 * @param {!Uint8Array} publicKey The uncompressed EC point (0x04 || X || Y).
 * @param {string} application The FIDO application (RP ID) string.
 * @return {!Uint8Array}
 */
export function skEcdsaKeyBlob(publicKey, application) {
  return concat(
      encodeString(SK_ECDSA_KEY_TYPE),
      encodeString('nistp256'),
      encodeString(publicKey),
      encodeString(application));
}

/**
 * An OpenSSH user certificate for an sk-ecdsa key: the blob, & what it says.
 * Times are in seconds since the epoch; validBefore is null for "forever".
 * verifyRequired is its verify-required option: servers then insist on user
 * verification.
 *
 * @typedef {{
 *   blob: !Uint8Array,
 *   publicKey: !Uint8Array,
 *   application: string,
 *   keyId: string,
 *   principals: !Array<string>,
 *   validAfter: number,
 *   validBefore: ?number,
 *   verifyRequired: boolean,
 * }}
 */
export let Certificate;

/** OpenSSH's SSH2_CERT_TYPE_USER. */
const CERT_TYPE_USER = 1;

/** A certificate's validBefore for "forever". */
const CERT_FOREVER = 0xffffffffffffffffn;

/**
 * @param {!Uint8Array} list Concatenated SSH strings.
 * @return {!Array<string>}
 */
function readStringList(list) {
  const r = new Reader(list);
  const strings = [];
  while (!r.eom()) {
    strings.push(r.text());
  }
  return strings;
}

/**
 * @param {!Uint8Array} options A certificate's options: name & data pairs.
 * @return {!Array<string>} Their names.
 */
function readOptionNames(options) {
  return readStringList(options).filter((_, i) => i % 2 === 0);
}

/**
 * Parse an sk-ecdsa user certificate.  Its CA signature isn't checked:
 * that's the server's job.
 *
 * @param {!Uint8Array} blob
 * @return {!Certificate}
 * @see https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
 */
export function parseCertificate(blob) {
  const r = new Reader(blob);
  if (r.text() !== SK_ECDSA_CERT_TYPE) {
    throw new Error('not an sk-ecdsa certificate');
  }
  r.string();  // Nonce.
  if (r.text() !== 'nistp256') {
    throw new Error('unsupported curve');
  }
  const publicKey = r.string();
  const application = r.text();
  r.uint64();  // Serial.
  if (r.uint32() !== CERT_TYPE_USER) {
    throw new Error('not a user certificate');
  }
  const keyId = r.text();
  const principals = readStringList(r.string());
  const validAfter = Number(r.uint64());
  const validBefore = r.uint64();
  const criticalOptions = readOptionNames(r.string());
  r.string();  // Extensions.
  r.string();  // Reserved.
  r.string();  // CA key.
  r.string();  // Signature.
  if (!r.eom()) {
    throw new Error('trailing data');
  }
  return {
    blob, publicKey, application, keyId, principals, validAfter,
    validBefore: validBefore === CERT_FOREVER ? null : Number(validBefore),
    verifyRequired: criticalOptions.includes('verify-required'),
  };
}

/**
 * Parse a certificate as ssh-keygen writes it (id-cert.pub): its type,
 * base64 & maybe a comment.
 *
 * @param {string} line
 * @return {!Certificate}
 * @throws {!Error} Saying what's wrong, for the user.
 */
export function parseCertificateLine(line) {
  const [type, base64] = line.trim().split(/\s+/);
  if (type !== SK_ECDSA_CERT_TYPE) {
    throw new Error(type?.endsWith('-cert-v01@openssh.com') ?
        'it\'s for another kind of key' : 'that isn\'t a certificate');
  }
  try {
    return parseCertificate(fromBase64(base64));
  } catch (e) {
    throw new Error('that isn\'t a certificate');
  }
}

/**
 * @param {!Certificate} cert
 * @param {number=} now In milliseconds since the epoch.
 * @return {boolean} Whether it's valid now (as far as this computer's clock
 *     can tell).
 */
export function isCertificateCurrent(cert, now = Date.now()) {
  const seconds = now / 1000;
  return cert.validAfter <= seconds &&
      (cert.validBefore === null || seconds < cert.validBefore);
}

/**
 * Format a key for ~/.ssh/authorized_keys.
 *
 * @param {!Uint8Array} keyBlob
 * @param {string} comment
 * @param {{verifyRequired: (boolean|undefined)}=} options verifyRequired
 *     makes sshd insist on user verification (a PIN or biometric) for every
 *     login, rather than just a touch.
 * @return {string}
 */
export function authorizedKeysLine(keyBlob, comment, {verifyRequired} = {}) {
  // The comment must not be able to add lines or options.
  const line =
      `${SK_ECDSA_KEY_TYPE} ${toBase64(keyBlob)} ${cleanName(comment)}`;
  return verifyRequired ? `verify-required ${line}` : line;
}

/**
 * Extract the raw EC point from a DER SubjectPublicKeyInfo for a P-256 key.
 *
 * @param {!Uint8Array} spki
 * @return {!Uint8Array} The 65 byte uncompressed point.
 */
export function p256PointFromSpki(spki) {
  // A P-256 SPKI is a fixed 91 bytes: 26 bytes of ASN.1 header (algorithm
  // OIDs & BIT STRING framing) followed by the uncompressed point.
  if (spki.length !== 91 || spki[26] !== 0x04) {
    throw new Error(`unexpected P-256 SPKI encoding (${spki.length} bytes)`);
  }
  return spki.slice(26);
}

/**
 * Decode a DER encoded ECDSA signature into its r & s components.
 *
 * Strict DER: definite, minimal lengths within bounds, and positive, minimally
 * encoded integers of at most 33 bytes (enough for P-256).
 *
 * @param {!Uint8Array} der SEQUENCE { r INTEGER, s INTEGER }.
 * @return {{r: !Uint8Array, s: !Uint8Array}} Unsigned big endian integers.
 */
export function decodeDerEcdsaSignature(der) {
  const fail = (why) => {
    throw new Error(`ECDSA signature: ${why}`);
  };
  let pos = 0;
  const byte = () => {
    if (pos >= der.length) {
      fail('truncated');
    }
    return der[pos++];
  };
  const readLength = () => {
    const first = byte();
    if (!(first & 0x80)) {
      return first;
    }
    const count = first & 0x7f;
    if (count < 1 || count > 2) {
      fail('bad length');
    }
    let len = 0;
    for (let i = 0; i < count; ++i) {
      len = (len << 8) | byte();
    }
    // Long form only for lengths that need it, without leading zeros.
    if (len < 0x80 || (count === 2 && len < 0x100)) {
      fail('non-minimal length');
    }
    return len;
  };
  const readInteger = () => {
    if (byte() !== 0x02) {
      fail('expected INTEGER');
    }
    const len = readLength();
    if (len < 1 || len > 33 || pos + len > der.length) {
      fail('bad INTEGER length');
    }
    const value = der.slice(pos, pos + len);
    pos += len;
    if (value[0] & 0x80) {
      fail('negative INTEGER');
    }
    if (len > 1 && value[0] === 0 && !(value[1] & 0x80)) {
      fail('non-minimal INTEGER');
    }
    return value;
  };

  if (byte() !== 0x30) {
    fail('expected SEQUENCE');
  }
  const seqLength = readLength();
  if (pos + seqLength !== der.length) {
    fail('bad SEQUENCE length');
  }
  const r = readInteger();
  const s = readInteger();
  if (pos !== der.length) {
    fail('trailing data');
  }
  return {r, s};
}

/**
 * Turn a WebAuthn assertion into an SSH "webauthn-sk-ecdsa" signature blob.
 *
 * @param {{
 *   authenticatorData: !Uint8Array,
 *   clientDataJSON: !Uint8Array,
 *   signature: !Uint8Array,
 * }} assertion
 * @return {!Uint8Array}
 */
export function webauthnAssertionToSshSignature(
    {authenticatorData, clientDataJSON, signature}) {
  // authenticatorData = rpIdHash[32] || flags[1] || signCount[4] || exts.
  if (authenticatorData.length < 37) {
    throw new Error('authenticatorData too short');
  }
  const flagsAndCounter = authenticatorData.subarray(32, 37);
  const extensions = authenticatorData.subarray(37);

  const clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));
  if (clientData.type !== 'webauthn.get' ||
      typeof clientData.origin !== 'string') {
    throw new Error('unexpected clientDataJSON');
  }

  const {r, s} = decodeDerEcdsaSignature(signature);
  return concat(
      encodeString(WEBAUTHN_SK_ECDSA_SIG_TYPE),
      encodeString(concat(encodeMpint(r), encodeMpint(s))),
      flagsAndCounter,
      encodeString(clientData.origin),
      encodeString(clientDataJSON),
      encodeString(extensions));
}

/**
 * Describe the data an SSH client asked us to sign, so the user knows what
 * they are approving.
 *
 * Logins sign an SSH_MSG_USERAUTH_REQUEST.  OpenSSH 8.9+ uses the
 * "publickey-hostbound-v00@openssh.com" method, which includes the server's
 * host key, so we can tell the user which server they're logging in to.
 *
 * @see https://www.rfc-editor.org/rfc/rfc4252#section-7
 * @see https://github.com/openssh/openssh-portable/blob/master/PROTOCOL
 *     (section 2.5, publickey-hostbound-v00@openssh.com)
 * @see https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
 * @param {!Uint8Array} data
 * @return {{kind: !SignedData, user: (string|undefined),
 *           sessionId: (!Uint8Array|undefined),
 *           hostKey: (!Uint8Array|undefined),
 *           namespace: (string|undefined)}} For a LOGIN, user & sessionId
 *     are set, and hostKey if known; for an SSHSIG, namespace.  The strings
 *     are untrusted: see text.js before showing them.
 */
export function describeSignData(data) {
  try {
    const magic = new TextEncoder().encode('SSHSIG');
    if (equalBytes(data.subarray(0, magic.length), magic)) {
      const r = new Reader(data.subarray(magic.length));
      return {kind: SignedData.SSHSIG, namespace: r.text()};
    }

    const r = new Reader(data);
    const sessionId = r.string();
    if (r.byte() !== SSH_MSG_USERAUTH_REQUEST) {
      return {kind: SignedData.UNKNOWN};
    }
    const user = r.text();
    const service = r.text();
    const method = r.text();
    // With a signature (TRUE): not a query.
    if (service !== 'ssh-connection' || r.byte() !== 1) {
      return {kind: SignedData.UNKNOWN};
    }
    r.string();  // Public key algorithm.
    r.string();  // Public key.
    if (method === 'publickey' && r.eom()) {
      return {kind: SignedData.LOGIN, user, sessionId};
    }
    if (method === 'publickey-hostbound-v00@openssh.com') {
      const hostKey = r.string();
      if (r.eom()) {
        return {kind: SignedData.LOGIN, user, sessionId, hostKey};
      }
    }
  } catch (e) {
    // Malformed: fall through.
  }
  return {kind: SignedData.UNKNOWN};
}

/**
 * @param {!Uint8Array} keyBlob An SSH public key blob.
 * @return {!Promise<string>} Its fingerprint as ssh shows it ("SHA256:...").
 */
export async function fingerprint(keyBlob) {
  return `SHA256:${toBase64(await sha256(keyBlob)).replace(/=+$/, '')}`;
}
