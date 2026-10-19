// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Creating, importing, storing & using SSH keys on security keys
 * & passkeys via WebAuthn.
 *
 * Where the private key lives depends on the authenticator:
 *
 * * Security key, non-discoverable credential (the default): the security key
 *   returns a credential ID that holds the private key wrapped (encrypted)
 *   with a secret that never leaves the security key, or the material to
 *   re-derive it.  Signing needs both: the credential ID, which we store, and
 *   that physical security key.
 * * Security key, discoverable credential (a.k.a. resident key): the private
 *   key is stored in one of the security key's slots, so it can be found &
 *   imported again with just the security key.
 * * Passkey provider (Google Password Manager, iCloud Keychain, Windows
 *   Hello, a password manager, a phone): always a discoverable credential,
 *   kept (and maybe synced) by the provider.
 *
 * Either way we keep only public data (public key, credential ID, RP ID &
 * settings) in chrome.storage.sync, one item per key, which Chrome syncs
 * across the user's devices if sync is on.  Synced data is untrusted: it's
 * validated on load, and a key's public key is only offered for copying into
 * authorized_keys once this computer has verified it (see verifyKey()).
 *
 * Keys are bound to this extension's RP ID (its chrome-extension:// origin):
 * browsers never let an extension assert the "ssh:" application that
 * `ssh-keygen -t ecdsa-sk` uses, so keys must be created here.  sshd doesn't
 * care what the application string is; it only checks that
 * SHA256(application) matches the rpIdHash the authenticator signed.
 */

import {recoverPublicKeys, verifySignature} from './p256.js';
import {Confirmation, loadSettings} from './settings.js';
import {cleanName, utf8Prefix} from './text.js';
import {
  authorizedKeysLine, concat, decodeDerEcdsaSignature, equalBytes,
  fromBase64Url, p256PointFromSpki, skEcdsaKeyBlob, toBase64Url,
  webauthnAssertionToSshSignature,
} from './ssh.js';

/** COSE algorithm identifier for ECDSA w/SHA-256 on P-256. */
const COSE_ALG_ES256 = -7;

/** How long to wait for the user to touch their key. */
export const WEBAUTHN_TIMEOUT_MS = 60 * 1000;

/**
 * chrome.storage.sync item name prefix: each key is its own item, as sync
 * storage limits items to 8 KiB.
 */
const STORAGE_PREFIX = 'key:';

/** Where keys used to be stored, all in one item. */
const LEGACY_STORAGE_KEY = 'keys';

/**
 * chrome.storage.local (not synced) item name prefix for the integrity
 * records of keys this computer created, imported or verified.
 */
const VERIFIED_PREFIX = 'verified:';

/**
 * The WebAuthn user handle is: random bytes, a flags byte, the key's name.
 *
 * Discoverable credentials for the same RP & user handle replace each other,
 * hence the random bytes.  The flags & name let an import restore the key's
 * settings.
 */
const USER_HANDLE_RANDOM_BYTES = 16;
const USER_HANDLE_MAX_BYTES = 64;
const USER_HANDLE_FLAG_VERIFY = 0x01;
const USER_HANDLE_NAME_BYTES = USER_HANDLE_MAX_BYTES - USER_HANDLE_RANDOM_BYTES -
    1;

/** authenticatorData flags. */
const FLAG_UV = 0x04;

/**
 * What to create the key on.
 *
 * @enum {string}
 */
export const Kind = {
  /** A roaming security key: YubiKey, Titan, … */
  SECURITY_KEY: 'security-key',
  /** A passkey provider: password manager, OS, phone. */
  PASSKEY: 'passkey',
};

/**
 * A key the user set up.  Binary fields are base64url.
 *
 * kind is where the key actually ended up (the user may pick something else
 * in the browser's dialog than we asked for).  resident is whether it's a
 * discoverable credential.  verify is whether every use needs user
 * verification; verifyEnforcedByKey whether the authenticator itself
 * confirmed it enforces that (CTAP credProtect), not just the servers.
 * confirmation is the key's own confirmation level, if not the default.
 *
 * @typedef {{
 *   credentialId: string,
 *   publicKey: string,
 *   application: string,
 *   comment: string,
 *   created: number,
 *   kind: (!Kind|undefined),
 *   resident: boolean,
 *   verify: boolean,
 *   verifyEnforcedByKey: (boolean|undefined),
 *   confirmation: (!Confirmation|undefined),
 * }}
 */
export let StoredKey;

/**
 * @param {!Uint8Array|string} data Strings are UTF-8 encoded.
 * @return {!Promise<!Uint8Array>}
 */
export async function sha256(data) {
  if (typeof data === 'string') {
    data = new TextEncoder().encode(data);
  }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

/**
 * Figure out which string the authenticator hashed as the RP ID.
 *
 * For extensions Chrome hashes the full chrome-extension:// origin, but check
 * rather than assume.
 *
 * @param {!Uint8Array} rpIdHash
 * @param {!Array<string>} candidates
 * @return {!Promise<?string>}
 */
export async function findApplication(rpIdHash, candidates) {
  for (const candidate of candidates) {
    if (equalBytes(await sha256(candidate), rpIdHash)) {
      return candidate;
    }
  }
  return null;
}

/**
 * @param {!Uint8Array} authData authenticatorData from the authenticator.
 * @return {!Promise<string>} The application (RP ID) hashed into authData.
 */
async function applicationFromAuthData(authData) {
  const {origin, hostname} = globalThis.location;
  const application =
      await findApplication(authData.subarray(0, 32), [origin, hostname]);
  if (application === null) {
    throw new Error(`unable to determine the RP ID used for ${origin}`);
  }
  return application;
}

/**
 * Work out where a credential lives from what the browser reports.
 *
 * @param {?string} attachment PublicKeyCredential.authenticatorAttachment.
 * @param {!Array<string>} transports How the authenticator is reached.
 * @return {!Kind}
 */
export function kindOf(attachment, transports) {
  // Platform authenticators (the OS or a password manager) & phones ("hybrid")
  // hold passkeys; anything else roaming (USB, NFC, BLE) is a security key.
  if (attachment === 'platform' || transports.includes('hybrid') ||
      transports.includes('internal')) {
    return Kind.PASSKEY;
  }
  return Kind.SECURITY_KEY;
}

/**
 * Check a stored key, which may come from sync & so can't be trusted.
 *
 * @param {*} raw
 * @param {!Array<string>} applications This extension's possible RP IDs (its
 *     origin or hostname, depending on the browser): keys are bound to them.
 * @return {?StoredKey} A clean copy, or null if it's malformed.
 */
export function validateKey(raw, applications) {
  if (typeof raw !== 'object' || raw === null) {
    return null;
  }
  const base64url = (v, max) => typeof v === 'string' && v.length > 0 &&
      v.length <= max && /^[A-Za-z0-9_-]+$/.test(v);
  if (!base64url(raw.credentialId, 1366) || !base64url(raw.publicKey, 88) ||
      !applications.includes(raw.application) || typeof raw.comment !== 'string' ||
      !Number.isFinite(raw.created) || typeof raw.resident !== 'boolean' ||
      typeof raw.verify !== 'boolean' ||
      ![undefined, ...Object.values(Kind)].includes(raw.kind) ||
      ![undefined, true, false].includes(raw.verifyEnforcedByKey) ||
      ![undefined, ...Object.values(Confirmation)].includes(raw.confirmation)) {
    return null;
  }
  let point;
  try {
    point = fromBase64Url(raw.publicKey);
  } catch (e) {
    return null;
  }
  if (point.length !== 65 || point[0] !== 0x04) {
    return null;
  }
  return {
    credentialId: raw.credentialId,
    publicKey: raw.publicKey,
    application: raw.application,
    comment: cleanName(raw.comment) || 'key',
    created: raw.created,
    kind: raw.kind,
    resident: raw.resident,
    verify: raw.verify,
    verifyEnforcedByKey: raw.verifyEnforcedByKey,
    confirmation: raw.confirmation,
  };
}

/** @return {!Promise<!Array<!StoredKey>>} Valid keys, oldest first. */
export async function loadKeys() {
  const {origin, hostname} = globalThis.location;
  const applications = [origin, hostname];
  const items = await chrome.storage.sync.get(null);
  const raws = Object.entries(items)
      .filter(([name]) => name.startsWith(STORAGE_PREFIX))
      .map(([, key]) => key);

  // Move keys from the old single item to one item per key.
  const legacy = items[LEGACY_STORAGE_KEY];
  if (Array.isArray(legacy)) {
    const valid =
        legacy.map((k) => validateKey(k, applications)).filter(Boolean);
    await chrome.storage.sync.set(Object.fromEntries(
        valid.map((key) => [STORAGE_PREFIX + key.credentialId, key])));
    // Never lose data: keep the old item unless everything moved.
    if (valid.length === legacy.length) {
      await chrome.storage.sync.remove(LEGACY_STORAGE_KEY);
    }
    raws.push(...valid);
  }

  const keys = new Map();
  for (const raw of raws) {
    const key = validateKey(raw, applications);
    if (key) {
      keys.set(key.credentialId, key);
    } else {
      console.warn('ignoring a malformed stored key', raw);
    }
  }
  return [...keys.values()].sort((a, b) => a.created - b.created);
}

/**
 * @param {!StoredKey} key
 * @return {!Promise<string>} A digest of what makes the key trustworthy.
 */
async function integrityDigest(key) {
  return toBase64Url(await sha256(JSON.stringify(
      [key.credentialId, key.publicKey, key.application, key.verify])));
}

/**
 * Remember on this computer (not synced) that a key is genuine.
 *
 * @param {!StoredKey} key
 * @return {!Promise<void>}
 */
async function recordVerified(key) {
  await chrome.storage.local.set(
      {[VERIFIED_PREFIX + key.credentialId]: await integrityDigest(key)});
}

/**
 * Whether this computer created, imported or verified the key, unchanged, or
 * the user chose to trust synced keys.  Synced data could have been tampered
 * with (e.g. via a compromised account) to swap the public key, so only
 * verified keys' public keys are offered.
 *
 * @param {!StoredKey} key
 * @return {!Promise<boolean>}
 */
export async function isVerified(key) {
  if ((await loadSettings()).trustSyncedKeys) {
    return true;
  }
  const name = VERIFIED_PREFIX + key.credentialId;
  const items = await chrome.storage.local.get(name);
  return items[name] === await integrityDigest(key);
}

/**
 * @param {!StoredKey} key
 * @return {!Promise<void>}
 */
async function addKey(key) {
  await chrome.storage.sync.set({[STORAGE_PREFIX + key.credentialId]: key});
  await recordVerified(key);
}

/**
 * Set a key's own confirmation level (synced with it), or go back to the
 * default.
 *
 * @param {!StoredKey} key
 * @param {?Confirmation} confirmation Null for the default.
 * @return {!Promise<void>}
 */
export async function setKeyConfirmation(key, confirmation) {
  if (confirmation !== null &&
      !Object.values(Confirmation).includes(confirmation)) {
    throw new Error(`invalid confirmation level ${confirmation}`);
  }
  const name = STORAGE_PREFIX + key.credentialId;
  const {origin, hostname} = globalThis.location;
  const stored = validateKey(
      (await chrome.storage.sync.get(name))[name], [origin, hostname]);
  if (!stored) {
    throw new Error('no such key');
  }
  stored.confirmation = confirmation ?? undefined;
  await chrome.storage.sync.set({[name]: stored});
}

/**
 * The confirmation level for a key.  Its own level is synced, so it's only
 * trusted for keys verified on this computer: a compromised account mustn't
 * be able to loosen it.
 *
 * @param {!StoredKey} key
 * @param {{confirmation: !Confirmation}} settings This computer's settings.
 * @return {!Promise<!Confirmation>}
 */
export async function confirmationFor(key, settings) {
  return key.confirmation && await isVerified(key) ?
      key.confirmation : settings.confirmation;
}

/**
 * Forget a key.  A discoverable credential stays on its authenticator; remove
 * it there with e.g. `ykman fido credentials delete` or the password
 * manager.
 *
 * @param {string} credentialId
 * @return {!Promise<void>}
 */
export async function deleteKey(credentialId) {
  await chrome.storage.sync.remove(STORAGE_PREFIX + credentialId);
  await chrome.storage.local.remove(VERIFIED_PREFIX + credentialId);
}

/**
 * @param {!StoredKey} key
 * @return {!Uint8Array} The SSH public key blob.
 */
export function keyBlob(key) {
  return skEcdsaKeyBlob(fromBase64Url(key.publicKey), key.application);
}

/**
 * @param {!StoredKey} key
 * @return {string} The key's line for ~/.ssh/authorized_keys.
 */
export function keyAuthorizedKeysLine(key) {
  return authorizedKeysLine(
      keyBlob(key), key.comment, {verifyRequired: key.verify});
}

/**
 * Create a new key & remember it.
 *
 * @param {string} comment Name for the key.
 * @param {{kind: (!Kind|undefined), resident: (boolean|undefined),
 *          verify: (boolean|undefined)}=} options
 *     kind: what to steer the browser's dialog towards (the user can still
 *     pick something else).  resident: for security keys, store the key on it
 *     as a discoverable credential so it can be imported elsewhere (passkeys
 *     always are).  verify: require user verification (PIN/biometric), not
 *     just a touch, for every use.
 * @return {!Promise<!StoredKey>}
 */
export async function createKey(
    comment, {kind = Kind.SECURITY_KEY, resident = false, verify = false} =
        {}) {
  comment = cleanName(comment);
  if (!comment) {
    throw new Error('the key needs a name');
  }
  const userId = concat(
      crypto.getRandomValues(new Uint8Array(USER_HANDLE_RANDOM_BYTES)),
      new Uint8Array([verify ? USER_HANDLE_FLAG_VERIFY : 0]),
      utf8Prefix(comment, USER_HANDLE_NAME_BYTES));
  const passkey = kind === Kind.PASSKEY;

  const credential = await navigator.credentials.create({
    publicKey: {
      // Leave rp.id unset so the browser uses this extension's own RP ID.
      rp: {name: 'WebAuthn SSH Agent'},
      user: {id: userId, name: comment, displayName: comment},
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      // OpenSSH only supports the webauthn signature format for ECDSA.
      pubKeyCredParams: [{type: 'public-key', alg: COSE_ALG_ES256}],
      authenticatorSelection: {
        residentKey: passkey || resident ? 'required' : 'discouraged',
        userVerification: verify ? 'required' : 'discouraged',
      },
      // Steer Chrome's dialog towards a security key or a passkey provider.
      hints: passkey ? ['client-device', 'hybrid'] : ['security-key'],
      extensions: {
        // Ask whether a discoverable credential was made.
        credProps: true,
        // CTAP credProtect: have the authenticator itself refuse to use a
        // "verify" key without a PIN/biometric, and refuse to list
        // discoverable credentials without one.
        credentialProtectionPolicy: verify ? 'userVerificationRequired' :
            'userVerificationOptionalWithCredentialIDList',
        enforceCredentialProtectionPolicy: false,
      },
      attestation: 'none',
      timeout: WEBAUTHN_TIMEOUT_MS,
    },
  });
  if (!credential) {
    throw new Error('no credential created');
  }

  const response = credential.response;
  if (response.getPublicKeyAlgorithm() !== COSE_ALG_ES256) {
    throw new Error('the authenticator did not create a P-256 key');
  }
  const authData = new Uint8Array(response.getAuthenticatorData());
  if (verify && !(authData[32] & FLAG_UV)) {
    throw new Error('the authenticator did not verify the user');
  }

  // Record where the key really is, not what we asked for.
  const actualKind = kindOf(credential.authenticatorAttachment,
                            response.getTransports?.() ?? []);
  const extensionResults = credential.getClientExtensionResults?.() ?? {};
  const rk = extensionResults.credProps?.rk;

  /** @type {!StoredKey} */
  const key = {
    credentialId: toBase64Url(credential.rawId),
    publicKey: toBase64Url(
        p256PointFromSpki(new Uint8Array(response.getPublicKey()))),
    application: await applicationFromAuthData(authData),
    comment,
    created: Date.now(),
    kind: actualKind,
    // Passkey providers always make discoverable credentials.
    resident: rk ?? (resident || actualKind === Kind.PASSKEY),
    verify,
    // Whether the authenticator confirmed it will refuse to use the key
    // without user verification; otherwise only servers enforce it.
    verifyEnforcedByKey:
        verify && extensionResults.credProtect === 'userVerificationRequired',
  };
  await addKey(key);
  return key;
}

/**
 * Get a WebAuthn assertion.
 *
 * @param {!Uint8Array} challenge
 * @param {?string} credentialId The credential to use, or null to let the
 *     user pick one of the authenticators' discoverable credentials.
 * @param {string} userVerification
 * @return {!Promise<{
 *   credentialId: string,
 *   attachment: ?string,
 *   authenticatorData: !Uint8Array,
 *   clientDataJSON: !Uint8Array,
 *   signature: !Uint8Array,
 *   userHandle: ?Uint8Array,
 * }>}
 */
async function getAssertion(challenge, credentialId, userVerification) {
  const publicKey = {challenge, userVerification, timeout: WEBAUTHN_TIMEOUT_MS};
  if (credentialId !== null) {
    publicKey.allowCredentials =
        [{type: 'public-key', id: fromBase64Url(credentialId)}];
  }
  const credential = await navigator.credentials.get({publicKey});
  if (!credential) {
    throw new Error('no assertion');
  }
  const response = credential.response;
  return {
    credentialId: toBase64Url(credential.rawId),
    attachment: credential.authenticatorAttachment ?? null,
    authenticatorData: new Uint8Array(response.authenticatorData),
    clientDataJSON: new Uint8Array(response.clientDataJSON),
    signature: new Uint8Array(response.signature),
    userHandle: response.userHandle ?
        new Uint8Array(response.userHandle) : null,
  };
}

/**
 * Sign SSH data with a key.
 *
 * The SSH data is the WebAuthn challenge; the browser base64url encodes it
 * into clientDataJSON, which is what sshd checks.
 *
 * @param {!StoredKey} key
 * @param {!Uint8Array} data
 * @return {!Promise<!Uint8Array>} The SSH signature.
 */
export async function sign(key, data) {
  const assertion = await getAssertion(
      data, key.credentialId, key.verify ? 'required' : 'discouraged');
  if (!equalBytes(assertion.authenticatorData.subarray(0, 32),
                  await sha256(key.application))) {
    throw new Error('RP ID hash mismatch');
  }
  return webauthnAssertionToSshSignature(assertion);
}

/**
 * Import a discoverable credential made by createKey() (a passkey, or a
 * security key with resident set), e.g. on another computer.
 *
 * Asks for two signatures: the first yields two candidate public keys and the
 * second tells us which one is right.
 *
 * @param {function()=} onSecondTouch Called before asking for the second
 *     signature, e.g. to tell the user to touch their key again.
 * @return {!Promise<!StoredKey>} The imported key, or the existing one if it
 *     was already known.
 */
export async function importKey(onSecondTouch = () => {}) {
  /**
   * @param {?string} credentialId
   * @return {!Promise<!Object>}
   */
  const assert = async (credentialId) => {
    const assertion = await getAssertion(
        crypto.getRandomValues(new Uint8Array(32)), credentialId, 'preferred');
    const signedData = concat(
        assertion.authenticatorData, await sha256(assertion.clientDataJSON));
    return {
      ...assertion,
      signedData,
      rs: decodeDerEcdsaSignature(assertion.signature),
    };
  };

  // No allowCredentials: the authenticators offer their discoverable
  // credentials.
  const first = await assert(null);
  const existing = (await loadKeys())
      .find((key) => key.credentialId === first.credentialId);
  if (existing) {
    return existing;
  }

  const candidates = recoverPublicKeys(
      await sha256(first.signedData), first.rs.r, first.rs.s);
  onSecondTouch();
  const second = await assert(first.credentialId);
  let publicKey = null;
  for (const candidate of candidates) {
    if (await verifySignature(candidate, second.signedData, second.rs)) {
      publicKey = candidate;
      break;
    }
  }
  if (publicKey === null) {
    throw new Error('unable to recover the public key');
  }

  const userHandle = first.userHandle ?? new Uint8Array(0);
  const flags = userHandle[USER_HANDLE_RANDOM_BYTES] ?? 0;
  const comment = cleanName(new TextDecoder().decode(
      userHandle.subarray(USER_HANDLE_RANDOM_BYTES + 1))) || 'imported-key';

  /** @type {!StoredKey} */
  const key = {
    credentialId: first.credentialId,
    publicKey: toBase64Url(publicKey),
    application: await applicationFromAuthData(first.authenticatorData),
    comment,
    created: Date.now(),
    kind: kindOf(first.attachment, []),
    resident: true,
    verify: !!(flags & USER_HANDLE_FLAG_VERIFY),
    // We can't tell after the fact; assume only servers enforce it.
    verifyEnforcedByKey: false,
  };
  await addKey(key);
  return key;
}

/**
 * Verify a key (e.g. one synced from another computer) with one touch: its
 * credential must sign for this extension, and the signature must check out
 * with the stored public key.  Remembers the result on this computer.
 *
 * @param {!StoredKey} key
 * @return {!Promise<void>} Rejects if the key isn't genuine.
 */
export async function verifyKey(key) {
  const assertion = await getAssertion(
      crypto.getRandomValues(new Uint8Array(32)), key.credentialId,
      key.verify ? 'required' : 'discouraged');
  if (!equalBytes(assertion.authenticatorData.subarray(0, 32),
                  await sha256(key.application))) {
    throw new Error('the key belongs to another site');
  }
  const signedData = concat(
      assertion.authenticatorData, await sha256(assertion.clientDataJSON));
  if (!await verifySignature(fromBase64Url(key.publicKey), signedData,
                             decodeDerEcdsaSignature(assertion.signature))) {
    throw new Error('the stored public key does not match the security key');
  }
  await recordVerified(key);
}

/**
 * @param {!StoredKey} key
 * @return {string} A short description of where the key lives, for humans.
 */
export function describeKey(key) {
  if (key.kind === Kind.PASSKEY) {
    return 'passkey (kept by your passkey provider)';
  }
  return key.resident ?
      'security key (stored on it: discoverable credential)' :
      'security key';
}
