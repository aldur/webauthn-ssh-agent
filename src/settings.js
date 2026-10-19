// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Security settings.
 *
 * Kept in chrome.storage.local, not synced: a compromised Google account
 * mustn't be able to loosen them on the user's computers.
 */

/**
 * How much to show for direct logins to a verified server.  Other requests
 * always show & wait for Continue.
 *
 * @enum {string}
 */
export const Confirmation = Object.freeze({
  /** Show the request, & open the prompt on Continue. */
  REVIEW: 'review',
  /** Open the prompt right away, with the request in a window beside it. */
  SHOW: 'show',
  /** Only the security key or passkey prompt. */
  SILENT: 'silent',
});

/**
 * @typedef {{
 *   allowUnrecognized: boolean,
 *   allowDevSecureShell: boolean,
 *   trustSyncedKeys: boolean,
 *   confirmation: !Confirmation,
 * }}
 */
export let Settings;

/** @type {!Settings} The safe defaults. */
export const DEFAULT_SETTINGS = Object.freeze({
  /** Offer to sign data that is neither a login nor a file signature. */
  allowUnrecognized: false,
  /** Accept connections from Secure Shell's dev channel. */
  allowDevSecureShell: false,
  /** Treat keys synced from other computers as verified. */
  trustSyncedKeys: false,
  /** For direct logins to a verified server. */
  confirmation: Confirmation.REVIEW,
});

/**
 * @param {string} name
 * @param {*} value
 * @return {boolean} Whether value is valid for the setting.
 */
function isValid(name, value) {
  return name === 'confirmation' ?
      Object.values(Confirmation).includes(value) :
      typeof value === typeof DEFAULT_SETTINGS[name];
}

/** @return {!Promise<!Settings>} */
export async function loadSettings() {
  const items = await chrome.storage.local.get('settings');
  const stored = items.settings ?? {};
  const settings = {...DEFAULT_SETTINGS};
  for (const name of Object.keys(DEFAULT_SETTINGS)) {
    if (isValid(name, stored[name])) {
      settings[name] = stored[name];
    }
  }
  // Before the confirmation levels, there was a checkbox.
  if (stored.confirmation === undefined && stored.skipConfirmation === true) {
    settings.confirmation = Confirmation.SHOW;
  }
  return settings;
}

/**
 * @param {string} name
 * @param {boolean|string} value
 * @return {!Promise<void>}
 */
export async function saveSetting(name, value) {
  if (!(name in DEFAULT_SETTINGS) || !isValid(name, value)) {
    throw new Error(`invalid setting ${name}: ${value}`);
  }
  const settings = await loadSettings();
  settings[name] = value;
  await chrome.storage.local.set({settings});
}
