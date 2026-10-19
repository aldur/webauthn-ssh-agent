// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Security settings.
 *
 * Kept in chrome.storage.local, not synced: a compromised Google account
 * mustn't be able to loosen them on the user's computers.
 */

/**
 * @typedef {{
 *   allowUnrecognized: boolean,
 *   allowDevSecureShell: boolean,
 * }}
 */
export let Settings;

/** @type {!Settings} The safe defaults. */
export const DEFAULT_SETTINGS = Object.freeze({
  /** Offer to sign data that is neither a login nor a file signature. */
  allowUnrecognized: false,
  /** Accept connections from Secure Shell's dev channel. */
  allowDevSecureShell: false,
});

/** @return {!Promise<!Settings>} */
export async function loadSettings() {
  const items = await chrome.storage.local.get('settings');
  const stored = items.settings ?? {};
  const settings = {...DEFAULT_SETTINGS};
  for (const name of Object.keys(DEFAULT_SETTINGS)) {
    if (typeof stored[name] === 'boolean') {
      settings[name] = stored[name];
    }
  }
  return settings;
}

/**
 * @param {string} name
 * @param {boolean} value
 * @return {!Promise<void>}
 */
export async function saveSetting(name, value) {
  if (!(name in DEFAULT_SETTINGS)) {
    throw new Error(`unknown setting ${name}`);
  }
  const settings = await loadSettings();
  settings[name] = value;
  await chrome.storage.local.set({settings});
}
