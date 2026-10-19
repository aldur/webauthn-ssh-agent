// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview The extensions allowed to use this agent.
 *
 * Keep in sync with "externally_connectable" in manifest.json, which makes
 * Chrome refuse connections from anything else (other extensions & all web
 * pages) before they reach us.
 *
 * IDs from Secure Shell's own list in libapps' nassh_external_api.js.
 *
 * Note: an extension ID is derived from a public key, so someone who can load
 * unpacked extensions on this computer could make one with Secure Shell's ID.
 * The allowlist protects against extensions installed from the Web Store,
 * not against local developer access.
 */

/** Secure Shell from the Chrome Web Store. */
export const SECURE_SHELL = 'iodihamcpbpeioajjeobimgagajmlibd';

/** Secure Shell's dev channel: only with the allowDevSecureShell setting. */
export const SECURE_SHELL_DEV = 'algkcnfjnajfhgimadimbjhmpaeohhln';

/**
 * @param {string} extensionId The caller.
 * @param {{allowDevSecureShell: boolean}} settings
 * @return {?string} The name to show the user, or null if not allowed.
 */
export function callerName(extensionId, settings) {
  if (extensionId === SECURE_SHELL) {
    return 'Secure Shell';
  }
  if (extensionId === SECURE_SHELL_DEV && settings.allowDevSecureShell) {
    return 'Secure Shell (dev)';
  }
  return null;
}
