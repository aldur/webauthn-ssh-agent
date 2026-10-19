// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Making untrusted text safe to show & store.
 *
 * Names & user names come from places an attacker may control (SSH requests,
 * synced storage, imported credentials).  Anything that could change how text
 * reads (line breaks, control characters, bidirectional overrides, invisible
 * characters) is made visible or removed.
 */

/**
 * Characters that can disguise text: C0/C1 controls & DEL, zero-width
 * characters, bidirectional marks/overrides/isolates, line & paragraph
 * separators, the BOM.
 */
const DISGUISING =
    /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/gu;

/**
 * Make untrusted text safe to display: disguising characters become visible
 * escapes, and long text is cut short.
 *
 * @param {string} text
 * @param {number=} maxLength In code points.
 * @return {string}
 */
export function displayText(text, maxLength = 64) {
  const escaped = String(text).replace(
      DISGUISING,
      (c) => `\\u{${c.codePointAt(0).toString(16).padStart(4, '0')}}`);
  const chars = [...escaped];
  return chars.length > maxLength ?
      chars.slice(0, maxLength - 1).join('') + '…' : escaped;
}

/**
 * Clean up a key name: no disguising characters (they're dropped, and line
 * breaks would add lines to authorized_keys), single spaces, bounded length.
 *
 * @param {string} name
 * @param {number=} maxLength In code points.
 * @return {string}
 */
export function cleanName(name, maxLength = 64) {
  const cleaned = String(name).replace(DISGUISING, ' ')
      .replace(/\s+/gu, ' ').trim();
  return [...cleaned].slice(0, maxLength).join('');
}

/**
 * Encode text as UTF-8 in at most maxBytes, without splitting a character.
 *
 * @param {string} text
 * @param {number} maxBytes
 * @return {!Uint8Array}
 */
export function utf8Prefix(text, maxBytes) {
  const encoder = new TextEncoder();
  let bytes = encoder.encode(text);
  if (bytes.length <= maxBytes) {
    return bytes;
  }
  const chars = [...text];
  while (chars.length && bytes.length > maxBytes) {
    chars.pop();
    bytes = encoder.encode(chars.join(''));
  }
  return bytes;
}
