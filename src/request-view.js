// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Showing a signature request: shared by the touch window and
 * the details window beside it.
 *
 * The service worker prepares display-safe, labelled facts (see policy.js);
 * this only shows them, as text.
 */

/**
 * Fill in the page's #facts & #warning, and its title.
 *
 * @param {{caller: string, fields: !Object, key: !Object,
 *          certificate: (string|undefined)}} request certificate is the key
 *     ID of the key's certificate, if that's what's used.
 */
export function showRequest({caller, fields, key, certificate}) {
  const facts = document.getElementById('facts');
  const add = (label, value) => {
    const dt = document.createElement('dt');
    dt.textContent = label;
    const dd = document.createElement('dd');
    dd.textContent = value;
    facts.append(dt, dd);
  };
  add('Requested by', caller);
  add('Action', fields.action);
  if (fields.user !== undefined) {
    add('As user', fields.user);
  }
  if (fields.namespace !== undefined) {
    add('Namespace', fields.namespace);
  }
  add('Server', fields.server);
  add('Route', fields.route);
  add('With key', certificate === undefined ? key.comment :
      `${key.comment}, certificate "${certificate}"`);

  // Window title bars show this too.
  document.title = [
    fields.user === undefined ? fields.action :
        `${fields.action} as ${fields.user}`,
    fields.server,
  ].join(' · ');

  if (fields.warning) {
    const warning = document.getElementById('warning');
    warning.textContent = fields.warning;
    warning.classList.remove('hidden');
  }
}
