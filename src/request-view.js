// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Showing a signature request: shared by the touch window and
 * the details window beside it.
 *
 * The background page prepares display-safe, labelled facts (see policy.js);
 * this only shows them, as text.
 */

import {describeKey} from './keys.js';

/**
 * Fill in the page's #facts & #warning, and its title.
 *
 * @param {{caller: string, fields: !Object, key: !Object}} request
 */
export function showRequest({caller, fields, key}) {
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
  add('With key', `${key.comment} (${describeKey(key)})`);

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
