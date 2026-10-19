// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview A window beside the touch window, showing the request while
 * Chrome's security key or passkey prompt covers the touch window.
 */

import {showRequest} from './request-view.js';

const request = await chrome.runtime.sendMessage(
    {type: 'get-request-details', id: location.hash.slice(1)});
if (request) {
  showRequest(request);
  chrome.runtime.sendMessage(
      {type: 'details-shown', id: location.hash.slice(1)});
}
