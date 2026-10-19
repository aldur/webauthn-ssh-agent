// SPDX-License-Identifier: BSD-3-Clause

/**
 * Try to use the agent like Secure Shell would.
 *
 * @param {string} agentId
 * @return {!Promise<string>} "refused", or what the agent answered.
 */
globalThis.tryAgent = (agentId) => new Promise((resolve) => {
  const port = chrome.runtime.connect(agentId);
  port.onDisconnect.addListener(() => resolve('refused'));
  port.onMessage.addListener((msg) => resolve(JSON.stringify(msg)));
  // SSH_AGENTC_REQUEST_IDENTITIES.
  port.postMessage({type: 'auth-agent@openssh.com', data: [11]});
});
