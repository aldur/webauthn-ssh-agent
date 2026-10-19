// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview The "Manage keys and settings" page.
 */

import {
  Kind, createKey, deleteKey, describeKey, importKey, isVerified,
  keyAuthorizedKeysLine, loadKeys, verifyKey,
} from './keys.js';
import {loadSettings, saveSetting} from './settings.js';

const $ = (id) => document.getElementById(id);

/** @param {string} message */
function setStatus(message) {
  $('status').textContent = message;
}

/**
 * @param {!Object} key A StoredKey.
 * @param {boolean} verified Whether this computer vouches for the key.
 * @return {!Element}
 */
function renderKey(key, verified) {
  const li = document.createElement('li');

  const remove = document.createElement('button');
  remove.textContent = '🗑';
  remove.title = 'Forget this key';
  remove.onclick = async () => {
    // Ask for a second click to confirm.
    if (remove.dataset.armed) {
      await deleteKey(key.credentialId);
      setStatus(`Forgot "${key.comment}".  Also remove it from ` +
                '~/.ssh/authorized_keys on your servers.');
      return;
    }
    remove.dataset.armed = '1';
    remove.textContent = 'Forget';
    setStatus(`Click "Forget" to confirm forgetting "${key.comment}".`);
    setTimeout(() => {
      delete remove.dataset.armed;
      remove.textContent = '🗑';
    }, 5000);
  };

  const name = document.createElement('span');
  name.textContent = key.comment;

  const details = document.createElement('span');
  details.className = 'details';
  details.textContent = [
    describeKey(key),
    ...(key.verify ? [key.verifyEnforcedByKey ? 'PIN required' :
                          'PIN required (enforced by servers only)'] : []),
    new Date(key.created).toLocaleDateString(),
  ].join(' · ');

  const copy = document.createElement('button');
  copy.textContent = 'Copy public key';
  copy.onclick = async () => {
    await navigator.clipboard.writeText(keyAuthorizedKeysLine(key));
    setStatus(verified ?
        `Copied the public key of "${key.comment}".  Add it to ` +
            '~/.ssh/authorized_keys on your servers.' :
        `Copied the public key of "${key.comment}", which is not verified: ` +
            'click Verify first to be sure it is really yours.');
  };
  li.append(remove, ' ', name, details);

  if (verified) {
    li.append(copy);
  } else {
    // Synced data could have been tampered with: say so, and offer to check
    // that the public key really belongs to the credential.
    const warning = document.createElement('span');
    warning.className = 'unverified';
    warning.textContent = 'Not verified on this computer: its public key ' +
        'comes from synced data, which could have been tampered with.';
    copy.textContent = 'Copy unverified public key';
    const verify = document.createElement('button');
    verify.textContent = 'Verify';
    verify.title = 'Check with one touch that this key really belongs to ' +
        'your security key or passkey';
    verify.onclick = async () => {
      setStatus(`Confirm with the security key or passkey of ` +
                `"${key.comment}"…`);
      try {
        await verifyKey(key);
        setStatus(`"${key.comment}" is verified.`);
        await load();
      } catch (e) {
        setStatus(`Not verified: ${e.message}`);
      }
    };
    li.append(warning, verify, copy);
  }
  return li;
}

/** Refresh the list of keys. */
async function load() {
  const keys = await loadKeys();
  if (keys.length) {
    const verified = await Promise.all(keys.map(isVerified));
    $('keys').replaceChildren(
        ...keys.map((key, i) => renderKey(key, verified[i])));
  } else {
    const li = document.createElement('li');
    li.textContent = 'No keys yet.  Add one below.';
    $('keys').replaceChildren(li);
  }
}

/**
 * Run a WebAuthn operation with the buttons disabled.
 *
 * @param {string} startMessage
 * @param {function(): !Promise<!Object>} operation Returns a StoredKey.
 */
async function run(startMessage, operation) {
  $('create').disabled = $('import').disabled = true;
  setStatus(startMessage);
  try {
    const key = await operation();
    setStatus(`"${key.comment}" is ready.  Copy its public key to add it to ` +
              'your servers.');
  } catch (e) {
    setStatus(`Failed: ${e.message}`);
  } finally {
    $('create').disabled = $('import').disabled = false;
  }
}

$('create').onclick = () => {
  const name = $('name').value.trim();
  if (!name) {
    $('name').focus();
    setStatus('Enter a name for the key first.');
    return;
  }
  run('Follow Chrome\'s prompt to create the key…', async () => {
    const kind = document.querySelector('input[name=kind]:checked').value;
    const key = await createKey(name, {
      kind,
      resident: kind === Kind.SECURITY_KEY && $('resident').checked,
      verify: $('verify').checked,
    });
    $('name').value = '';
    $('resident').checked = $('verify').checked = false;
    return key;
  });
};
$('name').onkeyup = (e) => {
  if (e.key === 'Enter') {
    $('create').click();
  }
};

$('import').onclick = () => run(
    'Pick the key in Chrome\'s prompt…',
    () => importKey(
        () => setStatus('Confirm once more to finish importing…')));

// The discoverable credential option only applies to security keys:
// passkeys always are.
for (const radio of document.querySelectorAll('input[name=kind]')) {
  radio.onchange = () => {
    $('resident').disabled = radio.value === Kind.PASSKEY && radio.checked;
  };
}

const option = `--ssh-agent=${chrome.runtime.id}`;
$('agent-option').textContent = option;
$('copy-option').onclick = async () => {
  await navigator.clipboard.writeText(option);
  setStatus('Copied.');
};

if (!globalThis.PublicKeyCredential) {
  $('create').disabled = $('import').disabled = true;
  setStatus('This browser does not support WebAuthn.');
}

// Security settings: kept on this computer only.
const settings = await loadSettings();
for (const name of
         ['allowUnrecognized', 'allowDevSecureShell', 'skipConfirmation']) {
  $(name).checked = settings[name];
  $(name).onchange = () => saveSetting(name, $(name).checked);
}

// Keys may change elsewhere, e.g. on another synced computer.
chrome.storage.onChanged.addListener(load);

// The name says "(Dev)" for the Load-unpacked build.
const {name, version} = chrome.runtime.getManifest();
$('version').textContent = `${name}, version ${version}`;

load();
