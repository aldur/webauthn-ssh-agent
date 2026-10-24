// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview The "Manage keys and settings" page.
 */

import {AAGUID_NAMES} from './aaguids.js';
import {
  Attachment, Kind, createKey, deleteKey, importKey, isMismatched, isVerified,
  keyAuthorizedKeysLine, keyBlob, keyCertificate, keyPublicKeyLine, loadKeys,
  removeCertificate, renameKey, reorderKeys, setCertificate,
  setKeyConfirmation, verifyKey,
} from './keys.js';
import {Confirmation, loadSettings, saveSetting} from './settings.js';
import {fingerprint, isCertificateCurrent} from './ssh.js';
import {displayText} from './text.js';

const $ = (id) => document.getElementById(id);

/** How long a status message stays up, unless something is in progress. */
const STATUS_MS = 10 * 1000;

/** The confirmation levels: name, & what it does. */
const LEVELS = {
  [Confirmation.REVIEW]: ['Review', 'shows the request & waits for Continue'],
  [Confirmation.SHOW]:
      ['Show', 'opens the prompt right away, showing the request beside it'],
  [Confirmation.SILENT]: ['Silent', 'only opens the prompt'],
};

/**
 * The key list's columns: heading, & what it means (shown on hover).
 */
const COLUMNS = [
  ['', ''],  // Drag handle.
  ['Name', 'Keys are offered to servers in this order: drag a row by its ' +
           'handle (or Alt+↑/↓ on it) to change it.'],
  ['Attachment', 'authenticatorAttachment, as last reported.\n' +
                 'Platform: built into the computer (OS or browser).\n' +
                 'Cross-platform: roaming, e.g. a security key (USB, NFC, ' +
                 'Bluetooth) or a phone (hybrid).\n' +
                 'Hover a cell for its transports & model (AAGUID), when ' +
                 'reported.'],
  ['Verified', 'Whether this computer checked the public key with the ' +
               'authenticator.  Synced keys need this once per computer: ' +
               'whoever controls your Google account could swap the public ' +
               'key.  It covers the public key & UV; the other columns are ' +
               'as synced.'],
  ['Discoverable', 'A discoverable credential (resident key) is stored on ' +
                   'the authenticator, so it can be imported on another ' +
                   'computer.'],
  ['Backup', 'The authenticator\'s backup flags, as last reported.\n' +
             '✓ Backed up (BS): multi-device, synced.\n' +
             '○ Backup eligible (BE): multi-device, not synced yet.\n' +
             'Single-device: not backup eligible, so bound to the ' +
             'authenticator: only it can use the private key.'],
  ['UV', 'Require a PIN or fingerprint: user verification (UV) on every ' +
         'login, not just user presence (a touch).\n' +
         'Green: the authenticator enforces it (credProtect).\n' +
         'Grey: only servers do (verify-required).'],
  ['Confirmation', 'How much to show before direct logins to a verified ' +
                   'server.'],
  ['', ''],
];

/** For what the authenticator hasn't reported yet (older keys). */
const UNKNOWN = 'Not known yet: updated the next time the key is used';

/** How much of a chosen certificate file to read: real ones are ~1 KiB. */
const MAX_CERTIFICATE_FILE_BYTES = 64 * 1024;

/** Clears the status message. */
let statusTimer;

/** A key to highlight briefly when the list shows it, as it's new. */
let highlight = null;

/** The keys' IDs, in the list's order. */
let order = [];
/** A key whose drag handle to focus once the list redraws. */
let focusAfterLoad = null;
/** The key whose certificate dialog is open. */
let certificateKey = null;

/**
 * @param {string} message
 * @param {boolean=} inProgress Keep it up until the next message.
 */
function setStatus(message, inProgress = false) {
  $('status').textContent = message;
  clearTimeout(statusTimer);
  if (!inProgress) {
    statusTimer = setTimeout(() => setStatus(''), STATUS_MS);
  }
}

/**
 * @param {string} tag
 * @param {string=} className
 * @param {string=} text
 * @param {string=} tip Shown on hover or click.
 * @return {!Element}
 */
function element(tag, className = '', text = '', tip = '') {
  const e = document.createElement(tag);
  e.className = className;
  e.textContent = text;
  if (tip) {
    e.dataset.tip = tip;
    if (tag === 'button') {
      e.setAttribute('aria-label', tip);  // For icon buttons.
    }
  }
  return e;
}

/**
 * Copy text, & show it worked on the (⧉) button for a moment.
 *
 * @param {!Element} button
 * @param {string} text
 * @return {!Promise<void>}
 */
async function copyText(button, text) {
  await navigator.clipboard.writeText(text);
  button.textContent = '✓';
  button.classList.add('yes');
  setTimeout(() => {
    button.textContent = '⧉';
    button.classList.remove('yes');
  }, 1500);
}

/**
 * A cell with a mark (or none), explained on hover.
 *
 * @param {string} mark E.g. ✓, ○ or ?, or '' for none.
 * @param {string} style yes, weak (grey), or wrong (red).
 * @param {string} tip What it means.
 * @return {!Element}
 */
function markCell(mark, style, tip) {
  const td = element('td', 'mark', '', tip);
  if (mark) {
    td.append(element('span', style, mark));
  }
  return td;
}

/**
 * Tooltips: the browser's own only show after a delay, and never on click
 * or tap, so show data-tip right away instead.
 */
const tooltip = element('div', 'tip');
tooltip.setAttribute('role', 'tooltip');
tooltip.hidden = true;
document.body.append(tooltip);

/** @param {?Element} target With data-tip, or null to hide the tooltip. */
function showTip(target) {
  if (!target?.dataset.tip) {
    tooltip.hidden = true;
    return;
  }
  tooltip.textContent = target.dataset.tip;
  tooltip.hidden = false;
  const box = target.getBoundingClientRect();
  tooltip.style.left = `${Math.max(8, Math.min(
      box.left, innerWidth - tooltip.offsetWidth - 8))}px`;
  tooltip.style.top = `${box.bottom + tooltip.offsetHeight + 4 < innerHeight ?
      box.bottom + 4 : box.top - tooltip.offsetHeight - 4}px`;
}
for (const type of ['mouseover', 'click', 'focusin']) {
  document.addEventListener(
      type, (e) => showTip(e.target.closest?.('[data-tip]') ?? null));
}
document.documentElement.addEventListener('mouseleave', () => showTip(null));
addEventListener('scroll', () => showTip(null), true);
addEventListener('keydown', (e) => e.key === 'Escape' && showTip(null));

/** @return {!Element} The key list's header: each column explains itself. */
function renderHead() {
  const tr = element('tr');
  for (const [name, meaning] of COLUMNS) {
    const th = element('th', '', '', meaning);
    th.append(meaning ? element('abbr', '', name) : name);
    tr.append(th);
  }
  const head = element('thead');
  head.append(tr);
  return head;
}

/**
 * @param {!Object} key A StoredKey.
 * @param {boolean} verified Whether this computer vouches for the key.
 * @return {!Element} The key's confirmation level dropdown.
 */
function renderLevel(key, verified) {
  const fallback = $('confirmation').value;
  const option = (value, name, title) => {
    const o = element('option', '', name);
    o.value = value;
    o.title = title;  // (Options are drawn by the browser.)
    return o;
  };
  const select = element('select');
  select.append(
      option('', 'Default',
             `The default from Settings, now ${LEVELS[fallback][0]}`),
      ...Object.entries(LEVELS).map(
          ([value, [name, does]]) => option(value, name, `${name}: ${does}`)));
  select.value = key.confirmation ?? '';
  if (!verified) {
    select.disabled = true;
    select.dataset.tip = 'A key\'s own level only applies once it\'s ' +
        'verified on this computer; until then, the default ' +
        `(${LEVELS[fallback][0]})`;
    return select;
  }
  // Hovering explains what the current choice does.
  const explain = () => {
    const [name, does] = LEVELS[select.value || fallback];
    select.dataset.tip = 'For direct logins to a verified server: ' +
        `${name}${select.value ? '' : ' (the default)'}, which ${does}.`;
  };
  explain();
  select.onchange = () => {
    explain();
    setKeyConfirmation(key, select.value || null);
  };
  return select;
}

/**
 * The key's name: hovering shows its details, clicking renames it (unless
 * it's stored on the authenticator, which keeps its own copy of the name).
 *
 * @param {!Object} key A StoredKey.
 * @param {string} keyFingerprint As ssh shows it, e.g. in server logs.
 * @return {!Element}
 */
function renderName(key, keyFingerprint) {
  const td = element('td', 'key-name');
  const details = (key.imported ? 'Imported ' : 'Added ') +
      `${new Date(key.created).toLocaleDateString()}\n` +
      keyFingerprint;
  if (key.resident) {
    td.append(element('span', '', key.comment,
        `${details}\nStored with this name on the authenticator, so it ` +
        'can\'t be renamed here'));
    return td;
  }
  const name = element('span', 'rename', key.comment,
      `${details}\nClick to rename`);
  name.onclick = () => {
    const input = element('input');
    input.value = key.comment;
    input.size = Math.max(key.comment.length, 8);
    let done = false;
    const finish = async (save) => {
      if (done) {
        return;
      }
      done = true;
      try {
        if (save && input.value.trim() !== key.comment) {
          await renameKey(key, input.value);  // The list reloads.
          return;
        }
      } catch (e) {
        setStatus(`Not renamed: ${e.message}`);
      }
      input.replaceWith(name);
    };
    input.onkeydown = (e) => {
      if (e.key === 'Enter' || e.key === 'Escape') {
        finish(e.key === 'Enter');
      }
    };
    input.onblur = () => finish(true);
    name.replaceWith(input);
    input.select();
  };
  td.append(name);
  return td;
}

/**
 * Move a key in the list.
 *
 * @param {string} id
 * @param {number} index Where to, in the list without it.
 */
function moveKey(id, index) {
  const ids = order.filter((other) => other !== id);
  ids.splice(Math.max(0, Math.min(index, ids.length)), 0, id);
  reorderKeys(ids);  // The list reloads.
}

/**
 * @param {!Object} key A StoredKey.
 * @return {!Element} A handle to drag the row by (or move it with Alt+↑/↓).
 */
function renderGrip(key) {
  const td = element('td', 'grip');
  if (order.length < 2) {
    return td;
  }
  const grip = element('button', 'grip', '',
      'Drag to reorder (or Alt+↑/↓): keys are offered to servers in this ' +
      'order');
  grip.draggable = true;
  grip.ondragstart = (e) => {
    e.dataTransfer.setData('application/x-key', key.credentialId);
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setDragImage(grip.closest('tr'), 0, 0);
  };
  grip.onkeydown = (e) => {
    const step = {ArrowUp: -1, ArrowDown: 1}[e.key];
    if (e.altKey && step) {
      e.preventDefault();
      focusAfterLoad = key.credentialId;
      moveKey(key.credentialId, order.indexOf(key.credentialId) + step);
    }
  };
  td.append(grip);
  return td;
}

/**
 * Let a row take dropped keys, before or after it.
 *
 * @param {!Element} tr
 * @param {string} id Its key's ID.
 */
function acceptDrops(tr, id) {
  const before = (e) => {
    const box = tr.getBoundingClientRect();
    return e.clientY < box.top + box.height / 2;
  };
  const clear = () => tr.classList.remove('drop-before', 'drop-after');
  tr.ondragover = (e) => {
    if (!e.dataTransfer.types.includes('application/x-key')) {
      return;
    }
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    clear();
    tr.classList.add(before(e) ? 'drop-before' : 'drop-after');
  };
  tr.ondragleave = clear;
  tr.ondrop = (e) => {
    const dragged = e.dataTransfer.getData('application/x-key');
    clear();
    if (!dragged || dragged === id) {
      return;
    }
    e.preventDefault();
    const at = order.filter((other) => other !== dragged).indexOf(id);
    moveKey(dragged, before(e) ? at : at + 1);
  };
}

/**
 * @param {!Object} key A StoredKey.
 * @return {!Element} Its authenticatorAttachment, & transports & model on
 *     hover.
 */
function renderAttachment(key) {
  // What else the authenticator reported when the key was created.
  const details = [
    key.transports?.length && `Transports: ${key.transports.join(', ')}`,
    key.aaguid && `Model: ${AAGUID_NAMES.get(key.aaguid) ?? 'unknown'} ` +
        `(AAGUID ${key.aaguid})`,
  ].filter(Boolean).map((line) => `\n${line}`).join('');
  switch (key.attachment) {
    case Attachment.PLATFORM:
      return element('td', '', 'Platform',
                     `Platform: built into the computer${details}`);
    case Attachment.CROSS_PLATFORM:
      return element('td', '', 'Cross-platform',
                     `Cross-platform: a roaming authenticator${details}`);
  }
  return element('td', 'weak', '?', UNKNOWN + details);
}

/**
 * @param {!Object} key A StoredKey.
 * @param {boolean} verified Whether this computer vouches for the key.
 * @return {!Element} ✓, or a button to verify it.
 */
function renderVerified(key, verified) {
  if (verified) {
    return markCell('✓', 'yes', 'Verified on this computer');
  }
  const td = element('td', 'mark');
  const verify = element('button', 'small', 'Verify',
      'Not verified on this computer: check that the public key belongs to ' +
      'the authenticator before adding it to a server');
  verify.onclick = async () => {
    setStatus(`Confirm with the security key or passkey of ` +
              `"${key.comment}"…`, true);
    try {
      await verifyKey(key);
      setStatus(`"${key.comment}" is verified.`);
    } catch (e) {
      setStatus(`Not verified: ${e.message}`);
    }
  };
  td.append(verify);
  return td;
}

/**
 * @param {!Object} key A StoredKey.
 * @return {!Element} Its backup flags, in red if a security key was asked
 *     for (those are single-device).
 */
function renderBackup(key) {
  if (key.backupEligible === undefined) {
    return element('td', 'mark weak', '?', UNKNOWN);
  }
  if (!key.backupEligible) {
    return element('td', 'mark', 'Single-device', 'Not backup eligible, so ' +
                   'bound to the authenticator: only it can use the ' +
                   'private key');
  }
  const wrong = isMismatched(key);
  const asked = wrong ? '.  You asked for a security key.' : '';
  return key.backedUp ?
      markCell('✓', wrong ? 'wrong' : 'yes',
               `Backed up (BS): multi-device, synced${asked}`) :
      markCell('○', wrong ? 'wrong' : 'weak',
               `Backup eligible (BE): multi-device, not synced yet${asked}`);
}

/**
 * @param {!Object} key A StoredKey.
 * @return {!Element} Whether it requires user verification, & who enforces
 *     it.
 */
function renderUv(key) {
  if (!key.verify) {
    return markCell('', '', 'Not required: a touch is enough');
  }
  return key.verifyEnforcedByKey ?
      markCell('✓', 'yes',
               'Required, enforced by the authenticator (credProtect)') :
      markCell('✓', 'weak',
               'Required, enforced by servers only (verify-required)');
}

/**
 * @param {!Object} key A StoredKey.
 * @param {boolean} verified Whether this computer vouches for the key.
 * @return {!Element} Copy & forget buttons.
 */
function renderActions(key, verified) {
  const td = element('td', 'actions');
  const copy = element('button', 'icon', '⧉',
      'Copy this key\'s authorized_keys line' +
      (verified ? '' : ' (not verified)'));
  copy.onclick = async () => {
    await copyText(copy, keyAuthorizedKeysLine(key));
    setStatus(verified ?
        `Copied "${key.comment}".  Add it to ~/.ssh/authorized_keys on ` +
            'your servers.' :
        `Copied "${key.comment}", which isn't verified: if it's someone ` +
            'else\'s, adding it lets them log in.');
  };
  const forget = element('button', 'icon forget', '✕', 'Forget this key');
  forget.onclick = async () => {
    // Ask for a second click to confirm.
    if (forget.dataset.armed) {
      await deleteKey(key.credentialId);
      setStatus(`Forgot "${key.comment}".  Also remove it from ` +
                '~/.ssh/authorized_keys on your servers' +
                (key.resident ? ', and from the authenticator' : '') + '.');
      return;
    }
    forget.dataset.armed = '1';
    forget.textContent = 'Forget?';
    setTimeout(() => {
      delete forget.dataset.armed;
      forget.textContent = '✕';
    }, 5000);
  };
  td.append(renderCertificate(key), copy, forget);
  return td;
}

/**
 * @param {number} seconds Since the epoch.
 * @return {string} The date, as the user writes them.
 */
function formatDate(seconds) {
  return new Date(seconds * 1000).toLocaleDateString(
      undefined, {dateStyle: 'medium'});
}

/**
 * @param {!Object} cert A Certificate (see ssh.js).
 * @param {number=} now In seconds since the epoch.
 * @return {string} E.g. 'expires Nov 22, 2026'.
 */
function describeValidity({validAfter, validBefore}, now = Date.now() / 1000) {
  if (now < validAfter) {
    return `valid from ${formatDate(validAfter)}`;
  }
  if (validBefore === null) {
    return 'never expires';
  }
  return `${validBefore < now ? 'expired' : 'expires'} ` +
      formatDate(validBefore);
}

/**
 * @param {!Object} cert A Certificate (see ssh.js).
 * @return {string} E.g. '"laptop" for alice, expires Nov 22, 2026'.
 */
function describeCertificate(cert) {
  const users = displayText(cert.principals.join(', '), 128) || 'any user';
  return `"${displayText(cert.keyId)}" for ${users}, ${describeValidity(cert)}`;
}

/**
 * @param {!Object} key A StoredKey.
 * @return {!Element} A button to add, or see & change, its certificate.
 */
function renderCertificate(key) {
  const cert = keyCertificate(key);
  const button = cert ?
      element('button',
              `icon cert ${isCertificateCurrent(cert) ? 'yes' : 'wrong'}`,
              'cert', `Certificate ${describeCertificate(cert)}`) :
      element('button', 'icon faint', '+',
              'Add an OpenSSH certificate for this key');
  button.onclick = () => openCertificateDialog(key);
  return button;
}

/**
 * @param {!Object} key A StoredKey.
 * @return {string} A command for the CA to sign the key with.
 */
function signingCommand(key) {
  return `ssh-keygen -s ca -I ${key.comment} -n $USER -V +52w ` +
      (key.verify ? '-O verify-required ' : '') + `${key.comment}.pub`;
}

/**
 * Show a key's certificate, & let the user add, replace or remove it.
 *
 * @param {!Object} key A StoredKey.
 */
function openCertificateDialog(key) {
  certificateKey = key;
  const cert = keyCertificate(key);
  $('cert-title').textContent = `Certificate for "${key.comment}"`;
  $('cert-current').hidden = !cert;
  $('cert-current').textContent =
      cert ? `Current: ${describeCertificate(cert)}.` : '';
  $('cert-pin').hidden = !(cert && key.verify && !cert.verifyRequired);
  $('cert-command').textContent = signingCommand(key);
  $('cert-text').value = '';
  $('cert-error').textContent = '';
  $('cert-remove').hidden = !cert;
  $('cert-save').textContent = cert ? 'Replace' : 'Add';
  $('cert-dialog').showModal();
}

/** Fill the certificate dialog's text box from the file the user chose. */
async function readCertificateFile() {
  const [file] = $('cert-file').files;
  $('cert-file').value = '';  // So choosing the same file again works.
  if (file) {
    $('cert-text').value =
        (await file.slice(0, MAX_CERTIFICATE_FILE_BYTES).text()).trim();
  }
}

/** Save the certificate the user pasted, or say what's wrong with it. */
async function saveCertificate() {
  try {
    await setCertificate(certificateKey, $('cert-text').value);
  } catch (e) {
    $('cert-error').textContent = `Can't use it: ${e.message}.`;
    return;
  }
  $('cert-dialog').close();
  setStatus(`Added the certificate to "${certificateKey.comment}".`);
}

/**
 * @param {!Object} key A StoredKey.
 * @param {boolean} verified Whether this computer vouches for the key.
 * @param {string} keyFingerprint
 * @return {!Element} The key's row, in COLUMNS' order.
 */
function renderKey(key, verified, keyFingerprint) {
  const level = element('td');
  const select = renderLevel(key, verified);
  // A disabled control gets no mouse events: explain it from its cell.
  if (select.disabled) {
    level.dataset.tip = select.dataset.tip;
  }
  level.append(select);

  const tr = element('tr', key.credentialId === highlight ? 'key new' : 'key');
  acceptDrops(tr, key.credentialId);
  tr.append(
      renderGrip(key),
      renderName(key, keyFingerprint),
      renderAttachment(key),
      renderVerified(key, verified),
      key.resident ?
          markCell('✓', 'yes', 'Discoverable credential (resident key)') :
          markCell('', '', 'Non-discoverable: needs its credential ID, ' +
                   'which this extension keeps (synced)'),
      renderBackup(key),
      renderUv(key),
      level,
      renderActions(key, verified));
  return tr;
}

/** Refresh the list of keys. */
async function load() {
  const keys = await loadKeys();
  const verified = await Promise.all(keys.map(isVerified));
  const fingerprints =
      await Promise.all(keys.map((key) => fingerprint(keyBlob(key))));
  showTip(null);  // Its target is about to go.
  order = keys.map((key) => key.credentialId);
  if (!keys.length) {
    const td = element('td', 'empty', 'No keys yet.  Add one below.');
    td.colSpan = COLUMNS.length;
    const tr = element('tr');
    tr.append(td);
    $('keys').replaceChildren(tr);
    return;
  }
  $('keys').replaceChildren(
      renderHead(),
      ...keys.map((key, i) => renderKey(key, verified[i], fingerprints[i])));
  if (focusAfterLoad) {
    const row = keys.findIndex((key) => key.credentialId === focusAfterLoad);
    focusAfterLoad = null;
    $('keys').querySelectorAll('button.grip')[row]?.focus();
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
  setStatus(startMessage, true);
  try {
    const key = await operation();
    // (The list may redraw more than once as storage changes.)
    highlight = key.credentialId;
    setTimeout(() => highlight = null, 3000);
    load();
    setStatus(`"${key.comment}" is ready.  Add its public key to your ` +
              'servers.');
  } catch (e) {
    setStatus(e.message === 'not kept' ? `Not kept.  ${leftover(e.key)}` :
              `Failed: ${e.message}`);
  } finally {
    $('create').disabled = $('import').disabled = false;
  }
}

/**
 * @param {!Object} key A StoredKey that wasn't kept.
 * @return {string} What's left of it on the authenticator.
 */
function leftover(key) {
  return key.resident ?
      'The authenticator still stores it; delete it there if you like ' +
          '(e.g. ykman fido credentials delete).' :
      'Nothing was stored on the authenticator.';
}

$('cert-copy-key').onclick = () =>
  copyText($('cert-copy-key'), keyPublicKeyLine(certificateKey));
$('cert-file').onchange = readCertificateFile;
$('cert-save').onclick = saveCertificate;
$('cert-remove').onclick = async () => {
  await removeCertificate(certificateKey);
  $('cert-dialog').close();
  setStatus(`Removed "${certificateKey.comment}"'s certificate.`);
};
$('cert-cancel').onclick = () => $('cert-dialog').close();

$('create').onclick = () => {
  const name = $('name').value.trim();
  if (!name) {
    $('name').focus();
    setStatus('Enter a name for the key first.');
    return;
  }
  run('Follow Chrome\'s prompt to create the key…', async () => {
    const where = document.querySelector('input[name=where]:checked').value;
    const key = await createKey(name, {
      kind: where === 'passkey' ? Kind.PASSKEY : Kind.SECURITY_KEY,
      resident: where === 'discoverable',
      verify: $('verify').checked,
      // Chrome's prompt offers other places: make sure it's what they want.
      keep: async (key) => !isMismatched(key) || confirm(
          `"${key.comment}" can sync (it's backup eligible), so it isn't ` +
          'bound to one security key.  Keep it?'),
    });
    $('name').value = '';
    $('verify').checked = false;
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
        () => setStatus('Confirm once more to finish importing…', true)));

const option = `--ssh-agent=${chrome.runtime.id}`;
$('agent-option').textContent = option;
$('copy-option').onclick = async () => {
  await copyText($('copy-option'), option);
  setStatus('Copied.  Paste it into the connection\'s SSH relay server ' +
            'options.');
};

if (!globalThis.PublicKeyCredential) {
  $('create').disabled = $('import').disabled = true;
  setStatus('This browser does not support WebAuthn.');
}

// Security settings: kept on this computer only.
const settings = await loadSettings();
for (const name of
         ['allowUnrecognized', 'allowDevSecureShell', 'trustSyncedKeys']) {
  $(name).checked = settings[name];
  $(name).onchange = () => saveSetting(name, $(name).checked);
}
$('confirmation').value = settings.confirmation;
// (Saving refreshes the keys, which show the default, via onChanged.)
$('confirmation').onchange =
    () => saveSetting('confirmation', $('confirmation').value);

// Keys may change elsewhere, e.g. on another synced computer.
chrome.storage.onChanged.addListener(load);

// The name says "(Dev)" for the Load-unpacked build.
const {name, version} = chrome.runtime.getManifest();
$('version').textContent = `${name}, version ${version}`;

load();
