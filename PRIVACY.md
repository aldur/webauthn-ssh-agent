# Privacy policy

WebAuthn SSH Agent does not collect, transmit or sell any data.

**What it stores.**  For each SSH key you create or import: the key's name,
its public key, its WebAuthn credential ID, the extension's RP ID, the creation
date and the key's settings.  This is stored with `chrome.storage.sync`, i.e.
in your Chrome profile, which Chrome syncs between your own devices if you
have sync turned on.  None of it is secret: the private keys never leave your
security key or passkey provider, and a credential ID is useless without the
physical security key.

On this computer only (`chrome.storage.local`, not synced): the extension's
security settings, and a fingerprint of each key verified on this computer.

**What it shares.**  Nothing.  The extension makes no network requests.  It
only answers SSH agent requests from Secure Shell, the extension that you
point at it, which sends the resulting signatures to the SSH servers you
connect to, as with any SSH key.

**What it can access.**  Only its own storage.  It has no access to websites,
your browsing, or other extensions' data.

**Removing data.**  Forget keys in the extension's **Manage keys and settings** page, or remove the
extension.  Keys stored on a security key are removed with the key's own tools
(e.g. `ykman fido credentials delete`).
