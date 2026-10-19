# WebAuthn SSH Agent

An SSH agent for Chrome's [Secure Shell] that keeps your SSH keys on a
**security key** (YubiKey, Titan, …) or a **passkey**, via WebAuthn.  The
extension never holds a private key, and every login needs your security key
or passkey.

Works with the regular Secure Shell; no native helpers.  Servers need OpenSSH
8.4+.

## Install

Install it from the [Chrome Web Store].

To try a development build, download the zip from the [releases page], unzip
it, and in `chrome://extensions` enable **Developer mode** and **Load
unpacked** the folder.

## Use

1. Click the extension's toolbar button to open **Manage keys and settings**,
   create a key, and add its public key to `~/.ssh/authorized_keys` on your
   servers.
2. In Secure Shell, set the connection's **SSH relay server options** to the
   `--ssh-agent=…` line shown in **Manage keys and settings**.
3. Connect, check the request that pops up, click **Continue** (or press
   Enter), and confirm with your security key or passkey.

For direct logins to a verified server, you can choose how much to see: the
**Confirmation** level, for each key (synced with it) or as a default.
**Review** (the default) shows the request and waits for Continue, **Show**
opens the security key or passkey prompt right away with the request beside
it, and **Silent** only shows the prompt.  A key's own level applies once
it's verified on this computer.  Other requests are always reviewed.

Agent forwarding (`ssh -A`) works, with an extra confirmation per login.  The
`ssh` on the server you forward from must be OpenSSH 10.3+: older versions
reject the WebAuthn signatures a browser makes when they come from an agent.

## Supported authenticators

Everything goes through WebAuthn, so any authenticator Chrome supports works:

| Authenticator | What you get |
|---|---|
| **U2F-only security key** (older keys) | Non-discoverable keys, and a touch to log in: U2F has no discoverable keys and no PIN or fingerprint. |
| **FIDO2 security key** (YubiKey 5, Titan, SoloKey, Nitrokey, …) | Everything: optional discoverable keys, and a PIN or fingerprint for every login, enforced by the security key itself. |
| **Passkey** (Google Password Manager, iCloud Keychain, Windows Hello, a phone, …) | Always discoverable, held (and usually synced) by the provider, unlocked with your screen lock or biometrics. |

Keys are ECDSA P-256 only: OpenSSH's WebAuthn signature format doesn't exist
for Ed25519.  Keys made with `ssh-keygen -t ecdsa-sk` can't be used (they're
bound to `ssh:`, which browsers don't allow); create keys here instead, and one
security key can hold both.

## Where keys live

| | Security key | Security key, stored on the key | Passkey |
|---|---|---|---|
| **Private key** | Stored encrypted in your Chrome profile (synced); only that specific security key can decrypt and use it | Stored in one of the security key's slots (a *discoverable credential*, or *resident key*) | Held by the passkey provider (may sync) |
| **Login needs** | The security key + the synced credential ID | The security key | The passkey provider |
| **How to use on a new computer** | Appears through Chrome sync; plug in the security key | Appears through Chrome sync, or **Import** with the security key | Appears through Chrome sync, or **Import**; the passkey must be available there (synced by the provider, or on your phone) |

The extension stores only the public key and credential ID, synced with your
Chrome profile.  For a key not stored on the security key, the credential ID
is the encrypted private key: neither it nor the security key works without
the other.

**Require a PIN or fingerprint** adds `verify-required` to the
`authorized_keys` line, and asks the security key to enforce it too
(`credProtect`).  The key list says "enforced by servers only" if the security
key didn't confirm it.

## Security

* Only Secure Shell can use the agent (Secure Shell's dev build only if you
  allow it in **Manage keys and settings**).
* The agent checks OpenSSH's session binding (`session-bind@openssh.com`): it
  shows the server's verified host key and refuses logins for any other
  session.
* Logins through a forwarded agent or from clients that don't bind sessions,
  and file signatures (e.g. git commits), come with a warning.  Anything else
  is refused unless you allow it.
* Keys sync through your Google account, so whoever controls it could swap
  in their own public key, which you'd then add to your servers.  Synced
  keys show as *not verified* until you **Verify** them (or
  turn on **Trust keys synced**).
* Only the `storage` permission, a strict content security policy, no
  dependencies.

## How it works

Secure Shell relays agent requests to this extension, which offers
`sk-ecdsa-sha2-nistp256@openssh.com` keys and signs with
`navigator.credentials.get()`, in OpenSSH's
`webauthn-sk-ecdsa-sha2-nistp256@openssh.com` format (see [PROTOCOL.u2f]).
Keys are bound to the extension's origin.

## Development

```
node --test 'test/*.test.js'   # unit tests
./test/e2e/run.sh              # end to end; needs sshd, jq & Playwright
scripts/package.sh out.zip     # --store: Chrome Web Store build
node scripts/store-assets.mjs  # Store images
```

To release, change the version in `manifest.json` and push to `main`: CI
publishes the release, tagged `v<version>`, with both zips.  Other builds of
`main` are versioned `<last version>.<CI run number>`.

[Secure Shell]: https://chromewebstore.google.com/detail/iodihamcpbpeioajjeobimgagajmlibd
[Chrome Web Store]: https://chromewebstore.google.com/detail/webauthn-ssh-agent/nkcmhjokohmhogfaanphnnfdjfplkklk
[releases page]: https://github.com/jlnt/webauthn-ssh-agent/releases
[PROTOCOL.u2f]: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
