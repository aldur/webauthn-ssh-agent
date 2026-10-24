#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# End-to-end test: builds upstream Secure Shell (unless given one), starts a
# throwaway sshd on 127.0.0.1:2222 and logs in as the current user through
# this agent with a virtual security key.
#
# Usage: run.sh [secure shell dir]
# Needs: git, jq, python3, sshd, node & playwright (set PLAYWRIGHT_DIR to its
# node_modules if it isn't resolvable from here) with its "chromium" browser.
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'kill $(cat "$work/sshd.pid" 2>/dev/null) 2>/dev/null; rm -rf "$work"' \
    EXIT

ssh_dir=${1:-}
if [[ -z $ssh_dir ]]; then
  ssh_dir=$work/secure-shell
  ./test/e2e/build-secure-shell.sh "$ssh_dir"
fi

ssh-keygen -q -t ed25519 -N '' -f "$work/hostkey"
ssh-keygen -q -t ed25519 -N '' -f "$work/ca"
cat > "$work/sshd_config" <<CFG
Port 2222
ListenAddress 127.0.0.1
HostKey $work/hostkey
PidFile $work/sshd.pid
AuthorizedKeysFile $work/authorized_keys
TrustedUserCAKeys $work/ca.pub
PermitRootLogin yes
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
CFG
"$(command -v sshd || echo /usr/sbin/sshd)" -f "$work/sshd_config" \
    -E "$work/sshd.log"

node test/e2e/e2e.mjs "$PWD" "$(realpath "$ssh_dir")" "$work/profile" \
    "$work/authorized_keys" 2222 "$(id -un)" \
    "$(ssh-keygen -lf "$work/hostkey.pub" | cut -d' ' -f2)" "$work/ca"
grep 'Accepted publickey' "$work/sshd.log"
