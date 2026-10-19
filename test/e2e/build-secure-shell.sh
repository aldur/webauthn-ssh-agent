#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Build an unmodified upstream Secure Shell for the end-to-end test.
#
# Usage: build-secure-shell.sh <output dir> [libapps commit]
#
# The extension keeps upstream's developer key, so it gets Secure Shell's dev
# extension ID: Chrome only grants chrome.sockets (direct TCP) to Secure
# Shell's known IDs, and our agent only accepts calls from them.
set -euo pipefail
out=$(realpath -m "$1")
commit=${2:-58a3c13e0ac1a36160b8d1a584ec25e982cad557}  # nassh 0.82.
src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT

git -C "$src" init -q
git -C "$src" fetch -q --depth 1 https://github.com/libapps/libapps-mirror \
    "$commit"
git -C "$src" checkout -q FETCH_HEAD
# mkdeps names the build after the latest nassh-* tag.
git -C "$src" tag "nassh-$(jq -r .version "$src/nassh/manifest.json")"

(cd "$src" && ./nassh/bin/mkdist >/dev/null)

version=$(jq -r .version "$src/nassh/manifest.json")
rm -rf "$out"
cp -r "$src/nassh/dist/tmp/SecureShell-$version" "$out"
jq --arg key "$(jq -r .key "$src/nassh/manifest.json")" '.key = $key' \
    "$out/manifest.json" > "$out/manifest.json.new"
mv "$out/manifest.json.new" "$out/manifest.json"
echo "$out"
