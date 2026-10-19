#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Package the extension.
#
#   package.sh <output.zip>          Dev build for "Load unpacked": keeps the
#                                    manifest "key", so the extension ID is
#                                    always balijighililfegobipoacjgpmpckepg.
#   package.sh --store <output.zip>  Chrome Web Store build: without "key"
#                                    (the Store rejects it & assigns its own
#                                    ID).
#
# manifest.json goes at the root of the zip: unzip tools then produce one
# folder to pick in "Load unpacked", and the Web Store requires it.
set -euo pipefail
store=false
if [[ ${1:-} == --store ]]; then
  store=true
  shift
fi
cd "$(dirname "$0")/.."
out=$(realpath -m "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cp -r manifest.json LICENSE README.md PRIVACY.md src "$tmp/"
mkdir "$tmp/icons"
cp icons/*.png "$tmp/icons/"
if $store; then
  jq 'del(.key)' manifest.json > "$tmp/manifest.json"
fi

rm -f "$out"
(cd "$tmp" && zip -qr "$out" .)
echo "$out"
