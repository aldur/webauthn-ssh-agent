#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Package the extension.
#
#   package.sh <output.zip>          Dev build for "Load unpacked": keeps the
#                                    manifest "key", so the extension ID is
#                                    always balijighililfegobipoacjgpmpckepg,
#                                    & is named "… (Dev)", with a black &
#                                    white icon, to tell it from the Store
#                                    version.
#   package.sh --store <output.zip>  Chrome Web Store build: without "key"
#                                    (the Store rejects it & assigns its own
#                                    ID).
#   --version <version>              Use this version instead of
#                                    manifest.json's (e.g. for dev builds).
#
# manifest.json goes at the root of the zip: unzip tools then produce one
# folder to pick in "Load unpacked", and the Web Store requires it.
set -euo pipefail
store=false
version=
while [[ ${1:-} == --* ]]; do
  case $1 in
    --store) store=true; shift ;;
    --version) version=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 1 ;;
  esac
done
cd "$(dirname "$0")/.."
out=$(realpath -m "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cp -r manifest.json LICENSE README.md PRIVACY.md src "$tmp/"
mkdir "$tmp/icons"
filter=.
if $store; then
  cp icons/*.png "$tmp/icons/"
  filter="$filter | del(.key)"
else
  cp icons/dev/*.png "$tmp/icons/"
  filter="$filter | .name += \" (Dev)\""
fi
if [[ -n $version ]]; then
  filter="$filter | .version = \$version"
fi
jq --arg version "$version" "$filter" manifest.json > "$tmp/manifest.json"

rm -f "$out"
(cd "$tmp" && zip -qr "$out" .)
echo "$out"
