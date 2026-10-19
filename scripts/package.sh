#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Package the extension for "Load unpacked".
#
# manifest.json goes at the root of the zip: unzip tools then produce one
# folder to pick in "Load unpacked".
#
# Usage: package.sh <output.zip>
set -euo pipefail
cd "$(dirname "$0")/.."
out=$(realpath -m "$1")
rm -f "$out"
zip -qr "$out" manifest.json LICENSE README.md icons/*.png src
echo "$out"
