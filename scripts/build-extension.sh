#!/usr/bin/env bash
# Package the Voidwire browser extension for Chromium MV3 and Firefox MV3.
#   scripts/build-extension.sh [out-dir]          release zips (sideload; Chromium keeps its fixed ID)
#   scripts/build-extension.sh --stores [out-dir] store uploads + AMO source zip
# Reproducible: the same source gives byte-identical zips (scripts/extension_pack.py).
set -euo pipefail
cd "$(dirname "$0")/.."
mode=release
if [ "${1:-}" = "--stores" ]; then mode=stores; shift; fi
python3 scripts/extension_pack.py "$mode" "${1:-dist}"
