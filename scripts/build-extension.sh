#!/usr/bin/env bash
# Package the Voidwire browser extension (M3.2) for Chromium MV3 and Firefox MV3.
#   scripts/build-extension.sh [out-dir]
set -euo pipefail
cd "$(dirname "$0")/.."
out_dir="${1:-dist}"
mkdir -p "$out_dir"

python3 - "$out_dir" << 'PY'
import json
import os
import sys
import zipfile

out_dir = sys.argv[1]
ext_dir = "extension"

common_files = [
    "background.js",
    "popup.html",
    "popup.css",
    "popup.js",
    "tokens.css",
    "fonts.css",
    "shapes.css",
    "fonts/web/SpaceGrotesk-Variable.latin.woff2",
    "fonts/web/JetBrainsMono-Variable.latin.woff2",
    "fonts/OFL-SpaceGrotesk.txt",
    "fonts/OFL-JetBrainsMono.txt",
    "README.md",
    "icons/icon-16.png",
    "icons/icon-32.png",
    "icons/icon-48.png",
    "icons/icon-128.png",
    "toolbar/toolbar-dark-16.png",
    "toolbar/toolbar-dark-32.png",
    "toolbar/toolbar-light-16.png",
    "toolbar/toolbar-light-32.png",
]

for rel in common_files + ["manifest.json", "manifest.firefox.json"]:
    p = os.path.join(ext_dir, rel)
    if not os.path.isfile(p):
        raise SystemExit(f"FATAL: missing extension file {p}")

# Validate JSON manifests and permission invariants before packaging.
for mf in ["manifest.json", "manifest.firefox.json"]:
    with open(os.path.join(ext_dir, mf), "rb") as f:
        data = json.load(f)
    assert data["manifest_version"] == 3, f"{mf}: must be MV3"
    assert data["permissions"] == ["nativeMessaging", "contextMenus", "activeTab"], (
        f"{mf}: unexpected permissions {data['permissions']}"
    )

def build_zip(zip_path: str, manifest_src: str) -> None:
    if os.path.exists(zip_path):
        os.remove(zip_path)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(os.path.join(ext_dir, manifest_src), arcname="manifest.json")
        for rel in common_files:
            zf.write(os.path.join(ext_dir, rel), arcname=rel)

chromium_zip = os.path.join(out_dir, "voidwire-extension-chromium.zip")
firefox_zip = os.path.join(out_dir, "voidwire-extension-firefox.zip")
build_zip(chromium_zip, "manifest.json")
build_zip(firefox_zip, "manifest.firefox.json")
print(f"Built {chromium_zip} and {firefox_zip}")
PY
