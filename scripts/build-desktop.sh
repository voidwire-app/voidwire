#!/usr/bin/env bash
# Build the desktop tray app bundles into dist/.
#   scripts/build-desktop.sh linux     # .deb + AppImage + raw binary
#   scripts/build-desktop.sh windows   # NSIS installer + .exe (cross, cargo-xwin)
#
# M1: release-profile builds (envelope encryption is implemented; the M0
# unencrypted preview builds are retired). Windows stays unsigned until M7.
set -euo pipefail
cd "$(dirname "$0")/.."
# Refuse the test harness in anything we ship (D1; core/build.rs).
export VOIDWIRE_SHIPPING_BUILD=1
source scripts/branding.sh
target="${1:-linux}"
root=$(pwd)
# D10: honour CARGO_TARGET_DIR / build.target-dir instead of assuming ./target.
target_dir=$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
mkdir -p dist
slug="${APP_NAME,,}"

# Copy the built binary: Tauri renames it to BINARY_NAME (mainBinaryName) when
# bundling; fall back to cargo's bin name. Fail loudly if neither exists.
copy_bin() { # <dir> <suffix> <dest>
  local src
  for n in "$BINARY_NAME$2" "voidwire-desktop$2"; do
    if [ -f "$1/$n" ]; then src="$1/$n"; break; fi
  done
  [ -n "${src:-}" ] || { echo "FATAL: no desktop binary in $1" >&2; exit 1; }
  cp "$src" "$3"
}
# Copy exactly-one-match globs; fail if the bundle is missing (no `|| true`).
copy_one() { # <glob> <dest-dir>
  local m=( $1 )
  [ -e "${m[0]}" ] || { echo "FATAL: expected bundle not found: $1" >&2; exit 1; }
  cp "${m[@]}" "$2"
}

# D8 + D9: branding and LICENSE/THIRD-PARTY-LICENSES.txt for every bundle
# (scripts/tauri-dist-config.py). Passed only via --config here, so a plain
# `cargo build` doesn't need the generated file.
TAURI_DIST_JSON="$root/build/tauri-dist.json"
scripts/tauri-dist-config.py "$TAURI_DIST_JSON"

cd desktop
case "$target" in
  linux)
    cargo tauri build --config "$TAURI_DIST_JSON" --bundles deb,appimage
    out="$target_dir/release"
    copy_bin "$out" "" "$root/dist/${slug}-desktop-linux-x86_64"
    copy_one "$out/bundle/deb/*.deb" "$root/dist/"
    copy_one "$out/bundle/appimage/*.AppImage" "$root/dist/"
    ;;
  windows)
    cargo tauri build --config "$TAURI_DIST_JSON" --runner cargo-xwin \
      --target x86_64-pc-windows-msvc --bundles nsis
    out="$target_dir/x86_64-pc-windows-msvc/release"
    copy_bin "$out" ".exe" "$root/dist/${slug}-desktop-windows-x86_64.exe"
    copy_one "$out/bundle/nsis/*-setup.exe" "$root/dist/"
    ;;
  *) echo "usage: $0 linux|windows" >&2; exit 2 ;;
esac
"$root/scripts/build-extension.sh" "$root/dist"
ls -la "$root/dist"
