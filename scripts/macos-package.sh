#!/usr/bin/env bash
# macOS release files from the universal app (M5.2), after
#   cargo tauri build --config ../build/tauri-dist.json --target universal-apple-darwin --bundles app
# Usage: scripts/macos-package.sh OUT_DIR
#
# Checks the app first: a full ad-hoc signature (sealed resources and a bound
# Info.plist, not just the linker's), both architectures, system libraries
# only, and the Info.plist keys M5.2 needs. Then writes
#   OUT_DIR/<App>_<version>_universal.dmg   (the app + an Applications link)
#   OUT_DIR/<App>.app.tar.gz                (the app alone, for a later in-app update)
# The disk image is made with hdiutil (no Finder scripting, so it works on a
# headless runner). Nothing is signed with an Apple identity: there is none.
set -euo pipefail
out=${1:?usage: scripts/macos-package.sh OUT_DIR}
root=$(cd "$(dirname "$0")/.." && pwd)
app=$(find "$root/target/universal-apple-darwin/release/bundle/macos" -maxdepth 1 -name '*.app' | head -1)
[ -n "$app" ] || { echo "no universal .app; build it first" >&2; exit 1; }
name=$(basename "$app" .app)
plist="$app/Contents/Info.plist"
pb() { /usr/libexec/PlistBuddy -c "Print :$1" "$plist"; }
ver=$(pb CFBundleShortVersionString)
exe="$app/Contents/MacOS/$(pb CFBundleExecutable)"
fail() { echo "macos-package: $*" >&2; exit 1; }

# Signature: complete ad-hoc seal, not the linker's partial one.
codesign --verify --deep --strict --verbose=2 "$app"
sig=$(codesign -dv --verbose=4 "$app" 2>&1)
echo "$sig" | grep -q 'Signature=adhoc' || fail "not ad-hoc signed"
echo "$sig" | grep -q 'linker-signed' && fail "only the linker's signature (set bundle.macOS.signingIdentity to \"-\")"
echo "$sig" | grep -q 'Sealed Resources=none' && fail "resources not sealed"
echo "$sig" | grep -q 'Info.plist=not bound' && fail "Info.plist not bound"

# Both architectures, system libraries only.
archs=$(lipo -archs "$exe")
for a in x86_64 arm64; do
  case " $archs " in *" $a "*) ;; *) fail "missing $a (has: $archs)";; esac
done
# Library lines are indented; the unindented ones name the file (once per
# architecture in a universal binary).
bad=$(otool -L "$exe" | grep -E '^[[:space:]]' | awk '{print $1}' | grep -v -E '^(/System/Library/|/usr/lib/)' || true)
[ -z "$bad" ] || fail "links outside the system: $bad"

# Info.plist keys (scripts/tauri-dist-config.py).
[ "$(pb LSUIElement)" = "true" ] || fail "LSUIElement is not true"
[ "$(pb LSMinimumSystemVersion)" = "13.0" ] || fail "LSMinimumSystemVersion is not 13.0"
[ -n "$(pb NSLocalNetworkUsageDescription)" ] || fail "no NSLocalNetworkUsageDescription"
[ "$(pb NSServices:0:NSMessage)" = "sendWithVoidwire" ] || fail "NSServices message"
[ "$(pb NSServices:0:NSPortName)" = "$name" ] || fail "NSServices port name"

mkdir -p "$out"
COPYFILE_DISABLE=1 tar -czf "$out/$name.app.tar.gz" -C "$(dirname "$app")" "$name.app"

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
ditto "$app" "$stage/$name.app"
ln -s /Applications "$stage/Applications"
dmg="$out/${name}_${ver}_universal.dmg"
rm -f "$dmg"
hdiutil create -volname "$name" -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$dmg"
hdiutil verify "$dmg"
ls -l "$out"
