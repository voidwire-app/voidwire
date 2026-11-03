#!/usr/bin/env bash
# macOS smoke test of the release files (M5.2), on a CI runner or a test Mac.
# Usage: scripts/macos-smoke.sh DIST_DIR   (holds the .dmg and .app.tar.gz)
#
# Uses a throwaway HOME, so the browser manifests it checks never touch the
# real ones. Steps:
#  1. Mount the disk image; the app on it has a valid signature.
#  2. Start the app from the disk image: the browser helper answers "running",
#     and no browser manifest is written (M3: it would point at a path that
#     goes away).
#  3. Copy the app out (as to Applications) and start it: all six manifests
#     are written, each pointing at this app, and the helper answers.
#  4. The app wrote nothing to stdout or stderr (it logs nothing by default).
#  5. The .app.tar.gz unpacks to an app with a valid signature.
set -euo pipefail
dist=${1:?usage: scripts/macos-smoke.sh DIST_DIR}
dmg=$(ls "$dist"/*.dmg | head -1)
tarball=$(ls "$dist"/*.app.tar.gz | head -1)
work=$(mktemp -d)
home="$work/home"
mkdir -p "$home"
pid=""
vol=""
cleanup() {
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  [ -n "$vol" ] && hdiutil detach "$vol" -quiet 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
fail() { echo "macos-smoke: FAIL: $*" >&2; exit 1; }
ok() { echo "macos-smoke: ok: $*"; }

chromium_id=mknbkjlaloblibdffcebiegchmcbmpbm
host=app.voidwire.native_host
manifests=(
  "Google/Chrome/NativeMessagingHosts"
  "BraveSoftware/Brave-Browser/NativeMessagingHosts"
  "Chromium/NativeMessagingHosts"
  "Microsoft Edge/NativeMessagingHosts"
  "Vivaldi/NativeMessagingHosts"
  "Mozilla/NativeMessagingHosts"
)

exe_of() { echo "$1/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$1/Contents/Info.plist")"; }

# One Native Messaging "status" request through the browser helper (the
# same binary, started the way Chrome starts it).
status() {
  HOME="$home" python3 - "$1" "$chromium_id" <<'PY'
import json, struct, subprocess, sys
req = json.dumps({"op": "status"}).encode()
p = subprocess.run([sys.argv[1], f"chrome-extension://{sys.argv[2]}/"],
                   input=struct.pack("<I", len(req)) + req, capture_output=True, timeout=20)
out = p.stdout
if len(out) < 4:
    sys.exit(f"no reply (exit {p.returncode})")
n = struct.unpack("<I", out[:4])[0]
print(out[4:4 + n].decode())
PY
}

start_app() { # app_dir log_prefix
  HOME="$home" "$(exe_of "$1")" >"$work/$2.out" 2>"$work/$2.err" &
  pid=$!
  for _ in $(seq 60); do
    if status "$(exe_of "$1")" 2>/dev/null | grep -q '"running":true'; then
      return 0
    fi
    kill -0 "$pid" 2>/dev/null || fail "$2: the app exited early: $(cat "$work/$2.err")"
    sleep 0.5
  done
  fail "$2: the helper never reached the running app"
}

stop_app() {
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  pid=""
}

# 1
vol=$(hdiutil attach -nobrowse -readonly "$dmg" | awk -F'\t' '/\/Volumes\//{print $NF}' | tail -1)
[ -d "$vol" ] || fail "could not mount $dmg"
src=$(find "$vol" -maxdepth 1 -name '*.app' | head -1)
codesign --verify --deep --strict "$src" || fail "signature on the disk image"
[ -L "$vol/Applications" ] || fail "no Applications link on the disk image"
ok "disk image mounts at $vol, app signature valid"

# 2
start_app "$src" dmg
for d in "${manifests[@]}"; do
  [ ! -e "$home/Library/Application Support/$d/$host.json" ] || fail "manifest written for a disk-image copy: $d"
done
stop_app
ok "run from the disk image: helper answers, no browser manifests"

# 3
mkdir -p "$work/Applications"
ditto "$src" "$work/Applications/$(basename "$src")"
app="$work/Applications/$(basename "$src")"
start_app "$app" app
exe=$(exe_of "$app")
for d in "${manifests[@]}"; do
  f="$home/Library/Application Support/$d/$host.json"
  [ -f "$f" ] || fail "missing manifest: $d"
  python3 - "$f" "$exe" <<'PY' || fail "manifest path: $d"
import json, sys
m = json.load(open(sys.argv[1]))
assert m["path"] == sys.argv[2], (m["path"], sys.argv[2])
assert m["name"] == "app.voidwire.native_host"
PY
  perm=$(stat -f '%Lp' "$f")
  [ "$perm" = "600" ] || fail "manifest mode $perm: $d"
done
status "$exe" | grep -q '"ok":true' || fail "status not ok"
stop_app
ok "run from a copy: six manifests point at it (mode 600), helper answers"

# 4
for f in "$work"/*.out "$work"/*.err; do
  [ ! -s "$f" ] || fail "the app wrote to $(basename "$f"): $(head -c 400 "$f")"
done
ok "nothing on stdout or stderr"

# 5
mkdir -p "$work/tar"
tar -xzf "$tarball" -C "$work/tar"
codesign --verify --deep --strict "$(find "$work/tar" -maxdepth 1 -name '*.app' | head -1)" || fail "signature in the .app.tar.gz"
ok ".app.tar.gz unpacks to a signed app"
echo "macos-smoke: all ok"
