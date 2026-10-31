#!/usr/bin/env bash
# Linux desktop smoke test (CI). Run inside a display and a private session bus:
#   xvfb-run -a dbus-run-session -- bash scripts/linux-smoke.sh target/release/voidwire-desktop
# Checks, with a throwaway HOME:
#   1. with a StatusNotifierWatcher stub, the tray item registers and no window opens;
#   2. the native host answers a status frame through the app's IPC socket;
#   3. the native-host manifests point at the binary, and files are 0600 / dirs 0700;
#   4. --send-clipboard reaches the running copy (L5); without a tray host,
#      the Devices window opens (L1);
#   5. stdout and stderr of the release app stay empty (V1).
# Test waits are bounded loops in this script; the app itself has no timers.
set -uo pipefail
BIN=$(readlink -f "${1:?usage: linux-smoke.sh <voidwire-desktop binary>}")
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
fail=0
ok()  { echo "PASS  $*"; }
bad() { echo "FAIL  $*"; fail=1; }

wait_for() { # wait_for <seconds> <command...>
  local n=$1; shift
  for _ in $(seq "$n"); do "$@" && return 0; sleep 1; done
  return 1
}

start_app() { # start_app <name>: fresh HOME, app in the background
  export HOME="$WORK/$1" XDG_RUNTIME_DIR="$WORK/$1/run"
  mkdir -p "$HOME" && mkdir -m 0700 "$XDG_RUNTIME_DIR"
  unset VOIDWIRE_DATA_DIR WAYLAND_DISPLAY
  "$BIN" >"$WORK/$1.out" 2>"$WORK/$1.err" &
  APP=$!
}

stop_app() {
  kill "$APP" 2>/dev/null; wait "$APP" 2>/dev/null
}

devices_window() { xdotool search --name "Paired devices" >/dev/null 2>&1; }

# --- run 1: tray host present ------------------------------------------------
python3 "$ROOT/scripts/sni-watcher-stub.py" >"$WORK/watcher.log" 2>&1 &
WATCHER=$!
wait_for 10 grep -q WATCHER_UP "$WORK/watcher.log" || bad "watcher stub did not start"
start_app tray
if wait_for 30 grep -q REGISTERED_ITEM "$WORK/watcher.log"; then ok "tray item registered"; else bad "tray item not registered"; fi

status_reply() {
  python3 - "$BIN" <<'PY'
import json, struct, subprocess, sys
req = json.dumps({"op": "status"}).encode()
p = subprocess.run([sys.argv[1], "--native-messaging-host"], input=struct.pack("<I", len(req)) + req,
                   capture_output=True, timeout=10)
out = p.stdout
n = struct.unpack("<I", out[:4])[0] if len(out) >= 4 else 0
r = json.loads(out[4:4 + n]) if n else {}
sys.exit(0 if r.get("ok") and r.get("running") else 1)
PY
}
if wait_for 20 status_reply; then ok "native host answers status (running)"; else bad "native host status"; fi

for d in .config/google-chrome/NativeMessagingHosts .config/chromium/NativeMessagingHosts \
         .config/microsoft-edge/NativeMessagingHosts .config/BraveSoftware/Brave-Browser/NativeMessagingHosts \
         .config/vivaldi/NativeMessagingHosts .mozilla/native-messaging-hosts; do
  f="$HOME/$d/app.voidwire.native_host.json"
  if [ -f "$f" ] && python3 -c 'import json,sys; sys.exit(json.load(open(sys.argv[1]))["path"]!=sys.argv[2])' "$f" "$BIN"; then
    ok "manifest $d"
  else
    bad "manifest $d missing or wrong path"
  fi
  [ "$(stat -c %a "$f" 2>/dev/null)" = 600 ] || bad "manifest $d not 0600"
done

state=$(find "$HOME/.local/share" -name state.bin 2>/dev/null | head -1)
if [ -n "$state" ]; then
  ok "state.bin written"
  [ "$(stat -c %a "$state")" = 600 ] && ok "state.bin 0600" || bad "state.bin not 0600"
  [ "$(stat -c %a "$(dirname "$state")")" = 700 ] && ok "data dir 0700" || bad "data dir not 0700"
else
  bad "no state.bin"
fi
if devices_window; then bad "a window opened although a tray host exists"; else ok "no window with a tray host"; fi
# L5: a second launch with --send-clipboard hands over to the running copy and
# exits; with nothing paired the running copy shows the Devices window.
if timeout 15 "$BIN" --send-clipboard >/dev/null 2>&1; then ok "--send-clipboard handed over and exited"; else bad "--send-clipboard did not exit cleanly"; fi
if wait_for 20 devices_window; then ok "--send-clipboard reached the running app"; else bad "--send-clipboard: no reaction in the running app"; fi
stop_app
kill "$WATCHER" 2>/dev/null; wait "$WATCHER" 2>/dev/null
for s in out err; do
  if [ -s "$WORK/tray.$s" ]; then bad "app wrote to std$s ($(wc -c <"$WORK/tray.$s") bytes)"; head -c 400 "$WORK/tray.$s"; echo; else ok "std$s empty"; fi
done

# --- run 2: no tray host (L1) -------------------------------------------------
start_app notray
if wait_for 30 devices_window; then ok "no tray host: Devices window opened (L1)"; else bad "no tray host: no window"; fi
stop_app
for s in out err; do
  if [ -s "$WORK/notray.$s" ]; then bad "app wrote to std$s without tray ($(wc -c <"$WORK/notray.$s") bytes)"; head -c 400 "$WORK/notray.$s"; echo; else ok "std$s empty without tray"; fi
done

rm -rf "$WORK"
[ "$fail" = 0 ] && echo "linux smoke: all passed" || echo "linux smoke: FAILED"
exit "$fail"
