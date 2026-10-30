#!/usr/bin/env bash
# android-qa.yml: start the Linux desktop app headless as the PC peer (CI runner
# only; it replaces /usr/bin/xdg-open). Xvfb :99, a private session bus, the
# then the app with its Pair a device window showing a code (Return on the
# autofocused "This PC shows a code").
# Writes DISPLAY / DBUS_SESSION_BUS_ADDRESS to $GITHUB_ENV for later steps.
set -euo pipefail
cd "$(dirname "$0")/../.."
P=/tmp/vw-peer; mkdir -p "$P/data"; : > "$P/opened.log"
sudo install -m 755 scripts/qa/rec-open.sh /usr/bin/xdg-open
Xvfb :99 -screen 0 1280x800x24 >"$P/xvfb.log" 2>&1 &
export DISPLAY=:99
sleep 1
# A window manager, so xdotool windowactivate / _NET_ACTIVE_WINDOW works
# (QA 8ee9a16: the code never reached the Pair window without one).
openbox >"$P/openbox.log" 2>&1 &
echo $! > "$P/openbox.pid"
eval "$(dbus-launch --sh-syntax)"
sleep 2
mkdir -p "$P/data" && : > "$P/data/diagnostics.on"
VOIDWIRE_DATA_DIR="$P/data" VOIDWIRE_SHOW=pair VOIDWIRE_THEME=dark \
  nohup target/debug/voidwire-desktop >"$P/desktop.log" 2>&1 &
echo $! > "$P/desktop.pid"
wid=$(timeout 120 xdotool search --sync --onlyvisible --name "Pair a device" | tail -1)
sleep 2
xdotool windowactivate --sync "$wid" || xdotool windowfocus --sync "$wid" || true
xdotool key Return
echo "DISPLAY=:99" >> "$GITHUB_ENV"
echo "DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS" >> "$GITHUB_ENV"
echo "host peer up: $(hostname), addresses: $(hostname -I)"
