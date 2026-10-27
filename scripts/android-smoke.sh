#!/usr/bin/env bash
# On-device smoke test for the Android app (QA M1 re-check C1).
#
#   scripts/android-smoke.sh boot            start the emulator headless (software CPU, NO KVM)
#   scripts/android-smoke.sh apk  <apk>      install <apk>, launch MainActivity + ShareActivity,
#                                            fail on any crash/abort or if the phone client didn't load
#   scripts/android-smoke.sh send [url]      (needs a paired PC) share [url] to ShareActivity, wait for the
#                                            "Send to <PC>" button to enable, tap its centre with
#                                            `adb shell input tap`, and check the phone reports it sent (S1)
#   scripts/android-smoke.sh instrumented    gradle connectedDebugAndroidTest (src/androidTest)
#   scripts/android-smoke.sh stop
#
# Uses AVD ${VOIDWIRE_AVD:-vw34} (API 34 x86_64). Software emulation (-accel off) on
# purpose: on the build box, creating a KVM guest crashes the host kernel. Never
# pass -accel on/kvm here. Expect a 5-15 min boot. On a real phone, plug it in and
# run `apk` / `instrumented` without `boot`.
set -euo pipefail
cd "$(dirname "$0")/.."
export ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
ADB="$ANDROID_HOME/platform-tools/adb"
PKG=app.voidwire.android
LOG="${VOIDWIRE_SMOKE_LOG:-/tmp/voidwire-smoke}"
mkdir -p "$LOG"

boot() {
  if "$ADB" devices | grep -q 'emulator-.*device$'; then echo "emulator already up"; return; fi
  nohup "$ANDROID_HOME/emulator/emulator" -avd "${VOIDWIRE_AVD:-vw34}" \
    -accel off -no-window -no-snapshot -no-audio -no-boot-anim \
    -gpu swiftshader_indirect -cores 4 -memory 2560 > "$LOG/emulator.log" 2>&1 &
  echo "emulator pid $!; waiting for boot (timeout ${BOOT_TIMEOUT:-2400}s)"
  "$ADB" wait-for-device
  local t=0
  until [ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do
    sleep 10; t=$((t+10))
    [ $t -ge "${BOOT_TIMEOUT:-2400}" ] && { echo "boot timeout"; exit 1; }
  done
  echo "booted after ~${t}s"
  "$ADB" shell settings put global window_animation_scale 0 || true
  "$ADB" shell settings put global transition_animation_scale 0 || true
  "$ADB" shell settings put global animator_duration_scale 0 || true
}

crashed() { # pattern search in logcat for our process dying
  "$ADB" logcat -d -b crash -b main -b system 2>/dev/null > "$LOG/logcat-$1.txt" || true
  grep -E "Fatal signal|FATAL EXCEPTION|android context was not initialized|Abort message|Process $PKG.*(died|has died)|Force finishing activity $PKG" \
    "$LOG/logcat-$1.txt" | grep -v "^--------- beginning" | head -20 || true  # no match = no crash
}

ui_has() { # wait up to $2 s (wall clock; one dump can take 20 s under TCG) for text $1 in the UI
  local end=$((SECONDS + $2))
  while [ $SECONDS -lt $end ]; do
    "$ADB" shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1 || true
    "$ADB" shell cat /sdcard/ui.xml 2>/dev/null > "$LOG/ui.xml" || true
    grep -q "$1" "$LOG/ui.xml" && return 0
    sleep 5
  done
  return 1
}

apk() {
  local apk=$1 fail=0
  "$ADB" uninstall "$PKG" >/dev/null 2>&1 || true
  "$ADB" install -r "$apk" > "$LOG/install.txt"
  "$ADB" shell pm grant "$PKG" android.permission.CAMERA >/dev/null 2>&1 || true
  "$ADB" logcat -c || true

  echo "--- MainActivity"
  "$ADB" shell am start -W -n "$PKG/.MainActivity" | tee "$LOG/am-main.txt"
  if ui_has "This phone" 180; then echo "PASS: home screen shown (Phone() built)"; else echo "FAIL: home screen not shown"; fail=1; fi
  grep -q "Couldn't start" "$LOG/ui.xml" && { echo "FAIL: app shows 'Couldn't start'"; fail=1; }
  pid=$("$ADB" shell pidof "$PKG" | tr -d '\r'); echo "pid after MainActivity: ${pid:-<none>}"
  [ -n "$pid" ] || fail=1
  c=$(crashed main); [ -z "$c" ] || { echo "FAIL: crash in logcat:"; echo "$c"; fail=1; }
  "$ADB" shell am force-stop "$PKG"

  echo "--- ShareActivity (cold process, explicit ACTION_SEND)"
  "$ADB" logcat -c || true
  "$ADB" shell am start -W -a android.intent.action.SEND -t text/plain \
    --es android.intent.extra.TEXT "'smoke https://example.com/smoke'" -n "$PKG/.ShareActivity" | tee "$LOG/am-share.txt"
  if ui_has "No PC is paired yet" 180; then echo "PASS: share sheet loaded the paired-PC list"; else echo "FAIL: share sheet didn't load"; fail=1; fi
  pid=$("$ADB" shell pidof "$PKG" | tr -d '\r'); echo "pid after ShareActivity: ${pid:-<none>}"
  [ -n "$pid" ] || fail=1
  c=$(crashed share); [ -z "$c" ] || { echo "FAIL: crash in logcat:"; echo "$c"; fail=1; }
  "$ADB" shell am force-stop "$PKG"
  [ $fail = 0 ] && echo "SMOKE_APK_PASS" || { echo "SMOKE_APK_FAIL"; exit 1; }
}

send_button() { # print "<enabled> <x> <y>" for the first "Send to <PC>" button in $LOG/ui.xml
  python3 - "$LOG/ui.xml" <<'PY'
import re, sys, xml.etree.ElementTree as ET
try:
    root = ET.parse(sys.argv[1]).getroot()
except Exception:
    sys.exit(1)
def walk(n):
    for c in n:
        if c.get("clickable") == "true" and any((d.get("text") or "").startswith("Send to ") for d in c.iter()):
            return c
        r = walk(c)
        if r is not None:
            return r
b = walk(root)
if b is None:
    sys.exit(1)
x1, y1, x2, y2 = map(int, re.findall(r"\d+", b.get("bounds")))
print(b.get("enabled"), (x1 + x2) // 2, (y1 + y2) // 2)
PY
}

send() {
  local url=${1:-"https://example.com/voidwire-s1?t=$(date +%s)"} t=0 btn="" fail=0
  "$ADB" logcat -c || true
  echo "--- ShareActivity with a paired PC: $url"
  "$ADB" shell am start -W -a android.intent.action.SEND -t text/plain \
    --es android.intent.extra.TEXT "'$url'" -n "$PKG/.ShareActivity" > "$LOG/am-send.txt"
  while [ $t -lt 240 ]; do
    "$ADB" shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1 || true
    "$ADB" shell cat /sdcard/ui.xml 2>/dev/null > "$LOG/ui.xml" || true
    btn=$(send_button || true)
    case "$btn" in true\ *) break ;; esac
    sleep 3; t=$((t+3))
  done
  cp "$LOG/ui.xml" "$LOG/ui-send-ready.xml"
  case "$btn" in
    true\ *) echo "PASS: Send button enabled ($btn) after ~${t}s" ;;
    "") echo "FAIL: no 'Send to <PC>' button (is a PC paired?)"; exit 1 ;;
    *) echo "FAIL: Send button still disabled after ${t}s ($btn)"; exit 1 ;;
  esac
  "$ADB" exec-out screencap -p > "$LOG/send-1-ready.png" || true
  set -- $btn
  echo "tap at $2,$3"
  # Screenshots straight after the tap: "Sending…" / "Sent to …" is only on
  # screen for the send plus 1.5 s, and one screencap takes seconds under TCG.
  "$ADB" shell "input tap $2 $3; for i in 1 2 3; do screencap -p /sdcard/vw-after-tap-\$i.png; done"
  for i in 1 2 3; do "$ADB" exec-out cat /sdcard/vw-after-tap-$i.png > "$LOG/send-2-after-tap-$i.png" || true; done
  "$ADB" shell rm -f /sdcard/vw-after-tap-1.png /sdcard/vw-after-tap-2.png /sdcard/vw-after-tap-3.png || true
  # The home screen's Recent list is the durable record of what happened
  # (cold start, so it re-reads the list).
  sleep 5
  "$ADB" shell am start -S -W -n "$PKG/.MainActivity" > /dev/null
  if ui_has "→ .*: \(prompted\|opened\)" 180; then
    grep -o 'text="[^"]*→[^"]*"' "$LOG/ui.xml" | head -3
    cp "$LOG/ui.xml" "$LOG/ui-recent.xml"
  else
    echo "FAIL: no prompted/opened entry in Recent"; fail=1
  fi
  c=$(crashed send); [ -z "$c" ] || { echo "FAIL: crash in logcat:"; echo "$c"; fail=1; }
  [ $fail = 0 ] && echo "SMOKE_SEND_PASS" || { echo "SMOKE_SEND_FAIL"; exit 1; }
}

instrumented() {
  cd android
  echo "sdk.dir=$ANDROID_HOME" > local.properties
  trap './gradlew --stop >/dev/null 2>&1 || true' EXIT
  "$ADB" uninstall "$PKG" >/dev/null 2>&1 || true
  "$ADB" uninstall "$PKG.test" >/dev/null 2>&1 || true
  ./gradlew --max-workers=2 --console=plain connectedDebugAndroidTest
  echo "SMOKE_INSTRUMENTED_PASS"
}

case "${1:-}" in
  boot) boot ;;
  apk) apk "${2:?apk path}" ;;
  send) send "${2:-}" ;;
  instrumented) instrumented ;;
  stop) "$ADB" emu kill || true ;;
  *) sed -n 2,16p "$0"; exit 2 ;;
esac
