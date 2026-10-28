#!/usr/bin/env bash
# android-qa.yml, inside the KVM emulator step (GitHub runner ONLY; never run
# an emulator on the build box). One boot, in order:
#   1. the 4 Espresso tests (DeviceSmokeTest, Gradle connected run + reports)
#   2. the screenshot flow + UI checks (instrumented, fake phone via the
#      debug-only DebugSeams), S10 with the camera denied
#   3. adb checks: cold-start splash luma, data inventory, host-peer pairing,
#      no-prompt send, Forget from the notification, Forget on save failure
# Spec: QA's android-qa-spec.md (M1.1). Output: $OUT (uploaded as artifacts).
# HARD checks fail the job; KNOWN/REPORT checks are recorded in summary.txt only.
set -uo pipefail
cd "$(dirname "$0")/../.."
OUT=${OUT:-$PWD/qa-out}; mkdir -p "$OUT/shots" "$OUT/instr" "$OUT/splash" "$OUT/data"
APK=android/app/build/outputs/apk/debug/app-debug.apk
TAPK=android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
AAPT2=$(ls "$ANDROID_HOME"/build-tools/*/aapt2 | tail -1)
PKG=$("$AAPT2" dump packagename "$APK")
RUNNER=$PKG.test/androidx.test.runner.AndroidJUnitRunner
EXT=/sdcard/Android/data/$PKG/files/vw-shots
P=/tmp/vw-peer
SUM=$OUT/summary.txt; : > "$SUM"
hard=0
pass() { echo "PASS   $1" | tee -a "$SUM"; }
fail() { echo "FAIL   $1${2:+: $2}" | tee -a "$SUM"; hard=$((hard + 1)); }
note() { echo "REPORT $1" | tee -a "$SUM"; }
ok() { local n=$1; shift; if "$@"; then pass "$n"; else fail "$n"; fi; }

adb logcat -c || true
adb logcat -v time > "$OUT/logcat.txt" 2>&1 &
# Slow CI emulator: keep "Process system isn't responding" dialogs off the screenshots.
adb shell settings put global hide_error_dialogs 1 || true
LOGCAT=$!

# Host-side capture helper (spec 0): PNG for review, UI dump as the assertion source.
shot() { adb exec-out screencap -p > "$OUT/shots/$1.png"; adb exec-out uiautomator dump /dev/tty > "$OUT/shots/$1.xml" 2>/dev/null || true; }
runas() { adb shell run-as "$PKG" "$@"; }
inventory() { runas find . -type f -exec ls -l {} \\\; > "$OUT/data/$1.txt" 2>&1; }

# instr <Class[#method]> [extra -e args...]: one instrumented run; 0 when "OK (".
instr() {
  local cls=$1; shift
  local log="$OUT/instr/${cls//[#.]/_}.txt"
  adb shell am instrument -w -r "$@" -e class "app.voidwire.android.$cls" "$RUNNER" > "$log" 2>&1
  grep -q "^OK (" "$log" && return 0
  # Failure evidence (d446e01): the screen as the test left it. The in-test
  # FailShotRule (androidTest Qa.kt) also saves vw-shots/FAIL-<test>.png.
  mkdir -p "$OUT/shots/fail"
  adb exec-out screencap -p > "$OUT/shots/fail/${cls//[#.]/_}.png" 2>/dev/null
  adb exec-out uiautomator dump /dev/tty > "$OUT/shots/fail/${cls//[#.]/_}.xml" 2>/dev/null || true
  return 1
}

# ---------------------------------------------------------------- 1. Espresso
( cd android && ./gradlew --no-daemon connectedDebugAndroidTest \
    -Pandroid.testInstrumentationRunnerArguments.class=app.voidwire.android.DeviceSmokeTest ) \
  > "$OUT/instr/espresso-gradle.txt" 2>&1
ok "espresso: DeviceSmokeTest (4 tests)" test $? -eq 0

# Fresh install for everything below (Gradle uninstalled after its run). No -g:
# the camera stays ungranted for S10.
adb install -r "$APK" >/dev/null && adb install -r "$TAPK" >/dev/null || fail "install APKs"
inventory data-0-fresh
# D1 / E: a fresh install keeps no prefs.
ok "D1 fresh install: no shared_prefs" bash -c "! adb shell run-as $PKG ls shared_prefs 2>/dev/null | grep -q ."

# ------------------------------------------------- 1b. pair with the host PC FIRST
# (d446e01: pairing ran ~16 min after the Pair window opened, the code had
# expired, and every flow that needs a paired PC cascaded.) Fresh QR below.
PAIRED=0
if [ ! -f "$P/desktop.pid" ] || ! kill -0 "$(cat "$P/desktop.pid")" 2>/dev/null; then
  fail "host peer" "desktop app not running (see desktop.log)"
else
  # pair_attempt <tag> <link>: one PairViaPasteTest run, the code typed on the PC.
  pair_attempt() {
    local tag=$1 link=$2
    echo "$link" | cut -c1-60 > "$OUT/data/pair-link-head-$tag.txt"
    echo "$link" | grep -o '&a=[^&]*' > "$OUT/data/pair-link-addrs-$tag.txt" || true
    adb shell rm -f "$EXT/pair-code.txt"
    adb shell "am instrument -w -r -e pairLink '$link' -e class app.voidwire.android.PairViaPasteTest $RUNNER" \
      > "$OUT/instr/PairViaPasteTest-$tag.txt" 2>&1 &
    local pair=$! code=""
    for i in $(seq 1 60); do
      code=$(adb shell cat "$EXT/pair-code.txt" 2>/dev/null | tr -dc 0-9)
      [ ${#code} -eq 6 ] && break; sleep 2
    done
    if [ ${#code} -eq 6 ]; then
      local wid; wid=$(xdotool search --onlyvisible --name "Pair a phone" | tail -1)
      xdotool windowactivate --sync "$wid" || xdotool windowfocus --sync "$wid"
      xdotool type --delay 80 "$code"; sleep 0.5; xdotool key Return
    fi
    wait $pair
    cp "$OUT/instr/PairViaPasteTest-$tag.txt" "$OUT/instr/PairViaPasteTest.txt"
    grep -q "^OK (" "$OUT/instr/PairViaPasteTest-$tag.txt"
  }
  # fresh_link <tag> [old]: decode the Pair window's QR right before use. A
  # code older than 10 min shows "Pairing paused" with "Show a new code"
  # autofocused (d446e01 harness defect 1): Return on the window gets a new
  # one. A single-use code already tried ([old]) is not reused.
  fresh_link() {
    local l="" i wid
    for i in $(seq 1 20); do
      import -display :99 -window root "$OUT/shots/host-pair-window-$1.png"
      l=$(zbarimg -q --raw "$OUT/shots/host-pair-window-$1.png" | head -1)
      [ -n "$l" ] && [ "$l" != "${2:-}" ] && break
      # Re-open/reset "Pair a phone" via the single-instance IPC (VOIDWIRE_SHOW=pair)
      # so if the host window already transitioned to "Paired" (where Return clicks "Done"
      # and closes the window), it cleanly starts a fresh pairing invite with a new QR!
      VOIDWIRE_DATA_DIR="$P/data" VOIDWIRE_SHOW=pair target/debug/voidwire-desktop >/dev/null 2>&1 || true
      wid=$(xdotool search --onlyvisible --name "Pair a phone" | tail -1)
      [ -n "$wid" ] && xdotool windowactivate --sync "$wid" || true
      sleep 3
    done
    echo "$l"
  }
  LINK=$(fresh_link direct)
  [ -n "$LINK" ] || fail "pair QR" "no QR decoded from the host Pair window"
  ss -lunp > "$OUT/data/host-udp-listeners.txt" 2>&1 || true
  if pair_attempt direct "$LINK"; then
    note "pairing: direct runner addresses worked"
  else
    # Fallback (760bad2 QA): the emulator's slirp can't always reach the
    # runner's own addresses. 10.0.2.2 is the host's loopback as seen from
    # the emulator; the desktop binds 0.0.0.0:48484 (PREFERRED_PORT), so a
    # fixed-port hint there reaches it. If 48484 was taken (random port),
    # socat relays 127.0.0.1:48484/udp to the real port.
    # The app's pairing port: 48484 when it holds it; never mDNS 5353
    # (d446e01 harness defect 2).
    PORTS=$(ss -lunp 2>/dev/null | grep voidwire | grep -oE '(0\.0\.0\.0|\*|\[::\]):[0-9]+' | cut -d: -f2- | grep -oE '[0-9]+$' | grep -vx 5353 | sort -u)
    echo "$PORTS" > "$OUT/data/host-app-udp-ports.txt"
    if echo "$PORTS" | grep -qx 48484; then REAL=48484; else REAL=$(echo "$PORTS" | head -1); fi
    if [ -n "$REAL" ] && [ "$REAL" != 48484 ]; then
      command -v socat >/dev/null || sudo apt-get install -y socat >/dev/null 2>&1
      socat UDP4-LISTEN:48484,bind=127.0.0.1,fork,reuseaddr UDP4:127.0.0.1:"$REAL" > "$P/socat.log" 2>&1 &
      note "pairing fallback: socat 127.0.0.1:48484 -> :$REAL"
    fi
    LINK2=$(fresh_link fallback "$LINK")
    LINK2=$(echo "$LINK2" | sed -E 's/&a=[^&]*//')'&a=10.0.2.2%3A48484'
    if pair_attempt fallback "$LINK2"; then note "pairing: fallback via 10.0.2.2:48484 worked"
    else fail "pairing fallback" "did not pair (see instr/PairViaPasteTest-fallback.txt, socat.log)"; fi
  fi
  if grep -q "^OK (" "$OUT/instr/PairViaPasteTest.txt"; then
    PAIRED=1; pass "pairing through the paste field with the host peer"
  else
    fail "pairing through the paste field with the host peer" "see instr/PairViaPasteTest.txt, $P/desktop.log"
  fi
fi

# ------------------------------------------------- 2. shots + UI checks
adb shell pm revoke "$PKG" android.permission.CAMERA 2>/dev/null || true
adb shell pm set-permission-flags "$PKG" android.permission.CAMERA user-fixed 2>/dev/null || true
ok "S10 scanner without camera (Use link disabled, helper, 'Pair a phone…')" instr ScannerNoCameraTest
adb shell pm clear-permission-flags "$PKG" android.permission.CAMERA user-fixed 2>/dev/null || true
adb shell pm grant "$PKG" android.permission.CAMERA

ok "S1-S8 screenshot flow, dark + light (+ wire strip at the bottom)" instr ScreenshotFlowTest
ok "S9 S11 S12 S13 extra shots + content checks" instr MoreShotsTest
ok "C1 bad-link corpus + oversize + IDN (ShareRefusalTest)" instr ShareRefusalTest
ok "D5 A-Z / LAST USED order (ShareOrderUiTest)" instr ShareOrderUiTest
ok "D1-D4 HISTORY chip + opt-in files (HistoryChipTest)" instr HistoryChipTest
ok "B4/B5 theme live switch, prefs, no stacked activity (ThemeSwitchTest)" instr ThemeSwitchTest

# >>> QA EXTRA ANDROID CHECKS GO HERE <<<
ok "Share sheet Pair with a PC + Back: one MainActivity (SharePairTaskTest)" instr SharePairTaskTest
ok "S1b 7 paired PCs: the list scrolls, strip stays pinned below (ManyPcsTest)" instr ManyPcsTest
# S15 timed series (0.5/1.5/3 s) is covered by ForgetSaveFailureTest's single
# assertion after the error (QA: "fine"); "Pair a phone…" is asserted in
# MoreShotsTest (S10/S11 pair instructions).
# Add `ok "<name>" instr <NewTestClass>` lines (tests in android/app/src/androidTest)
# or adb checks using shot/runas/inventory above. Keep them before the host-peer
# section: that one changes the phone's pairing state.

# ------------------------------------------------- 3a. cold-start splash (B1-B3)
# coldstart <name> <os night yes|no> <app theme system|dark|light> <dark|light>
# All HARD. 8 s recording; launcher frames (before the dark splash that
# follows the launch command) are excluded by luma, not by a focus poll.
coldstart() {
  local n=$1 night=$2 theme=$3 want=$4 d="$OUT/splash/$1"
  mkdir -p "$d"
  instr QaStateTest#setTheme -e theme "$theme" || fail "set theme $theme"
  adb shell cmd uimode night "$night"; sleep 2
  adb shell am force-stop "$PKG"; sleep 1
  # Diagnostics (8ee9a16): prove what night mode the system holds for us.
  { echo "## cmd uimode night"; adb shell cmd uimode night; echo "## dumpsys uimode"; adb shell dumpsys uimode; } > "$d/uimode.txt" 2>&1
  instr QaStateTest#nightMode >/dev/null 2>&1 || true
  adb logcat -d -s VoidwireQa:I 2>/dev/null | grep nightMode | tail -1 >> "$d/uimode.txt"
  adb shell am force-stop "$PKG"; sleep 1
  adb shell rm -f /sdcard/cold.mp4
  # 8 s recording; no focus polling (adb lag dropped every frame). The launch
  # time is measured from the recording start on the host instead.
  adb shell screenrecord --time-limit 8 --bit-rate 4000000 /sdcard/cold.mp4 &
  local rec=$! t0 tl; t0=$(date +%s%N)
  sleep 1
  tl=$(( ($(date +%s%N) - t0) / 1000000 ))
  adb shell am start -W -n "$PKG/.MainActivity" > "$d/am-start.txt" 2>&1
  wait $rec; sleep 1
  adb pull /sdcard/cold.mp4 "$d/cold.mp4" >/dev/null 2>&1
  [ -s "$d/cold.mp4" ] || { fail "$n" "no screen recording"; return; }
  ffmpeg -i "$d/cold.mp4" -vf "showinfo,signalstats,metadata=print:key=lavfi.signalstats.YAVG" -f null - 2>&1 \
    | awk '/pts_time:/{match($0,/pts_time:[0-9.]+/);t=substr($0,RSTART+9,RLENGTH-9)} /YAVG=/{split($0,a,"=");print t, a[2]}' > "$d/luma.txt"
  # Splash follows the OS theme (accepted M1.1 ruling, f71a65c): launcher is
  # ~76-84 luma, dark splash/content is < 60, light splash/content is >= 120.
  # First frame outside the launcher band (< 60 or >= 120) is the splash.
  awk -v t="$tl" '$1*1000 >= t-200' "$d/luma.txt" > "$d/luma-after.txt"
  local ts; ts=$(awk '$2 < 60 || $2 >= 120{print $1; exit}' "$d/luma-after.txt")
  if [ -z "$ts" ]; then fail "$n" "no splash/app frame after launch (luma-after.txt)"; return; fi
  awk -v t="$ts" '$1 >= t' "$d/luma-after.txt" > "$d/luma-app.txt"
  ffmpeg -v error -ss "$ts" -i "$d/cold.mp4" -vframes 1 "$d/frame-splash.png"
  ffmpeg -v error -sseof -0.3 -i "$d/cold.mp4" -vframes 1 "$d/frame-last.png"
  local nf max last lmin dmax
  nf=$(wc -l < "$d/luma-app.txt")
  max=$(cut -d' ' -f2 "$d/luma-app.txt" | sort -g | tail -1)
  last=$(tail -1 "$d/luma-app.txt" | cut -d' ' -f2)
  lmin=$(awk '$2 >= 120{on=1} on{print $2}' "$d/luma-app.txt" | sort -g | head -1)
  dmax=$(awk '$2 < 60{on=1} on{print $2}' "$d/luma-app.txt" | sort -g | tail -1)
  local msg="$n: splash at ${ts}s (launch ${tl}ms) frames=$nf max=$max last=$last darkmax=${dmax:-none} lightmin=${lmin:-none} ($(grep TotalTime "$d/am-start.txt" | tr -d '\r'))"
  if [ "$nf" -lt 3 ]; then fail "$msg" "too few app frames"
  elif [ "$want" = dark ] && [ "$night" = yes ]; then
    if awk -v m="$max" 'BEGIN{exit !(m < 60)}'; then pass "$msg (dark splash + all app frames dark < 60)"
    else fail "$msg" "a light frame after the splash (>= 60)"; fi
  elif [ "$want" = dark ]; then
    if [ -n "$dmax" ] && awk -v m="$dmax" -v l="$last" 'BEGIN{exit !(m < 60 && l < 60)}'; then pass "$msg (OS-light splash, then dark content stays < 60)"
    else fail "$msg" "dark content never settled, or a light frame after it"; fi
  else
    if [ -n "$lmin" ] && awk -v m="$lmin" -v l="$last" 'BEGIN{exit !(m >= 120 && l >= 120)}'; then pass "$msg (dark splash, then light content stays >= 120)"
    else fail "$msg" "light content never settled, or a dark frame after it"; fi
  fi
}

# B1/B2/B3: splash follows the OS theme; the content after it follows the in-app theme.
coldstart B1-osdark-appsystem yes system dark
coldstart B2-oslight-appdark no dark dark
coldstart B3-osdark-applight yes light light
instr QaStateTest#setTheme -e theme system; adb shell cmd uimode night yes

# ------------------------------------------------- 3b. host PC peer (item 7, C/D/E/F)
if [ "$PAIRED" != 1 ]; then
  note "C2/C3/D2/D3/S14/F skipped: no pairing (see section 1b)"
else
  if true; then
    pass "pairing through the paste field with the host peer"
    PCNAME=$(hostname)
    instr QaStateTest#optIns -e on true
    # C2 no-prompt send: exact URL opened within 5 s (open-notice toast removed in M1.2).
    U1='https://example.com/p?q=1#frag'
    n0=$(wc -l < "$P/opened.log")
    ok "C2 ShareE2eTest.sendsToHostPeer" instr ShareE2eTest#sendsToHostPeer -e url "$U1"
    sleep 5
    ok "C2 opened.log has the exact URL" grep -qF "OPENED argc=1 $U1" "$P/opened.log"
    ok "C2 no confirm window" bash -c "! xdotool search --onlyvisible --name 'Open link' >/dev/null"
    instr ShareE2eTest#sendsToHostPeer -e url 'https://example.org/m11/second?q=private' || fail "second send"
    inventory data-1-on
    runas cat shared_prefs/share.xml > "$OUT/data/share.xml" 2>&1
    runas cat shared_prefs/recent_sends.xml > "$OUT/data/recent_sends.xml" 2>&1
    ok "D2 share.xml: remember on + last_pc" bash -c "grep -q remember '$OUT/data/share.xml' && grep -q last_pc '$OUT/data/share.xml'"
    ok "D3 recent_sends.xml: host only, no path/query" \
      bash -c "grep -q 'example.org →' '$OUT/data/recent_sends.xml' && ! grep -qE 'private|/m11|q=' '$OUT/data/recent_sends.xml'"
    # C3 Forget from the PC Paired devices window.
    n1=$(wc -l < "$P/opened.log")
    pwid=$(xdotool search --onlyvisible --name "Pair a phone" | tail -1 || true)
    [ -n "$pwid" ] && xdotool windowactivate --sync "$pwid" key --clearmodifiers alt+F4 || true
    sleep 1
    VOIDWIRE_DATA_DIR="$P/data" target/debug/voidwire-desktop >/dev/null 2>&1 || true
    sleep 2
    dwid=$(xdotool search --onlyvisible --name "Paired devices" | tail -1 || true)
    if [ -n "$dwid" ]; then
      xdotool windowactivate --sync "$dwid" || xdotool windowfocus --sync "$dwid" || true
      xdotool mousemove --window "$dwid" 60 28 click 1
      sleep 0.3
      xdotool key --delay 120 Tab Tab Tab Tab Return
      sleep 0.5
      xdotool key Return
      for _ in $(seq 1 10); do
        grep -q "forgot " "$P/data/voidwire.log" 2>/dev/null && break
        sleep 0.5
      done
      if ! grep -q "forgot " "$P/data/voidwire.log" 2>/dev/null; then
        xdotool mousemove --window "$dwid" 415 117 click 1
        sleep 0.5
        xdotool click 1
        for _ in $(seq 1 10); do
          grep -q "forgot " "$P/data/voidwire.log" 2>/dev/null && break
          sleep 0.5
        done
      fi
    fi
    import -display :99 -window root "$OUT/shots/host-devices-after-forget.png" 2>/dev/null || true
    ok "C3 PC forgot the phone" grep -q "forgot " "$P/data/voidwire.log"
    ok "C3 share after the PC forgot: refused" instr ShareE2eTest#refusedAfterPcForgot
    ok "C3 opened.log unchanged" test "$(wc -l < "$P/opened.log")" -eq "$n1"
    ok "S14 main card shows Removed" instr ShareE2eTest#s14RemovedCard
    # F Forget on save failure (phone): no_backup read-only.
    runas chmod 500 no_backup
    if instr ForgetSaveFailureTest -e pcName "$PCNAME"; then pass "F card stays when the save fails"
    else fail "F card stays when the save fails" "phone forget rollback (core/src/net/phone.rs) not on this commit?"; fi
    runas chmod 700 no_backup
    adb shell am force-stop "$PKG"; adb shell am start -W -n "$PKG/.MainActivity" >/dev/null; sleep 6
    shot S15d-after-restart
    # HARD since 760bad2: the rolled-back PC must survive a restart.
    ok "F after restart: card present" grep -qF "$PCNAME" "$OUT/shots/S15d-after-restart.xml"
    grep -iE "AtomicFile|phone-state|EACCES|Permission denied" "$OUT/logcat.txt" | tail -20 > "$OUT/data/F-save-errors.txt" || true
  fi
fi

# ------------------------------------------------- 3c. E: data after all opt-ins off
instr QaStateTest#optIns -e on false; instr QaStateTest#setTheme -e theme system
mkdir -p "$OUT/shots/device"; adb pull "$EXT" "$OUT/shots/device" >/dev/null 2>&1
adb shell rm -rf "/sdcard/Android/data/$PKG"   # our own test output, before the check
adb shell am force-stop "$PKG"; adb shell am start -W -n "$PKG/.MainActivity" >/dev/null; sleep 8
shot E-main-all-off
ok "D4 chip says NO HISTORY with everything off" grep -q "NO HISTORY" "$OUT/shots/E-main-all-off.xml"
inventory data-2-off
ok "E data-2-off holds only the allowed files" bash -c "
  awk '{print \$NF}' '$OUT/data/data-2-off.txt' | grep -vE '^\\./(no_backup/phone-state\\.bin|no_backup/seen-[0-9a-f]+\\.bin|files/profileInstalled|files/profileinstaller_.*|cache/jna.*|cache/oat_primary.*|code_cache/.*)$' | grep . && exit 1; exit 0"
ok "E no shared_prefs/*.xml" bash -c "! grep -q 'shared_prefs/' '$OUT/data/data-2-off.txt'"
ok "E phone-state.bin is 0600" grep -qE '^-rw------- .*no_backup/phone-state\.bin' "$OUT/data/data-2-off.txt"
ok "E nothing under /sdcard/Android/data/$PKG" bash -c "! adb shell ls /sdcard/Android/data/$PKG >/dev/null 2>&1"

# ------------------------------------------------- crashes
kill $LOGCAT 2>/dev/null; sleep 1
ok "logcat: no FATAL EXCEPTION / ANR in $PKG" bash -c "! (grep -A2 'FATAL EXCEPTION' '$OUT/logcat.txt' | grep -qF '$PKG') && ! grep -qF 'ANR in $PKG' '$OUT/logcat.txt'"
[ -d "$P" ] && cp "$P"/*.log "$P"/*.out "$OUT/" 2>/dev/null
echo "== $hard hard failure(s)" | tee -a "$SUM"
exit $(( hard > 0 ? 1 : 0 ))
