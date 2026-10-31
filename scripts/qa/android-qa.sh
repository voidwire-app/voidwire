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
    -Pandroid.testInstrumentationRunnerArguments.class=app.voidwire.android.DeviceSmokeTest,app.voidwire.android.UiThreadTest ) \
  > "$OUT/instr/espresso-gradle.txt" 2>&1
ok "espresso: DeviceSmokeTest (4 tests) + UiThreadTest (UI coroutines resume on main)" test $? -eq 0

# Fresh install for everything below (Gradle uninstalled after its run). No -g:
# the camera stays ungranted for S10.
adb install -r "$APK" >/dev/null && adb install -r "$TAPK" >/dev/null || fail "install APKs"
adb shell pm grant "$PKG" android.permission.POST_NOTIFICATIONS 2>/dev/null || true
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
  # pair_attempt <tag> <linkfn>: one PairViaPasteTest run, the code typed on
  # the PC. The app is opened first; only when it waits on the scanner
  # (link-wanted.txt) is the link taken from the Pair window (<linkfn>) and
  # handed over (pair-link.txt). A link decoded before the app's cold start
  # could be replaced by the PC's 110 s refresh before the phone's hello, and
  # a replaced code answers "already used" (QA 41014088827).
  # pair_watch <tag>: once a second, log (harness only, no codes or names)
  # what the PC's Pair window shows: a short hash of the QR, or none; whether
  # it is mapped; whether it is the active window. Shows when a code is
  # replaced or revoked during an attempt.
  pair_watch() {
    local f="$OUT/data/pair-watch-$1.txt" img="$P/watch.png" q wid map act last=""
    : > "$f"
    while :; do
      import -display :99 -window root "$img" 2>/dev/null
      q=$(zbarimg -q --raw "$img" 2>/dev/null | head -1)
      [ -n "$q" ] && q=$(printf %s "$q" | sha256sum | cut -c1-8) || q=none
      wid=$(xdotool search --name "Pair a device" 2>/dev/null | tail -1)
      map=$( [ -n "$wid" ] && xwininfo -id "$wid" 2>/dev/null | awk '/Map State/{print $3}' || echo gone)
      act=$( [ -n "$wid" ] && [ "$(xdotool getactivewindow 2>/dev/null)" = "$wid" ] && echo active || echo inactive)
      [ "$q $map $act" != "$last" ] && echo "$(date +%T.%N | cut -c1-12) qr=$q map=$map $act" >> "$f"
      last="$q $map $act"
      sleep 1
    done
  }
  # restart_pair <data dir> [bus]: restart that instance with its Pair window
  # open and press Return on the first screen ("This PC shows a code").
  # The pid and log live next to the data dir.
  restart_pair() {
    local d=$1 bus=${2:-} base pid w
    base=$(dirname "$1")
    pid=$(cat "$base/desktop.pid" 2>/dev/null) && kill "$pid" 2>/dev/null && sleep 2
    env ${bus:+DBUS_SESSION_BUS_ADDRESS="$bus"} VOIDWIRE_DATA_DIR="$d" VOIDWIRE_SHOW=pair VOIDWIRE_THEME=dark \
      nohup target/debug/voidwire-desktop >> "$base/desktop.log" 2>&1 &
    echo $! > "$base/desktop.pid"
    w=$(timeout 60 xdotool search --sync --onlyvisible --pid "$(cat "$base/desktop.pid")" --name "Pair a device" 2>/dev/null | tail -1)
    [ -n "$w" ] && { sleep 2; xdotool windowactivate --sync "$w" || true; xdotool key Return; sleep 3; }
    return 0
  }
  pair_attempt() {
    local tag=$1 linkfn=$2
    pair_watch "$tag" & local watch=$!
    adb shell rm -f "$EXT/pair-code.txt" "$EXT/pair-link.txt" "$EXT/link-wanted.txt"
    adb shell "am instrument -w -r -e pairLink @file -e class app.voidwire.android.PairViaPasteTest $RUNNER" \
      > "$OUT/instr/PairViaPasteTest-$tag.txt" 2>&1 &
    local pair=$! code="" link="" i
    for i in $(seq 1 90); do
      adb shell "[ -f $EXT/link-wanted.txt ]" 2>/dev/null && break; sleep 2
    done
    echo "$(date +%T.%N | cut -c1-12) phone ready for the link" >> "$OUT/data/pair-watch-$tag.txt"
    link=$($linkfn)
    LAST_LINK=$link
    echo "$(date +%T.%N | cut -c1-12) link handed over qr=$(printf %s "$link" | sed -E 's/&a=10\.0\.2\.2(%3A|:)48484$//' | sha256sum | cut -c1-8)" >> "$OUT/data/pair-watch-$tag.txt"
    echo "$link" | cut -c1-60 > "$OUT/data/pair-link-head-$tag.txt"
    echo "$link" | grep -o '&a=[^&]*' > "$OUT/data/pair-link-addrs-$tag.txt" || true
    adb shell "echo '$link' > $EXT/pair-link.tmp && mv $EXT/pair-link.tmp $EXT/pair-link.txt"
    for i in $(seq 1 60); do
      code=$(adb shell cat "$EXT/pair-code.txt" 2>/dev/null | tr -dc 0-9)
      [ ${#code} -eq 6 ] && break; sleep 2
    done
    if [ ${#code} -eq 6 ]; then
      # The PC's window is on "Check the code" with the 6-digit field focused.
      local wid; wid=$(xdotool search --onlyvisible --name "Pair a device" | tail -1)
      xdotool windowactivate --sync "$wid" || xdotool windowfocus --sync "$wid"
      xdotool type --delay 80 "$code"; sleep 0.5; xdotool key Return
    fi
    [ ${#code} -eq 6 ] && echo "$(date +%T.%N | cut -c1-12) code typed on the PC" >> "$OUT/data/pair-watch-$tag.txt"
    wait $pair
    kill $watch 2>/dev/null; wait $watch 2>/dev/null
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
      # No QR: open "Pair a device" again. A second launch can't do it (the
      # single-instance IPC forwards argv, not VOIDWIRE_SHOW, and opens Paired
      # devices: QA 41165267560), so the instance restarts with SHOW=pair.
      # PEER_DATA / PEER_BUS pick the instance (3b2: a second PC).
      restart_pair "${PEER_DATA:-$P/data}" "${PEER_BUS:-}"
    done
    # An expired code is replaced while the window is open. Use it only once
    # it is new (it changed) or has held for 24 s.
    local held=0 n
    while [ -n "$l" ] && [ $held -lt 24 ]; do
      sleep 2; held=$((held + 2))
      import -display :99 -window root "$OUT/shots/host-pair-window-$1.png"
      n=$(zbarimg -q --raw "$OUT/shots/host-pair-window-$1.png" | head -1)
      if [ -n "$n" ] && [ "$n" != "$l" ]; then l=$n; break; fi
    done
    echo "$l"
  }
  link_direct() { fresh_link direct; }
  link_fallback() {
    local l; l=$(fresh_link fallback "$LINK")
    [ -n "$l" ] && echo "$l" | sed -E 's/&a=[^&]*//' | sed 's/$/\&a=10.0.2.2%3A48484/'
  }
  ss -lunp > "$OUT/data/host-udp-listeners.txt" 2>&1 || true
  LAST_LINK=""
  if pair_attempt direct link_direct; then
    note "pairing: direct runner addresses worked"
  else
    LINK=$LAST_LINK
    [ -n "$LINK" ] || fail "pair QR" "no QR decoded from the host Pair window"
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
    if pair_attempt fallback link_fallback; then note "pairing: fallback via 10.0.2.2:48484 worked"
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
ok "S10 scanner without camera (Use link disabled, helper, 'Pair a device…')" instr ScannerNoCameraTest
adb shell pm clear-permission-flags "$PKG" android.permission.CAMERA user-fixed 2>/dev/null || true
adb shell pm grant "$PKG" android.permission.CAMERA

ok "S1-S8 screenshot flow, dark + light (+ wire strip at the bottom)" instr ScreenshotFlowTest
ok "S9 S11 S12 S13 extra shots + content checks" instr MoreShotsTest
ok "C1 bad-link corpus + oversize + IDN (ShareRefusalTest)" instr ShareRefusalTest
ok "D5 A-Z / LAST USED order (ShareOrderUiTest)" instr ShareOrderUiTest
ok "D1-D4 HISTORY chip + opt-in files (HistoryChipTest)" instr HistoryChipTest
ok "B4/B5 theme live switch, prefs, no stacked activity (ThemeSwitchTest)" instr ThemeSwitchTest

# >>> QA EXTRA ANDROID CHECKS GO HERE <<<
ok "Share sheet Pair a device + Back: one MainActivity (SharePairTaskTest)" instr SharePairTaskTest
ok "S1b 7 paired PCs: the list scrolls, strip stays pinned below (ManyPcsTest)" instr ManyPcsTest
ok "Pair a device: Show a code / Type a code on screen at 360x640 dp, text 1.0/1.3/2.0 (PairScreenFitTest)" instr PairScreenFitTest
ok "M4.4 relays: via <host>, ⋯ → Change relay asks, a request asks the user, Settings → Relays (RelaysUiTest)" instr RelaysUiTest
# S15 timed series (0.5/1.5/3 s) is covered by ForgetSaveFailureTest's single
# assertion after the error (QA: "fine"); "Pair a device…" is asserted in
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
  note "C2/C3/D2/D3/F skipped: no pairing (see section 1b)"
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
    # F Forget on save failure (phone): no_backup read-only. Runs before C3
    # since M4.2: the PC's unpair notice erases the phone's side (spec §6),
    # so after C3 there is no card left to forget. A failed save sends no
    # unpair notice, so the PC stays paired for C3.
    runas chmod 500 no_backup
    if instr ForgetSaveFailureTest -e pcName "$PCNAME"; then pass "F card stays when the save fails"
    else fail "F card stays when the save fails" "phone forget rollback (core/src/net/phone.rs) not on this commit?"; fi
    runas chmod 700 no_backup
    adb shell am force-stop "$PKG"; adb shell am start -W -n "$PKG/.MainActivity" >/dev/null; sleep 6
    shot S15d-after-restart
    # HARD since 760bad2: the rolled-back PC must survive a restart.
    ok "F after restart: card present" grep -qF "$PCNAME" "$OUT/shots/S15d-after-restart.xml"
    grep -iE "AtomicFile|phone-state|EACCES|Permission denied" "$OUT/logcat.txt" | tail -20 > "$OUT/data/F-save-errors.txt" || true
    # C3 Forget from the PC Paired devices window.
    n1=$(wc -l < "$P/opened.log")
    pwid=$(xdotool search --onlyvisible --name "Pair a device" | tail -1 || true)
    [ -n "$pwid" ] && xdotool windowactivate --sync "$pwid" key --clearmodifiers alt+F4 || true
    sleep 1
    VOIDWIRE_DATA_DIR="$P/data" target/debug/voidwire-desktop >/dev/null 2>&1 || true
    sleep 2
    dwid=$(xdotool search --onlyvisible --name "Paired devices" | tail -1 || true)
    if [ -n "$dwid" ]; then
      xdotool windowactivate --sync "$dwid" || xdotool windowfocus --sync "$dwid" || true
      xdotool mousemove --window "$dwid" 60 28 click 1
      sleep 0.3
      # Devices tab → Settings tab → the row's ⋯ menu → Forget.
      xdotool key --delay 120 Tab Tab Tab Return
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
    # M4.2: a v2 pairing's unpair notice erases the phone's side (spec §6),
    # replacing the M1 "refused" send and the S14 REMOVED card (legacy only).
    ok "C3 phone erased the PC after the unpair notice" instr ShareE2eTest#pcErasedAfterUnpairNotice -e pcName "$PCNAME"
    ok "C3 opened.log unchanged" test "$(wc -l < "$P/opened.log")" -eq "$n1"
  fi
fi

# ------------------------------------------------- 3b2. M4.5: two PCs in the share sheet
# The host peer forgot this phone in C3. Re-pair it, then pair a second
# desktop instance (own data dir, own D-Bus session so its single-instance
# name doesn't hand off to the first), and check the share sheet lists one
# "Send to" per PC. One Pair window on screen at a time: the QR is read off
# the root window. Pairing state only; nothing is sent.
close_pc_windows() {
  local w
  for w in $(xdotool search --onlyvisible --name "Paired devices" 2>/dev/null; xdotool search --onlyvisible --name "Pair a device" 2>/dev/null); do
    xdotool windowactivate --sync "$w" key --clearmodifiers alt+F4 2>/dev/null || true
  done
  sleep 1
}
if [ "$PAIRED" != 1 ]; then
  note "M4.5 two-PC share sheet skipped: no pairing (see section 1b)"
else
  close_pc_windows
  # A plain second launch opens Paired devices, not Pair a device (QA
  # 41165267560: no QR, re-pair failed), so the host app is restarted with
  # VOIDWIRE_SHOW=pair on the same data dir, as peer-start.sh started it.
  restart_pair "$P/data"
  PEER_DATA="$P/data"; PEER_BUS=""
  if pair_attempt pc1-again link_direct || { LINK=$LAST_LINK; pair_attempt pc1-again-fb link_fallback; }; then
    pass "M4.5 host PC paired again"
  else
    fail "M4.5 host PC paired again" "see instr/PairViaPasteTest-pc1-again*.txt"
  fi
  close_pc_windows
  P2=/tmp/vw-peer2; mkdir -p "$P2/data"; : > "$P2/data/diagnostics.on"
  PC2_BUS=$(dbus-launch --sh-syntax | sed -n "s/^DBUS_SESSION_BUS_ADDRESS='\(.*\)';\$/\1/p")
  DBUS_SESSION_BUS_ADDRESS="$PC2_BUS" VOIDWIRE_DATA_DIR="$P2/data" VOIDWIRE_SHOW=pair VOIDWIRE_THEME=dark \
    nohup target/debug/voidwire-desktop > "$P2/desktop.log" 2>&1 &
  echo $! > "$P2/desktop.pid"
  w2=$(timeout 120 xdotool search --sync --onlyvisible --pid "$(cat "$P2/desktop.pid")" --name "Pair a device" 2>/dev/null | tail -1)
  if [ -z "$w2" ]; then
    fail "M4.5 second PC started" "no Pair window (see $P2/desktop.log)"
  else
    pass "M4.5 second PC started (own data dir + D-Bus session)"
    sleep 2; xdotool windowactivate --sync "$w2" || true; xdotool key Return
    PEER_DATA="$P2/data"; PEER_BUS="$PC2_BUS"
    # Fallback port 48485 for the second PC (48484 is the first one's).
    link_fallback2() {
      local l; l=$(fresh_link fallback2 "$LINK")
      [ -n "$l" ] && echo "$l" | sed -E 's/&a=[^&]*//' | sed 's/$/\&a=10.0.2.2%3A48485/'
    }
    if pair_attempt pc2 link_direct; then pass "M4.5 second PC paired"
    else
      LINK=$LAST_LINK
      PID2=$(cat "$P2/desktop.pid")
      REAL2=$(ss -lunp 2>/dev/null | grep "pid=$PID2," | grep -oE ':[0-9]+ ' | tr -dc '0-9\n' | grep -vx 5353 | head -1)
      [ -n "$REAL2" ] && socat UDP4-LISTEN:48485,bind=127.0.0.1,fork,reuseaddr UDP4:127.0.0.1:"$REAL2" > "$P2/socat.log" 2>&1 &
      if pair_attempt pc2-fb link_fallback2; then pass "M4.5 second PC paired (fallback 10.0.2.2:48485)"
      else fail "M4.5 second PC paired" "see instr/PairViaPasteTest-pc2*.txt, $P2/desktop.log"; fi
    fi
    PEER_DATA="$P/data"; PEER_BUS=""
  fi
  ok "M4.5 share sheet: one Send to per paired PC, 2 PCs (ShareTwoPcsTest)" instr ShareTwoPcsTest -e pcs 2
  cp "$P2/desktop.log" "$OUT/data/desktop2.log" 2>/dev/null || true
  close_pc_windows
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
