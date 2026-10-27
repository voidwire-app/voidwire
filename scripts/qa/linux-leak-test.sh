#!/bin/bash
# Linux window leak test (QA d446e01 High). Rerunnable:
#   scripts/qa/linux-leak-test.sh <voidwire-desktop binary> <out dir> [cycles=10] [display=:74]
# Opens Paired devices, then N times: real WM close (alt+F4 -> CloseRequested)
# and reopen through show_window (second launch -> single-instance). Asserts:
#  - the window is not visible after each close and renders after each reopen
#  - the WebKit process count never grows after cycle 1
#  - total RSS of the app + WebKit processes grows < 40 MB from cycle 1 to N
#  - no page data on disk under the app's cache/data dirs (no-storage rule)
set -u
BIN=$1; OUT=$2; N=${3:-10}; DPY=${4:-:74}
rm -rf "$OUT"; mkdir -p "$OUT/home"
export DISPLAY=$DPY HOME=$OUT/home XDG_CONFIG_HOME=$OUT/home/.config XDG_DATA_HOME=$OUT/home/.local/share XDG_CACHE_HOME=$OUT/home/.cache
Xvfb "$DPY" -screen 0 1280x900x24 >"$OUT/xvfb.log" 2>&1 & XV=$!; sleep 1
eval "$(dbus-launch --sh-syntax)"
xfwm4 --compositor=off >"$OUT/wm.log" 2>&1 & WM=$!; sleep 2
FAIL=0; fail(){ echo "FAIL: $*" | tee -a "$OUT/verdict.txt"; FAIL=1; }
shot(){ ffmpeg -loglevel error -y -f x11grab -video_size 1280x900 -i "$DPY" -frames:v 1 "$1"; }
wk(){ pgrep -f -u "$(id -u)" 'WebKit(Web|Network)Process' | while read -r p; do
        [ "$(tr '\0' '\n' < /proc/$p/environ 2>/dev/null | grep -c "^HOME=$OUT/home$")" = 1 ] && echo "$p"; done; }
rss(){ local t=0; for p in $APP $(wk); do r=$(awk '/VmRSS/{print $2}' /proc/$p/status 2>/dev/null); t=$((t+${r:-0})); done; echo $((t/1024)); }
renders(){ python3 - "$1" <<'PY'
import sys
from PIL import Image
im=Image.open(sys.argv[1]).convert('RGB'); w,h=im.size
a=im.crop((w//2-200,h//2-250,w//2+200,h//2+250)); n=len(set(a.get_flattened_data() if hasattr(a,'get_flattened_data') else a.getdata()))
print(n); sys.exit(0 if n>300 else 1)
PY
}
VOIDWIRE_SHOW=devices "$BIN" > "$OUT/app.log" 2>&1 & APP=$!
for i in $(seq 1 40); do xdotool search --onlyvisible --name "Paired devices" >/dev/null 2>&1 && break; sleep 1; done; sleep 3
shot "$OUT/00-open.png"
echo "cycle,webkit_procs,rss_mb,visible_after_close,colours_after_reopen" > "$OUT/cycles.csv"
echo "start: webkit=$(wk | wc -l) rss=$(rss)MB" | tee "$OUT/log.txt"
for n in $(seq 1 "$N"); do
  W=$(xdotool search --onlyvisible --name "Paired devices" | head -1)
  xdotool windowactivate --sync "$W" key --clearmodifiers alt+F4; sleep 2
  vis=$(xdotool search --onlyvisible --name "Paired devices" 2>/dev/null | wc -l)
  [ "$vis" = 0 ] || fail "cycle $n: window still visible after close"
  kill -0 $APP || { fail "app exited on close"; break; }
  "$BIN" > "$OUT/second$n.log" 2>&1
  for i in $(seq 1 20); do xdotool search --onlyvisible --name "Paired devices" >/dev/null 2>&1 && break; sleep 1; done; sleep 3
  shot "$OUT/$(printf %02d $n)-reopened.png"
  col=$(renders "$OUT/$(printf %02d $n)-reopened.png") || fail "cycle $n: reopen blank (colours=$col)"
  c=$(wk | wc -l); r=$(rss)
  echo "$n,$c,$r,$vis,$col" >> "$OUT/cycles.csv"
  echo "cycle $n: webkit=$c rss=${r}MB colours=$col" | tee -a "$OUT/log.txt"
  ps -o pid,rss,args -p "$APP $(wk | tr '\n' ' ')" > "$OUT/ps-$n.txt" 2>/dev/null
done
python3 - "$OUT/cycles.csv" >> "$OUT/verdict.txt" <<'PY'
import csv,sys
r=list(csv.DictReader(open(sys.argv[1])))
if not r: print("FAIL: no cycles"); sys.exit()
c=[int(x['webkit_procs']) for x in r]; m=[int(x['rss_mb']) for x in r]
print(f"webkit procs per cycle: {c}"); print(f"rss MB per cycle: {m}")
print("PASS: webkit count flat" if max(c)==c[0] else f"FAIL: webkit count grew {c[0]}->{max(c)}")
print("PASS: rss flat (<40 MB growth)" if m[-1]-m[0]<40 else f"FAIL: rss grew {m[-1]-m[0]} MB")
PY
find "$OUT/home" -type f \( -path '*webview*' -o -iname '*localstorage*' -o -iname '*indexeddb*' -o -iname '*cookies*' \) > "$OUT/disk-webview-files.txt"
kill $APP; sleep 2
find "$OUT/home" -type f -path '*webview*' > "$OUT/disk-after-quit.txt"
# SIGTERM skips the app's exit cleanup (tray Quit removes the dir; QA item 5),
# so only the keyed context's empty skeleton may remain: salts + an empty HSTS db.
grep -vE '/webview/[a-z]+/((mediakeys/v1|WebKitCache/Version [0-9]+|storage)/salt|hsts-storage\.sqlite)$' "$OUT/disk-after-quit.txt" > "$OUT/disk-unexpected.txt"
[ -s "$OUT/disk-unexpected.txt" ] && fail "webview data beyond the skeleton: $(head -3 "$OUT/disk-unexpected.txt")"
for db in $(grep 'hsts-storage.sqlite$' "$OUT/disk-after-quit.txt" | tr ' ' '?'); do
  n=$(python3 -c "import sqlite3,sys,glob;c=sqlite3.connect(glob.glob(sys.argv[1])[0]);print(sum(c.execute(f'select count(*) from \"{t}\"').fetchone()[0] for (t,) in c.execute(\"select name from sqlite_master where type='table'\")))" "$db")
  [ "$n" = 0 ] || fail "HSTS db not empty ($n rows): $db"
done
echo "skeleton dirs (one per label, not per open): $(ls "$OUT/home/.cache/app.voidwire.desktop/webview" 2>/dev/null | tr '\n' ' ')" | tee -a "$OUT/verdict.txt"
[ "$(ls "$OUT/home/.cache/app.voidwire.desktop/webview" 2>/dev/null | wc -l)" -le 3 ] || fail "more than one context dir per label"
grep -qiE 'localstorage|indexeddb|cookies' "$OUT/disk-webview-files.txt" && fail "web storage on disk"
kill $WM $XV "$DBUS_SESSION_BUS_PID" 2>/dev/null
grep -q FAIL "$OUT/verdict.txt" && FAIL=1
[ $FAIL = 0 ] && echo "VERDICT: PASS" | tee -a "$OUT/verdict.txt" || echo "VERDICT: FAIL" | tee -a "$OUT/verdict.txt"
exit $FAIL
