#!/usr/bin/env bash
# Security gates, run by CI (.github/workflows/ci.yml `gates` job) and locally.
#
#   scripts/gates.sh                 source + build gates
#   scripts/gates.sh --source-only   greps and banned crates only (fast)
#   scripts/gates.sh --artifacts     only scan dist/ (unpacked: APK, deb, NSIS
#                                    payload via 7z, AppImage squashfs) for
#                                    test-harness markers
#
# D3: every gate FAILS CLOSED. A gate that expects a build to be refused only
# passes when cargo fails with that gate's specific compile_error text; any
# other failure (network, lockfile, toolchain, a different compile error)
# fails the gate. A positive control proves the toolchain works.
# D4: the clock and shell greps cover aliases, imports, `.elapsed()`, absolute
# shell paths and Windows launchers; clippy `disallowed-methods` backstops both.
set -uo pipefail
cd "$(dirname "$0")/.."
fails=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1: $2"; fails=$((fails + 1)); }

# Code lines only (drop //, //!, /// and block-comment continuation lines).
code_grep() { # <regex> <paths...>
  local re=$1; shift
  rg -n --no-heading -e "$re" "$@" 2>/dev/null | rg -v '^[^:]+:[0-9]+:\s*(//|\*|/\*)' || true
}

# expect_refused <gate> <required compile_error text> <cmd...>
expect_refused() {
  local gate=$1 needle=$2; shift 2
  local out rc
  out=$("$@" 2>&1); rc=$?
  if [ $rc -eq 0 ]; then
    fail "$gate" "build succeeded but must be refused"
  elif grep -qF -- "$needle" <<<"$out"; then
    pass "$gate"
  else
    fail "$gate" "cargo failed for a different reason (fail closed); last lines:"
    tail -15 <<<"$out" | sed 's/^/      /'
  fi
}

mode=${1:-all}
if [ "$mode" != "--artifacts" ]; then
# ---------------------------------------------------------------------------
# 1. Banned crates (`open`, opener/shell plugins) absent from the resolve for
#    every target and feature combination. cargo metadata failure = FAIL.
if meta=$(cargo metadata --format-version 1 --all-features --locked 2>/dev/null); then
  banned=$(python3 -c '
import json,sys
m=json.load(sys.stdin)
bad={"open","tauri-plugin-opener","tauri-plugin-shell"}
print(" ".join(sorted({p["name"] for p in m["packages"] if p["name"] in bad})))' <<<"$meta")
  if [ $? -ne 0 ]; then fail banned-crates "could not parse cargo metadata"
  elif [ -n "$banned" ]; then fail banned-crates "found: $banned"
  else pass banned-crates; fi
else
  fail banned-crates "cargo metadata failed (fail closed)"
fi

# 2. Clock reads only in core/src/time.rs (H-2). Any SystemTime/Instant/
#    UNIX_EPOCH mention (covers `use ... as Alias` imports), any `std::time::`
#    path other than Duration, any `::now(` and any `.elapsed(` call.
clock_re='\b(SystemTime|Instant|UNIX_EPOCH)\b|std::time::(\*|\{|[a-zA-Z_]+\b)|::now\s*\(|\.elapsed\s*\(|\b(chrono|time)::(Utc|Local|OffsetDateTime)|\bclock_gettime\b|\bgettimeofday\b|GetSystemTime'
hits=$(code_grep "$clock_re" core/src core/tests desktop/src mailbox/src push-gw/src --glob '!core/src/time.rs' \
  | rg -v 'std::time::Duration\b' | rg -v '\bSystemClock\b' || true)
if [ -n "$hits" ]; then fail clock-reads "clock access outside core/src/time.rs:"; echo "$hits" | sed 's/^/      /'
else pass clock-reads; fi

# 3. No shell / launcher in Rust code; process spawning only in opener.rs (URL-11).
shell_re='(?i)"(/usr)?(/bin/)?(sh|bash|zsh|dash|ksh|csh|fish)"|(?i)\b(sh|bash|zsh)\s+-c\b|(?i)\bcmd(\.exe)?\s*/[ck]\b|(?i)\b(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|explorer|conhost|wt)\.exe\b|(?i)"(cmd|powershell|pwsh|explorer|start)"|(?i)system32[\\/]+cmd'
hits=$(code_grep "$shell_re" -P --type rust core desktop mailbox push-gw tools || true)
if [ -n "$hits" ]; then fail shell-launchers "shell/launcher string in Rust code:"; echo "$hits" | sed 's/^/      /'
else pass shell-launchers; fi
spawn_re='\bstd::process\b|\bCommand::new\b|\bprocess::Command\b|\b(execv|execvp|posix_spawn|libc::system)\b|\b(CreateProcess|ShellExecute|WinExec)\w*|xdg-open|/usr/bin/open|\bgio\s+open'
hits=$(code_grep "$spawn_re" --type rust core desktop mailbox push-gw tools --glob '!core/src/opener.rs' || true)
if [ -n "$hits" ]; then fail process-spawn "spawn/launcher outside core/src/opener.rs:"; echo "$hits" | sed 's/^/      /'
else pass process-spawn; fi
kt_re='Runtime\.getRuntime\(\)\.exec|\bProcessBuilder\b'
hits=$(code_grep "$kt_re" android/app/src --glob '!**/uniffi/**' || true)
if [ -n "$hits" ]; then fail android-spawn "process spawn in Android code:"; echo "$hits" | sed 's/^/      /'
else pass android-spawn; fi

if [ "$mode" = "--source-only" ]; then echo "gates: $fails failure(s)"; exit $((fails > 0)); fi

# 4. Release gates (ENV-16/17). Since M1 envelope encryption is implemented,
#    so the release profile is THE build: positive control = a release build of
#    core. The retired M0 `insecure-preview` feature must not come back, and the
#    encryption flag must be a literal `true` (the const assert refuses false).
if cargo check -q --release -p voidwire-core 2>/dev/null; then pass toolchain-control-release
else fail toolchain-control-release "release build of core does not compile; build gates below are meaningless"; fi
TU_MSG='the `test-util` feature is for tests only'
if grep -qE '^pub const ENCRYPTION_IMPLEMENTED: bool = true;' core/src/envelope.rs \
   && grep -qF 'assert!(' core/src/envelope.rs; then pass encryption-flag
else fail encryption-flag "ENCRYPTION_IMPLEMENTED is not a literal true guarded by a const assert"; fi
if cargo check -q -p voidwire-core --features insecure-preview 2>/dev/null; then
  fail preview-retired "the insecure-preview feature exists again"
else pass preview-retired; fi
hits=$(git grep -n -i -E 'insecure.preview|INSECURE PREVIEW' -- core desktop android/app/src scripts ':!scripts/gates.sh' || true)
if [ -n "$hits" ]; then fail preview-labels "preview labels/features left in shipping code:"; echo "$hits" | sed 's/^/      /'
else pass preview-labels; fi
# M1 networking and FFI features also build in release (what ships).
if cargo check -q --release -p voidwire-core --features ffi 2>/dev/null; then pass release-net-ffi
else fail release-net-ffi "release build of core with net+ffi does not compile"; fi
# Webview capabilities (AUTH-13, OQ-13): one file per window, only our own
# app commands (allow-<command>), never core/shell/opener/fs/http permissions.
caps_out=$(python3 - <<'PY'
import glob, json, sys
bad = []
files = sorted(glob.glob("desktop/capabilities/*.json"))
if not files: bad.append("no capability files")
for f in files:
    c = json.load(open(f))
    w = c.get("windows", [])
    if w in ([], ["*"]) or any("*" in x for x in w): bad.append(f"{f}: windows {w}")
    for p in c.get("permissions", []):
        pid = p if isinstance(p, str) else p.get("identifier", "")
        if ":" in pid or not pid.startswith("allow-"): bad.append(f"{f}: {pid}")
print("\n".join(bad))
PY
)
if [ -n "$caps_out" ]; then fail webview-capabilities "$caps_out"; else pass webview-capabilities; fi
# NSIS firewall rule (M1): Private profile only, removed on uninstall.
hook=desktop/installer-hooks.nsh
if grep -q 'NSIS_HOOK_POSTINSTALL' "$hook" && grep -q 'NSIS_HOOK_POSTUNINSTALL' "$hook" \
   && [ "$(grep -c 'firewall add rule' "$hook")" = 1 ] \
   && grep 'firewall add rule' "$hook" | grep -q 'profile=private' \
   && grep 'firewall add rule' "$hook" | grep -q 'remoteip=localsubnet' \
   && ! grep 'firewall add rule' "$hook" | grep -qiE 'profile=(any|public|domain)|,public|,domain' \
   && sed -n '/NSIS_HOOK_POSTUNINSTALL/,/macroend/p' "$hook" | grep -q 'firewall delete rule' \
   && grep -q '"installerHooks": "installer-hooks.nsh"' desktop/tauri.conf.json; then pass nsis-firewall-private
else fail nsis-firewall-private "installer firewall rule must be Private-only, local-subnet-only and removed on uninstall"; fi
# QA M1 / M3.1.1: the confirm prompt brings itself to the foreground, and
# primary actions are armed only after a >= 1 s delay so focus cannot trigger
# an accidental keystroke/click.
if rg -q 'const ARM_MS = [1-9][0-9]{3}' desktop/ui/confirm.js; then pass confirm-window-no-focus-steal
else fail confirm-window-no-focus-steal "confirm window primary actions must have a >=1 s arm delay"; fi

# Default open mode (REV-06 documented in THREAT-MODEL.md): no-prompt
# by default, with "Ask before opening" kept as a working setting. Checks the
# default, the fresh-state default, that confirm mode still exists and is
# handled, that deliver re-checks membership before it mints an approval, and
# that the desktop still offers the setting.
deliver_body=$(sed -n '/^pub fn deliver(/,/^}/p' core/src/opener.rs)
if rg -q -U '#\[default\]\s*OpenImmediately' core/src/opener.rs \
  && rg -q -U '^\s*ConfirmBeforeOpen,' core/src/opener.rs \
  && printf '%s' "$deliver_body" | rg -q 'OpenMode::ConfirmBeforeOpen => Ok\(Delivery::NeedsConfirmation' \
  && [ "$(printf '%s' "$deliver_body" | rg -n 'recheck\(inbox, &url\)\?' | cut -d: -f1)" -lt \
       "$(printf '%s' "$deliver_body" | rg -n 'OpenApproval \{' | cut -d: -f1)" ] \
  && rg -q 'Ok\(\(identity, receive, roster, Vec::new\(\), true, false, None\)\)' core/src/net/pc.rs \
  && rg -q 'Ask before opening' desktop/ui/devices.html \
  && rg -q 'settings_set_no_prompt", \{ on: !e\.target\.checked' desktop/ui/devices.js; then pass default-no-prompt-ask-setting
else fail default-no-prompt-ask-setting "default must be OpenImmediately (fresh state no_prompt=true), with ConfirmBeforeOpen ('Ask before opening') kept and deliver re-checking membership before minting"; fi
# M1.1 privacy rule: nothing logged or kept as history
# unless the user turns it on. Desktop: only diag.rs and node.rs write files,
# and the log path exists only while Diagnostics are on; the Theme setting
# (diag.rs) stores nothing for the default, System. Android: the only
# SharedPreferences users are the opt-in RecentSends and UiPrefs.kt (Theme:
# nothing for System; Remember last PC: opt-in, writes nothing while off);
# the only other file is the sealed state (StateStore.kt).
desk_writers=$(code_grep 'OpenOptions::new|fs::write\(|File::create\(' desktop/src | cut -d: -f1 | sort -u | tr '\n' ' ')
and_prefs=$(code_grep 'getSharedPreferences\(|openFileOutput|FileOutputStream|DataStore|RoomDatabase|SQLiteOpenHelper' android/app/src/main | cut -d: -f1 | sort -u | tr '\n' ' ')
if [ "$desk_writers" = "desktop/src/diag.rs desktop/src/node.rs " ] \
  && rg -q 'let Some\(path\) = crate::diag::log_path\(\) else' desktop/src/node.rs \
  && rg -q 'enabled\(\)\.then' desktop/src/diag.rs \
  && rg -q '"system" => match std::fs::remove_file' desktop/src/diag.rs \
  && [ "$and_prefs" = "android/app/src/main/java/app/voidwire/android/RecentSends.kt android/app/src/main/java/app/voidwire/android/UiPrefs.kt " ] \
  && rg -q 'if \(!enabled\(context\)\) return' android/app/src/main/java/app/voidwire/android/RecentSends.kt \
  && rg -q 'if \(enabled\(context\)\) prefs\(context\)\.edit\(\)\.putString\(KEY, id\)' android/app/src/main/java/app/voidwire/android/UiPrefs.kt \
  && rg -q 'LastPc\.enforce\(context\)' android/app/src/main/java/app/voidwire/android/Core.kt \
  && rg -q '\.incognito\(true\)' desktop/src/main.rs \
  && rg -q 'window\.vwClear' desktop/ui/devices.js \
  && rg -q 'pub const DEFAULT_LOG_LEVEL: &str = "off";' mailbox/src/lib.rs; then pass privacy-no-default-logs
else fail privacy-no-default-logs "file writers: desktop [$desk_writers] android [$and_prefs]; logs/history must be opt-in"; fi
# M1.2 privacy rule: no desktop open notifications
# (OS notification centers such as Windows Action Center wpndatabase.db log
# toast payloads to disk).
if ! [ -e desktop/src/notify.rs ] \
  && ! rg -q 'tauri[-_]plugin[-_]notification' desktop/Cargo.toml desktop/src/ \
  && ! rg -q 'settings_set_notify|notify_open|NOTIFY_OFF|Show a notice when a link opens' desktop/src/ desktop/ui/ desktop/build.rs desktop/capabilities/ \
  && ! rg -q 'open_notification' core/src/; then pass no-open-notice
else fail no-open-notice "desktop open-notice toast feature must stay removed (OS notification centers log payloads to disk)"; fi
# M1.1 NSIS: a running app is closed silently; uninstall removes all data by
# default (checkbox checked; /S too); upgrades keep it.
if grep -q 'NSIS_HOOK_PREINSTALL' "$hook" && grep -q 'NSIS_HOOK_PREUNINSTALL' "$hook" \
  && [ "$(grep -c 'insertmacro VW_KILL_APP' "$hook")" -ge 3 ] && grep -q 'taskkill /F /T /IM' "$hook" \
  && grep -q 'NSD_Check} \$VwRemoveDataBox' "$hook" \
  && grep -q 'RMDir /r "\$APPDATA\\\${BUNDLEID}"' "$hook" \
  && grep -q 'RMDir /r "\$LOCALAPPDATA\\\${BUNDLEID}"' "$hook" \
  && grep -q 'WTSQuerySessionInformationW' "$hook" && grep -q 'RMDir /r "\$VwUserAppData' "$hook" \
  && sed -n '/NSIS_HOOK_PREUNINSTALL/,/macroend/p' "$hook" | grep -q 'SESSION eq \$VwSession' \
  && sed -n '/Function un.VwDataLeave/,/FunctionEnd/p' "$hook" | grep -q 'SendMessage \$HWNDPARENT 0x408 2 0'; then pass nsis-kill-and-data-removal
else fail nsis-kill-and-data-removal "installer must kill the app silently (uninstall: the launching session only) and remove the launching user's %APPDATA%/%LOCALAPPDATA%\\<BUNDLEID> behind one data checkbox"; fi
# M1.1 design tokens: every generated file (CSS, Compose theme, bundled fonts)
# matches brand/voidwire/ui/tokens.json. Regenerate into a temp tree and diff.
tok_tmp=$(mktemp -d)
tok_files="brand/voidwire/ui/tokens.css brand/voidwire/ui/fonts.css brand/voidwire/ui/compose/Color.kt brand/voidwire/ui/compose/Type.kt brand/voidwire/ui/compose/Theme.kt desktop/ui/tokens.css desktop/ui/fonts.css desktop/ui/shapes.css extension/tokens.css extension/fonts.css extension/shapes.css brand/voidwire/ui/shapes.css android/app/src/main/java/app/voidwire/android/ui/theme/Color.kt android/app/src/main/java/app/voidwire/android/ui/theme/Type.kt android/app/src/main/java/app/voidwire/android/ui/theme/Theme.kt"
tok_bad=""
if python3 brand/voidwire/ui/build_tokens.py --root "$tok_tmp" >/dev/null; then
  for f in $tok_files $(cd "$tok_tmp" && ls desktop/ui/fonts/web/* extension/fonts/web/* extension/fonts/OFL-*.txt android/app/src/main/res/font/*); do
    cmp -s "$f" "$tok_tmp/$f" || tok_bad="$tok_bad $f"
  done
else tok_bad="build_tokens.py failed"; fi
rm -rf "$tok_tmp"
if [ -z "$tok_bad" ]; then pass design-tokens-in-sync
else fail design-tokens-in-sync "regenerate with python3 brand/voidwire/ui/build_tokens.py:$tok_bad"; fi
expect_refused test-util-release               "$TU_MSG" cargo check --release -p voidwire-core --features test-util
expect_refused test-util-release-debug-assert  "$TU_MSG" env CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true cargo check --release -p voidwire-core --features test-util
expect_refused test-util-shipping              "$TU_MSG" env VOIDWIRE_SHIPPING_BUILD=1 cargo check -p voidwire-core --features test-util

# M3.1 §5 M31-G1: Mobile notification privacy — VoidwireNotifications.kt must
# enforce VISIBILITY_PRIVATE, exact generic copy, and zero item parameters/extras.
notif_kt="android/app/src/main/java/app/voidwire/android/VoidwireNotifications.kt"
if [ -f "$notif_kt" ] \
   && rg -q 'VISIBILITY_PRIVATE' "$notif_kt" \
   && rg -q 'Voidwire — New item waiting \(tap to view\)' "$notif_kt" \
   && rg -q 'fun buildIncomingNotification\(context: Context\): Notification' "$notif_kt" \
   && rg -q 'fun notifyIncomingIfEnabled\(context: Context\): Boolean' "$notif_kt" \
   && ! rg -q 'fun (buildIncomingNotification|notifyIncoming)\w*\([^)]*String' "$notif_kt" \
   && ! rg -q 'putExtra\(' "$notif_kt"; then
  pass mobile-notification-privacy
else
  fail mobile-notification-privacy "VoidwireNotifications.kt must enforce VISIBILITY_PRIVATE, generic copy, and zero item parameters/extras"
fi

# M3.1 §5 M31-G6: Device inbox RAM-only — INBOX_PUT / INBOX_PULL / INBOX_ACK
# store envelopes in Zeroizing<Vec<u8>>, zeroize on removal, and never write to disk.
inbox_handlers=$(sed -n '/mb_frame::INBOX_PUT => {/,/_ => Self::status_reply(mb_status::MALFORMED)/p' mailbox/src/lib.rs)
if [ -n "$inbox_handlers" ] \
   && rg -q 'pub envelope: Zeroizing<Vec<u8>>' mailbox/src/lib.rs \
   && printf '%s\n' "$inbox_handlers" | rg -q 'removed\.envelope\.zeroize\(\)' \
   && ! printf '%s\n' "$inbox_handlers" | rg -q 'persist_mailbox|encode_disk|mbx_path|std::fs::|File::|OpenOptions'; then
  pass device-inbox-ram-only
else
  fail device-inbox-ram-only "mailbox INBOX_* handlers must keep envelopes in Zeroizing RAM only and never touch disk"
fi

# M3.2 AUTH-13: Local IPC pipe is send/status-only and restricted to current user.
if [ -f desktop/src/ipc.rs ]    && rg -q 'pub enum IpcRequest' desktop/src/ipc.rs    && ! rg -q 'UrlOpener|SystemOpener|opener::|\.deliver\(|\.decide\(' desktop/src/ipc.rs    && rg -q 'PIPE_REJECT_REMOTE_CLIENTS' desktop/os-theme/src/lib.rs    && rg -q 'D:P\(A;;GA;;;' desktop/os-theme/src/lib.rs    && rg -q '0o700' desktop/os-theme/src/lib.rs    && rg -q '0o600' desktop/os-theme/src/lib.rs; then
  pass auth-13-ipc-send-only
else
  fail auth-13-ipc-send-only "desktop/src/ipc.rs must be send/status-only (no opener access) with current-user pipe ACLs"
fi

# M3.2 Browser extension privacy & MV3 manifest invariants.
if python3 - << 'PYEXT'
import json
for mf in ["extension/manifest.json", "extension/manifest.firefox.json"]:
    with open(mf, "rb") as f:
        d = json.load(f)
    assert d.get("manifest_version") == 3
    assert d.get("permissions") == ["nativeMessaging", "contextMenus", "activeTab"]
    assert "host_permissions" not in d
    assert "content_scripts" not in d
    csp = d.get("content_security_policy", {}).get("extension_pages", "")
    assert "connect-src 'none'" in csp
PYEXT
then
  pass m32-extension-privacy
else
  fail m32-extension-privacy "extension manifests must be MV3 with only nativeMessaging/contextMenus/activeTab and connect-src 'none'"
fi

# M3.2.1: right-click menus send an explicit phone_id per paired phone (mock API test).
if node scripts/qa/extension-menus.test.js >/tmp/voidwire-ext-menus.log 2>&1; then pass m321-extension-menus
else fail m321-extension-menus "extension right-click submenus: see /tmp/voidwire-ext-menus.log"; fi

# M3.2.1: the popup uses only the desktop design tokens; chamfer on primary buttons, secondary rounded.
if python3 - << 'PYPOP'
import re
css = open("extension/popup.css").read()
html = open("extension/popup.html").read()
assert not re.search(r"#[0-9a-fA-F]{3,8}\b", css), "raw hex colour in popup.css"
for f in ("tokens.css", "fonts.css", "shapes.css", "popup.css"):
    assert f'href="{f}"' in html, f
for cls in re.findall(r'class="([^"]*\bbtn\b[^"]*)"', html):
    c = cls.split()
    if "btn-primary" in c:
        assert {"vw-cut", "vw-cut-frame"} <= set(c), cls
    else:
        assert not any(x.startswith("vw-cut") for x in c), cls
PYPOP
then pass m321-popup-design-tokens
else fail m321-popup-design-tokens "extension popup must use desktop tokens only (chamfer only primary buttons)"; fi

# 5. Compile-fail probes (AUTH-12/17): fail for exactly the expected reason.
if scripts/compile-fail-probes.sh >/tmp/voidwire-probes.log 2>&1; then pass compile-fail-probes
else fail compile-fail-probes "see below"; sed 's/^/      /' /tmp/voidwire-probes.log; fi

fi # end of source + build gates

# 6. (--artifacts) Shipped artifacts carry no test-harness code. N2: archives
#    are unpacked first (APK zip, deb, NSIS payload with 7z, AppImage squashfs
#    with unsquashfs), so compressed payloads are scanned too. A missing
#    unpacker or a failed unpack FAILS the gate (fail closed).
if [ "$mode" = "--artifacts" ]; then
  markers='SpyOpener|FakePeer|FakeClock|test-handshake|voidwire/test-key|voidwire/test-receive-key|seeded_rng|keypair_from_label|new_unchecked_for_tests|setFakePhone|fakePhone'
  shopt -s nullglob
  files=(dist/*)
  if [ ${#files[@]} -eq 0 ]; then fail artifacts "dist/ is empty"; fi
  for tool in 7z unsquashfs unzip dpkg-deb; do
    command -v $tool >/dev/null || fail "unpacker-$tool" "not installed (apt install p7zip-full squashfs-tools unzip dpkg)"
  done
  tmp=$(mktemp -d)
  for f in "${files[@]}"; do
    d="$tmp/$(basename "$f").x"; mkdir -p "$d"; ok=1
    case "$f" in
      *.apk|*.zip) unzip -q -o "$f" -d "$d" || ok=0 ;;
      *.deb) dpkg-deb -x "$f" "$d" || ok=0 ;;
      *.tar.gz) tar -xzf "$f" -C "$d" || ok=0 ;;
      *-setup.exe) 7z x -y -o"$d" "$f" >/dev/null || ok=0
                   [ -n "$(find "$d" -iname '*.exe' -not -iname 'uninstall*')" ] || ok=0 ;;
      *.AppImage) off=$(python3 scripts/appimage-offset.py "$f") \
                    && unsquashfs -q -f -d "$d/root" -o "$off" "$f" >/dev/null || ok=0
                  [ -d "$d/root/usr/bin" ] || ok=0 ;;
      *) cp "$f" "$d/" ;;
    esac
    if [ $ok -eq 0 ]; then fail "artifact $(basename "$f")" "could not unpack (fail closed)"; continue; fi
    n=$(find "$d" -type f | wc -l)
    if rg -a -q -uuu -e "$markers" "$d"; then fail "artifact $(basename "$f")" "test-harness marker found"
    else pass "artifact $(basename "$f") has no test-harness markers ($n files scanned unpacked)"; fi
  done
  rm -rf "$tmp"
fi

echo "gates: $fails failure(s)"
exit $((fails > 0))
