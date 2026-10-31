#!/usr/bin/env bash
# Build the signed Android release APK into dist/ (M1 test builds).
# Signing: a local dev key outside the repo, created on first run at
# ~/.voidwire/android-dev-release.jks (password in the .pass file next to it,
# both 0600). Override with VOIDWIRE_ANDROID_KEYSTORE(+_PASSWORD, KEY_ALIAS).
# Needs: ANDROID_HOME (SDK with NDK 27.2.12479018), JDK 17+, cargo-ndk,
# rustup targets aarch64-linux-android armv7-linux-androideabi x86_64-linux-android.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/branding.sh
export ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/27.2.12479018}"

# 1. Host build of the core with the FFI scaffolding (for bindgen + JVM unit tests).
# VOIDWIRE_SHIPPING_BUILD=1 refuses the test harness in anything we ship.
export VOIDWIRE_SHIPPING_BUILD=1
cargo build -p voidwire-core --features ffi
target_dir=$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
export VOIDWIRE_CORE_LIB_DIR="$target_dir/debug"

# 2. Kotlin bindings from the compiled library's metadata (library mode).
rm -rf android/app/src/main/java/uniffi
cargo run -q -p uniffi-bindgen -- generate --library "$VOIDWIRE_CORE_LIB_DIR/libvoidwire_core.so" \
  --language kotlin --out-dir android/app/src/main/java --no-format

# 3. Guard: nothing that can open a URL crosses the FFI (AUTH-12).
# (comment lines are ignored; only code may not mention these types)
if grep -rhvE '^\s*(\*|//|/\*)' android/app/src/main/java/uniffi \
    | grep -qE "\b(VerifiedUrl|Inbox|UrlOpener|SystemOpener|OpenApproval|PendingOpen|RejectReason)\b"; then
  echo "FATAL: verify/opener types leaked into the UniFFI bindings" >&2
  exit 1
fi

# 4. Core .so for each ABI (release profile, stripped by the NDK packager).
#    C1: the Android library unwinds instead of aborting. UniFFI catches a Rust
#    panic at the FFI boundary and raises it in Kotlin as an exception, and
#    iroh's/netdev's catch_unwind around ndk_context works as designed. The
#    desktop keeps panic = "abort" (workspace [profile.release]).
CARGO_PROFILE_RELEASE_PANIC=unwind cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o android/app/src/main/jniLibs \
  build --release -p voidwire-core --features ffi
# cargo-ndk copies every .so in the target dir; iroh's crates also emit
# cdylibs nobody loads. Ship only our core (JNA's libjnidispatch comes from Gradle).
find android/app/src/main/jniLibs -name '*.so' ! -name 'libvoidwire_core.so' -delete

# 5. Third-party notices (D8) and the Android license gate (D12): Gradle
#    report first, then the combined THIRD-PARTY-LICENSES.txt for the APK.
cd android
echo "sdk.dir=$ANDROID_HOME" > local.properties
./gradlew --no-daemon -q generateLicenseReport
cd ..
scripts/check-android-licenses.py android/app/build/reports/dependency-license/licenses.csv
scripts/gen-third-party.py android build/licenses/android/THIRD-PARTY-LICENSES.txt

# 6. Signing key (never in the repo): use VOIDWIRE_ANDROID_KEYSTORE_BASE64 from
#    CI secrets when present, otherwise fall back to the local dev key.
cleanup_keystore=""
if [ -z "${VOIDWIRE_ANDROID_KEYSTORE:-}" ]; then
  keydir="$HOME/.voidwire"
  mkdir -p "$keydir" && chmod 700 "$keydir"
  if [ -n "${VOIDWIRE_ANDROID_KEYSTORE_BASE64:-}" ]; then
    export VOIDWIRE_ANDROID_KEYSTORE="$keydir/android-ci-release.jks"
    cleanup_keystore="$VOIDWIRE_ANDROID_KEYSTORE"
    trap 'rm -f "$cleanup_keystore"' EXIT
    (umask 077; printf '%s' "$VOIDWIRE_ANDROID_KEYSTORE_BASE64" | base64 -d > "$VOIDWIRE_ANDROID_KEYSTORE")
    chmod 600 "$VOIDWIRE_ANDROID_KEYSTORE"
    export VOIDWIRE_ANDROID_KEY_ALIAS="${VOIDWIRE_ANDROID_KEY_ALIAS:-voidwire-dev}"
  else
    export VOIDWIRE_ANDROID_KEYSTORE="$keydir/android-dev-release.jks"
    if [ ! -f "$VOIDWIRE_ANDROID_KEYSTORE" ]; then
      (umask 077; head -c 24 /dev/urandom | base64 | tr -d '/+=' > "$keydir/android-dev-release.pass")
      keytool -genkeypair -keystore "$VOIDWIRE_ANDROID_KEYSTORE" -storetype PKCS12 \
        -alias voidwire-dev -keyalg EC -groupname secp256r1 -validity 3650 \
        -dname "CN=${APP_NAME} dev release (not for store)" \
        -storepass "$(cat "$keydir/android-dev-release.pass")" >/dev/null
      chmod 600 "$VOIDWIRE_ANDROID_KEYSTORE"
    fi
    export VOIDWIRE_ANDROID_KEYSTORE_PASSWORD="$(cat "$keydir/android-dev-release.pass")"
  fi
fi

# 7. APK + JVM unit tests (bindings exercised against the host .so), and the
# instrumented tests compiled (not run: no emulator here), so a broken
# androidTest source fails ci instead of the first android-qa build.
cd android
./gradlew --no-daemon -q assembleRelease testDebugUnitTest compileDebugAndroidTestKotlin
cd ..
apk=android/app/build/outputs/apk/release/app-release.apk
"$ANDROID_HOME/build-tools/35.0.0/apksigner" verify --print-certs "$apk" | head -3
mkdir -p dist
rm -f dist/*-android-*.apk
cp "$apk" "dist/${APP_NAME,,}-android-m1.apk"
ls -la dist
