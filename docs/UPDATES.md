# Updates (U1)

Voidwire checks for new versions itself. This page covers what the apps do,
the signed channel files, the keys, and the release steps.

## What the apps do

- **Checks are on by default** (Settings → Updates → Check for updates). A
  check is one HTTPS GET of a small signed file on GitHub Pages. No device id,
  no account, nothing about the user's devices is sent. The host learns the IP
  address, the time and the channel.
- **When:** at most once a UTC day, and only on an event: the desktop app
  starting, the Devices window opening, Android's `MainActivity.onStart`, or
  the user pressing **Check now**. There is no timer, no polling and no
  background job. The Android receive service never checks. Gate
  `update-checks-event-driven` (scripts/gates.sh) enforces this.
- **Turning checks off** deletes the stored check date and sequence numbers.
  "Not now" is kept in memory only, so the banner comes back after a restart.
- **A failed check** never retries on its own. With Diagnostics on, the
  desktop writes one line, `update check failed: <kind>` (network, signature,
  format, channel, rollback or unavailable). It never logs a URL or address.
- **Nothing installs without the user's say-so:**

| Platform | What happens |
|---|---|
| Windows (NSIS) | **Update** downloads and checks the installer; **Install now** runs it (Windows asks for permission) and restarts Voidwire. The opt-in **Install updates automatically** downloads in the background after a check and installs when you quit. |
| Linux AppImage | The new AppImage is downloaded next to the running one, checked, and swapped in. It is used after a restart (**Restart now**). |
| Linux deb, macOS | **Download** opens the release page in the browser. |
| Android | **Update** downloads and checks the APK, then hands it to Android's PackageInstaller. Android shows its own confirmation every time. Needs the "install unknown apps" permission (`REQUEST_INSTALL_PACKAGES`); the app explains and opens the setting. No notification is ever shown for updates. |

Every download is checked against the size and SHA-256 in the signed
manifest and checked again right before it is run. A file that doesn't match
is deleted.

## Channels

There are two channels, `stable` and `test`. Each install starts on the
channel of the build it came from: a version with a `-` (`0.9.8-m4.7`) is a
test build. **Settings → Updates → Test builds** switches. Switching from test
to stable never downgrades; the app waits until stable passes the installed
build.

- `test.json` always points at the newest release (stable releases included).
  It is signed in CI.
- `stable.json` points only at stable releases. It is signed offline. Until
  the first one is published, stable builds see "up to date".

## The files

```
https://voidwire-app.github.io/voidwire/update/v1/test.json     (+ test.json.sig)
https://voidwire-app.github.io/voidwire/update/v1/stable.json   (+ stable.json.sig)
```

```json
{ "schema": 1, "channel": "test", "seq": 1793611969, "version": "0.9.8-m4.7",
  "build": 34, "released": "2026-11-05",
  "notes_url": "https://github.com/voidwire-app/voidwire/releases/tag/v0.9.8-m4.7",
  "files": {
    "windows-x86_64-nsis":   { "url": "https://github.com/…/Voidwire_0.9.8-m4.7_x64-setup.exe", "sha256": "…", "size": 9876543 },
    "android-apk":           { "url": "…", "sha256": "…", "size": 0 },
    "linux-x86_64-appimage": { "url": "…", "sha256": "…", "size": 0 },
    "linux-x86_64-deb":      { "url": "…", "sha256": "…", "size": 0 } } }
```

- File names follow `Voidwire_<version>_<platform>` (`scripts/release_assets.py`):
  `_x64-setup.exe`, `_android.apk`, `_amd64.AppImage`, `_amd64.deb`, where
  `<version>` is the tag without the `v`. `scripts/update-manifest.py` takes
  the exact names from the same table, so a renamed file fails the release.
- `build` is the Android `versionCode` (android/app/build.gradle.kts), which
  every app is stamped with at build time. `seq` is the Unix time the
  manifest was written.
- The `.sig` file is one line:
  `voidwire-update-sig-v1 <key id, 16 hex> <Ed25519 signature, 128 hex>`.
  The signed bytes are `voidwire-update-v1\0` followed by the manifest file
  exactly as published. The key id is the first 8 bytes of SHA-256 of the
  public key.

A manifest is accepted only if all of these hold, in this order:

1. The signature verifies with a key pinned for that channel.
2. `schema` is 1 and `channel` is the channel asked for.
3. `seq` is at least the highest seen on that channel (anti-replay).
4. `build` is above the installed build. A downgrade is never offered.
5. File URLs are https on `github.com` or GitHub's release-asset hosts (also
   after redirects), the size is at most 200 MB, and `notes_url` is a page
   of this repository's releases.

A platform missing from `files` is "up to date".

## Keys

The apps pin a **list** of public keys per channel in
`core/src/update/keys.rs`:

- **test:** a CI key. Its private half exists only as the repository secret
  `VOIDWIRE_UPDATE_TEST_KEY` (it was generated straight into the secret and
  never written to disk). Public key id `0a42b9cf14c31878`.
- **stable:** the maintainer's offline key, kept off any server and backed up.
  CI never sees it. Public key id `30873e8d9e31b728` (pinned from 0.9.9).

A list makes changes possible without breaking installed apps:

- **Rotation:** release N adds the new public key to the list and is signed
  with the old key. Releases after that are signed with the new key; a later
  release drops the old one.
- **Moving stable signing into CI** later works the same way: add the CI
  key's public half to `STABLE_KEYS` in a release signed offline.
- **A lost or leaked key:** keep a second offline key (a backup) pinned next
  to the current one so a release signed by the backup can replace the list.
  If every pinned key is lost, users have to install the next version by hand.

## The signing tool, `voidwire-sign`

Every release carries `voidwire-sign-windows-x86_64.exe` and
`voidwire-sign-linux-x86_64`. To build it yourself (any OS with Rust):

```
cargo build --release -p voidwire-sign      # target/release/voidwire-sign(.exe)
```

```
voidwire-sign keygen [--out FILE]          new key, passphrase-protected (default voidwire-update.key)
voidwire-sign keygen --ci                  raw key on stdout, public line on stderr (pipe into a CI secret)
voidwire-sign pubkey FILE                  print the public key line of a key file
voidwire-sign sign (--key FILE | --key-env VAR) MANIFEST [--out SIG]
voidwire-sign verify (--channel test|stable | --pub LINE) MANIFEST [SIG]
```

The key file is encrypted with the passphrase (Argon2id, 64 MiB, 3 passes,
then XChaCha20-Poly1305). The passphrase needs at least 12 characters.
`keygen` never overwrites an existing file. `sign` prints the channel,
version, build and every file's size, hash and URL before asking for the
passphrase, so you can see what you are about to sign.

### One-time setup (stable key)

On your own computer, not a server:

```
voidwire-sign keygen --out voidwire-update.key
```

1. Enter a passphrase (twice). The tool prints one line,
   `voidwire-update-pub-v1 <64 hex>`.
2. Put that line in `STABLE_KEYS` in `core/src/update/keys.rs` and release
   it. Only builds that contain the line accept stable updates.
3. Back up `voidwire-update.key` and the passphrase somewhere separate
   (for example, an encrypted USB stick). Without both you cannot sign.
4. Optional: make a second key the same way as a backup and pin it too.

### Per stable release

The release workflow attaches `voidwire-update-stable.json` (unsigned) to
every stable `v*` release; it is also the `update-stable-unsigned` artifact
of the prerelease run.

1. Download `voidwire-update-stable.json` from the release page.
2. Optional: compare the hashes it lists with the release's `SHA256SUMS`.
3. Sign it:
   ```
   voidwire-sign sign --key voidwire-update.key voidwire-update-stable.json
   ```
   Read the summary, then enter the passphrase. This writes
   `voidwire-update-stable.json.sig`.
4. In GitHub, go to **Actions → publish-stable-update → Run workflow**.
   Enter the tag (`v1.2.3`) and paste the one line from the `.sig` file.

The workflow checks the signature against the stable keys pinned in the code
and that the manifest belongs to that tag. Only then does it publish
`stable.json` and its signature to Pages and attach the `.sig` to the
release. A bad signature publishes nothing.

Test releases need no manual step: the prerelease workflow writes, signs and
publishes `test.json` for every `v*` tag.

## Stored data

| Where | What | When |
|---|---|---|
| Desktop `settings.bin`, Android `phone-settings.bin` (both sealed) | Check for updates, Test builds, Install automatically (desktop) when changed from the default; the last check day (UTC date) and the highest `seq` per channel | Only while checks are on; turning checks off deletes them |
| Desktop `update/` in the app data folder; the AppImage's own folder (`.voidwire-update.AppImage`); Android `cache/update/` | The downloaded installer, AppImage or APK | Only between download and install; cleaned at the next start |
