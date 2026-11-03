# Voidwire

**Open-source, privacy-first, end-to-end encrypted link and file sharing between Android and Desktop (Windows, Linux and macOS; Linux and macOS in beta).**

Pair once by scanning a QR code and typing a 6-digit verification code—no accounts, no cloud sign-in, and no phone numbers. Share a link or file from your phone and it arrives on your PC over direct LAN QUIC first, or automatically over an untrusted encrypted relay when you are away from your home network.

---

## Key Capabilities (`v1.0.1`)

- **Accountless QR + SAS Pairing:** Pair devices using a single-use, short-lived QR code and a 6-digit Short Authentication String (SAS) bound to the TLS 1.3 handshake transcript and Ed25519/X25519 device certificates.
- **Pair Any Two Devices:** PC↔PC, phone↔phone or PC↔phone with a short typed code (`VW-…`) or a QR code, confirmed with a 6-digit code on both screens. The code is single-use, expires after 5 minutes (it can be copied on a PC: kept out of Windows clipboard history and cloud sync, and cleared when pairing ends), and its relay is bound into the pairing so it cannot be swapped.
- **Instant Link Sharing:** Share any `http`/`https` link from Android's system share sheet to your paired PC. Links open immediately in your default desktop browser by default, or wait in a focus-safe **"Open link?"** confirmation window when **Ask before opening** is enabled.
- **Bidirectional PC → Phone Sharing & Browser / OS Integrations:** Send links, clipboard text, or files from Desktop to your paired Android phone (with direct LAN QUIC first, blind RAM-only device inbox fallback for links/text when the phone is asleep, and a 256 KB relay confirmation threshold / 25 MB relay cap for larger items). Includes a MV3 browser extension for Chrome/Brave/Edge and Firefox (`extension/`) via Native Messaging (`voidwire --native-messaging-host`) and a per-user Windows File Explorer **"Send with Voidwire"** right-click context menu (`voidwire --send-file`).
- **Encrypted File, Photo & Clipboard Sharing:** Send files, photos, or clipboard text from Android to Desktop with end-to-end XChaCha20-Poly1305 chunked encryption (256 KiB chunks, BLAKE3 whole-file integrity verification), recipient approval on the receiving device (files also go PC↔PC and phone↔phone), partial downloads deleted when a transfer fails, is cancelled or times out, automatic chunk-level resume across Wi-Fi ↔ cellular network handoffs, and strict executable-file safeguards (saved to disk only, never auto-launched).
- **Direct LAN First + Untrusted Relay Fallback:** Connects directly over LAN QUIC (`iroh` + mDNS) whenever possible and falls back seamlessly to `https://relay.voidwire.app` across NATs or mobile data. The relay sees only QUIC/TLS ciphertext and padded envelopes.
- **Your Own Relays, Per Pairing:** Save up to 8 relays (the public relay is the default home; self-hosted ones are added with a `voidwire:relay?…` link or an HTTPS URL), with up to 4 in use at once. Each pairing has its own relay, shown on its device row, and moving a pairing to another relay needs both devices to agree; the change is signed by both. Phones keep only their home relay in the background and use other relays while the app is open or for a send you start. A relay that stays down is retried slowly and affects only the pairings on it.
- **Blind Pull-Based Revocation Mailbox (`voidwire-mailbox`):** Device removals propagate immediately over peer sync and through an append-only, epoch-keyed blind mailbox on the relay so offline devices learn revocations before accepting messages—without exposing group membership, device names, or plaintext operations to the relay.
- **Strict Privacy-First Defaults:**
  - Dark mode by default (unless the OS explicitly requests light mode, or overridden in Settings).
  - Zero telemetry and zero server logs (`RUST_LOG=off`).
  - Zero unrequested local history: recent sends, last-used PC ordering, completed file history, connection path statistics, and the local diagnostics log are all **opt-in and off by default**. Turning any opt-in off deletes its stored data immediately.
  - No desktop OS toast notifications (preventing OS notification centers such as Windows Action Center `wpndatabase.db` from logging opened hosts to disk).
- **Full Self-Hosting Support:** Run your own `iroh-relay` and `voidwire-mailbox` with Docker or plain binaries ([guide](docs/self-host-relay.md)), open to everyone or limited to devices that have your relay link, and add it in the apps with one `voidwire:relay?…` link.

---

## Install

Download from the [latest release](https://github.com/voidwire-app/voidwire/releases/latest) and check the file against `SHA256SUMS`:

| Platform | Download | Notes |
|---|---|---|
| Windows 10/11 (x64) | `Voidwire_<version>_x64-setup.exe` | Not code-signed, so SmartScreen may warn. Updates itself (signed updates). |
| Android 8.0+ | `Voidwire_<version>_android.apk` | Not on Google Play or F-Droid. Updates itself (signed updates). |
| Linux (beta), x86_64 | `Voidwire_<version>_amd64.deb` (Ubuntu 22.04+, Debian 12+) or `Voidwire_<version>_amd64.AppImage` | Beta: less tested than Windows and Android. Please report problems. |
| Browser extension | `Voidwire_<version>_extension-chromium.zip`, `Voidwire_<version>_extension-firefox.zip` | Needs the desktop app on the same PC. Loaded unpacked / as a temporary add-on. |
| macOS (beta), 13 Ventura or later, Apple silicon and Intel | `Voidwire_<version>_universal.dmg` | Beta, from the first release that has it. Not notarized by Apple: allow it once with **Open Anyway** (below). Menu bar app. "Update available" opens the release page. |
| iOS | — | Not available. |

### macOS: first launch

Voidwire isn't notarized by Apple (it is signed ad hoc, not with an Apple Developer ID), so macOS 13 and later block it the first time you open it. To allow it:

1. Check the `.dmg` against `SHA256SUMS` (`shasum -a 256 -c SHA256SUMS --ignore-missing`).
2. Open the `.dmg` and drag **Voidwire** to **Applications**. Run it from Applications: from anywhere else the browser extension can't find it.
3. Open Voidwire from Applications. macOS says it can't verify the app. Close the message; don't choose **Move to Trash**.
4. Open **System Settings** › **Privacy & Security** and scroll down to **Security**. Click **Open Anyway** next to the message about Voidwire. The button is there for about an hour after you tried to open the app.
5. Enter your login password. When the message comes back, click **Open**.

After that it opens normally from Applications. You may need to repeat this after downloading a new version. Apple describes the same steps in [Safely open apps on your Mac](https://support.apple.com/en-us/102445).

Voidwire has not been independently audited. See [SECURITY.md](SECURITY.md) to report a vulnerability.

---

## Repository Layout

| Path | Description |
|---|---|
| `core/` | `voidwire-core`: protocol types, HPKE envelope, signed wire format, verification pipeline (`Inbox::receive` → `VerifiedUrl`), chunked file transfer engine, opener, pairing, group log & blind mailbox client, rate limits, replay cache, URL policy, and UniFFI bindings (`ffi` feature) |
| `desktop/` | Tauri 2 desktop tray application (Windows, Linux, macOS menu bar) |
| `extension/` | MV3 WebExtension (Chromium & Firefox) bridging to the local desktop app over Native Messaging |
| `android/` | Kotlin + Jetpack Compose Android application consuming `voidwire-core` via UniFFI |
| `mailbox/` | `voidwire-mailbox`: blind relay daemon holding RAM-only per-device inboxes (nothing written to disk) and serving the signed relay configuration |
| `push-gw/` | Push gateway stub (`axum`, `/healthz`) reserved for M3 PC → phone push notifications |
| `ops/relay/` | Self-hosting files: Docker compose (`docker/`), systemd units, `relay.toml`, `mailbox.toml`, `nftables.conf` |
| `brand/voidwire/ui/` | Design system source of truth (`tokens.json`, `build_tokens.py`, `SPEC.md`, bundled OFL fonts) |
| `tools/` | `uniffi-bindgen` CLI wrapper and compile-fail security probes (`tools/probes/`) |
| `scripts/` | Build, license verification, and fail-closed security gate scripts (`gates.sh`, `build-desktop.sh`, `build-android.sh`) |
| `docs/` | Architecture and security documentation: [PROTOCOL.md](docs/PROTOCOL.md), [THREAT-MODEL.md](docs/THREAT-MODEL.md), [TEST-PLAN.md](docs/TEST-PLAN.md), [LICENSES-INVENTORY.md](docs/LICENSES-INVENTORY.md), [UPDATES.md](docs/UPDATES.md) |

---

## Security Architecture

Voidwire enforces a strict compile-time and runtime invariant for opening links:

> **The URL opener can only ever receive URLs from a message that has been authenticated as coming from a cryptographically paired device in the owner's device group.**

- `verify::Inbox::receive` is the sole constructor of `VerifiedUrl`, and only after verifying transport peer membership, HPKE decryption, strict Ed25519 signature (`verify_strict`), group and recipient binding, per-device and global rate limits, group-log head freshness, ±10-minute timestamp window, fsync'd replay cache (`seen.bin`), and RFC 3986 `http`/`https` URL canonicalization (rejecting loopback, link-local, unspecified hosts, userinfo, and control/bidi characters).
- `UrlOpener::open` consumes an unforgeable `OpenApproval` token by value, minted only by `opener::deliver` (in default no-prompt mode) or `PendingOpen::confirm` (when **Ask before opening** is enabled) after re-checking that the sender is still paired immediately before invoking the OS opener (`ShellExecuteW` on Windows, `/usr/bin/xdg-open` on Linux, `/usr/bin/open` on macOS—never via a shell or the `open` crate).
- Incoming files never pass through `UrlOpener::open`; they require recipient acceptance, stream to a `<uuid>.part` file with per-chunk AEAD authentication and final BLAKE3 verification, and are saved to the configured download folder (`Downloads/Voidwire` by default).

For full cryptographic and protocol details, see:
- [Protocol Specification (`docs/PROTOCOL.md`)](docs/PROTOCOL.md)
- [Threat Model & Data Inventory (`docs/THREAT-MODEL.md`)](docs/THREAT-MODEL.md)
- [Security & QA Test Plan (`docs/TEST-PLAN.md`)](docs/TEST-PLAN.md)
- [Third-Party License Inventory (`docs/LICENSES-INVENTORY.md`)](docs/LICENSES-INVENTORY.md)
- [Updates: channels, signing keys and release steps (`docs/UPDATES.md`)](docs/UPDATES.md)

---

## Building and Testing

```sh
# Format, lint, and dependency/license policy checks
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p voidwire-core --features ffi,system-opener --all-targets -- -D warnings
cargo deny check

# Run workspace and FFI test suites
cargo test --workspace
cargo test -p voidwire-core --features ffi

# Run all fail-closed security & privacy gates (24 gates + compile-fail probes)
scripts/gates.sh

# Build release artifacts
scripts/build-desktop.sh linux     # dist/: .deb, .AppImage, raw binary
scripts/build-desktop.sh windows   # dist/: NSIS installer + .exe (cross-compiled via cargo-xwin)
scripts/build-android.sh           # dist/: release APK + Android license gate + JVM unit tests
scripts/gates.sh --artifacts       # verify dist/ artifacts contain zero test-harness symbols
```

---

## Self-Hosting a Relay & Mailbox

By default, Voidwire uses `https://relay.voidwire.app` when devices can't connect directly. To run your own relay and mailbox, follow [docs/self-host-relay.md](docs/self-host-relay.md). It covers Docker and plain binaries, TLS on the relay or behind a proxy, access control, and adding the relay link in the apps (PC: Devices → Relays; Android: Settings → Relays).

---

## License

Voidwire's first-party code is released under [CC0 1.0 Universal with an MIT License fallback](LICENSE). Third-party dependency notices are documented in [`docs/LICENSES-INVENTORY.md`](docs/LICENSES-INVENTORY.md) and bundled into every release artifact as `THIRD-PARTY-LICENSES.txt`.
