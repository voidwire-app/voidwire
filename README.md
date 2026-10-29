# Voidwire

**Open-source, privacy-first, end-to-end encrypted link and file sharing between Android and Desktop (Windows & Linux; macOS planned).**

Pair once by scanning a QR code and typing a 6-digit verification code—no accounts, no cloud sign-in, and no phone numbers. Share a link or file from your phone and it arrives on your PC over direct LAN QUIC first, or automatically over an untrusted encrypted relay when you are away from your home network.

---

## Key Capabilities (`v0.6.1`)

- **Accountless QR + SAS Pairing:** Pair devices using a single-use, short-lived QR code and a 6-digit Short Authentication String (SAS) bound to the TLS 1.3 handshake transcript and Ed25519/X25519 device certificates.
- **Instant Link Sharing:** Share any `http`/`https` link from Android's system share sheet to your paired PC. Links open immediately in your default desktop browser by default, or wait in a focus-safe **"Open link?"** confirmation window when **Ask before opening** is enabled.
- **Bidirectional PC → Phone Sharing & Browser / OS Integrations:** Send links, clipboard text, or files from Desktop to your paired Android phone (with direct LAN QUIC first, blind RAM-only device inbox fallback for links/text when the phone is asleep, and a 256 KB relay confirmation threshold / 25 MB relay cap for larger items). Includes a MV3 browser extension for Chrome/Brave/Edge and Firefox (`extension/`) via Native Messaging (`voidwire --native-messaging-host`) and a per-user Windows File Explorer **"Send with Voidwire"** right-click context menu (`voidwire --send-file`).
- **Encrypted File, Photo & Clipboard Sharing:** Send files, photos, or clipboard text from Android to Desktop with end-to-end XChaCha20-Poly1305 chunked encryption (256 KiB chunks, BLAKE3 whole-file integrity verification), recipient approval on the PC, automatic chunk-level resume across Wi-Fi ↔ cellular network handoffs, and strict executable-file safeguards (saved to disk only, never auto-launched).
- **Direct LAN First + Untrusted Relay Fallback:** Connects directly over LAN QUIC (`iroh` + mDNS) whenever possible and falls back seamlessly to `https://relay.voidwire.app` across NATs or mobile data. The relay sees only QUIC/TLS ciphertext and padded envelopes.
- **Blind Pull-Based Revocation Mailbox (`voidwire-mailbox`):** Device removals propagate immediately over peer sync and through an append-only, epoch-keyed blind mailbox on the relay so offline devices learn revocations before accepting messages—without exposing group membership, device names, or plaintext operations to the relay.
- **Strict Privacy-First Defaults:**
  - Dark mode by default (unless the OS explicitly requests light mode, or overridden in Settings).
  - Zero telemetry and zero server logs (`RUST_LOG=off`).
  - Zero unrequested local history: recent sends, last-used PC ordering, completed file history, connection path statistics, and the local diagnostics log are all **opt-in and off by default**. Turning any opt-in off deletes its stored data immediately.
  - No desktop OS toast notifications (preventing OS notification centers such as Windows Action Center `wpndatabase.db` from logging opened hosts to disk).
- **Full Self-Hosting Support:** Run your own `iroh-relay` and `voidwire-mailbox` instance using [`ops/relay/`](ops/relay/README.md) and point both the Desktop and Android apps at your custom Relay URL and 64-hex Mailbox Endpoint ID in Settings.

---

## Repository Layout

| Path | Description |
|---|---|
| `core/` | `voidwire-core`: protocol types, HPKE envelope, signed wire format, verification pipeline (`Inbox::receive` → `VerifiedUrl`), chunked file transfer engine, opener, pairing, group log & blind mailbox client, rate limits, replay cache, URL policy, and UniFFI bindings (`ffi` feature) |
| `desktop/` | Tauri 2 desktop tray application (Windows & Linux) |
| `extension/` | MV3 WebExtension (Chromium & Firefox) bridging to the local desktop app over Native Messaging |
| `android/` | Kotlin + Jetpack Compose Android application consuming `voidwire-core` via UniFFI |
| `mailbox/` | `voidwire-mailbox`: blind, append-only epoch mailbox daemon for pull-based device revocation and signed relay configuration announcements |
| `push-gw/` | Push gateway stub (`axum`, `/healthz`) reserved for M3 PC → phone push notifications |
| `ops/relay/` | Self-hosting bundle (`docker-compose.yml`, `Caddyfile`, `nftables.conf`, `relay.toml`, `mailbox.toml.example`) for running your own relay + mailbox server |
| `brand/voidwire/ui/` | Design system source of truth (`tokens.json`, `build_tokens.py`, `SPEC.md`, bundled OFL fonts) |
| `tools/` | `uniffi-bindgen` CLI wrapper and compile-fail security probes (`tools/probes/`) |
| `scripts/` | Build, license verification, and fail-closed security gate scripts (`gates.sh`, `build-desktop.sh`, `build-android.sh`) |
| `docs/` | Architecture and security documentation: [PROTOCOL.md](docs/PROTOCOL.md), [THREAT-MODEL.md](docs/THREAT-MODEL.md), [TEST-PLAN.md](docs/TEST-PLAN.md), [LICENSES-INVENTORY.md](docs/LICENSES-INVENTORY.md) |

---

## Security Architecture

Voidwire enforces a strict compile-time and runtime invariant for opening links:

> **The URL opener can only ever receive URLs from a message that has been authenticated as coming from a cryptographically paired device in the owner's device group.**

- `verify::Inbox::receive` is the sole constructor of `VerifiedUrl`, and only after verifying transport peer membership, HPKE decryption, strict Ed25519 signature (`verify_strict`), group and recipient binding, per-device and global rate limits, group-log head freshness, ±10-minute timestamp window, fsync'd replay cache (`seen.bin`), and RFC 3986 `http`/`https` URL canonicalization (rejecting loopback, link-local, unspecified hosts, userinfo, and control/bidi characters).
- `UrlOpener::open` consumes an unforgeable `OpenApproval` token by value, minted only by `opener::deliver` (in default no-prompt mode) or `PendingOpen::confirm` (when **Ask before opening** is enabled) after re-checking roster membership immediately before invoking the OS opener (`ShellExecuteW` on Windows, `/usr/bin/xdg-open` on Linux, `/usr/bin/open` on macOS—never via a shell or the `open` crate).
- Incoming files never pass through `UrlOpener::open`; they require recipient acceptance, stream to a `<uuid>.part` file with per-chunk AEAD authentication and final BLAKE3 verification, and are saved to the configured download folder (`Downloads/Voidwire` by default).

For full cryptographic and protocol details, see:
- [Protocol Specification (`docs/PROTOCOL.md`)](docs/PROTOCOL.md)
- [Threat Model & Data Inventory (`docs/THREAT-MODEL.md`)](docs/THREAT-MODEL.md)
- [Security & QA Test Plan (`docs/TEST-PLAN.md`)](docs/TEST-PLAN.md)
- [Third-Party License Inventory (`docs/LICENSES-INVENTORY.md`)](docs/LICENSES-INVENTORY.md)

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

By default, Voidwire uses `https://relay.voidwire.app` when direct LAN QUIC is unavailable. To run your own relay and blind epoch mailbox server, follow the guide in [`ops/relay/README.md`](ops/relay/README.md), then open **Settings → Configure relay…** on both Desktop and Android to enter your custom `https://` Relay URL and 64-character hex Mailbox Endpoint ID.

---

## License

Voidwire's first-party code is released under [CC0 1.0 Universal with an MIT License fallback](LICENSE). Third-party dependency notices are documented in [`docs/LICENSES-INVENTORY.md`](docs/LICENSES-INVENTORY.md) and bundled into every release artifact as `THIRD-PARTY-LICENSES.txt`.
