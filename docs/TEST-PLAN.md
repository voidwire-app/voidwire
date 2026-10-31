# urlshare: QA test plan, M1 to M4

*QA test plan (rev 2). Source of truth: [PROTOCOL.md §8](PROTOCOL.md#8-architecture-decisions) and [THREAT-MODEL.md](THREAT-MODEL.md). Crate `voidwire-core` (`wire`, `envelope`, `verify::Inbox::receive` → `VerifiedUrl`, `opener::{UrlOpener, deliver, OpenMode, SystemOpener}`, `url_policy`, `ratelimit`, `replay`, `roster`, `pairing`, `reject::RejectReason`, `test_util`), plus `desktop`, `push-gw` and `android`.*

---

## 0. The rule this plan exists to enforce

> **Only messages authenticated as coming from a cryptographically paired device in the owner's group may ever reach the URL opener.**

This is the core security invariant for opening links on the PC **with no prompt**. Every case that defends this rule is **P0**. An open is allowed only when **all** of the following hold:

1. The transport peer is an EndpointId in the **current** roster (§3 "Transport"), and the connection is not a pairing-mode connection.
2. The envelope HPKE-decrypts with our current (or grace-period) receive key.
3. The inner Ed25519 signature verifies under the identity key of `sender_id`.
4. `sender_id` == the transport peer's EndpointId, `recipient_id` == us, and `group` == our group.
5. `sender_id` is a non-removed member in our group log.
6. `timestamp` is within ±10 min of our clock, and `msg_id` has not been seen before.
7. The sender is within the per-device limit (burst 5, refill 10/min) and the global limit (20/min, burst 20). The sender's `log_head` is not behind ours (revocation).
8. The URL passes the allow-list: parse, canonicalize, scheme ∈ {http, https}, no userinfo, length ≤ cap, safe character set.
9. The opener gets **exactly the canonical string** as **one argument**, with **no shell**: one direct `ShellExecuteW(NULL, L"open", canon, NULL, NULL, SW_SHOWNORMAL)` on Windows, and one exec of `/usr/bin/xdg-open` / `/usr/bin/open` with argv = [canon] on Linux/macOS. There is no fallback launcher. The `open` crate is banned (deny.toml + CI).
10. In the default `OpenMode::OpenImmediately` (no-prompt) the link opens through `opener::deliver`; with the "Ask before opening" setting (`ConfirmBeforeOpen`) the user confirms first. In both modes membership is re-checked right before the OS call (`opener::deliver` / `PendingOpen::confirm`).

The normative check order is PROTOCOL.md §5.

**Fail-closed:** any error, panic, timeout or unknown state in steps 1-9 means no open.

### 0.1 Standard assertion for every negative P0 case ("NO-OPEN")
Unless a case says otherwise, a rejection case passes only if **all** of these are true:
- `OpenerSpy.calls == 0`, checked after draining all queues and advancing the fake clock past every timer.
- `reject_reason == <expected enum>` (see the harness section). A "rejected for the wrong reason" result **fails**, because it usually means the right check is missing.
- No toast or notification is shown (`NotifierSpy.calls == 0`).
- The URL, host, keys and secret do not appear in any log line at any level (the `LogCapture` grep is empty).
- The process is still alive, and the next **valid** message from a paired device still opens. This proves the rejection did not cause a lockout or DoS unless that was intended.

### 0.2 Methods
- **U**: Rust unit or property test in `core` (or `desktop` for the opener). Fake clock, deterministic RNG, no network. Runs in CI on all 3 OSes.
- **I**: integration test. A real `core` endpoint plus a **fake malicious peer** (FMP) over a real iroh/QUIC loopback, a box-local `iroh-relay`, or a box-local `push-gw` with a mock FCM. Runs in CI on Linux; desktop-opener cases also run on the Windows runner.
- **Fz**: cargo-fuzz / proptest target. It runs in CI for 5 min per PR and 4 h nightly. A corpus seed list is included.
- **M**: manual on a real Android phone and Windows PC using a release/pre-release build, plus an Android emulator and Windows VM where noted.
- **E**: emulator, VM, netns or pcap end-to-end on the box (§9 QA role: "network-namespace impairment to force the relay path").

Priorities:
- **P0**: mandatory requirement. It blocks the release gate.
- **P1**: security or privacy issue that is not on the opener path, or a high-impact functional issue.
- **P2**: robustness or UX.

---

## 1. AUTH: Only authenticated, paired senders reach the opener (P0)

| ID | Pri | Case | Method | Steps / assertion | Expected | MS |
|---|---|---|---|---|---|---|
| AUTH-01 | P0 | Unknown EndpointId dials the PC (not in roster, no pairing active) | I (FMP) | FMP with a fresh Ed25519 key dials the PC's EndpointId on the app ALPN and sends a well-formed envelope | Connection refused at QUIC/TLS accept, before any envelope bytes are read. `NotInRoster`. NO-OPEN. Envelope parser call count == 0 | M1 |
| AUTH-02 | P0 | Unknown peer during an active pairing window | I (FMP) | PC shows a QR. FMP (which does not know `s`) connects via the pairing ALPN and sends a URL frame instead of a pairing frame | Only pairing frames are accepted on a pairing connection. URL frame gives `UnexpectedFrame`. NO-OPEN. Pairing session is aborted | M1 |
| AUTH-03 | P0 | Pending device (knows `s`, SAS not yet confirmed) sends a URL | I (FMP) | FMP completes steps 2-3 of pairing, then sends an envelope before the user taps confirm | `NotInRoster` (pending is not a member). NO-OPEN | M1 |
| AUTH-04 | P0 | SAS rejected by user, then the device sends | I (FMP) + M | User taps "doesn't match" or cancel. FMP reconnects and sends | Not in the roster. No `add_device` op in the log. NO-OPEN | M1 |
| AUTH-05 | P0 | Forged `sender_id`: a paired device A sends an envelope claiming `sender_id` = paired device B | I (FMP holding A's keys) | Inner `sender_id` = B and the signature is made with A's key (also try B's id with a garbage signature) | `SenderMismatch` (transport peer ≠ sender_id) or `BadSignature`. NO-OPEN | M1 |
| AUTH-06 | P0 | Valid signature by a key that is not in our group (attacker's own group) | I (FMP with its own genesis) | Attacker pairs with nothing. Envelope is correctly HPKE-sealed to the PC's receive key (it is public in the certs) and correctly signed by the attacker | Rejected at transport (AUTH-01). If injected below transport through the test hook, rejected with `NotInRoster`/`WrongGroup`. NO-OPEN. **This proves HPKE base mode alone is not authentication** | M1 |
| AUTH-07 | P0 | `group` field ≠ our group, with a valid sender in our roster | U | Craft a signed envelope with group = random | `WrongGroup`. NO-OPEN | M1 |
| AUTH-08 | P0 | `recipient_id` ≠ us (another PC in the group): forwarding/confused deputy | U + I | Paired phone signs for PC2, and FMP delivers it to PC1 (sealed to PC1) | `WrongRecipient`. NO-OPEN | M1 |
| AUTH-09 | P0 | Signature does not cover all fields | U (test vectors) | For each field (group, sender_id, recipient_id, msg_id, timestamp, url, version, padding length), mutate only that field after signing, then re-seal | `BadSignature` for every field. The signature input must be a defined canonical encoding (vector file) | M1 |
| AUTH-10 | P0 | Unsigned / empty signature / all-zero signature / signature of wrong length / small-order or non-canonical Ed25519 public key or signature (malleability) | U + Fz | Use the ed25519 "verify_strict" edge-case vectors. `ids::DeviceId::verifying_key` uses `VerifyingKey::from_bytes`, which accepts weak (small-order) keys, so the verify path must call `verify_strict` and the roster must refuse `is_weak()` keys at pairing | All rejected (`BadSignature`). Verification uses strict mode | M1 |
| AUTH-11 | P0 | Valid inner message from a roster member delivered over a connection from a *different* roster member | I (FMP with A's and B's keys) | Connect as B and deliver A's validly signed envelope | `SenderMismatch`. NO-OPEN. (The decision is recorded in OQ-6) | M1 |
| AUTH-12 | P0 | Opener is reachable **only** from the verified-message path (static check) | U + code review | Static test: the opener trait is constructed in exactly one place and is only invoked by `deliver_verified(VerifiedUrl)`. `VerifiedUrl` has no public constructor (newtype) | Compile-time guarantee that nothing else can call the opener. The test fails if `pub fn new` is added | M1 |
| AUTH-13 | P0 | Other local paths into the opener: native-messaging pipe, `urlshare:` URI handler, Tauri IPC/webview commands, tray menu, deep links, CLI args | I (desktop) + M | Enumerate every IPC command and pipe message type. Send an "open"-shaped payload to each. Launch `urlshare.exe "urlshare:pair?...&url=..."` and `urlshare.exe https://evil`. Call every Tauri command from the webview devtools | None reaches the opener. Tauri capabilities do **not** grant `shell:open`/`opener` to the webview. The pipe is used only for *sending*. The pipe ACL is current-user only | M3 (pipe), M1 (rest) |
| AUTH-14 | P0 | Webview content | M + I | Pairing/device-list windows load only bundled assets (CSP, no remote origin). A device name containing HTML/JS (`<img src=x onerror=…>`) is shown in the device list and the open toast | Rendered as text. No script runs. No IPC call | M1 |
| AUTH-15 | P0 | Pairing secret alone is not enough to send | I (FMP) | FMP knows a valid `s` but loses the SAS race (user confirms the legit phone) | FMP never enters the roster. Every later envelope is rejected. NO-OPEN | M1 |
| AUTH-16 | P1 | Rejection cost before crypto | I + bench | 1,000 connection attempts/s from unknown EndpointIds. Measure CPU, and confirm no HPKE/sig work is done (counter) | Rejected at TLS accept. HPKE/verify counters == 0. PC stays responsive and legit opens are still < 2 s | M1 |
| AUTH-17 | P0 | Open mode can't be skipped | U (static) + probe | In `desktop` (and any future host), `UrlOpener::open` is reached only through `opener::deliver` / `PendingOpen::confirm` with the app's single `Roster`. The default `OpenMode` is `ConfirmBeforeOpen`. Probe: from outside core, mint a `VerifiedUrl` against a self-made roster and call `SystemOpener.open` directly | **M0 QA: the probe compiles and opens** (public API, no unsafe), so the guarantee holds per process, not per roster, and confirm-before-open is a convention. Fix: an `ApprovedOpen` token that only `deliver`/`confirm` can create, plus a static check of opener call sites (OQ-18) | M1 |
| AUTH-18 | P0 | Android share target never sends on its own (QA M1 High) | U (Robolectric) + M | Any app can start the exported `ShareActivity`. Launch it programmatically (one and two PCs paired), deliver repeated and new intents, deliver an intent while it is backgrounded, recreate it from saved state | No send in any of these. Only a tap on **Send to <PC>** while resumed + focused, ≥ 500 ms after the content appeared, and not obscured sends, exactly once. `ShareActivityTest` | M1 |
| AUTH-19 | P1 | Desktop confirm window can't be clicked by accident (QA M1) | M + gate | Trigger a prompt while typing/clicking in another app; click Open immediately after a new prompt appears | The window doesn't take focus and isn't always-on-top (taskbar flash). Open is disabled for 1 s after the window appears or the list changes. Gate `confirm-window-no-focus-steal` | M1 |
| AUTH-20 | P1 | Stale prompts (QA M1) | I | Leave a prompt unanswered past the TTL, then click Open; decide an unknown id | Expired prompt is dropped and never opens (`PromptExpired`, TTL 2 min, `limits::PENDING_PROMPT_TTL_MS`); unknown/already-decided id gives `NoSuchPrompt`. `e2e_net` prompt-expiry test | M1 |

## 2. PAIR: Pairing secret single-use, short-lived, tamper-evident (P0)

*TTL = 120 s per §3 step 1. Boundary tests use the injectable clock. The PC decides expiry with **its own** clock (the QR's `exp` is informational for the scanner).*

| ID | Pri | Case | Method | Steps / assertion | Expected | MS |
|---|---|---|---|---|---|---|
| PAIR-01 | P0 | Happy path | I + M | Show QR, scan, both show the same SAS, confirm on the inviter | Phone is in the roster. `add_device` op is signed by the PC. Secret store is empty | M1 |
| PAIR-02 | P0 | Replay of a consumed QR | I (FMP) | After PAIR-01, FMP replays the same `s` (fresh handshake) | `PairingSecretUnknown`/`Used`. No SAS shown on the PC | M1 |
| PAIR-03 | P0 | Replay of the full recorded pairing transcript | I (FMP) | Record a successful handshake's frames and replay them byte-for-byte on a new connection | Rejected: the secret is already spent (`PairingSecretUsed`), and the transcript `handshake` is the TLS exporter + both certs (PROTOCOL §6.3), so the proof wouldn't verify anyway | M1 |
| PAIR-04 | P0 | Expiry at TTL−1 s | U (clock) | Create the secret at t0 and attempt at t0+119 s | Accepted (proceeds to SAS) | M1 |
| PAIR-05 | P0 | Expiry at TTL exactly | U (clock) | Attempt at t0+120 000 ms (monotonic) | **Decided: expired at ≥ 120 s** → `PairingSecretExpired`, and the secret is burnt | M0 core / M1 |
| PAIR-06 | P0 | Expiry at TTL+1 s | U (clock) | Attempt at t0+121 s | `PairingSecretExpired` | M1 |
| PAIR-07 | P0 | SAS confirm timeout | U (clock) | Proof accepted at t0+110 s. Code typed at proof+120 000 ms, then at proof+120 001 ms | **Decided:** SAS must be typed within 120 s of the proof (`SAS_CONFIRM_TTL_MS`). Later → `SasTimeout`, no roster change | M0 core / M1 |
| PAIR-08 | P0 | Concurrent double use (race) | I (FMP ×2, barrier) | Two clients present the same `secret_id` in the same instant. Repeat 1,000× with randomized interleaving | Exactly one gets a grant. The other gets `PairingSecretUsed`. **Decided:** consumed by the first attempt of any kind (valid, bad proof, expired), atomically under the registry lock | M1 (deferred from M0) |
| PAIR-09 | P0 | Wrong secret / HMAC over the wrong transcript | U + I | Flip 1 bit of the proof. Use the proof from another session. Use an empty proof | `PairingHmacBad`. **The secret is burnt** (a correct retry afterwards gets `PairingSecretUsed`). No SAS | M0 core / M1 |
| PAIR-10 | P0 | Tampered QR fields | U (parser) + I | Mutate each of `v`, `id`, `r`, `g`, `s`, `exp`. Add duplicate params, unknown params, missing params, swapped param order, `%`-encoded values, overlong values, non-UTF-8, extra `&` | Wrong `id` means the dial fails or TLS identity mismatches (never "connect to whoever answers"). Wrong `s` gives PAIR-09. Parser rejects duplicates and missing required fields. Unknown `v` gives `UnsupportedVersion` | M1 |
| PAIR-11 | P0 | QR `id` points at the attacker (attacker shows their own QR to the user's phone) | I + M | The phone scans the attacker's QR | The phone would join the *attacker's* group. Verify that the phone **asks before joining a new group** when it already belongs to one, and never merges rosters. Document that the PC side is not affected. The risk goes in OQ-9 | M1. **SE M1 (QA fix):** done on the phone: `inspect_pairing` + warning dialog (Cancel default, explicit Join) + core refusal `GroupChangeNotConfirmed` without confirmation; QR `n=` verified against the PC cert. e2e: `e2e_net` group-change refused then confirmed, forged `n=` refused. **QA re-check (M1 Medium) fixed:** "same group" is no longer judged from the QR's unauthenticated `g=`; the inviter must be the owner/member of a signed log the phone holds (checked before traffic, after the cert, and before storing the welcome log), and duplicate PC names warn. e2e `e2e_fake_pc_reusing_group_id_and_name_is_warned` (QA's fake PC reusing `g=` + name). PC side n/a in M1 (the PC never scans QRs) |
| PAIR-12 | P0 | QR photographed and raced | I (FMP) + M | FMP redeems the photographed `s` first. The legit phone then tries | The legit phone gets `PairingSecretUsed` and shows "code already used / someone else scanned". **Decided:** the PC confirm screen shows the joining device's **name**, and the user must **type** the 6-digit code shown on the joiner. FMP's code is on FMP's screen, not the user's phone, so the user has nothing correct to type and the grant fails | M1 (UI) |
| PAIR-13 | P0 | SAS derivation binds everything | U (vectors) | Changing any of transcript, either key, or `s` changes the SAS. Distribution is uniform over 10^6 (chi-square on 10^5 samples) | Pass | M1 |
| PAIR-14 | P0 | Secret is high-entropy and never reused | U (RNG hook) | 10^5 secrets from the real RNG have no duplicates and are 128 bits. With an injected stuck RNG, `pair` refuses (self-test) | Pass | M1 |
| PAIR-15 | P0 | Secret store inspection | U | After success, expiry, cancel or app restart, the store is empty. The secret is not persisted to disk and not logged | Pass | M1 |
| PAIR-16 | P1 | Pairing brute-force / DoS | I (FMP flood) | 100 bad attempts/s during a window | The first attempt burns the secret. The legit user regenerates the QR (DoS, not bypass). No CPU blowup | M1 |
| PAIR-17 | P1 | Pairing listener closes | I | After success, cancel or expiry, unknown peers on the pairing ALPN are refused | Pass | M1 |
| PAIR-18 | P1 | Signed device cert validation | U | Cert with a receive key not signed by the identity key, a wrong platform enum, an oversized name (10 KB), control chars/RTL in the name, or an empty name | Rejected or sanitized. The name is length-capped and shown with bidi isolation | M1 |
| PAIR-19 | P1 | Manual: real devices | M | On real Android + Windows hardware: pair, wait 125 s, scan the old QR (expired); pair, scan again (used); screenshot the QR and scan it from an emulator during a real pairing (race) | Matches PAIR-02/06/12 | M1 |
| PAIR-20 | P0 | Typed code is one try and exact | U | Wrong code, 5- and 7-digit codes, non-digits, the code with spaces, the right code after a wrong one, `confirm_typed_code` after timeout | Only the exact 6 digits within 120 s succeed. Any wrong code consumes the `PairingGrant` (one try, `SasRejected`). Only `PairingGrant::confirm_typed_code` creates a `ConfirmedPairing`, and only `Roster::add_paired_device` consumes one (compile probe) | M0 core / M1 |

## 3. RL: Rate limits (P0)

*Decided (PROTOCOL §8): per device burst **5**, refill 10/min. Global **20/min**, burst 20. Both are configurable through `InboxConfig`, with counters visible via `Inbox::counters` / `tokens_available`. Every **authenticated** message counts against the per-device limit, valid or not (RL-06), keyed only by the authenticated sender (RL-07). The global limit is checked after per-device, replay and timestamp, and before URL policy (PROTOCOL §5 steps 6 and 10). Excess messages are **dropped, not queued**. Tests read `limits::DEFAULT_*` and also run with injected values.*

| ID | Pri | Case | Method | Steps / assertion | Expected | MS |
|---|---|---|---|---|---|---|
| RL-01 | P0 | Per-device burst | U (clock) | Paired A sends `burst+1` valid URLs at t=0 | The first `burst` open. The rest get `RateLimitedDevice`. Opener calls == burst | M1 |
| RL-02 | P0 | Per-device sustained | U (clock) | A sends 1 msg/s for 10 min | Opens ≤ L_dev per window, at every window boundary | M1 |
| RL-03 | P0 | Recovery after the window | U (clock) | After RL-01, advance the clock by window+1 s | The next message opens. At window−1 s it is still limited | M1 |
| RL-04 | P0 | Global cap | U | 5 paired devices each stay under L_dev but together exceed L_glob | Total opens ≤ L_glob. `RateLimitedGlobal` | M4 |
| RL-05 | P0 | Fairness: one flooder vs others | U + I | A floods at 1,000 msg/s. B sends 1 msg every 10 s | A's over-budget rejects don't touch the global bucket, so B still opens. **Known limit:** A's *in-budget* messages (and bad-URL messages that passed steps 1-9) do spend global tokens, so 2 flooding paired devices at 10/min each can use the whole 20/min. That's accepted because paired devices are trusted (threat model #1). The test pins it | M0 core / M4 |
| RL-06 | P0 | Rejected messages count against the limit (no "invalid messages are free" loophole) | U | Flood of replays, bad-scheme messages and expired timestamps from paired A | Decide and pin: invalid-but-authenticated messages also count, so a compromised device cannot spin CPU forever. No opens | M1 |
| RL-07 | P0 | Limiter state is not keyed by attacker-controlled fields | U | Vary msg_id/timestamp/url per message | The limiter is keyed by the authenticated sender EndpointId only | M1 |
| RL-08 | P0 | Limiter across restart | U | Flood, restart the core, flood again | Limiter state is in memory: a restart refills the buckets (accepted, at most 5 + 20 extra). Since `panic = "abort"`, the test also confirms no inbound input can panic (fuzz, ENV-13) | M1 |
| RL-09 | P1 | Unauthenticated flood (connection level) | I (FMP ×N) | 10k connection attempts from random keys | Refused at TLS. PC CPU < X%. A legit open still < 2 s | M1 |
| RL-10 | P1 | Relay per-client rate limits are configured | E | Box-local `iroh-relay` with the shipped config. One client floods | The relay throttles it. Other clients are unaffected | M2 |
| RL-11 | P1 | push-gw limits per sealed token and per IP | I | Flood with a single sealed token, then the same IP with many tokens | 429 after the limit. Mock-FCM call count is bounded | M3 |
| RL-12 | P1 | Phone notification flood | I + M | PC floods the phone via push | The phone collapses or limits notifications. The phone UI stays usable | M3 |
| RL-13 | P2 | Manual flood | M | Share 30 links from the phone in about 10 s | Matches the limits. One "N links blocked (rate limit)" toast. No browser tab explosion | M1 |

## 4. URL: Opener allow-list and safe invocation (P0)

**Required design (QA will test against it).** The check runs on the **parsed and re-serialized** URL, using a WHATWG-conformant parser (`url` crate). The pipeline is:

1. Reject raw input with C0/C1 controls, DEL, U+2028/2029, bidi controls (U+202A-202E, U+2066-2069, U+200E/F), or a NUL anywhere. This happens before parsing, and the input is **not** stripped first.
2. Parse.
3. Require scheme ∈ {`http`,`https`} (the parser lowercases it) and a non-empty host.
4. Reject a non-empty username or password.
5. Re-serialize to `canon`.
6. Require `canon.len() ≤ CAP`. Check that `canon` contains only RFC 3986 characters (no `"`, space, `<>`, `\`, `^`, `\|`, backtick, `{}`, or non-ASCII; the host is punycode).
7. Pass `canon` (and only `canon`) to the opener as **one argument**: Windows `ShellExecuteW(NULL, L"open", canon, NULL, NULL, SW_SHOWNORMAL)` with `lpParameters = NULL`; macOS `open` / Linux `xdg-open` through `Command::new(bin).arg(canon)` with **no shell**. Linux and macOS are M5, but the unit corpus runs on all CI OSes from M1.

**CAP (decided):** `limits::MAX_URL_BYTES` = 8192 on LAN/relay. Padding buckets 512/1K/2K/4K/8K plus a top bucket of 8K+256 (8448), so an 8 KiB URL fits. Push-path cap `limits::MAX_PUSH_URL_BYTES` = **2048** (`url_policy::check_push_url`). The rest of this paragraph is historical: The skeleton's `envelope::padded_len` pads beyond PLAN's 3072 bucket in 4 KiB steps (so an 8 KB URL becomes a 12 KiB envelope), which makes 8 KB reachable on LAN/relay. The push path can't carry it (OQ-4). Boundary tests use `CAP_eff` = `MAX_URL_BYTES` on LAN/relay, plus a separate exported push cap.

### 4.1 Allow-list cases

| ID | Pri | Case | Method | Steps / assertion | Expected | MS |
|---|---|---|---|---|---|---|
| URL-01 | P0 | Accept the basics | U | `http://example.com`, `https://example.com/a?b=c#d`, IPv4, `[IPv6]`, port, IDN host | Accepted. `canon` equals the expected serialization (vector file) | M1 |
| URL-02 | P0 | Scheme deny corpus | U + Fz | `file:///C:/Windows/System32/calc.exe`, `file://host/share`, `javascript:alert(1)`, `data:text/html,…`, `vbscript:`, `about:`, `blob:`, `filesystem:`, `ftp:`, `ws:`/`wss:`, `chrome:`, `edge:`, `ms-settings:`, `ms-msdt:`, `search-ms:`, `ms-officecmd:`, `ms-word:`, `mailto:`, `tel:`, `sms:`, `intent:`, `market:`, `steam:`, `zoommtg:`, `urlshare:`, `shell:`, `res:`, `jar:`, `view-source:https://…`, `microsoft-edge:https://…`, `x-callback-url:` | All `SchemeNotAllowed`. Opener calls == 0 | M1 |
| URL-03 | P0 | Case tricks | U | `HTTP://x`, `HtTpS://x` (accepted, canon is lowercase); `JaVaScRiPt:`, `FILE:`, `Data:` | Mixed-case http(s) is accepted and canonicalized. The others are rejected | M1 |
| URL-04 | P0 | Whitespace and controls | U + Fz | Leading/trailing space, `\t`, `\n`, `\r`, `\0`, `\x0b`, `\x7f`, `\u00a0`, `\u2028`, `\ufeff` BOM; `java\nscript:`; `https://ex\tample.com`; `https://x/\r\nHost: y` | Rejected (`UrlBadChars`). **Not silently stripped**, because WHATWG strips tab/newline, so `java\tscript:` would otherwise become `javascript:`. Input is rejected rather than stripped | M1 |
| URL-05 | P0 | Percent-encoded scheme or separator | U | `%68ttps://x`, `javascript%3Aalert(1)`, `https%3A%2F%2Fx`, `%2F%2Fevil.com` | Parse error or non-http(s), so rejected. Never decoded into an allowed scheme | M1 |
| URL-06 | P0 | Userinfo tricks | U | `https://good.com@evil.com`, `https://user:pass@x`, `https://good.com%40evil.com`, `https://@x`, `https://:@x`, `https://good.com\@evil.com` | Any username or password gives `UrlHasUserinfo`. Encoded `@` in the host is rejected (parse error) | M1 |
| URL-07 | P0 | Backslash vs slash | U | `https:\\evil.com\`, `https:/\evil.com`, `https:evil.com`, `https://x\@y/`, `\\evil.com\share`, `\\?\UNC\host\share`, `//evil.com` | WHATWG normalization is accepted where the host stays unambiguous (`https:evil.com` → `https://evil.com/`, `https://x\@y/` → host `x`, path `/@y/`), and the toast shows that host. UNC, schemeless and protocol-relative inputs are rejected | M0 core / M1 |
| URL-08 | P0 | Length boundaries | U | `canon` length CAP_eff−1, CAP_eff, CAP_eff+1. Also raw input under the cap whose `canon` exceeds it (percent-encoding inflation, IDN→punycode growth) | ≤ CAP accepted, > CAP gives `UrlTooLong`. **The cap is applied to `canon`**, not to the raw input | M1 |
| URL-09 | P0 | Sender-side cap | U + M | Share a 10 KB URL on the phone | The phone refuses with a message. Nothing is sent. No partial or truncated URL is ever sent | M1 |
| URL-10 | P0 | Arg/quote injection for ShellExecute / browser command line | U + I (Windows runner, real ShellExecute with a test-registered http handler that logs its argv) | `https://x" --foo`, `https://x/" -osint -url "file:///c:/`, `https://x/&calc`, `https://x/\|calc`, `https://x/^calc`, `https://x/%22%20--single-argument`, `https://x/'$(id)'`, `` https://x/`id` ``, `https://x/;id`, `https://x/a b`, `https://a"b.com/` | Either rejected, or `canon` contains no `"`, space or backtick (percent-encoded). The test handler receives **exactly one argv element** equal to `canon`. No extra args. No process other than the handler is spawned | M1 |
| URL-11 | P0 | Opener never uses a shell or a fallback | U (static) + I | CI gates: `open` crate absent (`cargo tree -i open` + deny.toml ban), no shell names in `.rs`, clippy `disallowed-methods` on `Command::new` except in `opener.rs`. On Linux/macOS the spy or strace shows exactly one `execve("/usr/bin/xdg-open"|"/usr/bin/open", [bin, canon])`. On Windows exactly one `ShellExecuteW` with verb `open`, `lpParameters` NULL, no `SHELLEXECUTEINFO` mask | One process / one call, absolute path, no retry | M0 static / M1 runtime |
| URL-12 | P0 | xdg-open / open specifics | U + E (M5) | Canon can't start with `-` (asserted). Exec `/usr/bin/xdg-open` with a URL containing `$`, `;` and backticks against a stub `x-www-browser` that records argv. Missing `/usr/bin/xdg-open` gives an error, not a fallback | One argv. No expansion. No fallback | M5 |
| URL-13 | P0 | IDN / homoglyph / mixed script | U + M | `https://аpple.com` (Cyrillic а), `https://xn--80ak6aa92e.com`, `https://exаmple.com` (mixed script), `https://ex%61mple.com`, full-width `ｈｔｔｐｓ://`, `https://example.com．evil.com` (full-width dot), dotless-i, `ß` | Opens are allowed (the host is legitimate http). **The toast shows the punycode/ASCII host** (§3 #1), and the full-width scheme is rejected or normalized. The test asserts the toast text equals the ASCII host. Manual check on Windows that the toast shows `xn--…` | M1 |
| URL-14 | P0 | RTL override / bidi in the URL or device name | U + M | `https://evil.com/\u202Egpj.exe`, a device name with `\u202E` | URL rejected (URL-04 rule). Device name is isolated (FSI/PDI) in the toast so it can't spoof the "Opened from X: host" layout | M1 |
| URL-15 | P0 | Host edge cases | U | Empty host (`https:///x`), `http://0`, `http://0x7f.1`, `http://2130706433`, `http://[::ffff:127.0.0.1]`, trailing dot, `http://localhost`, `http://192.168.1.1/admin`, port 0/65536 | Empty host and bad port are rejected. Numeric hosts are canonicalized. **localhost and private ranges follow the decision in OQ-8** (the test pins it) | M1 |
| URL-16 | P0 | Non-UTF-8 / invalid surrogates / overlong UTF-8 in the URL field | U + Fz | Raw bytes in the envelope `url` field | `MalformedFrame` before URL parsing | M1 |
| URL-17 | P0 | Validator fuzz | Fz | Property: for any input, `validate(x) == Ok(c)` implies that `c` starts with `http://` or `https://`, `validate(c) == Ok(c)` (idempotent), `c.len() ≤ CAP`, the safe char set holds, and there is no userinfo. Never panics | 4 h nightly, 0 failures | M1 |
| URL-18 | P0 | Toast and open use the same string | U | The toast is derived from the same `canon` that was opened, not from the raw input | Pass | M1 |
| URL-19 | P1 | Phone side (PC→phone) applies the same validator before showing "tap to open" and before `Intent.ACTION_VIEW` | U (core, shared) + M | Push deny-corpus URLs to the phone | No notification for rejected URLs. An `intent:` URL never reaches `startActivity` | M3 |
| URL-21 | P0 | No `open` crate, direct OS call (decided) | U (static) + CI + I (Windows runner) | (a) `cargo tree --all-features --target all -i open` finds nothing, and `cargo deny check bans` fails if it appears; (b) `SystemOpener` re-runs `check_url` and requires a fixed point before the OS call; (c) on the Windows runner, Process Monitor / job object shows no `powershell`, `explorer`, `cmd` child | Pass. Gate verified to fail on an injected `open` dep (M0 QA) | M0 static / M1 runtime |
| URL-22 | P1 | Stray `%` is normalized | U | `https://x/%`, `https://x/%zz`, `https://x/?a=%` | Canon is RFC 3986 valid (`%25`), or the URL is rejected. M0 passes them through unchanged (harmless for ShellExecuteW, but not RFC 3986) | M1 |
| URL-23 | P0 | No desktop open notifications (replaces M1.1 open-notice toast) | U + CI + I | CI gate `no-open-notice` in `scripts/gates.sh` (`notify.rs` and `tauri-plugin-notification` absent). I: `e2e_every_no_prompt_open_notifies_host_and_device_only` verifies `PcEvent::Opened` carries only the ASCII host and sender name (never path, query, fragment or port) and rejects emit `PcEvent::Rejected`. Desktop open notifications were removed in M1.2 because OS notification centers (`wpndatabase.db` on Windows) log toast payloads to disk | No OS toast notification is emitted on link open; `PcEvent::Opened` carries host + device name in memory only | M1.2 |
| URL-20 | P1 | Windows handler sanity | M | On a Windows PC with Chrome or Edge default, and again with Firefox default, open URL-10 corpus survivors | One tab each. No extra windows or args | M1 |

## 5. ENV: Envelope integrity, replay and reorder (P0)

| ID | Pri | Case | Method | Steps / assertion | Expected | MS |
|---|---|---|---|---|---|---|
| ENV-01 | P0 | Exact replay within the window | I (FMP as paired peer, or the capture/inject hook) | Deliver the same envelope twice, 1 s apart | 1 open. The second gets `Replay` | M1 |
| ENV-02 | P0 | Replay with the same msg_id and a different ciphertext (re-sealed by the paired sender) | U | Same msg_id, new HPKE enc | `Replay` (the cache is keyed on msg_id, scoped to the sender) | M1 |
| ENV-03 | P0 | Replay after the window | U (clock) | Replay at ts+10 min+1 s | `StaleTimestamp` | M1 |
| ENV-04 | P0 | Timestamp boundaries | U (clock) | ts = now−600 000 ms, now−600 001 ms, now+600 000 ms, now+600 001 ms, `u64::MAX`, 0 | **Decided: inclusive.** ±600 000 accepted, ±600 001 → `StaleTimestamp` / `FutureTimestamp`. No overflow | M0 core |
| ENV-05 | P0 | **Replay after PC restart** | I | Capture a valid envelope, restart the tray app (and kill -9 it mid-receive), re-inject within 10 min | **Decided:** the seen-ID cache is persisted and fsync'd before `receive` returns Ok. A replay after restart gives `Replay`, and a failed persist gives `Internal` (fail closed). **Expected PASS from M1.** M0 ships only the `replay::SeenIdStore` seam with `NoPersistence`, so this fails at M0 by design | M1 |
| ENV-06 | P0 | Seen-cache eviction under flood | U | A paired peer sends > `REPLAY_CACHE_MAX_ENTRIES` (20 000) distinct msg_ids, then replays the first | `CacheFull` (fail closed, never evict in-window ids). Entries are kept `REPLAY_RETENTION_MS` = 2 × window, and evicted only after both wall and monotonic expiry | M0 core |
| ENV-07 | P0 | Reordering | I (FMP) | Send m1, m2, m3 and deliver them as m3, m1, m2 | Defined: each opens once (no sequence numbers in PLAN), or the design adds ordering. Pin it. No duplicates | M1 |
| ENV-08 | P0 | Bit-flip anywhere | U + Fz | Flip every bit position of the HPKE `enc`, ciphertext and tag (exhaustive for one vector) | All `DecryptFailed`. NO-OPEN. No panic | M1 |
| ENV-09 | P0 | Truncation / extension | U + Fz | Truncate at every offset. Append 1 byte, 1 KB or 1 MB. A frame length prefix that disagrees with the body | `MalformedFrame`/`DecryptFailed`. Memory is bounded (no allocation from an attacker length > max frame) | M1 |
| ENV-10 | P0 | Cross-session / cross-device ciphertext | U | An envelope sealed to PC2's receive key delivered to PC1. An envelope sealed to PC1's *old* receive key after rotation plus the grace period | `DecryptFailed` / `WrongRecipient` | M1 / M4 |
| ENV-11 | P0 | Padding validation | U | Length not a bucket. `body_len` that fits a smaller bucket. Non-zero padding. > 8448 bytes | `MalformedFrame` | M0 core |
| ENV-12 | P0 | Version / downgrade | U | Envelope version 0, 2 or 255. HPKE suite IDs other than X25519/HKDF-SHA256/ChaCha20-Poly1305. QR `v=0`. An iroh ALPN for an older protocol | `UnsupportedVersion`. **No fallback** to any other suite or mode | M1 |
| ENV-13 | P0 | Frame parser fuzz | Fz | Targets: `parse_frame`, `open_envelope` (with fixed keys), `parse_pair_qr`, `parse_device_cert`, `parse_group_op` | 4 h nightly, no panic or OOM, invariant: no `VerifiedUrl` produced from mutated input | M1 |
| ENV-14 | P0 | Duplicate delivery across paths (LAN and relay both deliver) | E | Force both paths (netns) and send once | One open | M2 |
| ENV-16 | P0 | Encryption actually on before no-prompt open ships | U + CI | While `envelope::ENCRYPTION_IMPLEMENTED == false`, a `--release` build of `voidwire-core` fails to compile (const assert), and CI checks that. From M1: `true`, and `seal` output ≠ plaintext (marker URL absent from sealed bytes) | Pass at M0 (gate verified). Flip in M1 | M0 / M1 |
| ENV-17 | P0 | Release gates can't be bypassed, and cover shipped artifacts | CI | (a) Build with `CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true cargo build --release -p voidwire-core`, and a dev-profile build with `--features test-util`. (b) Scan every artifact in a pre-release for test-util symbols (`SpyOpener`, `FakePeer`, `FakeClock`) and check that the encryption flag is set | Both must fail or be detected. **M0 QA: (a) succeeds today**: both gates key on `debug_assertions`, and M0/M1 pre-releases are dev-profile builds. Gate on a dedicated cfg/env or an artifact scan instead (OQ-17) | M1 |
| ENV-18 | P0 | Replay cache file lost or damaged (QA M1) | U + I | Delete `seen.bin`, truncate it mid-record, flip bytes in an early record, **truncate at a record boundary, cut to the header, damage the last record (QA re-check L2: high-water mark in state.bin)**, then restart and replay a captured in-window envelope | Torn tail: dropped and realigned, cache otherwise intact. Missing/corrupt on an initialised install: fail closed, for one replay window after startup only messages timestamped after startup are accepted (`ReplayStartupGuard`), so the replay is refused. File is `0600` (private dir; Windows protected DACL) | M1 |
| ENV-15 | P1 | msg_id randomness | U | 10^6 msg_ids have no collisions. With a stuck RNG the sender refuses | Pass | M1 |

## 6. REV: Revocation / unpaired device (P0)

| ID | Pri | Case | Method | Steps / assertion | Expected | MS |
|---|---|---|---|---|---|---|
| REV-01 | P0 | Send immediately after "Forget this device" | U (M0 core) + I | PC calls `Roster::remove_device(A)`, then A sends (open connection, and from M1 a new connection) | `Removed` (tombstone). From M1 the existing connection from A is closed on forget. NO-OPEN | M0 core / M1 |
| REV-02 | P0 | After restart of the PC | I | Remove A, restart the PC, A sends | `NotInRoster`/`Removed` (the log persisted) | M4 |
| REV-03 | P0 | Removed device with cached keys and roster | I (FMP with A's full state) | A keeps its keys and its old log and dials over LAN and relay | Refused at transport | M4 |
| REV-04 | P0 | In-flight at revoke time | I (clock + hook) | A's envelope is decrypted and queued for the opener, then the remove is applied before the opener runs | **Re-check membership immediately before the opener call** (TOCTOU). NO-OPEN | M4 |
| REV-05 | P0 | Removal by another device: direct + relay pull | E | Phone P1 removes P2 while PC1 is online. PC2 is offline, then comes online | **Decided (pull-based):** the signed `remove_device` op reaches members by `SYNC`/`OPS` on every connect; from M2 the relay holds the group's latest signed ops (PROTOCOL §7.1) and PC2 pulls them on reconnect before accepting any URL. No per-device delivery tracking. PC2 rejects P2 as soon as it has the op from the relay or any member. Measure the window | M1 (direct on connect) / M2 (relay pull) / M4 |
| REV-06 | P0 | **Removed device is the only one PC2 hears from** | I (FMP = removed device withholding the remove op, presenting a pre-removal head that PC2 still considers current) | PC2 missed the removal and P2 connects first | **Residual risk, documented for alpha (PROTOCOL §7, THREAT-MODEL §6.2):** PC2 accepts P2 until any other member reaches it. Test asserts (a) that the window closes the moment any member delivers the op, and (b) that a **local** "Forget this device" on PC2 closes it immediately | M1 / M4 |
| REV-07 | P0 | Concurrent ops by the removed device | U (DAG) | P2 issues `add_device(X)` concurrent with `remove(P2)`. Then X sends | "Remove wins": the add is invalid, and X and everything X added (transitively) are invalid. NO-OPEN from X | M4 |
| REV-08 | P0 | Back-dated op by a removed device | U | P2, after removal, crafts an op whose parents predate the remove | Treated as concurrent, so it is invalid | M4 |
| REV-09 | P0 | Mutual concurrent removes (A removes B, B removes A) | U | Both are applied | Deterministic outcome on every device (both removed?). Pin it. Every device converges to the same roster (property test with random merge orders) | M4 |
| REV-10 | P0 | Group-log op validation | U + Fz | Forged signature, author not a member, unknown op type, op with a cycle, 10^5 ops, duplicate op | Rejected. Bounded memory. A log merge never adds a member without a valid chain | M4 |
| REV-11 | P0 | Removed device can't *receive* (M4 exit criterion) | I | After remove, senders' fan-out excludes A, and its sealed push token is not used | 0 envelopes to A | M4 |
| REV-12 | P0 | Manual on real devices | M | 2 phones + 2 PCs (real Android + Windows hardware plus an emulator and a VM). Remove phone B from PC1. Phone B shares a link to PC1 and PC2. Check that all devices show the change | No open anywhere. A "removed" notice appears on every member (M4 exit criterion) | M4 |
| REV-13 | P1 | Lost-phone flow before M4 | M | M1-M3 builds: user revokes a lost phone | **Decided:** "Forget this device" ships in the M1 PC UI (local, immediate). REV-01/REV-15 apply | M1 |
| REV-14 | P0 | Stale or unknown log head rejected | U (M0 core) + I | After any roster change on the PC, a member sends with its old head, then with a random head | Old head → `StaleGroupHead`, random head → `UnknownGroupHead` (M1: sync, then retry). NO-OPEN. Also check that the head is covered by the signature (AUTH-09) | M0 core / M1 |
| REV-15 | P0 | Forget-device UI end to end | M + I | On the PC: Forget the phone in the tray UI. Share from the phone. Restart the PC and share again. Also test a prompt open at the moment of forget | No open (or prompt) after the forget, including across restart. A pending confirm prompt fails on click (`PendingOpen::confirm` re-check) | M1 |
| REV-16 | P0 | Relay learns nothing about membership | U + I (box-local relay) | Derive `mbx_e`/`kenc_e`/`wtok_e` (PROTOCOL §7.1 (a)) for two groups and two epochs; capture everything the relay stores and sees | Mailbox ids are unlinkable across groups and epochs and don't contain or hash the group id or device keys in a recomputable way; records are padded ciphertext; no ids or names in relay storage or logs | M2 |
| REV-17 | P0 | Removed device can't roll back or wipe its removal | I (FMP = removed device holding `gs_0..gs_e`) | After the removal, the FMP appends junk, old ops, a forked log and a replayed pre-removal record to `mbx_e`; tries delete/overwrite | Relay has no delete/overwrite; `mbx_e` is sealed; clients drop every junk record and still see the removal; roster unchanged | M2 |
| REV-18 | P0 | Removed device can't flood or write the new mailbox | I | FMP fills `mbx_e` to quota before the removal, then tries to append to `mbx_e` (after seal) and to guess/write `mbx_{e+1}` | Removal record still lands (sealing append exempt from quota); later appends to `mbx_e` refused; `mbx_{e+1}` unknown to it and writes without `wtok_{e+1}` refused; per-mailbox rate limit holds | M2 |
| REV-19 | P0 | Pull before trust after offline | I | PC2 offline during the removal; on reconnect only P2 (removed, withholding the op) reaches it, relay reachable | PC2 pulls from the relay before accepting P2's URL and refuses it (`Removed`). Then with the relay blocked: **fails open**: P2's URL is accepted on peer sync alone (M1 behaviour), the pull is retried, the last successful pull time is kept, and Paired devices shows "Couldn't check for removals since <time>" until a pull succeeds | M2 |
| REV-20 | P1 | No relay configured | I | LAN only / self-host off | Same as M1: peer `SYNC`/`OPS` + local Forget; no waiting on a relay; UI says "Removed on this PC…" | M2 |
| REV-22 | P1 | Mailbox limits and retention | I (box-local relay, fake clock) | Fill a mailbox to 1 MiB / 512 records; append at > 20/min; leave a mailbox untouched for 180 days, and another read (not written) every 179 days | Over-quota and over-rate appends refused, nothing evicted; untouched mailbox deleted whole after 180 days since last access; a read renews it just like an append | M2 |
| REV-21 | P0 | Remover's write is the only ack | I | Forget a device with the relay reachable, then unreachable | Reachable: one relay round trip, then "Removed". Unreachable: removal effective locally, UI says other devices learn on connect; no retry queue | M2 |

## 7. META: Relay and push see only padded ciphertext (P0)

| ID | Pri | Case | Method | Steps / assertion | Expected | MS |
|---|---|---|---|---|---|---|
| META-01 | P0 | Relay pcap and relay-side tap | E | Box-local `iroh-relay`, phone emulator in netns A, PC in netns B, direct path blocked. Send 50 marker URLs (`https://qa-marker-<random>.example/<random>`). Capture on the relay host and use the relay's internal tap | No marker, host, device name, group id, msg_id or receive key appears in any capture (grep the plaintext, UTF-16 and base64 forms) | M2 |
| META-02 | P0 | Padding buckets on the relay path | E | Send URLs of lengths 10, 400, 500, 1000, 2000 and 2900 | Envelope sizes are ∈ {512, 1024, 2048, 3072} + fixed HPKE overhead. Same-bucket URLs are indistinguishable by size | M2 |
| META-03 | P0 | Push payload capture (push-gw tap + mock FCM) | I | Capture the POST to push-gw and the gw→FCM request | The body holds only `{sealed, padded_ciphertext}` → FCM data. No URL, host, sender identity or group. FCM `collapse_key`/`notification` fields carry no plaintext. The notification is built on the device | M3 |
| META-04 | P0 | Padding on the push path | I | Bucket sizes as in META-02. Oversized messages are rejected at the sender with a message (§3) | Pass, see OQ-4 | M3 |
| META-05 | P0 | n0 discovery and default relays off | E | pcap/DNS log over a full M2 session | No queries to `dns.iroh.link` or pkarr, and no connection to n0 default relays. Only the roster's relay URL is used | M2 |
| META-06 | P1 | mDNS advertisement content | E | Capture mDNS on the LAN | Only what iroh needs (EndpointId). No device name, user name or group id | M1 |
| META-07 | P1 | push-gw logs and state | I | Run 1,000 pushes and inspect stdout/stderr, files and the process env | No tokens, sealed blobs or ciphertext logged. No disk writes. It is stateless across a restart | M3 |
| META-08 | P1 | Sealed token is bound to the gateway | U | A tampered `sealed` value, or one sealed under a different gw key | 4xx. Nothing is forwarded | M3 |
| META-09 | P1 | Relay sees only expected metadata | E | Document the relay's logs at the shipped log level | Matches the §3 table (IPs, EndpointIds, timing, sizes), nothing more | M2 |
| META-10 | P1 | Timing/size of the "most recently active PC" probe or log sync | E | Inspect for plaintext roster sync over the relay | Log sync runs inside QUIC/TLS between roster peers only | M4 |

## 8. Other areas

### 8.1 KEY: Key storage at rest
| ID | Pri | Case | Method | Steps / assertion | Expected | MS |
|---|---|---|---|---|---|---|
| KEY-01 | P1 | Windows: identity and receive keys are DPAPI-protected | M + I (Windows runner) | Search the app data dir for raw 32-byte key material and known test-vector keys. Copy the file to another Windows user or machine and try to load it | Not plaintext. Fails to load elsewhere | M1 |
| KEY-02 | P1 | Android: Keystore-wrapped | M + E (emulator, root) | Inspect `/data/data/<pkg>`. Check `allowBackup=false` / backup rules exclude keys. Check uninstall/reinstall behavior | Wrapped blobs only. Not in ADB or cloud backup | M1 |
| KEY-03 | P1 | Corrupt or missing key file | U + M | Truncate or delete the key blob | Fail closed: the app asks to re-pair. It **never** silently generates a new identity while keeping the old roster trust | M1 |
| KEY-04 | P1 | Receive-key rotation (monthly) | U (clock) | Advance 31 days | New key signed by the identity key and distributed. Old key accepted only during the grace period (pin it). Then `DecryptFailed` | M4 |
| KEY-05 | P1 | Secrets zeroized and never in crash dumps or logs | U + review | `zeroize` on secret types. Panic messages don't include key bytes | Pass | M1 |

### 8.2 GRP: Group membership, owner semantics, multi-device
| ID | Pri | Case | Method | Expected | MS |
|---|---|---|---|---|---|
| GRP-01 | P0 | Roles field present. Every v1 device is `owner`. A `guest`/`member` role from a crafted op is not granted extra rights. Unknown role is rejected | U | Pass | M4 |
| GRP-02 | P1 | Invite from any device (phone invites PC2). `add_device` is signed by the inviter. All members see an "added device" notice | I + M | Pass | M4 |
| GRP-03 | P1 | One send, one device: no surface (tray, extension popup or menu, IPC) offers a multi-device target, and an `all_phones` id is refused as an unpaired device. Most-recently-active-PC default. Per-device share-sheet target | I + M | Pass | M4 |
| GRP-04 | P1 | Two separate groups on one LAN never cross-accept | I | Pass | M4 |
| GRP-05 | P1 | 10-device group: log size stays a few KB and sync converges | U | Pass | M4 |

### 8.3 CLK: Clock skew
| ID | Pri | Case | Method | Expected | MS |
|---|---|---|---|---|---|
| CLK-01 | P0 | Phone clock +9 min or −9 min vs the PC | U + M | Accepted | M1 |
| CLK-02 | P0 | Skew of ±11 min | U + M | Rejected (NO-OPEN). **The sender sees a "clock out of sync" error** rather than silent failure. Needs a reject-reason feedback path or a documented limitation | M1 |
| CLK-03 | P0 | PC clock jumps backward 30 min after receiving m1, then m1 is replayed | U | The seen-cache is time-independent until eviction, so it is still rejected. Eviction uses a monotonic clock | M1 |
| CLK-04 | P2 | DST change / timezone change | U | Timestamps are UTC epoch. No effect | M1 |

### 8.4 OFF: Offline and queued delivery
| ID | Pri | Case | Method | Expected | MS |
|---|---|---|---|---|---|
| OFF-01 | P0 | Phone shares while the PC is offline, and the PC comes online 30 min later | E + M | Per OQ-11: either the send fails immediately ("PC is offline"), or the queued message is re-signed with a fresh timestamp **only with the user's action**. A stale queued message must not burst-open | M1 |
| OFF-02 | P1 | Network change mid-send (Wi-Fi to LTE) | E | Delivered once or failed with an error. Never twice | M2 |
| OFF-03 | P1 | Push to a phone that has been offline for 1 h, then reconnects | E | FCM delivers late, so the timestamp is stale and there is no notification, or behavior is otherwise defined | M3 |

### 8.5 FC: Fail-closed
| ID | Pri | Case | Method | Expected | MS |
|---|---|---|---|---|---|
| FC-01 | P0 | Fault injection at every stage | U (fault hooks) | Inject an error or panic in decrypt, verify, roster lookup, replay cache, rate limiter, validator, toast and log store. Opener calls == 0 for every injected fault. **Release builds use `panic = "abort"` (root `Cargo.toml`)**, so any remotely reachable panic kills the tray app and wipes the in-memory replay cache and rate limiter (see ENV-05, OQ-5). The fuzz targets must therefore show **zero panics** on inbound paths, and `unwrap`/indexing on attacker-controlled data is reviewed (e.g. `wire::decode`) | M1 (hooks H-14 deferred from M0) |
| FC-02 | P0 | Opener error | U | `ShellExecuteW` returns an error (≤ 32). Logged without the URL, no retry loop, toast "couldn't open" | M1 |
| FC-03 | P0 | Corrupt or partially written group log on disk | U | Load fails, so no roster, so **nothing opens** (not "empty roster = accept all"). The user is prompted to repair or re-pair | M1/M4 |
| FC-04 | P0 | Config tamper: missing limits config or validator flag | U | Safe defaults are used. There is no "disabled" value for the allow-list | M1 |

### 8.6 LOG: Logging hygiene
| ID | Pri | Case | Method | Expected | MS |
|---|---|---|---|---|---|
| LOG-01 | P0 | Run the whole automated suite at TRACE with `LogCapture` | I | No URL, host, `s`, key bytes, sealed token or SAS in any log line on any component. Reject logs show reason + sender short-id only | M1 |
| LOG-02 | P1 | Android logcat, Windows event log and crash reports during manual M1-M4 runs | M | Same as LOG-01 | M1-M4 |
| LOG-04 | P0 | `Debug` impls don't leak URLs or keys | U | `format!("{:?}")` of `wire::SignedMessage` (currently `#[derive(Debug)]` with `url` and `signed_bytes`, `core/src/wire.rs:37-48`), `VerifiedUrl`, pairing-secret types and the QR struct contains no marker URL or secret. `DeviceKeypair` already redacts | M1 |
| LOG-03 | P1 | No URL history persisted ("no history", §3) | M + I | grep the app data dirs after 20 opens | M1 |

### 8.7 FUNC: Milestone exit-criteria functional cases
| ID | Pri | Case | Method | Expected | MS |
|---|---|---|---|---|---|
| FUNC-01 | P1 | M0: hello-world tray from a GitHub pre-release installs on the PC. APK installs on the phone. CI green on Linux/Windows/macOS | M + CI | Pass | M0 |
| FUNC-02 | P1 | M1: 20 links from 3 apps (e.g. Chrome, YouTube, Reddit/X) on home Wi-Fi each open in < 2 s (measure share-tap to browser-foreground. Screen recording, or `ts` log on both sides) | M | 20/20 < 2 s | M1 |
| FUNC-03 | P1 | M2: phone on mobile data, PC at home, link opens via relay | M + E | Pass | M2 |
| FUNC-04 | P1 | M2: load test with 10k idle iroh connections on one $6-class box (relay CPU/mem/fd steady for 30 min) | E | Pass | M2 |
| FUNC-05 | P1 | M3: app swiped away, phone on mobile data. Right-click "Send to phone" (Chromium and Firefox) shows a notification within 5 s. Tapping it opens the link. The clipboard hotkey works too | M | 10/10 < 5 s | M3 |
| FUNC-06 | P1 | M4: 2 phones + 2 PCs. Invite from any device, remove, per-device targeting. The removed device can neither send nor receive (REV-*), and the others show the change | M + E | Pass | M4 |
| FUNC-07 | P1 | M3: native-messaging host manifest `allowed_origins` / `allowed_extensions` lists only our extension IDs. The pipe rejects other local users | I + M | Pass | M3 |

---

## 9. Milestone exit criteria → required tests

The exit criteria are quoted from PLAN.md §8. "All P0 for MS" means every P0 whose MS column is that milestone or earlier.

| MS | PLAN.md exit criterion (quoted) | Must pass |
|---|---|---|
| M0 | "CI green on 3 OSes. Install a hello-world tray app on PC and an APK on phone from a GitHub pre-release." | FUNC-01. Plus the M0 core deliverables: H-1..H-6, one `RejectReason`, redacting `Debug`, `verify_strict`, the release-build gate, and confirm-before-open as default. These are verified by the P0s marked "M0 core" (AUTH-04..12, AUTH-15, PAIR-01/02/04-07/09/10/13-15/20, RL-01..07, URL-01..11/13/14/16/18/21, ENV-01..04/06/08/09/11/12/16, REV-01/04/14, CLK-01..03, LOG-04) against the in-process harness. Results: `qa-m0-report.md` in QA's working directory |
| M1 | "Pair and open 20 links from 3 different apps on home Wi-Fi, each opening in under 2 s. **QA confirms non-http(s), oversized and unpaired-sender messages are rejected.**" | FUNC-02. All of AUTH-01..17, PAIR-01..15, PAIR-20, RL-01..03, RL-06..08, URL-01..11, URL-13..18, URL-20, URL-21, ENV-01..13, ENV-16, ENV-17, LOG-04, CLK-01..03, OFF-01, FC-01..04, LOG-01, **ENV-05 (now expected PASS: fsync'd seen-ID store lands in M1)**, PAIR-08 (race, deferred from M0), REV-01, REV-13..15 (Forget-device UI), REV-05 direct remove-op fan-out (M1 part). P1 PAIR-16..19, KEY-01..03, KEY-05, META-06, AUTH-16, URL-22 |
| M2 | "Works with the phone on mobile data. **A packet capture on the relay shows only ciphertext.** A load test holds 10k idle connections on one box." | FUNC-03, FUNC-04, META-01, META-02, META-05, ENV-14, RL-10, OFF-02, META-09, REV-05 (relay pull), REV-16..22 (pull-based revocation mailbox, PROTOCOL §7.1), plus M1 regression |
| M3 | "With the app swiped away and the phone on mobile data, right-click 'Send to phone' shows a notification within 5 s, and tapping it opens the link." | FUNC-05, FUNC-07, META-03, META-04, META-07, META-08, URL-19, AUTH-13 (pipe), RL-11, RL-12, OFF-03, plus regression |
| M4 | "2 phones + 2 PCs … **A removed device can neither send nor receive, and the others show the change.**" | FUNC-06, REV-01..15 (REV-06 as a documented residual risk), RL-04, RL-05, GRP-01..05, KEY-04, ENV-10 (rotation), META-10, plus full regression |
| M5 | "Ubuntu/GNOME and macOS pass the M1–M4 test script." | URL-11/URL-12 on real `xdg-open`/`open`, plus the full suite on Linux/macOS |

## 10. Release gate: v1 no-prompt opening

**v1 no-prompt opening on the PC is not enabled unless every P0 in this document passes on the release candidate, on CI (Linux + Windows) and manually on real Android + Windows hardware.** The specific conditions are:
- No-prompt (`OpenImmediately`) is the default (`opener::OpenMode::default()`, fresh PC state) and "Ask before opening" (`ConfirmBeforeOpen`) is a setting, off by default; saved choices are kept. AUTH-17 must still pass so the mode can't be skipped, and tests `default_mode_opens_without_prompt_via_deliver`, `ask_before_opening_mode_waits_for_confirm`, `removed_between_verify_and_open_is_refused_in_both_modes` must pass (gate `default-no-prompt-ask-setting`). The remaining conditions below still gate the **v1 public release**.
- ENV-05 passes (persisted, fsync'd seen-ID store, M1).
- REV-06 is a **documented residual risk** (PROTOCOL §7, THREAT-MODEL §6.2). "Accepted" means the risk is documented, not that the test is skipped: REV-06 (a) and (b) must pass.
- ENV-16 and ENV-17 pass: encryption on, and no release-gate bypass through a profile with `debug_assertions`, or through dev-profile pre-releases (OQ-17).
- Fuzz targets (URL-17, ENV-13, REV-10) have run ≥ 24 h cumulative on the RC commit with 0 crashes. Release builds use `panic = "abort"`, so any inbound panic is a remote restart.
- Any change to `core` crypto, the protocol, the validator, the opener or `verify` after the gate re-runs all P0s.

## 11. Harness / hooks needed in core (asks for the SE)

Each ask is listed with what it enables. H-1..H-6 are needed **by the start of M1** (stubs at M0 are fine).

| # | Ask | Notes |
|---|---|---|
| H-1 | **`UrlOpener` trait** in `desktop` (`fn open(&self, canon: &str) -> Result<()>`). Real implementations: Windows `ShellExecuteW`, plus macOS/Linux `Command` (no shell). A `SpyOpener` records calls and **never spawns anything in tests**. The opener takes a `VerifiedUrl` newtype that only the verify pipeline can construct | AUTH-*, URL-*, NO-OPEN invariant |
| H-2 | **Injectable `Clock`**. Partly met: `time.rs` says time is passed explicitly everywhere. Keep it that way for `Inbox::receive`, pairing expiry, replay and ratelimit, and add a monotonic source for eviction. No hidden `UnixMillis::now()` calls inside verification. CI greps for this | PAIR-04..07, ENV-03/04, RL-*, CLK-*, KEY-04 |
| H-3 | **Injectable RNG / deterministic keys** (seeded `CryptoRng` behind a `test-util` feature, **compiled out of release**, plus a release-build check that it is absent). Today `MsgId::random` and `DeviceKeypair::generate` hard-wire `OsRng`. `from_secret_bytes` covers fixed keys | Test vectors, PAIR-13/14, ENV-15 |
| H-4 | **Structured `RejectReason` enum** returned or emitted for every drop. Today there are separate `wire::DecodeError` and `envelope::EnvelopeError`; please map them into one enum (`NotInRoster`, `PairingNotActive`, `UnexpectedFrame`, `BadSignature`, `SenderMismatch`, `WrongRecipient`, `WrongGroup`, `Removed`, `DecryptFailed`, `MalformedFrame`, `UnsupportedVersion`, `Replay`, `StaleTimestamp`, `FutureTimestamp`, `CacheFull`, `RateLimitedDevice`, `RateLimitedGlobal`, `SchemeNotAllowed`, `UrlHasUserinfo`, `UrlTooLong`, `UrlBadChars`, `UrlParseError`, `PairingSecretUnknown`, `PairingSecretUsed`, `PairingSecretExpired`, `PairingHmacBad`, `SasRejected`, `Internal`) plus a test event bus/channel to observe them | Every negative test |
| H-5 | **Fake malicious peer (FMP)** crate (`core/tests/fmp` or a `urlshare-testpeer` bin). It must be able to: use a fresh key or a stolen/paired key; dial on any ALPN; skip or abort the pairing handshake at any step; send raw bytes or crafted frames; forge `sender_id`/`group`/`recipient_id`/timestamp/msg_id; sign with any key; seal to any receive key; replay, duplicate, reorder, truncate and bit-flip recorded frames; and hold a stale group log that withholds ops | AUTH, PAIR, ENV, REV |
| H-6 | **Pipeline entry point below transport**: `verify::Inbox::receive(transport_peer_id, envelope_bytes, now)` callable from tests, taking the transport peer id so OQ-6 binding is enforced there, so envelope checks are tested independently of the QUIC accept filter (defense in depth) | AUTH-06/07, ENV-* |
| H-7 | **Pairing-secret store inspection**: `pairing::store_snapshot()` (test-util) showing active secrets, consumed flag and expiry, plus a hook to pause between "HMAC verified" and "secret consumed" for race tests | PAIR-08, PAIR-15 |
| H-8 | **Rate-limiter config injection** (`L_dev`, burst, `L_glob`, window) and counters exposed for tests | RL-* |
| H-9 | **Revocation API callable in tests** (`group::remove_device(id)` → op), **log import of arbitrary op sets** (to simulate gossip order and withheld ops), and a membership re-check hook right before the opener (REV-04) | REV-* |
| H-10 | **Relay/push capture tap**: the box-local `iroh-relay` run in docker-compose with a pcap sidecar; a `push-gw` test mode that dumps raw request bodies to a QA dir; a mock FCM endpoint (`FCM_BASE_URL` override) | META-*, RL-11 |
| H-11 | **Fuzz entry points** (`cargo fuzz` targets in `core/fuzz`): `validate_url`, `parse_frame`, `open_envelope` (fixed key), `parse_pair_qr`, `parse_device_cert`, `apply_group_ops` | URL-17, ENV-13, REV-10 |
| H-12 | **Test-vector file** `core/tests/vectors/*.json`: QR strings, transcripts → HMAC → SAS, envelope sign input → signature → HPKE sealed bytes, padding outputs, URL raw → canon/reject reason. These are shared by the Kotlin/Swift bindings later | AUTH-09, PAIR-13, URL-01 |
| H-13 | **`LogCapture`** test subscriber (tracing layer) for grep assertions, plus a `NotifierSpy` for toasts/notifications | LOG-*, NO-OPEN |
| H-14 | **Fault-injection points** (`fail` crate or cfg(test) hooks) at decrypt, verify, roster, cache, limiter, validator, opener | FC-01 |
| H-15 | **Exported constants**. Mostly met by `limits.rs` and `envelope::PAD_BUCKETS`. Still needed: a push-path URL cap, plus a replay-cache retention constant (≥ 2 × window) | URL-08, PAIR-04..06, ENV-04/06 |
| H-16 | **Windows test URL handler**: a CI script that registers a temp `http`/`https` handler (HKCU) logging argv, and restores it afterward. Runs on the GitHub Windows runner only | URL-10, URL-20 |
| H-17 | **netns e2e script** on the box: phone (emulator or CLI peer) and PC (headless core) in separate namespaces, with a toggle to block the direct path (forcing relay) | META-01/02, ENV-14, OFF-02 |
| H-18 | **Headless desktop core binary** (`urlshare-desktop --headless --opener=spy`) so e2e runs without a GUI | E-method tests |

### 11.1 Harness status after M0 (Software Engineer, Oct 9, 2026)

Architecture decisions are recorded in [PROTOCOL.md §8](PROTOCOL.md#8-architecture-decisions) and [THREAT-MODEL.md](THREAT-MODEL.md). Names below are the real ones in `core`.

| # | Status | Where / deferred to |
|---|---|---|
| H-1 | **Done (M0).** `opener::UrlOpener::open(VerifiedUrl)` (by value) lives in `core` (not `desktop`) so mobile/desktop share it; `test_util::SpyOpener`; `SystemOpener` = direct `ShellExecuteW` / `/usr/bin/xdg-open` / `/usr/bin/open`, no `open` crate (banned in deny.toml + CI). `opener::deliver` re-checks membership before opening. | core/src/opener.rs |
| H-2 | **Done (M0).** `time::Now { wall, mono }` passed into `Inbox::receive`, pairing, replay, rate limits; `time::SystemClock` is the only system-clock read (CI grep); `test_util::FakeClock` with `advance` / `set_wall`. | core/src/time.rs |
| H-3 | **Done (M0).** `DeviceKeypair::generate_with(rng)`, `MsgId::random_with(rng)`, `PairingRegistry::issue(now, rng)`; `test_util::seeded_rng`, `keypair_from_label`. `test-util` feature has `compile_error!` without `debug_assertions`; CI checks a release build with it fails. | core/src/test_util.rs |
| H-4 | **Done (M0).** Single `reject::RejectReason` (all names from this table, plus `StaleGroupHead`, `UnknownGroupHead`, `FromSelf`, `UrlMissingHost`, `SasTimeout`). Event channel: `Inbox::counters()` (per-reason counts, labels never contain message content). A push-style event bus is deferred to M1 with the transport. | core/src/reject.rs, verify.rs |
| H-5 | **Done for M1** (Oct 10): `net::phone` test hooks (`fake_peer_for_tests`, `send_envelope_for_tests`, `raw_request_for_tests`, `adopt_pc_for_tests`) dial the PC over real QUIC on both ALPNs, send crafted/sealed/raw frames, replay and tamper; used by `core/tests/e2e_net.rs`. Stale log that withholds ops: M4. *Before:* **Partly done (M0).** `test_util::FakePeer`: any key, forged fields (`forged`, `RawBody`), arbitrary signatures, raw frames (`seal_raw`), replay, bit-flips, truncation; used by `core/tests/inbound.rs`. **Deferred to M1:** dialing over iroh/ALPN, aborting the pairing handshake mid-way, sealing to receive keys (HPKE). **M4:** stale group log that withholds ops. | core/src/test_util.rs |
| H-6 | **Done (M0).** `Inbox::receive(roster, transport_peer, bytes, now)`; `SenderMismatch` enforced (OQ-6 made normative). | core/src/verify.rs |
| H-7 | **Done (M0).** `PairingRegistry::snapshot()` (ids, expiry, spent reason; no secret bytes). The pause hook between "HMAC verified" and "consumed" is unnecessary: the secret is consumed **before** the HMAC is checked. Concurrency race test (PAIR-08) **deferred to M1** when the registry sits behind the transport's lock. | core/src/pairing.rs |
| H-8 | **Done (M0).** `InboxConfig { per_device, global, timestamp_window_ms, replay_cache_max_entries }`; `Inbox::tokens_available`. | core/src/verify.rs |
| H-9 | **Partly done.** `Roster::remove_device` (local "Forget this device", immediate) and the pre-open re-check exist. Log import of arbitrary op sets **deferred to M4** (group log). | core/src/roster.rs |
| H-10 | **Deferred:** relay tap → M2; push-gw test mode + mock FCM → M3. | |
| H-11 | **Deferred to M1** (`cargo fuzz` targets). Decode/validate are already panic-free on all tested inputs. | |
| H-12 | **Deferred to M1** (vectors once HPKE fixes the sealed bytes). | |
| H-13 | **Deferred to M1** (no logging exists yet in core). LOG-04 `Debug` redaction is **done** and tested. | |
| H-14 | **Deferred to M1.** | |
| H-15 | **Done (M0).** `limits::MAX_PUSH_URL_BYTES = 2048`, `REPLAY_RETENTION_MS = 2 × window`, `envelope::PAD_BUCKETS`. | core/src/limits.rs |
| H-16 | **Deferred to M1** (Windows runner). | |
| H-17 | **Deferred to M2.** | |
| H-18 | **Deferred to M1** (headless desktop needs the transport). | |

**QA check at `9e682b4` (rev 2):** H-1, H-2, H-3, H-4, H-6 and H-8 are present and used by `core/tests/inbound.rs`. H-5 is partial, as stated above. H-15 is present. Gaps are in `qa-m0-report.md` in QA's working directory.

Resolved OQs: OQ-1 (limits: burst 5/device, 20/min global; invalid-but-authenticated messages count), OQ-2 (typed SAS + device name), OQ-3 (consumed on first attempt; expired at ≥120 s; SAS timeout 120 s), OQ-4 (buckets 512/1K/2K/4K/8K + 8K+256 top bucket; push cap 2048), OQ-5 (persisted fsync'd seen-ID store, M1), OQ-6 (sender == transport peer), OQ-7 (direct remove op + log head in every message; REV-06 residual risk documented), OQ-10 (Forget this device in M1), OQ-12 (confirm-before-open default; changed 10-11-2026 to no-prompt default with "Ask before opening" setting), OQ-14 (version byte, canonical signature input, strict padding: PROTOCOL.md §3–4), OQ-16 (no `open` crate), OQ-8 (allow RFC 1918/ULA, reject loopback/link-local/unspecified), OQ-9 (phone-side different-group warning, M1; PC side n/a). Still open: OQ-11, OQ-13 (partly: no webview IPC, strict CSP), OQ-15.

### 11.2 M1 status (Software Engineer, Oct 10, 2026)

Automated, all in `cargo test --workspace` (plus the Android JVM tests):
- `core/tests/e2e_net.rs` (real UDP/QUIC on loopback, PC node = desktop core service without UI, Rust phone client): QR pairing with the typed code (PAIR-01), QR consumed by the first attempt (PAIR-02/12), wrong code (PAIR-20/AUTH-04), 20 sends with latency (FUNC), prompt then click and no-prompt delivery, rejections over the socket path: non-http(s) (URL), oversized (URL-cap), unpaired sender refused at the socket (AUTH-01), replay (ENV), tampered ciphertext and wrong receive key (ENV), wrong recipient, and Forget this device reaching the phone as a signed remove op (REV). Restart test: replay is still refused after a PC restart (ENV-05). mDNS discovery test (opt-in, `VOIDWIRE_E2E_MDNS=1`).
- `core/src/ffi.rs`: the exported Android `Phone` object end to end against a PC node (pair, used QR, send, refused scheme, reload from storage, removal).
- Android JVM (`PhoneFfiTest`, `ShareParsingTest`): bindings against the host core, foreign storage persistence, readable errors (incl. `inspectPairing` and `beginPairing(qr, false)` on junk QRs), ZXing decode of a pairing QR.
- Android Robolectric (`ShareActivityTest`, AUTH-18): programmatic launch, repeated/new intents, backgrounded intent and restored state never send; taps too early, without focus or while paused don't count; an explicit tap after 500 ms sends exactly once; unknown PC / invalid link never sends; `TapGate` rules.
- QA M1 fixes, core: prompt expiry + `NoSuchPrompt` (AUTH-20, `e2e_net`), replay file hardening and fail-closed startup (ENV-18, `replay.rs` / `state.rs` tests), clean in-process restart (`one_inbox_per_process.rs`), phone fallback to fresh mDNS on a poisoned or dead cached address (`e2e_net`, opt-in mDNS), OQ-9 group change and forged `n=` (`e2e_net`, PAIR-11), zeroize compile-time checks (`keys.rs`).
- Gates: `confirm-window-no-focus-steal` (AUTH-19), `nsis-firewall-private` now also requires `remoteip=localsubnet`.
- Manual on the build box: desktop pair window + `core/examples/phone_sim` (pair, send, confirm window → Open launched the browser).

Still manual (QA, real network): docs/M1-TEST-SHEET.md (Android + Windows on home Wi-Fi; now with the tap-to-send share step, a rejected-link step, the burst-of-5 check, Forget, uninstall + firewall-rule-removed check, troubleshooting and the different-group warning), PAIR-19, AUTH-14 visual check, AUTH-19 focus behaviour on Windows, firewall Private-only + local-subnet behaviour.

**Harness items landing per milestone (unchanged):** the Robolectric share-target harness (injectable `ShareBackend`, clock and IO dispatcher in `ShareActivity`) landed in M1 for AUTH-18; H-14 fault hooks, H-11 fuzz targets and H-17 netns e2e remain as scheduled in the table above.

## 12. Open questions and resolved design items

**Resolved design decisions (PROTOCOL.md §8):**
- **OQ-1 rate limits:** per device burst 5 (refill 10/min), global 20/min. Invalid-but-authenticated messages count. Residual: 2 paired flooders can use the whole global budget (RL-05, accepted under threat model #1).
- **OQ-2 SAS UX:** the confirm screen shows the device name, and the user types the joiner's 6-digit code (PAIR-12, PAIR-20).
- **OQ-3 secret consumption:** consumed on the first attempt of any kind. Hard 120 s expiry, expired at ≥ 120 s. SAS timeout 120 s.
- **OQ-4 sizes:** buckets 512/1K/2K/4K/8K (+8448). URL cap 8 KiB on LAN/relay, 2,048 on push.
- **OQ-5 replay after restart:** the seen-ID cache is persisted and fsync'd. ENV-05 is expected to pass from M1 (M0 has the seam only).
- **OQ-6:** inner sender == transport peer is normative (`SenderMismatch`).
- **OQ-7 revocation:** the signed remove op goes directly to members via `SYNC`/`OPS` on every connect; **pull-based**, no relay queue/retry/ack. From M2 the relay holds the group's latest signed ops in an append-only, group-encrypted mailbox that devices pull before trusting peers (PROTOCOL §7.1). Every message carries the log head, and a stale head is rejected. "Forget this device" is local and ships in M1. **Residual REV-06 risk documented for the alpha.**
- **OQ-10:** "Forget this device" is in the M1 UI (core API exists at M0).
- **OQ-12:** no-prompt is the default; "Ask before opening" is a setting.
- **OQ-14:** version byte, canonical signature input and strict padding are specified (PROTOCOL §3-4).
- **OQ-16:** no `open` crate (banned in deny.toml + CI). Direct `ShellExecuteW`. Single exec of `/usr/bin/xdg-open` / `/usr/bin/open` with no fallback.
- **OQ-8 (Oct 9):** RFC 1918 and IPv6 ULA hosts allowed; loopback, link-local and unspecified rejected in every spelling (PROTOCOL §9.1.1).
- **OQ-9 (Oct 10; done in M1):** a phone already in a group that scans a QR for a different group gets "This will join a different device group (named X)", Cancel by default, and pairs only after an explicit Join (PAIR-11, PROTOCOL §6.7). "Different group" is judged from the authenticated inviter (owner/member of a signed log the phone holds), not from the QR's `g=` (fixed after the QA re-check); duplicate PC names warn too. **The PC side doesn't apply in M1**: the PC only shows QRs and never scans one.

**Still open:**
- **OQ-11 offline/queue semantics.** Recommend no queue in v1 and a "PC is offline" error.
- **OQ-13 local attack surface.** M1: the desktop now has Tauri commands, scoped **per window** by capabilities (pair / devices / confirm windows each get only their own commands; none takes a URL, none grants shell/opener/fs), `withGlobalTauri: true` (only `invoke` is used), strict CSP, no deep-link handler, no CLI parsing; the Android app exports only the launcher and the `text/plain` share target (no deep links). *M0 state:* no Tauri commands, empty capabilities, `withGlobalTauri: false`, a strict CSP, no deep-link handler and no CLI parsing. Native-messaging pipe ACL/message types are still to specify (M3).
- **OQ-15** Android Keystore wrapping of Ed25519 (M1, KEY-02).

**New from the M0 review (details in the M0 QA report):**
- **OQ-17 release gates key on `debug_assertions`.** `CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true cargo build --release` compiles with the encryption stub and with `test-util`. Early M0/M1 pre-releases were dev-profile builds, so neither gate applies to them. Once networking lands in M1, a pre-release could ship without HPKE. Gate on a dedicated cfg or on the artifacts (ENV-17).
- **OQ-18 confirm-before-open and "the app's roster" hold by convention.** Any in-process code can mint a `VerifiedUrl` against a self-made `Roster` (public API, no unsafe) and call `UrlOpener::open` directly, skipping `deliver`'s mode and re-check (AUTH-17). Make `open` require an `ApprovedOpen` that only `deliver` / `PendingOpen::confirm` produce. Consider having `Inbox` own (or be bound to) the roster.
- **OQ-19 cost before the per-device limit (M1).** From M1, HPKE open and `verify_strict` run before the per-device bucket. Only roster peers get that far, and the transport peer id is already authenticated, so a cheap pre-decrypt bucket keyed on `transport_peer` would cap a compromised device's CPU cost.
- **OQ-20 CI gates fail open and are grep-based.** `cargo tree`/`cargo build` failures for any reason (network, lockfile) count as "gate passed". The clock grep misses aliases (`use SystemTime as T; T::now()`) and `.elapsed()`. The shell grep misses `"/bin/sh"`, `"powershell.exe"` and absolute `cmd.exe` paths (clippy's `Command::new` ban catches the spawns, though). Suggest clippy `disallowed-methods` for `SystemTime::now`/`Instant::now`/`elapsed`, and gates that check the specific error text.

## 13. M4.1: pairing core, state v2 and relay supervisor

All automated; no UI changes. Real-hardware checks are in the release test sheet.

| Area | Test | Where |
|---|---|---|
| Pairing log | Genesis needs both signatures; co-signed ops round-trip; ops without a valid co-signature (or co-signed by a third device) are refused on apply and on load; `Rename` is self-only and `Unpair` is self-signed, final and local; `Rekey` epochs go up by exactly one; `Caps` gates v2; compaction keeps state; a stored log with a broken chain is refused | `core/src/pairwise/tests.rs` |
| Renames (M4.5) | A rename reaches the peer on the next connection (and at once on a live one), both ways; it survives a restart; only the latest unsent rename waits; crossing renames converge (one re-signed); a forged, foreign, truncated or padded frame changes nothing; a local nickname wins over the peer's name | `core/src/net/pair_ops.rs` tests, `core/tests/e2e_v2_files.rs` (`v2_pc_rename_reaches_the_phone`, `v2_phone_rename_reaches_the_pc_after_a_restart`, `v2_renames_on_both_sides_both_land`) |
| Convergence (property) | Random interleavings of concurrent proposals, drops and re-proposals over many seeds: both replicas end on the same head and state; the lower-hash op wins | `concurrent_proposals_converge_property`, `concurrent_proposals_lower_hash_wins` |
| Legacy split | Both ends compute the same legacy pairing id; one pairing per peer; a forgotten device stays gone | `legacy_ids_match_on_both_sides`, `sync_legacy_splits_one_pairing_per_peer` |
| State v2 | A damaged pairings section (public fields, sealed secrets or its MAC) fails closed; the 17th pairing is refused on both sides | `core/tests/state_damage.rs`, `mailbox/tests/m43_pair.rs` |
| Limits | 16 pairings, 8 saved relays, 4 relays in use | `relay_settings_limits`, `seventeenth_pairing_is_refused_on_both_sides` |
| Supervisor (pure) | Park after 30 s; at most 8 probes in the first hour after parking; four dead relays at the cap make about 8 attempts an hour in total; healthy relays are never touched; 60 s unpark grace, flapping relays keep backing off; network change and Retry reset the backoff; phone background never retries away relays | `core/src/relay_supervisor.rs` tests |
| Supervisor (live) and cost bench | `tools/relay-bench` (CI job `relay-bench`): real iroh relays on loopback behind counting TCP/UDP proxies that can play "relay down" | thresholds below |

**relay-bench thresholds (CI fails on any):**
- a dead home relay is parked;
- at most 8 supervisor probes in the first hour after parking (timings compressed 60x);
- with real timings, everything that still reaches a parked dead home relay is at most 15 % of the unsupervised rate. Each rate is measured over at least 180 s (the CI run uses 240 s windows): iroh's redials come every 16-32 s, so a 60 s window held only 2-4 of them and the result swung by whole events. The parked hour is the measured redial rate plus the supervisor's first-hour probe count (taken from the compressed run), not a short window scaled up;
- with real timings, after the relay comes back and a network change, it reconnects with exactly one probe-and-unpark and a peer can dial in through it;
- direct (IP) paths form in standard mode and in the lighter background check mode;
- the lighter background check cuts idle packet events per hour by at least a third.

**Measured (loopback, iroh 1.3, Oct 2026, 240 s windows; ranges are across local and CI runs), per hour:**

| Setup | Packet events | Bytes | TCP connects | Direct path |
|---|---|---|---|---|
| Idle, standard (today) | ~1,650-2,400 (CI v0.5.1: 1,680) | ~0.8-1.2 MB | 0 | yes |
| Idle, lighter background check | ~840-1,300 (about half of standard) | ~100-115 KB | ~60-75 | yes |
| Dead home relay, no supervisor | — | — | ~1,320-1,440, plus UDP probes | — |
| Dead home relay, parked | — | — | ~165-180 (iroh's own redials, plus 3-8 supervisor probes in the first hour), no UDP | — |

The idle rows are measurements, not thresholds: CI checks only that the lighter check cuts standard by at least a third (v0.5.1 CI run: 1,680 vs 960), so a standard figure below the old ~1,800 floor is not a failure.

The lighter check stays off by default until it is confirmed on real phones (direct LAN connections still form, battery and data drop). *Residual:* iroh 1.3 keeps redialing its home relay after it is removed from the relay map (there is no API to stop it short of closing the endpoint), so the "8 attempts an hour" bound holds for the supervisor's probes and for non-home relays, not for iroh's leftover redials to a dead home relay.

---

*Rev 4 (Software Engineer, Oct 10, QA M1 re-check fixes): C1 on-device smoke test (`DeviceSmokeTest`, `scripts/android-smoke.sh`, emulator without KVM) plus the `Phone()`-without-init unit test; PAIR-11 bypass test; L1 overlay tests (ShareActivityTest +4); L2 high-water tests (ENV-18); L3 cold-process mDNS fallback (e2e, `VOIDWIRE_E2E_MDNS=1`). No new case IDs.*

*Rev 3 (Software Engineer, Oct 10, M1 QA fixes): added AUTH-18 (P0), AUTH-19, AUTH-20, ENV-18 (P0); PAIR-11 status; OQ-8/OQ-9 resolved. **150 cases, 107 P0** (AUTH 17/20, ENV 17/18, others unchanged).*

*Counts (rev 2): **146 cases, 105 P0** (AUTH 16/17, PAIR 16/20, RL 8/13, URL 19/22, ENV 16/17, REV 14/15, META 5/10, CLK 3/4, FC 4/4, LOG 2/4, OFF 1/3, GRP 1/5, KEY 0/5, FUNC 0/7; P0/total). Rev 1 was 140 cases / 100 P0. The "158" reported in rev 1 wrongly counted the 18 harness rows (H-1..H-18) as cases. Test IDs are stable. New cases append numbers and never renumber.*
