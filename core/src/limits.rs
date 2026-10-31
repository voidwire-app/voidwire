//! Hard limits. One place, so QA, the threat model and tests cite the same
//! numbers (TEST-PLAN H-15). Decisions: docs/PROTOCOL.md §8.

/// Max URL length (bytes, measured on the canonical form) on LAN/relay.
pub const MAX_URL_BYTES: usize = 8 * 1024;

/// Max URL length on the push path (PC → phone via FCM/APNs). Keeps the sealed
/// payload under FCM's 4 KB data limit.
pub const MAX_PUSH_URL_BYTES: usize = 2048;

/// Accepted clock skew between sender timestamp and receiver wall clock.
/// Inclusive: |ts − now| ≤ window is accepted.
pub const TIMESTAMP_WINDOW_MS: u64 = 10 * 60 * 1000;

/// How long a seen (sender, msg_id) is remembered: 2 × window, so a message
/// stamped at the far future edge is still covered until it goes stale.
pub const REPLAY_RETENTION_MS: u64 = 2 * TIMESTAMP_WINDOW_MS;

/// Upper bound on remembered message ids. If full we fail closed (reject) rather
/// than evict, because eviction would re-open a replay window.
pub const REPLAY_CACHE_MAX_ENTRIES: usize = 20_000;

/// Pairing secrets expire this long after issue. Expired at `>= TTL` (exclusive).
pub const PAIRING_SECRET_TTL_MS: u64 = 120 * 1000;

/// M4.3: a v2 pairing code (typed code, its rendezvous card and its v=2 QR)
/// lives this long. Typing ~30 characters on another device takes longer
/// than a scan, so it gets 5 minutes instead of the QR's 2. The code is
/// still single use and its card is deleted on use, cancel, replace or
/// expiry. Must stay below the spent-secret memory (`10 * PAIRING_SECRET_TTL_MS`).
pub const PAIRING_CODE_TTL_MS: u64 = 5 * 60 * 1000;

/// After a valid pairing proof, the inviter must type the SAS within this time.
pub const SAS_CONFIRM_TTL_MS: u64 = 120 * 1000;

/// A confirm-before-open prompt on the PC is dropped if it isn't answered
/// within this time (an old link can't be opened hours later). Also the
/// ceiling for `PcConfig::prompt_ttl_ms`.
pub const PENDING_PROMPT_TTL_MS: u64 = 120 * 1000;

/// Max device-name length accepted in a pairing request (bytes).
pub const MAX_DEVICE_NAME_BYTES: usize = 64;

/// Per-device rate limit (decision: burst 5). Sustained refill 10/min.
pub const DEFAULT_PER_DEVICE_BURST: u32 = 5;
pub const DEFAULT_PER_DEVICE_PER_MINUTE: u32 = 10;

/// D13: per-peer budget charged before decryption (cheap, keyed on the
/// authenticated transport peer). Looser than the per-device budget so it only
/// bites on floods.
pub const DEFAULT_PRE_DECRYPT_BURST: u32 = 20;
pub const DEFAULT_PRE_DECRYPT_PER_MINUTE: u32 = 60;

/// Global rate limit across all devices (decision: 20/min).
pub const DEFAULT_GLOBAL_BURST: u32 = 20;
pub const DEFAULT_GLOBAL_PER_MINUTE: u32 = 20;

/// Bounds enforced by `InboxConfig::validate` (D5 / TEST-PLAN FC-04). Out of
/// range values are rejected, never clamped silently.
pub const RATE_BURST_MIN: u32 = 1;
pub const RATE_BURST_MAX: u32 = 10_000;
pub const RATE_PER_MINUTE_MIN: u32 = 1;
pub const RATE_PER_MINUTE_MAX: u32 = 10_000;
/// The window can be narrowed for tests but never widened past the default:
/// replay retention ([`REPLAY_RETENTION_MS`]) is sized from the default window,
/// so a wider window would let a replay outlive its cache entry.
pub const TIMESTAMP_WINDOW_MIN_MS: u64 = 30_000;
pub const TIMESTAMP_WINDOW_MAX_MS: u64 = TIMESTAMP_WINDOW_MS;
pub const REPLAY_CACHE_MIN_ENTRIES: usize = 1;
pub const REPLAY_CACHE_MAX_ENTRIES_CEILING: usize = 1_000_000;

/// Maximum UTF-8 byte length for inline `MessageKind::ClipboardText` inside a single
/// 8,448-byte padded HPKE envelope (`M3-PLAN.md` §2.2: 7.5 KiB = 7,680 bytes).
pub const MAX_INLINE_CLIPBOARD_BYTES: usize = 7_680;

/// Maximum UTF-8 byte length for streamed clipboard text (`M3-PLAN.md` §2.3: 10 MiB).
pub const MAX_STREAMED_CLIPBOARD_BYTES: usize = 10 * 1024 * 1024;

/// Default maximum pending envelopes per RAM-only blind device inbox (`M3-PLAN.md` §1.4.2).
pub const DEFAULT_INBOX_MAX_ITEMS: usize = 4;
pub const INBOX_MAX_ITEMS_MIN: usize = 1;
pub const INBOX_MAX_ITEMS_MAX: usize = 256;

/// Default TTL in seconds for each item in a RAM-only blind device inbox (`M3-PLAN.md` §1.4.2).
pub const DEFAULT_INBOX_TTL_SECS: u64 = 3_600;
pub const INBOX_TTL_SECS_MIN: u64 = 60;
pub const MAX_INBOX_TTL_SECS: u64 = 604_800;

/// Default global RAM ceiling across all device inboxes on `voidwire-mailbox` (`M3-PLAN.md` §1.4.2: 32 MiB).
pub const DEFAULT_INBOX_MAX_TOTAL_BYTES: usize = 33_554_432;
pub const INBOX_MAX_TOTAL_BYTES_MIN: usize = 65_536;
pub const INBOX_MAX_TOTAL_BYTES_MAX: usize = 1_073_741_824;

// A spent secret is remembered for `10 * PAIRING_SECRET_TTL_MS`; a code must
// expire well before that so a replay is always answered "used".
const _: () = assert!(PAIRING_CODE_TTL_MS < 10 * PAIRING_SECRET_TTL_MS);
