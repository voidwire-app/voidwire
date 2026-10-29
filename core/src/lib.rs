//! `voidwire-core`: the one implementation of the protocol, crypto and inbound
//! verification shared by every platform.
//!
//! # The opener guarantee (core security invariant)
//!
//! A URL can only reach the OS opener as a [`verify::VerifiedUrl`]. That type has
//! private fields, no public constructor, and no `Clone`/`Default`/`From`/serde
//! impls, so the **only** way to obtain one is [`verify::Inbox::receive`], which
//! rejects anything that is not:
//!
//! 1. delivered by a transport peer that is an active (paired, not removed)
//!    roster member, and claiming to be that same peer,
//! 2. addressed to this device in this group,
//! 3. correctly signed (`verify_strict`) by that member's Ed25519 key,
//! 4. from a sender whose group-log head is not behind ours,
//! 5. fresh (±10 min) and not a replay,
//! 6. within the per-device and global rate limits,
//! 7. an `http`/`https` URL, no userinfo, RFC 3986 canonical form, at most
//!    [`limits::MAX_URL_BYTES`].
//!
//! The `Inbox` **owns** the app's roster (no way to verify against another
//! device list), and every `VerifiedUrl` is tagged with the inbox that minted it.
//!
//! [`opener::UrlOpener::open`] takes an [`opener::OpenApproval`] *by value*.
//! Approvals are minted only by [`opener::deliver`] (no-prompt mode, the default
//! since 10-11-2026) and [`opener::PendingOpen::confirm`]
//! (the user clicked "Open"). Both refuse URLs from another inbox and re-check
//! the sender's membership right before opening. So the opener cannot be called
//! with a `String`, a `Url`, a bare `VerifiedUrl`, or anything that skipped those
//! checks. None of these types is exported over UniFFI.
//!
//! ```compile_fail,E0451
//! // Struct-literal construction is impossible outside the verify module.
//! fn f(u: url::Url, s: voidwire_core::ids::DeviceId, m: voidwire_core::ids::MsgId) -> voidwire_core::verify::VerifiedUrl {
//!     voidwire_core::verify::VerifiedUrl { url: u, sender: s, msg_id: m }
//! }
//! ```
//!
//! ```compile_fail,E0277
//! // There is no From<String>/From<Url> conversion.
//! let u: voidwire_core::verify::VerifiedUrl = String::from("https://example.com").into();
//! ```
//!
//! ```compile_fail,E0599
//! // Not Clone: a verified URL is opened at most once.
//! fn f(v: voidwire_core::verify::VerifiedUrl) { let _a = v.clone(); }
//! ```
//!
//! AUTH-17 (QA probe p01): the opener can't be called with a bare `VerifiedUrl`,
//! skipping `deliver`/`confirm` (OpenMode and the membership re-check).
//!
//! ```compile_fail,E0308
//! use voidwire_core::opener::UrlOpener;
//! fn launder(o: &dyn UrlOpener, v: voidwire_core::verify::VerifiedUrl) {
//!     let _ = o.open(v);
//! }
//! ```
//!
//! An `OpenApproval` can't be built outside the opener module.
//!
//! ```compile_fail,E0451
//! use voidwire_core::{opener::OpenApproval, verify::VerifiedUrl};
//! fn mint(v: VerifiedUrl) -> OpenApproval { OpenApproval { url: v } }
//! ```
//!
//! Nor can a `PendingOpen` (which `confirm` would turn into an approval).
//!
//! ```compile_fail,E0451
//! use voidwire_core::{opener::PendingOpen, verify::VerifiedUrl};
//! fn mint(v: VerifiedUrl) -> PendingOpen { PendingOpen { url: v } }
//! ```
//!
//! `receive` can't be pointed at some other roster (p01 passed its own).
//!
//! ```compile_fail,E0061
//! use voidwire_core::{ids::DeviceId, roster::Roster, time::Now, verify::Inbox};
//! fn f(i: &mut Inbox, r: &Roster, p: &DeviceId, b: &[u8], n: Now) {
//!     let _ = i.receive(r, p, b, n);
//! }
//! ```
//!
//! There's no roster-less `Inbox`.
//!
//! ```compile_fail,E0599
//! let _ = voidwire_core::verify::Inbox::default();
//! ```

pub mod clipboard;
pub mod disk;
pub mod envelope;
pub mod file_transfer;
pub mod grouplog;
pub mod ids;
pub mod keys;
pub mod limits;
pub mod mailbox;
#[cfg(feature = "net")]
pub mod net;
pub mod opener;
pub mod pairing;
pub mod pairwise;
pub mod protocol;
pub mod ratelimit;
pub mod reject;
pub mod relay_supervisor;
pub mod replay;
pub mod roster;
pub mod time;
pub mod url_policy;
pub mod verify;
pub mod wire;

pub mod hex;

#[cfg(feature = "test-util")]
pub mod test_util;

#[cfg(feature = "ffi")]
mod ffi;
#[cfg(feature = "ffi")]
mod platform_init;

#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!();

// Release gates: envelope encryption is on (envelope.rs const assert), and the
// test harness never builds in release/shipping builds (test_util.rs, build.rs).

/// Crate version, for "about" screens and bug reports.
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");
