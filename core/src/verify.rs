#![forbid(unsafe_code)]
//! Inbound verification: the **only** producer of [`VerifiedUrl`].
//!
//! Entry point (TEST-PLAN H-6): `Inbox::receive(transport_peer, bytes, now)`.
//!
//! The `Inbox` **owns** the roster it verifies against (D2 / AUTH-17): there is
//! no way to hand `receive` some other device list, and every `VerifiedUrl`
//! is tagged with the inbox that minted it, so it can only be delivered or
//! confirmed through that same inbox (`opener::deliver`, `PendingOpen::confirm`).
//! Order (cheap and unauthenticated checks first, docs/THREAT-MODEL.md §4):
//!
//! 1. transport peer is an active roster member (`NotInRoster` / `Removed`):
//!    nothing is parsed or decrypted for strangers
//!    then (D13) a per-peer pre-decryption budget keyed on the authenticated
//!    transport peer (`RateLimitedPeer`), before any HPKE or signature work
//! 2. envelope shape, HPKE open with our receive key (`DecryptFailed`),
//!    strict unpad, strict decode
//! 3. inner sender == transport peer (`SenderMismatch`), sender != self
//! 4. group == ours, recipient == us
//! 5. Ed25519 `verify_strict` under the sender's key (weak keys can't exist:
//!    `DeviceId` refuses them at parse)
//! 6. per-device rate limit (counts every authenticated message, valid or not)
//! 7. sender's group-log head is current (`StaleGroupHead` / `UnknownGroupHead`)
//! 8. timestamp within ±10 min, inclusive (`StaleTimestamp` / `FutureTimestamp`)
//! 9. replay cache (`Replay` / `CacheFull`)
//! 10. global rate limit
//! 11. URL policy (http/https, no userinfo, RFC 3986 canon, ≤ 8 KiB)
//!
//! Only if every step passes is a `VerifiedUrl` constructed.

use crate::envelope;
use crate::ids::{DeviceId, MsgId};
use crate::keys::{ReceiveKeypair, ReceivePublicKey};
use crate::limits::{
    DEFAULT_GLOBAL_BURST, DEFAULT_GLOBAL_PER_MINUTE, DEFAULT_PER_DEVICE_BURST,
    DEFAULT_PER_DEVICE_PER_MINUTE, DEFAULT_PRE_DECRYPT_BURST, DEFAULT_PRE_DECRYPT_PER_MINUTE,
    RATE_BURST_MAX, RATE_BURST_MIN, RATE_PER_MINUTE_MAX, RATE_PER_MINUTE_MIN,
    REPLAY_CACHE_MAX_ENTRIES, REPLAY_CACHE_MAX_ENTRIES_CEILING, REPLAY_CACHE_MIN_ENTRIES,
    TIMESTAMP_WINDOW_MAX_MS, TIMESTAMP_WINDOW_MIN_MS, TIMESTAMP_WINDOW_MS,
};
use crate::pairing::ConfirmedPairing;
use crate::ratelimit::{RateLimit, TokenBucket};
use crate::reject::RejectReason;
use crate::replay::{NoPersistence, ReplayCache, ReplayVerdict, SeenIdStore};
use crate::roster::{HeadStatus, MemberStatus, Role, Roster};
use crate::time::Now;
use crate::url_policy;
use crate::wire;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Identity of one `Inbox` instance (process-unique, never reused).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InboxTag(u64);

static NEXT_INBOX_TAG: AtomicU64 = AtomicU64::new(1);

/// R1: at most one **live** production `Inbox` per process. Set when one is
/// built, cleared only by that Inbox's `Drop` (clean in-process restart).
static PRODUCTION_INBOX_CREATED: AtomicBool = AtomicBool::new(false);

/// A URL that passed every check in [`Inbox::receive`].
///
/// * Fields are private; there is no public constructor.
/// * No `Clone`, `Copy`, `Default`, `From`/`TryFrom`, `FromStr` or serde impls.
/// * Not exported over UniFFI.
///
/// Holding one is proof it came out of the verify path. The opener
/// ([`crate::opener::UrlOpener::open`]) only accepts this type, by value.
pub struct VerifiedUrl {
    url: url::Url,
    sender: DeviceId,
    msg_id: MsgId,
    inbox: InboxTag,
}

impl VerifiedUrl {
    /// The canonical URL that was checked (and is what gets opened).
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// ASCII (punycode) host, for the "Open link?" prompt and UI events.
    pub fn host_for_display(&self) -> &str {
        self.url.host_str().unwrap_or("")
    }

    pub fn sender(&self) -> DeviceId {
        self.sender
    }

    pub fn msg_id(&self) -> MsgId {
        self.msg_id
    }

    pub(crate) fn inbox_tag(&self) -> InboxTag {
        self.inbox
    }
}

impl fmt::Debug for VerifiedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedUrl")
            .field("sender", &self.sender)
            .field("url", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InboxConfig {
    /// D13: charged per authenticated transport peer *before* decryption.
    pub pre_decrypt: RateLimit,
    pub per_device: RateLimit,
    pub global: RateLimit,
    pub timestamp_window_ms: u64,
    pub replay_cache_max_entries: usize,
}

/// An `InboxConfig` field outside its floor/ceiling (limits.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("inbox config field `{field}` is out of range")]
pub struct InboxConfigError {
    pub field: &'static str,
}

impl InboxConfig {
    /// Reject out-of-range values (D5 / FC-04). Called by every `Inbox` constructor.
    pub fn validate(&self) -> Result<(), InboxConfigError> {
        let rate = |r: &RateLimit, burst: &'static str, pm: &'static str| {
            if !(RATE_BURST_MIN..=RATE_BURST_MAX).contains(&r.burst) {
                return Err(InboxConfigError { field: burst });
            }
            if !(RATE_PER_MINUTE_MIN..=RATE_PER_MINUTE_MAX).contains(&r.per_minute) {
                return Err(InboxConfigError { field: pm });
            }
            Ok(())
        };
        rate(
            &self.pre_decrypt,
            "pre_decrypt.burst",
            "pre_decrypt.per_minute",
        )?;
        rate(
            &self.per_device,
            "per_device.burst",
            "per_device.per_minute",
        )?;
        rate(&self.global, "global.burst", "global.per_minute")?;
        if !(TIMESTAMP_WINDOW_MIN_MS..=TIMESTAMP_WINDOW_MAX_MS).contains(&self.timestamp_window_ms)
        {
            return Err(InboxConfigError {
                field: "timestamp_window_ms",
            });
        }
        if !(REPLAY_CACHE_MIN_ENTRIES..=REPLAY_CACHE_MAX_ENTRIES_CEILING)
            .contains(&self.replay_cache_max_entries)
        {
            return Err(InboxConfigError {
                field: "replay_cache_max_entries",
            });
        }
        Ok(())
    }
}

impl Default for InboxConfig {
    fn default() -> Self {
        InboxConfig {
            pre_decrypt: RateLimit {
                burst: DEFAULT_PRE_DECRYPT_BURST,
                per_minute: DEFAULT_PRE_DECRYPT_PER_MINUTE,
            },
            per_device: RateLimit {
                burst: DEFAULT_PER_DEVICE_BURST,
                per_minute: DEFAULT_PER_DEVICE_PER_MINUTE,
            },
            global: RateLimit {
                burst: DEFAULT_GLOBAL_BURST,
                per_minute: DEFAULT_GLOBAL_PER_MINUTE,
            },
            timestamp_window_ms: TIMESTAMP_WINDOW_MS,
            replay_cache_max_entries: REPLAY_CACHE_MAX_ENTRIES,
        }
    }
}

/// Visible counters (TEST-PLAN H-4/H-8). Labels come from
/// [`RejectReason::label`], never from message content.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InboxCounters {
    pub accepted: u64,
    pub rejected: HashMap<&'static str, u64>,
}

impl InboxCounters {
    pub fn rejected_for(&self, r: &RejectReason) -> u64 {
        self.rejected.get(r.label()).copied().unwrap_or(0)
    }
}

/// Why an `Inbox` could not be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InboxError {
    #[error(transparent)]
    Config(#[from] InboxConfigError),
    /// R1: this process already has a live `Inbox`.
    #[error("this process already has a live Inbox (one at a time)")]
    SecondInbox,
}

/// Receiver state for this device: **its roster**, its receive key, rate
/// limiters, replay cache, counters. **One live per process** (R1): a second
/// [`Inbox::new`] / [`Inbox::with_store`] fails with `SecondInbox` while the
/// first exists. Dropping it releases the slot, so a PC node can be shut down
/// and started again in the same process; links verified by the old Inbox
/// stay bound to its (never reused) tag and are refused by the new one
/// (`ForeignInbox`). (The test harness has an unchecked constructor; it is
/// refused in release and shipping builds.) In-process hostile code is outside
/// the guarantee (THREAT-MODEL §2).
pub struct Inbox {
    tag: InboxTag,
    /// This Inbox holds the process-wide R1 slot (production constructors).
    holds_slot: bool,
    roster: Roster,
    receive: ReceiveKeypair,
    config: InboxConfig,
    pre_decrypt: HashMap<DeviceId, TokenBucket>,
    global: Option<TokenBucket>,
    per_device: HashMap<DeviceId, TokenBucket>,
    replay: ReplayCache,
    counters: InboxCounters,
}

impl Inbox {
    /// Take ownership of the app's roster and receive key. Config is
    /// validated (D5). In-memory replay cache only: apps use [`Inbox::with_store`]
    /// with an fsync'd [`crate::replay::FileSeenIdStore`] (ENV-05).
    pub fn new(
        roster: Roster,
        receive: ReceiveKeypair,
        config: InboxConfig,
    ) -> Result<Self, InboxError> {
        Self::with_store(roster, receive, config, Box::new(NoPersistence))
    }

    /// With a seen-id persistence backend (the app's fsync'd file).
    pub fn with_store(
        roster: Roster,
        receive: ReceiveKeypair,
        config: InboxConfig,
        store: Box<dyn SeenIdStore + Send>,
    ) -> Result<Self, InboxError> {
        config.validate()?;
        if PRODUCTION_INBOX_CREATED.swap(true, Ordering::SeqCst) {
            return Err(InboxError::SecondInbox);
        }
        let mut inbox = Self::build(roster, receive, config, store);
        inbox.holds_slot = true;
        Ok(inbox)
    }

    /// Test harness only: no one-per-process check (tests run many inboxes
    /// in one process). Refused in release/shipping builds with `test-util`.
    #[cfg(feature = "test-util")]
    pub fn new_unchecked_for_tests(
        roster: Roster,
        receive: ReceiveKeypair,
        config: InboxConfig,
        store: Box<dyn SeenIdStore + Send>,
    ) -> Result<Self, InboxError> {
        config.validate()?;
        Ok(Self::build(roster, receive, config, store))
    }

    fn build(
        roster: Roster,
        receive: ReceiveKeypair,
        config: InboxConfig,
        store: Box<dyn SeenIdStore + Send>,
    ) -> Self {
        Inbox {
            tag: InboxTag(NEXT_INBOX_TAG.fetch_add(1, Ordering::Relaxed)),
            holds_slot: false,
            roster,
            receive,
            config,
            pre_decrypt: HashMap::new(),
            global: None,
            per_device: HashMap::new(),
            replay: ReplayCache::new(config.replay_cache_max_entries, store),
            counters: InboxCounters::default(),
        }
    }

    /// Our receive public key (goes into our device certificate).
    /// (R1 slot release: see `impl Drop for Inbox`.)
    pub fn receive_public(&self) -> ReceivePublicKey {
        self.receive.public()
    }

    pub(crate) fn tag(&self) -> InboxTag {
        self.tag
    }

    /// Read-only view of the roster this inbox verifies against.
    pub fn roster(&self) -> &Roster {
        &self.roster
    }

    /// L2: the seen-id store's high-water mark, for the app's state blob.
    pub fn replay_high_water(&self) -> Option<crate::replay::HighWater> {
        self.replay.high_water()
    }

    /// The only way to add a device: consume a typed-SAS `ConfirmedPairing`.
    pub fn add_paired_device(&mut self, pairing: ConfirmedPairing, role: Role) -> DeviceId {
        self.roster.add_paired_device(pairing, role)
    }

    /// "Forget this device": local, immediate. Pending prompts from it can no
    /// longer be confirmed (they re-check this roster).
    pub fn forget_device(&mut self, id: &DeviceId) -> bool {
        let changed = self.roster.remove_device(id);
        let roster = &self.roster;
        self.per_device
            .retain(|d, _| roster.status(d) == MemberStatus::Active);
        self.pre_decrypt
            .retain(|d, _| roster.status(d) == MemberStatus::Active);
        changed
    }

    /// Undo [`Inbox::forget_device`] when the new state could not be saved.
    /// Rate-limit buckets dropped by the forget start fresh.
    pub fn rekey(&mut self, payload: crate::mailbox::RekeyPayload) -> bool {
        self.roster.rekey(payload)
    }

    /// Rename an active device in the roster and update its signed certificate (`M2.8`).
    pub fn rename_device(
        &mut self,
        id: &DeviceId,
        name: String,
        cert: Option<crate::keys::DeviceCert>,
    ) -> bool {
        self.roster.rename_device(id, name, cert)
    }

    #[cfg_attr(not(feature = "net"), allow(dead_code))]
    pub(crate) fn undo_forget(&mut self, id: &DeviceId) -> bool {
        self.roster.undo_last_remove(id)
    }

    pub fn counters(&self) -> &InboxCounters {
        &self.counters
    }

    /// Tokens left for one device / globally (visible counters).
    pub fn tokens_available(&mut self, device: &DeviceId, now: Now) -> (u32, u32) {
        let d = self
            .per_device
            .get_mut(device)
            .map(|b| b.available(now.mono))
            .unwrap_or(self.config.per_device.burst);
        let g = self
            .global
            .as_mut()
            .map(|b| b.available(now.mono))
            .unwrap_or(self.config.global.burst);
        (d, g)
    }

    /// Verify one inbound envelope that arrived on a connection authenticated
    /// as `transport_peer` (the iroh EndpointId in M1).
    pub fn receive(
        &mut self,
        transport_peer: &DeviceId,
        envelope_bytes: &[u8],
        now: Now,
    ) -> Result<VerifiedUrl, RejectReason> {
        let r = self.receive_inner(transport_peer, envelope_bytes, now);
        match &r {
            Ok(_) => self.counters.accepted += 1,
            Err(e) => *self.counters.rejected.entry(e.label()).or_insert(0) += 1,
        }
        r
    }

    fn receive_inner(
        &mut self,
        peer: &DeviceId,
        envelope_bytes: &[u8],
        now: Now,
    ) -> Result<VerifiedUrl, RejectReason> {
        let roster = &self.roster;
        // 1. strangers get nothing parsed
        match roster.status(peer) {
            MemberStatus::Active => {}
            MemberStatus::Removed => return Err(RejectReason::Removed),
            MemberStatus::Unknown => return Err(RejectReason::NotInRoster),
        }
        if *peer == roster.self_id() {
            return Err(RejectReason::FromSelf);
        }

        // 1b. D13: cheap per-peer budget before any decryption/verification.
        //     Keyed on the authenticated transport peer (only active members
        //     get here), so it bounds a compromised device's CPU cost.
        let pre_limit = self.config.pre_decrypt;
        let pre = self
            .pre_decrypt
            .entry(*peer)
            .or_insert_with(|| TokenBucket::new(pre_limit, now.mono));
        if !pre.try_take(now.mono) {
            return Err(RejectReason::RateLimitedPeer);
        }

        // 2. shape, HPKE open, strict unpad, strict decode
        let body = envelope::open(&self.receive, &roster.self_id(), envelope_bytes)?;
        let msg = wire::decode(&body)?;

        // 3. binding to the transport identity
        if msg.sender != *peer {
            return Err(RejectReason::SenderMismatch);
        }

        // 4. addressing
        if msg.group != roster.group() {
            return Err(RejectReason::WrongGroup);
        }
        if msg.recipient != *roster.self_id().as_bytes() {
            return Err(RejectReason::WrongRecipient);
        }

        // 5. authenticity
        let key = msg
            .sender
            .verifying_key()
            .ok_or(RejectReason::BadSignature)?;
        key.verify_strict(&wire::signing_input(&msg.signed_part), &msg.signature())
            .map_err(|_| RejectReason::BadSignature)?;

        // 6. per-device budget: every authenticated message counts (RL-06),
        //    keyed only by the authenticated sender (RL-07).
        let per_device_limit = self.config.per_device;
        let bucket = self
            .per_device
            .entry(msg.sender)
            .or_insert_with(|| TokenBucket::new(per_device_limit, now.mono));
        if !bucket.try_take(now.mono) {
            return Err(RejectReason::RateLimitedDevice);
        }

        // 7. revocation: sender must not be behind our group log
        match self.roster.head_status(&msg.log_head) {
            HeadStatus::Current => {}
            HeadStatus::Behind => return Err(RejectReason::StaleGroupHead),
            HeadStatus::Unknown => return Err(RejectReason::UnknownGroupHead),
        }

        // 8. freshness (inclusive window, no overflow: abs_diff on u64)
        let w = self.config.timestamp_window_ms;
        if msg.timestamp.0 < now.wall.0 && now.wall.0 - msg.timestamp.0 > w {
            return Err(RejectReason::StaleTimestamp);
        }
        if msg.timestamp.0 > now.wall.0 && msg.timestamp.0 - now.wall.0 > w {
            return Err(RejectReason::FutureTimestamp);
        }

        // 9. replay
        match self
            .replay
            .check_and_insert(&msg.sender, &msg.msg_id, msg.timestamp, now)
        {
            ReplayVerdict::Fresh => {}
            ReplayVerdict::Replay => return Err(RejectReason::Replay),
            ReplayVerdict::Full => return Err(RejectReason::CacheFull),
            ReplayVerdict::PersistFailed => return Err(RejectReason::Internal),
            ReplayVerdict::StartupGuard => return Err(RejectReason::ReplayStartupGuard),
        }

        // 10. global budget (per-device first, so a flooder's rejects don't
        //     consume it: RL-05)
        let global_limit = self.config.global;
        let global = self
            .global
            .get_or_insert_with(|| TokenBucket::new(global_limit, now.mono));
        if !global.try_take(now.mono) {
            return Err(RejectReason::RateLimitedGlobal);
        }

        // 11. URL policy on the canonical form
        let url = url_policy::check_url(&msg.url)?;

        Ok(VerifiedUrl {
            url,
            sender: msg.sender,
            msg_id: msg.msg_id,
            inbox: self.tag,
        })
    }

    /// Verify an inbound `FILE_OFFER` envelope that arrived on a connection
    /// authenticated as `transport_peer` (`M26-H1`).
    ///
    /// Enforces all [`Inbox::receive`] gates:
    /// 1. Active roster membership (`NotInRoster` / `Removed`) and `peer != self`.
    /// 2. Pre-decrypt rate limit (`RateLimitedPeer`).
    /// 3. HPKE open, inner sender/group/recipient binding, Ed25519 `verify_strict`,
    ///    and static offer policy (`open_file_offer`).
    /// 4. Per-device rate limit (`RateLimitedDevice`).
    /// 5. Group-log head check (`StaleGroupHead` / `UnknownGroupHead`).
    /// 6. Timestamp freshness (`±timestamp_window_ms` for initial offers,
    ///    `< expires_at` for an active `.part` resume).
    /// 7. Replay cache (`seen.bin`) on initial offers (`!is_active_resume`).
    /// 8. Global rate limit (`RateLimitedGlobal`).
    pub fn verify_file_offer<F>(
        &mut self,
        transport_peer: &DeviceId,
        envelope_bytes: &[u8],
        is_active_resume: F,
        now: Now,
    ) -> Result<
        (
            crate::file_transfer::FileOffer,
            crate::file_transfer::FileTransferKey,
        ),
        RejectReason,
    >
    where
        F: FnOnce(&crate::file_transfer::FileOffer) -> bool,
    {
        let r = self.verify_file_offer_inner(transport_peer, envelope_bytes, is_active_resume, now);
        match &r {
            Ok(_) => self.counters.accepted += 1,
            Err(e) => *self.counters.rejected.entry(e.label()).or_insert(0) += 1,
        }
        r
    }

    fn verify_file_offer_inner<F>(
        &mut self,
        peer: &DeviceId,
        envelope_bytes: &[u8],
        is_active_resume: F,
        now: Now,
    ) -> Result<
        (
            crate::file_transfer::FileOffer,
            crate::file_transfer::FileTransferKey,
        ),
        RejectReason,
    >
    where
        F: FnOnce(&crate::file_transfer::FileOffer) -> bool,
    {
        // 1. Strangers get nothing parsed
        match self.roster.status(peer) {
            MemberStatus::Active => {}
            MemberStatus::Removed => return Err(RejectReason::Removed),
            MemberStatus::Unknown => return Err(RejectReason::NotInRoster),
        }
        if *peer == self.roster.self_id() {
            return Err(RejectReason::FromSelf);
        }

        // 1b. Per-peer pre-decrypt rate limit before HPKE/signature work
        let pre_limit = self.config.pre_decrypt;
        let pre = self
            .pre_decrypt
            .entry(*peer)
            .or_insert_with(|| TokenBucket::new(pre_limit, now.mono));
        if !pre.try_take(now.mono) {
            return Err(RejectReason::RateLimitedPeer);
        }

        // 2-5. HPKE open, strict unpad, decode, sender/group/recipient binding, Ed25519 verify_strict
        let self_id = self.roster.self_id();
        let group = self.roster.group();
        let (offer, k_file) = crate::file_transfer::open_file_offer(
            &self.receive,
            &self_id,
            &group,
            peer,
            envelope_bytes,
        )?;

        // 6. Group-log head check (`M26-R1`: unconditional, matching `Inbox::verify`)
        match self
            .roster
            .head_status(&crate::ids::LogHead(offer.log_head))
        {
            HeadStatus::Current => {}
            HeadStatus::Behind => return Err(RejectReason::StaleGroupHead),
            HeadStatus::Unknown => return Err(RejectReason::UnknownGroupHead),
        }

        let active_resume = is_active_resume(&offer);
        if active_resume {
            if let Some(pre) = self.pre_decrypt.get_mut(peer) {
                pre.refund_one();
            }
        }

        // 7. Freshness check
        let w = self.config.timestamp_window_ms;
        if !active_resume {
            if offer.issued_at.0 < now.wall.0 && now.wall.0 - offer.issued_at.0 > w {
                return Err(RejectReason::StaleTimestamp);
            }
            if offer.issued_at.0 > now.wall.0 && offer.issued_at.0 - now.wall.0 > w {
                return Err(RejectReason::FutureTimestamp);
            }
        }
        if now.wall.0 >= offer.expires_at.0 {
            return Err(RejectReason::StaleTimestamp);
        }

        // 8. Replay cache (`seen.bin`): record initial offers so completed/cancelled/declined
        //    transfers cannot be replayed during the 24h retention window, while allowing
        //    legitimate resume of an active in-progress transfer (`active_resume == true`).
        if !active_resume {
            let msg_id = MsgId(offer.transfer_id.0);
            match self
                .replay
                .check_and_insert(&offer.sender, &msg_id, offer.issued_at, now)
            {
                ReplayVerdict::Fresh => {}
                ReplayVerdict::Replay => return Err(RejectReason::Replay),
                ReplayVerdict::Full => return Err(RejectReason::CacheFull),
                ReplayVerdict::PersistFailed => return Err(RejectReason::Internal),
                ReplayVerdict::StartupGuard => return Err(RejectReason::ReplayStartupGuard),
            }
        }

        // 9. Per-device rate limit (for new offers)
        if !active_resume {
            let per_device_limit = self.config.per_device;
            let bucket = self
                .per_device
                .entry(offer.sender)
                .or_insert_with(|| TokenBucket::new(per_device_limit, now.mono));
            if !bucket.try_take(now.mono) {
                return Err(RejectReason::RateLimitedDevice);
            }
        }

        // 10. Global rate limit (for new offers; active resume / pending-accept polls do not burn global quota, M27-H1)
        if !active_resume {
            let global_limit = self.config.global;
            let global = self
                .global
                .get_or_insert_with(|| TokenBucket::new(global_limit, now.mono));
            if !global.try_take(now.mono) {
                return Err(RejectReason::RateLimitedGlobal);
            }
        }

        Ok((offer, k_file))
    }
}

impl Drop for Inbox {
    /// R1: free the process slot so a clean restart can build a new Inbox.
    /// Only the Inbox that took the slot releases it.
    fn drop(&mut self) {
        if self.holds_slot {
            PRODUCTION_INBOX_CREATED.store(false, Ordering::SeqCst);
        }
    }
}
