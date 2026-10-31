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
//! 1. transport peer is an active roster member (`NotPaired` / `Removed`):
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
//! 7. (removed in message format 2: messages no longer carry a group-log head;
//!    an unpaired link is deleted, so its peer fails step 1)
//! 8. timestamp within ±10 min, inclusive (`StaleTimestamp` / `FutureTimestamp`)
//! 9. replay cache (`Replay` / `CacheFull`)
//! 10. global rate limit
//! 11. URL policy (http/https, no userinfo, RFC 3986 canon, ≤ 8 KiB)
//!
//! Only if every step passes is a `VerifiedUrl` constructed.

use crate::envelope;
use crate::ids::{DeviceId, GroupId, MsgId};
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
use crate::roster::{MemberStatus, Role, Roster};
use crate::time::Now;
use crate::url_policy;
use crate::wire;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// Identity of one `Inbox` instance (process-unique, never reused).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InboxTag(u64);

static NEXT_INBOX_TAG: AtomicU64 = AtomicU64::new(1);

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
    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

/// Verified inline clipboard text that passed every check in [`Inbox::receive_message`]
/// or [`Inbox::receive_from_device_inbox`] (`M3-PLAN.md` §2.2 & §2.5).
pub struct VerifiedClipboard {
    text: String,
    sensitive: bool,
    sender: DeviceId,
    msg_id: MsgId,
    #[allow(dead_code)]
    inbox: InboxTag,
}

impl VerifiedClipboard {
    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn into_string(self) -> String {
        self.text
    }

    pub fn is_sensitive(&self) -> bool {
        self.sensitive
    }

    pub fn sender(&self) -> DeviceId {
        self.sender
    }

    pub fn msg_id(&self) -> MsgId {
        self.msg_id
    }

    #[allow(dead_code)]
    pub(crate) fn inbox_tag(&self) -> InboxTag {
        self.inbox
    }
}

impl fmt::Debug for VerifiedClipboard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedClipboard")
            .field("sender", &self.sender)
            .field("sensitive", &self.sensitive)
            .field("text", &"<redacted>")
            .finish()
    }
}

/// Verified offline file-offer wake pointer (`MessageKind::FileWake`, `M3-PLAN.md` §1.5 & §2.2).
pub struct VerifiedFileWake {
    transfer_id: [u8; 16],
    size_bytes: u64,
    expires_at: crate::time::UnixMillis,
    filename: String,
    is_executable: bool,
    sender: DeviceId,
    msg_id: MsgId,
    #[allow(dead_code)]
    inbox: InboxTag,
}

impl VerifiedFileWake {
    pub fn transfer_id(&self) -> [u8; 16] {
        self.transfer_id
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn expires_at(&self) -> crate::time::UnixMillis {
        self.expires_at
    }

    pub fn filename(&self) -> &str {
        &self.filename
    }

    pub fn is_executable(&self) -> bool {
        self.is_executable
    }

    pub fn sender(&self) -> DeviceId {
        self.sender
    }

    pub fn msg_id(&self) -> MsgId {
        self.msg_id
    }

    #[allow(dead_code)]
    pub(crate) fn inbox_tag(&self) -> InboxTag {
        self.inbox
    }
}

impl fmt::Debug for VerifiedFileWake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedFileWake")
            .field("sender", &self.sender)
            .field("transfer_id", &self.transfer_id)
            .field("size_bytes", &self.size_bytes)
            .field("expires_at", &self.expires_at)
            .field("is_executable", &self.is_executable)
            .field("filename", &"<redacted>")
            .finish()
    }
}

/// A verified pairing notice (M4.2): the signed pairing-log op it carries
/// is checked again by the pairing log before anything acts on it.
pub struct VerifiedPairNotice {
    op: Vec<u8>,
    sender: DeviceId,
    #[allow(dead_code)]
    inbox: InboxTag,
}

impl VerifiedPairNotice {
    pub fn op_bytes(&self) -> &[u8] {
        &self.op
    }

    pub fn sender(&self) -> DeviceId {
        self.sender
    }
}

impl fmt::Debug for VerifiedPairNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedPairNotice")
            .field("sender", &self.sender)
            .field("len", &self.op.len())
            .finish()
    }
}

/// Any verified message produced by [`Inbox::receive_message`] or
/// [`Inbox::receive_from_device_inbox`] (`M3-PLAN.md` §2.2).
#[derive(Debug)]
pub enum VerifiedMessage {
    Url(VerifiedUrl),
    Clipboard(VerifiedClipboard),
    FileWake(VerifiedFileWake),
    PairNotice(VerifiedPairNotice),
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
}

/// Who an inbox accepts messages from: a whole roster (the PC hub and tests,
/// until the roster is removed), or exactly one v2 pairing's peer.
enum Members {
    Roster(Roster),
    Link(PeerBinding),
}

/// One v2 pairing as its verifier sees it (M4-ROSTER-REMOVAL §2): only `peer`
/// may send, under `pairing_id`, to `me`. Built only from a live `PairLink`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PeerBinding {
    pub pairing_id: GroupId,
    pub me: DeviceId,
    pub peer: DeviceId,
}

impl Members {
    fn status(&self, id: &DeviceId) -> MemberStatus {
        match self {
            Members::Roster(r) => r.status(id),
            Members::Link(b) if *id == b.peer => MemberStatus::Active,
            Members::Link(_) => MemberStatus::Unknown,
        }
    }
    fn self_id(&self) -> DeviceId {
        match self {
            Members::Roster(r) => r.self_id(),
            Members::Link(b) => b.me,
        }
    }
    fn group(&self) -> GroupId {
        match self {
            Members::Roster(r) => r.group(),
            Members::Link(b) => b.pairing_id,
        }
    }
    /// The one peer a link accepts (`None` for a roster).
    fn only_peer(&self) -> Option<DeviceId> {
        match self {
            Members::Roster(_) => None,
            Members::Link(b) => Some(b.peer),
        }
    }
}

/// Receiver state for this device: **its roster**, its receive key, rate
/// limiters, replay cache, counters. The apps build one per pairing (one per
/// link); one live PC node per process is enforced by `PcNode`. URLs verified
/// by one Inbox stay bound to its (never reused) tag and are refused by any
/// other (`ForeignInbox`). In-process hostile code is outside the guarantee
/// (THREAT-MODEL §2).
pub struct Inbox {
    tag: InboxTag,
    members: Members,
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
        Ok(Self::build(roster, receive, config, store))
    }

    /// The verifier for one v2 pairing (phone and PC links): accepts only
    /// `binding.peer`. Validates `config`.
    #[cfg(any(feature = "net", feature = "test-util"))]
    pub(crate) fn for_link(
        binding: PeerBinding,
        receive: ReceiveKeypair,
        config: InboxConfig,
        store: Box<dyn SeenIdStore + Send>,
    ) -> Result<Self, InboxError> {
        config.validate()?;
        Ok(Self::build_members(
            Members::Link(binding),
            receive,
            config,
            store,
        ))
    }

    /// Point a link verifier at the pairing's current binding, keeping its
    /// replay state. Rate-limit buckets of anyone else are dropped.
    #[cfg(feature = "net")]
    pub(crate) fn rebind(&mut self, binding: PeerBinding) {
        self.members = Members::Link(binding);
        self.per_device.retain(|d, _| *d == binding.peer);
        self.pre_decrypt.retain(|d, _| *d == binding.peer);
    }

    fn build(
        roster: Roster,
        receive: ReceiveKeypair,
        config: InboxConfig,
        store: Box<dyn SeenIdStore + Send>,
    ) -> Self {
        Self::build_members(Members::Roster(roster), receive, config, store)
    }

    fn build_members(
        members: Members,
        receive: ReceiveKeypair,
        config: InboxConfig,
        store: Box<dyn SeenIdStore + Send>,
    ) -> Self {
        Inbox {
            tag: InboxTag(NEXT_INBOX_TAG.fetch_add(1, Ordering::Relaxed)),
            members,
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

    /// Read-only view of the roster this inbox verifies against (`None` for
    /// a v2 link verifier, which has no roster).
    pub fn roster(&self) -> Option<&Roster> {
        match &self.members {
            Members::Roster(r) => Some(r),
            Members::Link(_) => None,
        }
    }

    /// Whether `id` may send to this inbox right now.
    pub fn member_status(&self, id: &DeviceId) -> MemberStatus {
        self.members.status(id)
    }

    /// This device's id as the inbox addresses it.
    pub fn self_id(&self) -> DeviceId {
        self.members.self_id()
    }

    /// The group (or pairing) id messages must carry.
    pub fn group(&self) -> GroupId {
        self.members.group()
    }

    fn roster_mut(&mut self) -> Option<&mut Roster> {
        match &mut self.members {
            Members::Roster(r) => Some(r),
            Members::Link(_) => None,
        }
    }

    /// L2: the seen-id store's high-water mark, for the app's state blob.
    pub fn replay_high_water(&self) -> Option<crate::replay::HighWater> {
        self.replay.high_water()
    }

    /// The only way to add a device: consume a typed-SAS `ConfirmedPairing`.
    /// A link verifier has no roster: it adds nothing and returns the id.
    pub fn add_paired_device(&mut self, pairing: ConfirmedPairing, role: Role) -> DeviceId {
        match self.roster_mut() {
            Some(r) => r.add_paired_device(pairing, role),
            None => pairing.into_parts().0,
        }
    }

    /// "Forget this device": local, immediate. Pending prompts from it can no
    /// longer be confirmed (they re-check this roster).
    pub fn forget_device(&mut self, id: &DeviceId) -> bool {
        let Some(r) = self.roster_mut() else {
            return false;
        };
        let changed = r.remove_device(id);
        let members = &self.members;
        self.per_device
            .retain(|d, _| members.status(d) == MemberStatus::Active);
        self.pre_decrypt
            .retain(|d, _| members.status(d) == MemberStatus::Active);
        changed
    }

    /// Undo [`Inbox::forget_device`] when the new state could not be saved.
    /// Rate-limit buckets dropped by the forget start fresh.
    pub fn rekey(&mut self, payload: crate::mailbox::RekeyPayload) -> bool {
        self.roster_mut().is_some_and(|r| r.rekey(payload))
    }

    /// Rename an active device in the roster and update its signed certificate (`M2.8`).
    pub fn rename_device(
        &mut self,
        id: &DeviceId,
        name: String,
        cert: Option<crate::keys::DeviceCert>,
    ) -> bool {
        self.roster_mut()
            .is_some_and(|r| r.rename_device(id, name, cert))
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

    /// Verify one inbound URL envelope that arrived on a connection authenticated
    /// as `transport_peer` (the iroh EndpointId in M1).
    pub fn receive(
        &mut self,
        transport_peer: &DeviceId,
        envelope_bytes: &[u8],
        now: Now,
    ) -> Result<VerifiedUrl, RejectReason> {
        let r = match self.receive_message_inner(Some(transport_peer), envelope_bytes, None, now) {
            Ok(VerifiedMessage::Url(u)) => Ok(u),
            Ok(_) => Err(RejectReason::MalformedFrame),
            Err(e) => Err(e),
        };
        match &r {
            Ok(_) => self.counters.accepted += 1,
            Err(e) => *self.counters.rejected.entry(e.label()).or_insert(0) += 1,
        }
        r
    }

    /// Verify an inbound live message (`Url`, `ClipboardText`, or `FileWake`) that
    /// arrived on a connection authenticated as `transport_peer` (`M3-PLAN.md` §2.2).
    pub fn receive_message(
        &mut self,
        transport_peer: &DeviceId,
        envelope_bytes: &[u8],
        now: Now,
    ) -> Result<VerifiedMessage, RejectReason> {
        let r = self.receive_message_inner(Some(transport_peer), envelope_bytes, None, now);
        match &r {
            Ok(_) => self.counters.accepted += 1,
            Err(e) => *self.counters.rejected.entry(e.label()).or_insert(0) += 1,
        }
        r
    }

    /// Verify an envelope pulled from this device's blind RAM inbox on `voidwire-mailbox`
    /// (`M3-PLAN.md` §1.3 & §2.2).
    ///
    /// Because the blind RAM inbox is fetched over a throwaway relay session rather than
    /// a direct connection from the sender, transport peer binding is replaced by the
    /// inner authenticated `msg.sender` roster membership + Ed25519 signature check, and
    /// past timestamp freshness allows up to `min(inbox_ttl_secs, MAX_INBOX_TTL_SECS) * 1000 + timestamp_window_ms`.
    pub fn receive_from_device_inbox(
        &mut self,
        envelope_bytes: &[u8],
        inbox_ttl_secs: u64,
        now: Now,
    ) -> Result<VerifiedMessage, RejectReason> {
        let r = self.receive_message_inner(None, envelope_bytes, Some(inbox_ttl_secs), now);
        match &r {
            Ok(_) => self.counters.accepted += 1,
            Err(e) => *self.counters.rejected.entry(e.label()).or_insert(0) += 1,
        }
        r
    }

    fn receive_message_inner(
        &mut self,
        transport_peer: Option<&DeviceId>,
        envelope_bytes: &[u8],
        inbox_ttl_secs: Option<u64>,
        now: Now,
    ) -> Result<VerifiedMessage, RejectReason> {
        if let Some(peer) = transport_peer {
            // 1. strangers get nothing parsed
            match self.members.status(peer) {
                MemberStatus::Active => {}
                MemberStatus::Removed => return Err(RejectReason::Removed),
                MemberStatus::Unknown => return Err(RejectReason::NotPaired),
            }
            if *peer == self.members.self_id() {
                return Err(RejectReason::FromSelf);
            }

            // 1b. D13: cheap per-peer budget before any decryption/verification.
            let pre_limit = self.config.pre_decrypt;
            let pre = self
                .pre_decrypt
                .entry(*peer)
                .or_insert_with(|| TokenBucket::new(pre_limit, now.mono));
            if !pre.try_take(now.mono) {
                return Err(RejectReason::RateLimitedPeer);
            }
        }

        // 2. shape, HPKE open, strict unpad, strict decode
        let self_id = self.members.self_id();
        let body = envelope::open(&self.receive, &self_id, envelope_bytes)?;
        let msg = wire::decode(&body)?;

        // 3. binding to the transport identity (or roster membership for device inbox pulls)
        if let Some(peer) = transport_peer {
            if msg.sender != *peer {
                return Err(RejectReason::SenderMismatch);
            }
        } else {
            if msg.sender == self_id {
                return Err(RejectReason::FromSelf);
            }
            if self.members.only_peer().is_some_and(|p| p != msg.sender) {
                return Err(RejectReason::SenderMismatch);
            }
            match self.members.status(&msg.sender) {
                MemberStatus::Active => {}
                MemberStatus::Removed => return Err(RejectReason::Removed),
                MemberStatus::Unknown => return Err(RejectReason::NotPaired),
            }
        }

        // 4. addressing
        if msg.group != self.members.group() {
            return Err(RejectReason::WrongGroup);
        }
        if msg.recipient != *self_id.as_bytes() {
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

        // 8. freshness (inclusive window, extended past window for blind RAM inbox pulls)
        let future_w = self.config.timestamp_window_ms;
        let past_w = match inbox_ttl_secs {
            Some(ttl) => ttl
                .min(crate::limits::MAX_INBOX_TTL_SECS)
                .saturating_mul(1000)
                .saturating_add(future_w),
            None => future_w,
        };
        if msg.timestamp.0 < now.wall.0 && now.wall.0 - msg.timestamp.0 > past_w {
            return Err(RejectReason::StaleTimestamp);
        }
        if msg.timestamp.0 > now.wall.0 && msg.timestamp.0 - now.wall.0 > future_w {
            return Err(RejectReason::FutureTimestamp);
        }

        // 9. replay (retention covers the full accepted `past_w + future_w` window)
        let retention_ms = crate::limits::REPLAY_RETENTION_MS.max(past_w.saturating_add(future_w));
        match self.replay.check_and_insert_with_retention(
            &msg.sender,
            &msg.msg_id,
            msg.timestamp,
            now,
            retention_ms,
        ) {
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

        // 11. Payload validation by MessageKind
        match msg.kind {
            wire::MessageKind::Url(raw_url) => {
                let url = url_policy::check_url(&raw_url)?;
                Ok(VerifiedMessage::Url(VerifiedUrl {
                    url,
                    sender: msg.sender,
                    msg_id: msg.msg_id,
                    inbox: self.tag,
                }))
            }
            wire::MessageKind::ClipboardText { text, sensitive } => {
                Ok(VerifiedMessage::Clipboard(VerifiedClipboard {
                    text,
                    sensitive,
                    sender: msg.sender,
                    msg_id: msg.msg_id,
                    inbox: self.tag,
                }))
            }
            wire::MessageKind::FileWake(wake) => {
                if now.wall.0 >= wake.expires_at.0 {
                    return Err(RejectReason::StaleTimestamp);
                }
                Ok(VerifiedMessage::FileWake(VerifiedFileWake {
                    transfer_id: wake.transfer_id,
                    size_bytes: wake.size_bytes,
                    expires_at: wake.expires_at,
                    filename: wake.filename,
                    is_executable: wake.is_executable,
                    sender: msg.sender,
                    msg_id: msg.msg_id,
                    inbox: self.tag,
                }))
            }
            wire::MessageKind::PairNotice(op) => {
                Ok(VerifiedMessage::PairNotice(VerifiedPairNotice {
                    op,
                    sender: msg.sender,
                    inbox: self.tag,
                }))
            }
        }
    }

    /// Verify an inbound `FILE_OFFER` envelope that arrived on a connection
    /// authenticated as `transport_peer` (`M26-H1`).
    ///
    /// Enforces all [`Inbox::receive`] gates:
    /// 1. Active roster membership (`NotPaired` / `Removed`) and `peer != self`.
    /// 2. Pre-decrypt rate limit (`RateLimitedPeer`).
    /// 3. HPKE open, inner sender/group/recipient binding, Ed25519 `verify_strict`,
    ///    and static offer policy (`open_file_offer`).
    /// 4. Per-device rate limit (`RateLimitedDevice`).
    /// 5. (removed in message format 2: no group-log head check.)
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
        match self.members.status(peer) {
            MemberStatus::Active => {}
            MemberStatus::Removed => return Err(RejectReason::Removed),
            MemberStatus::Unknown => return Err(RejectReason::NotPaired),
        }
        if *peer == self.members.self_id() {
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
        let self_id = self.members.self_id();
        let group = self.members.group();
        let (offer, k_file) = crate::file_transfer::open_file_offer(
            &self.receive,
            &self_id,
            &group,
            peer,
            envelope_bytes,
        )?;

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
