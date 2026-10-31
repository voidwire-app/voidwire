#![forbid(unsafe_code)]
//! `voidwire-mailbox`: relay-only blind encrypted revocation mailbox daemon
//! (`docs/PROTOCOL.md` §7.1, `docs/M2-PLAN.md` rev. 3 §2.3, §3.2, §6.2, §6b).
//!
//! Security & privacy invariants:
//! - Binds **zero UDP sockets** (`Endpoint::builder(...).clear_ip_transports()`):
//!   reachable exclusively through the configured iroh relay over outbound TCP/TLS.
//! - Stores only opaque `mailbox_id`, verifiers (`write_verifier`, `seal_verifier`),
//!   encrypted padded records, an optional seal tombstone, and a **UTC day number**
//!   (`u32 = unix_secs / 86_400`) for 180-day whole-mailbox expiry. Never stores
//!   fine-grained timestamps, IP addresses, or client `DeviceId`s.
//! - Rate limits (`20 appends/min, burst 20`) live strictly in RAM.
//! - Default log level is `"off"` (`DEFAULT_LOG_LEVEL = "off"`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{routing::get, Router};
use iroh::{endpoint::presets, Endpoint, SecretKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use voidwire_core::ids::DeviceId;
use voidwire_core::keys::DeviceKeypair;
use voidwire_core::limits::{
    DEFAULT_INBOX_MAX_ITEMS, DEFAULT_INBOX_MAX_TOTAL_BYTES, DEFAULT_INBOX_TTL_SECS,
    INBOX_MAX_ITEMS_MAX, INBOX_MAX_ITEMS_MIN, INBOX_MAX_TOTAL_BYTES_MAX, INBOX_MAX_TOTAL_BYTES_MIN,
    INBOX_TTL_SECS_MIN, MAX_INBOX_TTL_SECS,
};
use voidwire_core::mailbox::{
    mb_frame, mb_status, AdvertisedInboxCaps, DeviceInboxId, InboxAckReq, InboxPullItem,
    InboxPullReq, InboxPullResp, InboxPutReq, MailboxId, SignedConfig,
};
use voidwire_core::net::{build_relay_mode, default_net_report_config, DEFAULT_RELAY_URL};
use voidwire_core::protocol::ALPN_MAILBOX;
use voidwire_core::ratelimit::{RateLimit, TokenBucket};
use voidwire_core::time::MonoMillis;
use voidwire_core::time::{Clock, SystemClock};
use zeroize::{Zeroize, Zeroizing};

/// Strict no-logs default (`privacy-no-default-logs`).
pub const DEFAULT_LOG_LEVEL: &str = "off";

/// Loopback healthcheck bind address (`docs/M2-PLAN.md` §3.2).
pub const DEFAULT_HEALTHZ_ADDR: &str = "127.0.0.1:48486";

/// Maximum wire frame payload accepted on `voidwire/v1/mailbox` (`5 MiB`, `M2-L1`).
pub use voidwire_core::mailbox::MAX_MAILBOX_WIRE_FRAME;

/// Per-mailbox append rate limit (`20 appends/min, burst 20`, RAM-only).
pub const MAILBOX_APPEND_LIMIT: RateLimit = RateLimit {
    burst: 20,
    per_minute: 20,
};

/// Default per-peer read rate limit (`60 reads/min`, RAM-only).
pub const DEFAULT_PER_IP_READS_PER_MIN: u32 = 60;
/// Default per-peer append/write rate limit (`30 writes/min`, RAM-only).
pub const DEFAULT_PER_IP_APPENDS_PER_MIN: u32 = 30;
/// Default global read rate limit across all connections (`6,000 reads/min`, RAM-only, `M2-R2`).
pub const DEFAULT_GLOBAL_READS_PER_MIN: u32 = 6_000;
/// Default global append/write rate limit across all connections (`1,200 writes/min`, RAM-only, `M2-R2`).
pub const DEFAULT_GLOBAL_APPENDS_PER_MIN: u32 = 1_200;
/// Maximum entries in any RAM rate-limit table before oldest-entry eviction (`M2-M3`).
pub const MAX_RATE_BUCKETS: usize = 4_096;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Configurable quotas, retention, and rate limits for [`MailboxEngine`] (`M2-H2`, `M2-M4`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxLimits {
    pub appends_per_min: u32,
    pub append_burst: u32,
    pub per_ip_reads_per_min: u32,
    pub per_ip_appends_per_min: u32,
    pub global_reads_per_min: u32,
    pub global_appends_per_min: u32,
    /// Server-advertised relay file size cap in bytes (`25 MiB` default; `0` = unlimited up to 2 GiB, `M2.9`).
    pub max_relay_file_bytes: u64,
    /// Maximum queued items per RAM-only blind device inbox (`4` default, `1..=256`, `M3-PLAN.md` §1.4.2).
    pub inbox_max_items: usize,
    /// TTL in seconds for each item in a RAM-only blind device inbox (`3600` default, `60..=604_800`, `M3-PLAN.md` §1.4.2).
    pub inbox_ttl_secs: u64,
    /// Global RAM ceiling in bytes across all RAM-only blind device inboxes (`32 MiB` default, `64 KiB..=1 GiB`, `M3-PLAN.md` §1.4.2).
    pub inbox_max_total_bytes: usize,
}

impl MailboxLimits {
    pub fn validate(&self) -> Result<(), String> {
        if !(INBOX_MAX_ITEMS_MIN..=INBOX_MAX_ITEMS_MAX).contains(&self.inbox_max_items) {
            return Err(format!(
                "inbox_max_items {} out of range {}..={}",
                self.inbox_max_items, INBOX_MAX_ITEMS_MIN, INBOX_MAX_ITEMS_MAX
            ));
        }
        if !(INBOX_TTL_SECS_MIN..=MAX_INBOX_TTL_SECS).contains(&self.inbox_ttl_secs) {
            return Err(format!(
                "inbox_ttl_secs {} out of range {}..={}",
                self.inbox_ttl_secs, INBOX_TTL_SECS_MIN, MAX_INBOX_TTL_SECS
            ));
        }
        if !(INBOX_MAX_TOTAL_BYTES_MIN..=INBOX_MAX_TOTAL_BYTES_MAX)
            .contains(&self.inbox_max_total_bytes)
        {
            return Err(format!(
                "inbox_max_total_bytes {} out of range {}..={}",
                self.inbox_max_total_bytes, INBOX_MAX_TOTAL_BYTES_MIN, INBOX_MAX_TOTAL_BYTES_MAX
            ));
        }
        Ok(())
    }
}

impl Default for MailboxLimits {
    fn default() -> Self {
        Self {
            appends_per_min: MAILBOX_APPEND_LIMIT.per_minute,
            append_burst: MAILBOX_APPEND_LIMIT.burst,
            per_ip_reads_per_min: DEFAULT_PER_IP_READS_PER_MIN,
            per_ip_appends_per_min: DEFAULT_PER_IP_APPENDS_PER_MIN,
            global_reads_per_min: DEFAULT_GLOBAL_READS_PER_MIN,
            global_appends_per_min: DEFAULT_GLOBAL_APPENDS_PER_MIN,
            max_relay_file_bytes: voidwire_core::file_transfer::DEFAULT_RELAY_FILE_CAP_BYTES,
            inbox_max_items: DEFAULT_INBOX_MAX_ITEMS,
            inbox_ttl_secs: DEFAULT_INBOX_TTL_SECS,
            inbox_max_total_bytes: DEFAULT_INBOX_MAX_TOTAL_BYTES,
        }
    }
}

/// Configuration for [`MailboxServer`].
#[derive(Debug, Clone)]
pub struct MailboxServerConfig {
    pub secret_key: [u8; 32],
    pub relay_url: String,
    pub healthz_addr: Option<SocketAddr>,
    pub signed_config: Option<SignedConfig>,
    pub limits: MailboxLimits,
    pub log: String,
}

impl Default for MailboxServerConfig {
    fn default() -> Self {
        let kp = DeviceKeypair::generate();
        Self {
            secret_key: *kp.secret_bytes(),
            relay_url: DEFAULT_RELAY_URL.to_owned(),
            healthz_addr: Some(DEFAULT_HEALTHZ_ADDR.parse().expect("valid loopback addr")),
            signed_config: None,
            limits: MailboxLimits::default(),
            log: DEFAULT_LOG_LEVEL.to_owned(),
        }
    }
}

/// One HPKE envelope held strictly in RAM inside a [`RamDeviceInbox`] (`M3-PLAN.md` §1.4.1).
/// Never serialized to disk; zeroized on ACK, TTL expiry, or global RAM ceiling eviction.
#[derive(Clone)]
pub struct RamInboxItem {
    pub item_id: [u8; 16],
    pub inserted_at: MonoMillis,
    pub seq_order: u64,
    pub envelope: Zeroizing<Vec<u8>>,
}

/// Per-device blind inbox held strictly in RAM (`M3-PLAN.md` §1.4.1).
pub struct RamDeviceInbox {
    pub inbox_id: DeviceInboxId,
    pub write_verifier: [u8; 32],
    pub read_verifier: [u8; 32],
    pub items: std::collections::VecDeque<RamInboxItem>,
}

/// Core stateful mailbox engine (used both by the network listener and unit tests).
pub struct MailboxEngine {
    inboxes: HashMap<DeviceInboxId, RamDeviceInbox>,
    inbox_total_bytes: usize,
    inbox_seq_counter: u64,
    append_buckets: HashMap<MailboxId, (TokenBucket, MonoMillis)>,
    peer_read_buckets: HashMap<DeviceId, (TokenBucket, MonoMillis)>,
    peer_append_buckets: HashMap<DeviceId, (TokenBucket, MonoMillis)>,
    global_read_bucket: Option<(TokenBucket, RateLimit)>,
    global_append_bucket: Option<(TokenBucket, RateLimit)>,
    global_create_bucket: Option<(TokenBucket, RateLimit)>,
    limits: MailboxLimits,
    signed_config: Option<SignedConfig>,
    clock: Arc<dyn Clock + Send + Sync>,
}

impl MailboxEngine {
    pub fn new(signed_config: Option<SignedConfig>) -> Result<Self, String> {
        Self::with_limits_and_clock(
            signed_config,
            MailboxLimits::default(),
            Arc::new(SystemClock),
        )
    }

    pub fn with_clock(
        signed_config: Option<SignedConfig>,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Result<Self, String> {
        Self::with_limits_and_clock(signed_config, MailboxLimits::default(), clock)
    }

    pub fn with_limits_and_clock(
        signed_config: Option<SignedConfig>,
        limits: MailboxLimits,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Result<Self, String> {
        limits.validate()?;
        let engine = Self {
            inboxes: HashMap::new(),
            inbox_total_bytes: 0,
            inbox_seq_counter: 0,
            append_buckets: HashMap::new(),
            peer_read_buckets: HashMap::new(),
            peer_append_buckets: HashMap::new(),
            global_read_bucket: None,
            global_append_bucket: None,
            global_create_bucket: None,
            limits,
            signed_config,
            clock,
        };
        Ok(engine)
    }

    pub fn set_clock(&mut self, clock: Arc<dyn Clock + Send + Sync>) {
        self.clock = clock;
    }

    pub fn set_signed_config(&mut self, cfg: Option<SignedConfig>) {
        self.signed_config = cfg;
    }

    pub fn limits(&self) -> &MailboxLimits {
        &self.limits
    }

    pub fn set_limits(&mut self, limits: MailboxLimits) {
        self.limits = limits;
        self.global_read_bucket = None;
        self.global_append_bucket = None;
        self.global_create_bucket = None;
    }

    /// Number of active RAM-only blind device inboxes currently holding items.
    pub fn device_inbox_count(&self) -> usize {
        self.inboxes.len()
    }

    /// Total envelope bytes currently held across all RAM-only blind device inboxes.
    pub fn device_inbox_total_bytes(&self) -> usize {
        self.inbox_total_bytes
    }

    /// Number of queued items currently in `id`'s RAM-only blind device inbox.
    pub fn device_inbox_item_count(&self, id: &DeviceInboxId) -> usize {
        self.inboxes.get(id).map(|b| b.items.len()).unwrap_or(0)
    }

    /// Sweep and zeroize all RAM-only device inbox items whose age `>= inbox_ttl_secs` (`M3-PLAN.md` §1.4.1).
    pub fn purge_expired_inboxes(&mut self, now: MonoMillis) -> usize {
        let ttl_ms = self.limits.inbox_ttl_secs.saturating_mul(1000);
        let mut purged = 0usize;
        let mut empty_ids = Vec::new();
        for (id, inbox) in &mut self.inboxes {
            let mut i = 0;
            while i < inbox.items.len() {
                if now.0.saturating_sub(inbox.items[i].inserted_at.0) >= ttl_ms {
                    if let Some(mut item) = inbox.items.remove(i) {
                        self.inbox_total_bytes =
                            self.inbox_total_bytes.saturating_sub(item.envelope.len());
                        item.envelope.zeroize();
                        purged += 1;
                    }
                } else {
                    i += 1;
                }
            }
            if inbox.items.is_empty() {
                empty_ids.push(*id);
            }
        }
        for id in empty_ids {
            self.inboxes.remove(&id);
        }
        purged
    }

    /// Evict and zeroize the globally oldest item across all RAM-only device inboxes
    /// (`M3-PLAN.md` §1.4.1 rule 3).
    fn evict_oldest_inbox_item(&mut self) -> bool {
        let oldest_inbox_id = self
            .inboxes
            .iter()
            .filter_map(|(id, inbox)| {
                inbox
                    .items
                    .front()
                    .map(|front| (*id, (front.inserted_at.0, front.seq_order)))
            })
            .min_by_key(|(_, key)| *key)
            .map(|(id, _)| id);

        let Some(victim_id) = oldest_inbox_id else {
            return false;
        };
        let mut remove_inbox = false;
        if let Some(inbox) = self.inboxes.get_mut(&victim_id) {
            if let Some(mut item) = inbox.items.pop_front() {
                self.inbox_total_bytes = self.inbox_total_bytes.saturating_sub(item.envelope.len());
                item.envelope.zeroize();
            }
            remove_inbox = inbox.items.is_empty();
        }
        if remove_inbox {
            self.inboxes.remove(&victim_id);
        }
        true
    }

    fn take_from_bounded_map<K: Copy + Eq + std::hash::Hash>(
        map: &mut HashMap<K, (TokenBucket, MonoMillis)>,
        key: K,
        limit: RateLimit,
        now: MonoMillis,
    ) -> bool {
        if limit.per_minute == 0 || limit.burst == 0 {
            return false;
        }
        if map.len() >= MAX_RATE_BUCKETS && !map.contains_key(&key) {
            if let Some(oldest_key) = map
                .iter()
                .min_by_key(|(_, (_, touched))| touched.0)
                .map(|(k, _)| *k)
            {
                map.remove(&oldest_key);
            }
        }
        let (bucket, touched) = map
            .entry(key)
            .or_insert_with(|| (TokenBucket::new(limit, now), now));
        *touched = now;
        bucket.try_take(now)
    }

    fn allow_append(&mut self, id: MailboxId, now: MonoMillis) -> bool {
        let limit = RateLimit {
            burst: self.limits.append_burst,
            per_minute: self.limits.appends_per_min,
        };
        Self::take_from_bounded_map(&mut self.append_buckets, id, limit, now)
    }

    fn allow_peer_read(&mut self, peer: DeviceId, now: MonoMillis) -> bool {
        let limit = RateLimit {
            burst: self.limits.per_ip_reads_per_min,
            per_minute: self.limits.per_ip_reads_per_min,
        };
        Self::take_from_bounded_map(&mut self.peer_read_buckets, peer, limit, now)
    }

    fn allow_peer_append(&mut self, peer: DeviceId, now: MonoMillis) -> bool {
        let limit = RateLimit {
            burst: self.limits.per_ip_appends_per_min,
            per_minute: self.limits.per_ip_appends_per_min,
        };
        Self::take_from_bounded_map(&mut self.peer_append_buckets, peer, limit, now)
    }

    fn allow_global_read(&mut self, now: MonoMillis) -> bool {
        let limit = RateLimit {
            burst: self.limits.global_reads_per_min,
            per_minute: self.limits.global_reads_per_min,
        };
        if limit.per_minute == 0 || limit.burst == 0 {
            return false;
        }
        let bucket = match &mut self.global_read_bucket {
            Some((b, l)) if *l == limit => b,
            slot => &mut slot.insert((TokenBucket::new(limit, now), limit)).0,
        };
        bucket.try_take(now)
    }

    fn allow_global_append(&mut self, now: MonoMillis) -> bool {
        let limit = RateLimit {
            burst: self.limits.global_appends_per_min,
            per_minute: self.limits.global_appends_per_min,
        };
        if limit.per_minute == 0 || limit.burst == 0 {
            return false;
        }
        let bucket = match &mut self.global_append_bucket {
            Some((b, l)) if *l == limit => b,
            slot => &mut slot.insert((TokenBucket::new(limit, now), limit)).0,
        };
        bucket.try_take(now)
    }

    fn allow_global_create(&mut self, now: MonoMillis) -> bool {
        let total = self.limits.global_appends_per_min;
        if total == 0 {
            return false;
        }
        // Reserve at least half of global write capacity for authenticated operations
        // (`APPEND`, `SEAL`, `ROTATE`) on existing mailboxes when total >= 6 (`M26-H3`).
        let create_cap = if total >= 6 { total / 2 } else { total };
        let limit = RateLimit {
            burst: create_cap,
            per_minute: create_cap,
        };
        let bucket = match &mut self.global_create_bucket {
            Some((b, l)) if *l == limit => b,
            slot => &mut slot.insert((TokenBucket::new(limit, now), limit)).0,
        };
        bucket.try_take(now)
    }

    fn status_reply(code: u8) -> (u8, Vec<u8>) {
        (mb_frame::STATUS, vec![code])
    }

    pub fn handle_frame(&mut self, frame_type: u8, payload: &[u8]) -> (u8, Vec<u8>) {
        self.handle_frame_from_peer(None, frame_type, payload)
    }

    pub fn handle_frame_from_peer(
        &mut self,
        peer: Option<DeviceId>,
        frame_type: u8,
        payload: &[u8],
    ) -> (u8, Vec<u8>) {
        let now = self.clock.now();
        self.purge_expired_inboxes(now.mono);

        if let Some(peer_id) = peer {
            let allowed = match frame_type {
                mb_frame::CONFIG_GET | mb_frame::INBOX_PULL | mb_frame::INBOX_ACK => {
                    self.allow_peer_read(peer_id, now.mono)
                }
                mb_frame::INBOX_PUT => self.allow_peer_append(peer_id, now.mono),
                _ => true,
            };
            if !allowed {
                return Self::status_reply(mb_status::RATE_LIMITED);
            }
        }

        match frame_type {
            mb_frame::CONFIG_GET => {
                if !payload.is_empty() {
                    return Self::status_reply(mb_status::MALFORMED);
                }
                if !self.allow_global_read(now.mono) {
                    return Self::status_reply(mb_status::RATE_LIMITED);
                }
                match &self.signed_config {
                    Some(cfg) => (mb_frame::CONFIG, cfg.encode().to_vec()),
                    None => Self::status_reply(mb_status::NOT_FOUND),
                }
            }
            mb_frame::INBOX_PUT => {
                let Ok(req) = InboxPutReq::decode(payload) else {
                    return Self::status_reply(mb_status::MALFORMED);
                };
                let (exp_wv, exp_rv) = match self.inboxes.get(&req.inbox_id) {
                    Some(existing) => (Some(existing.write_verifier), Some(existing.read_verifier)),
                    None => (None, None),
                };
                let is_new_inbox = exp_wv.is_none();
                let Ok(computed_wv) = req.verify_write(exp_wv.as_ref(), exp_rv.as_ref()) else {
                    return Self::status_reply(mb_status::BAD_AUTH);
                };
                if !self.allow_append(MailboxId(req.inbox_id.0), now.mono)
                    || (is_new_inbox && !self.allow_global_create(now.mono))
                    || !self.allow_global_append(now.mono)
                {
                    return Self::status_reply(mb_status::RATE_LIMITED);
                }
                if let Some(existing) = self.inboxes.get(&req.inbox_id) {
                    if let Some(dup) = existing.items.iter().find(|i| i.item_id == req.item_id) {
                        if *dup.envelope == *req.envelope {
                            return Self::status_reply(mb_status::OK);
                        }
                        return Self::status_reply(mb_status::ALREADY_EXISTS);
                    }
                    if existing.items.len() >= self.limits.inbox_max_items {
                        return Self::status_reply(mb_status::QUOTA_EXCEEDED);
                    }
                }
                let item_bytes = req.envelope.len();
                if item_bytes > self.limits.inbox_max_total_bytes
                    || self.limits.inbox_max_items == 0
                {
                    return Self::status_reply(mb_status::QUOTA_EXCEEDED);
                }
                while self.inbox_total_bytes.saturating_add(item_bytes)
                    > self.limits.inbox_max_total_bytes
                {
                    if !self.evict_oldest_inbox_item() {
                        return Self::status_reply(mb_status::QUOTA_EXCEEDED);
                    }
                }
                self.inbox_seq_counter = self.inbox_seq_counter.wrapping_add(1);
                let seq_order = self.inbox_seq_counter;
                let inbox = self
                    .inboxes
                    .entry(req.inbox_id)
                    .or_insert_with(|| RamDeviceInbox {
                        inbox_id: req.inbox_id,
                        write_verifier: computed_wv,
                        read_verifier: req.read_verifier,
                        items: std::collections::VecDeque::new(),
                    });
                inbox.items.push_back(RamInboxItem {
                    item_id: req.item_id,
                    inserted_at: now.mono,
                    seq_order,
                    envelope: req.envelope,
                });
                self.inbox_total_bytes = self.inbox_total_bytes.saturating_add(item_bytes);
                Self::status_reply(mb_status::OK)
            }
            mb_frame::INBOX_PULL => {
                let Ok(req) = InboxPullReq::decode(payload) else {
                    return Self::status_reply(mb_status::MALFORMED);
                };
                if !self.allow_global_read(now.mono) {
                    return Self::status_reply(mb_status::RATE_LIMITED);
                }
                let ttl_ms = self.limits.inbox_ttl_secs.saturating_mul(1000);
                let items = match self.inboxes.get(&req.inbox_id) {
                    Some(inbox) => {
                        if req.verify_read(&inbox.read_verifier).is_err() {
                            return Self::status_reply(mb_status::BAD_AUTH);
                        }
                        inbox
                            .items
                            .iter()
                            .map(|item| {
                                let elapsed = now.mono.0.saturating_sub(item.inserted_at.0);
                                let rem_ms = ttl_ms.saturating_sub(elapsed);
                                let remaining_ttl_secs = ((rem_ms.saturating_add(999)) / 1000)
                                    .min(u32::MAX as u64)
                                    as u32;
                                InboxPullItem {
                                    item_id: item.item_id,
                                    remaining_ttl_secs,
                                    envelope: item.envelope.clone(),
                                }
                            })
                            .collect()
                    }
                    None => {
                        if req.verify_signature_self().is_err() {
                            return Self::status_reply(mb_status::BAD_AUTH);
                        }
                        Vec::new()
                    }
                };
                let resp = InboxPullResp { items };
                let caps = AdvertisedInboxCaps {
                    max_relay_file_bytes: self.limits.max_relay_file_bytes,
                    inbox_max_items: self.limits.inbox_max_items as u16,
                    inbox_ttl_secs: self.limits.inbox_ttl_secs as u32,
                };
                (mb_frame::INBOX_PULL_OK, resp.encode_with_caps(caps))
            }
            mb_frame::INBOX_ACK => {
                let Ok(req) = InboxAckReq::decode(payload) else {
                    return Self::status_reply(mb_status::MALFORMED);
                };
                if !self.allow_global_read(now.mono) {
                    return Self::status_reply(mb_status::RATE_LIMITED);
                }
                let mut remove_empty = false;
                if let Some(inbox) = self.inboxes.get_mut(&req.inbox_id) {
                    if req.verify_ack(&inbox.read_verifier).is_err() {
                        return Self::status_reply(mb_status::BAD_AUTH);
                    }
                    let mut i = 0;
                    while i < inbox.items.len() {
                        if req.item_ids.contains(&inbox.items[i].item_id) {
                            if let Some(mut removed) = inbox.items.remove(i) {
                                self.inbox_total_bytes = self
                                    .inbox_total_bytes
                                    .saturating_sub(removed.envelope.len());
                                removed.envelope.zeroize();
                            }
                        } else {
                            i += 1;
                        }
                    }
                    remove_empty = inbox.items.is_empty();
                } else if req.verify_signature_self().is_err() {
                    return Self::status_reply(mb_status::BAD_AUTH);
                }
                if remove_empty {
                    self.inboxes.remove(&req.inbox_id);
                }
                Self::status_reply(mb_status::OK)
            }
            _ => Self::status_reply(mb_status::MALFORMED),
        }
    }
}

/// Running `voidwire-mailbox` server.
pub struct MailboxServer {
    endpoint: Endpoint,
    device_id: DeviceId,
    engine: Arc<Mutex<MailboxEngine>>,
    #[cfg(test)]
    seen_peers: Arc<Mutex<Vec<DeviceId>>>,
    healthz_addr: Option<SocketAddr>,
    healthz_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl MailboxServer {
    /// Bind the relay-only iroh endpoint (`.clear_ip_transports()` so zero UDP
    /// sockets are bound) and optional loopback `/healthz` HTTP server.
    pub async fn start(cfg: MailboxServerConfig) -> Result<Self, String> {
        let engine = Arc::new(Mutex::new(MailboxEngine::with_limits_and_clock(
            cfg.signed_config,
            cfg.limits.clone(),
            Arc::new(SystemClock),
        )?));
        let kp = DeviceKeypair::from_secret_bytes(&zeroize::Zeroizing::new(cfg.secret_key));
        let device_id = kp.device_id();
        let (relay_mode, _) =
            build_relay_mode(Some(&cfg.relay_url)).map_err(|e| format!("relay_url: {e}"))?;

        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&cfg.secret_key))
            .alpns(vec![ALPN_MAILBOX.to_vec()])
            .relay_mode(relay_mode)
            .clear_address_lookup()
            .clear_ip_transports()
            .net_report_config(default_net_report_config())
            .bind()
            .await
            .map_err(|e| format!("endpoint bind: {e}"))?;

        let (healthz_addr, healthz_shutdown) = match cfg.healthz_addr {
            Some(addr) => {
                let listener = tokio::net::TcpListener::bind(addr)
                    .await
                    .map_err(|e| format!("healthz bind {addr}: {e}"))?;
                let bound = listener
                    .local_addr()
                    .map_err(|e| format!("healthz local_addr: {e}"))?;
                let (tx, rx) = tokio::sync::oneshot::channel::<()>();
                let app = Router::new().route("/healthz", get(|| async { "ok\n" }));
                tokio::spawn(async move {
                    let _ = axum::serve(listener, app)
                        .with_graceful_shutdown(async move {
                            let _ = rx.await;
                        })
                        .await;
                });
                (Some(bound), Some(tx))
            }
            None => (None, None),
        };

        #[cfg(test)]
        let seen_peers: Arc<Mutex<Vec<DeviceId>>> = Arc::new(Mutex::new(Vec::new()));
        #[cfg(test)]
        let sp = seen_peers.clone();

        let sweep_eng = engine.clone();
        let ep = endpoint.clone();
        let eng = engine.clone();
        let accept_task = tokio::spawn(async move {
            let _sweep_guard = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    let mut g = sweep_eng.lock().unwrap_or_else(|p| p.into_inner());
                    let now = g.clock.now();
                    g.purge_expired_inboxes(now.mono);
                }
            });
            while let Some(incoming) = ep.accept().await {
                let eng = eng.clone();
                #[cfg(test)]
                let sp = sp.clone();
                tokio::spawn(async move {
                    let Ok(accepting) = incoming.accept() else {
                        return;
                    };
                    let Ok(conn) = accepting.await else {
                        return;
                    };
                    if conn.alpn() != ALPN_MAILBOX {
                        conn.close(1u32.into(), b"alpn");
                        return;
                    }
                    #[cfg(test)]
                    if let Ok(did) = DeviceId::from_bytes(*conn.remote_id().as_bytes()) {
                        sp.lock().unwrap_or_else(|p| p.into_inner()).push(did);
                    }
                    handle_conn(eng, conn).await;
                });
            }
        });

        Ok(Self {
            endpoint,
            device_id,
            engine,
            #[cfg(test)]
            seen_peers,
            healthz_addr,
            healthz_shutdown,
            accept_task,
        })
    }

    /// Server's iroh `DeviceId` (public key).
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Bound UDP sockets — guaranteed empty because `.clear_ip_transports()` is set!
    pub fn bound_udp_sockets(&self) -> Vec<SocketAddr> {
        self.endpoint.bound_sockets()
    }

    /// Bound loopback `/healthz` TCP address, if enabled.
    pub fn healthz_addr(&self) -> Option<SocketAddr> {
        self.healthz_addr
    }

    /// Underlying engine handle.
    pub fn engine(&self) -> Arc<Mutex<MailboxEngine>> {
        self.engine.clone()
    }

    #[cfg(test)]
    pub fn seen_client_ids_for_test(&self) -> Vec<DeviceId> {
        self.seen_peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.healthz_shutdown.take() {
            let _ = tx.send(());
        }
        self.accept_task.abort();
        self.endpoint.close().await;
    }
}

async fn handle_conn(engine: Arc<Mutex<MailboxEngine>>, conn: iroh::endpoint::Connection) {
    let peer = DeviceId::from_bytes(*conn.remote_id().as_bytes()).ok();
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let eng = engine.clone();
        tokio::spawn(async move {
            let Ok((ft, payload)) = read_mb_frame(&mut recv).await else {
                return;
            };
            let (resp_ft, resp_payload) = {
                let mut guard = eng.lock().unwrap_or_else(|p| p.into_inner());
                let (rft, mut rp) = guard.handle_frame_from_peer(peer, ft, &payload);
                if rft == mb_frame::STATUS
                    && rp.len() == 1
                    && (rp[0] == mb_status::OK || rp[0] == mb_status::NOT_FOUND)
                {
                    rp.extend_from_slice(&guard.limits.max_relay_file_bytes.to_be_bytes());
                }
                (rft, rp)
            };
            let _ = write_mb_frame(&mut send, resp_ft, &resp_payload).await;
            let _ = send.finish();
        });
    }
}

/// Read one `[type: u8][len: u32 BE][payload]` frame from a QUIC stream.
pub async fn read_mb_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<(u8, Vec<u8>), String> {
    let mut hdr = [0u8; 5];
    tokio::time::timeout(IO_TIMEOUT, r.read_exact(&mut hdr))
        .await
        .map_err(|_| "timeout".to_owned())?
        .map_err(|e| e.to_string())?;
    let ft = hdr[0];
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    if len > MAX_MAILBOX_WIRE_FRAME {
        return Err("oversize frame".into());
    }
    let mut buf = vec![0u8; len];
    tokio::time::timeout(IO_TIMEOUT, r.read_exact(&mut buf))
        .await
        .map_err(|_| "timeout".to_owned())?
        .map_err(|e| e.to_string())?;
    Ok((ft, buf))
}

/// Write one `[type: u8][len: u32 BE][payload]` frame to a QUIC stream.
pub async fn write_mb_frame<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    ft: u8,
    payload: &[u8],
) -> Result<(), String> {
    let mut hdr = [0u8; 5];
    hdr[0] = ft;
    hdr[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    tokio::time::timeout(IO_TIMEOUT, async {
        w.write_all(&hdr).await?;
        w.write_all(payload).await?;
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|_| "timeout".to_owned())?
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use voidwire_core::mailbox::EpochSecret;
    use voidwire_core::net::test_relay::TestRelay;
    use voidwire_core::time::Now;
    use voidwire_core::time::{MonoMillis, UnixMillis};

    struct FakeClock {
        wall_ms: AtomicU64,
        mono_ms: AtomicU64,
    }

    impl FakeClock {
        fn new(days: u32) -> Self {
            let ms = (days as u64) * 86_400 * 1000 + 12_345_678; // sub-day offset to prove stripping
            Self {
                wall_ms: AtomicU64::new(ms),
                mono_ms: AtomicU64::new(1_000),
            }
        }

        fn advance_mono_ms(&self, ms: u64) {
            self.mono_ms.fetch_add(ms, Ordering::SeqCst);
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Now {
            Now {
                wall: UnixMillis(self.wall_ms.load(Ordering::SeqCst)),
                mono: MonoMillis(self.mono_ms.load(Ordering::SeqCst)),
            }
        }
    }

    #[tokio::test]
    async fn server_binds_zero_udp_sockets_and_serves_over_relay_with_throwaway_client() {
        let relay = std::thread::spawn(TestRelay::start).join().unwrap();
        let cfg_sk = [0x88u8; 32];
        let signed_cfg = SignedConfig::sign(&cfg_sk, 20_000, 20_010, 25 * 1024 * 1024).unwrap();

        let server = MailboxServer::start(MailboxServerConfig {
            secret_key: [0x44u8; 32],
            relay_url: relay.url(),
            healthz_addr: Some("127.0.0.1:0".parse().unwrap()),
            signed_config: Some(signed_cfg),
            limits: MailboxLimits::default(),
            log: "off".into(),
        })
        .await
        .expect("start MailboxServer");

        // 1. Verify zero UDP sockets bound (.clear_ip_transports())
        assert!(
            server.bound_udp_sockets().is_empty(),
            "voidwire-mailbox must bind ZERO UDP sockets, got: {:?}",
            server.bound_udp_sockets()
        );

        // 2. Verify loopback /healthz responds "ok\n"
        let hz_addr = server.healthz_addr().expect("healthz_addr");
        let mut tcp = tokio::net::TcpStream::connect(hz_addr).await.unwrap();
        tcp.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut http_resp = Vec::new();
        tcp.read_to_end(&mut http_resp).await.unwrap();
        assert!(
            http_resp.ends_with(b"ok\n"),
            "unexpected healthz response: {:?}",
            String::from_utf8_lossy(&http_resp)
        );

        // Wait for server to register on TestRelay
        let server_id = server.device_id();
        for _ in 0..200 {
            if relay.has_peer(&server_id) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            relay.has_peer(&server_id),
            "mailbox server registered on relay"
        );

        // 3. Dial the mailbox server from a throwaway client Endpoint (random key != any DeviceId)
        let throwaway_kp = DeviceKeypair::generate();
        assert_ne!(throwaway_kp.device_id(), server_id);
        let (rm, _) = build_relay_mode(Some(&relay.url())).unwrap();
        let client_ep = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&throwaway_kp.secret_bytes()))
            .relay_mode(rm)
            .clear_address_lookup()
            .clear_ip_transports()
            .net_report_config(default_net_report_config())
            .bind()
            .await
            .unwrap();

        let addr =
            iroh::EndpointAddr::new(iroh::PublicKey::from_bytes(server_id.as_bytes()).unwrap())
                .with_relay_url(relay.url().parse().unwrap());
        let conn = client_ep.connect(addr, ALPN_MAILBOX).await.unwrap();

        // Send CONFIG_GET
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        write_mb_frame(&mut s, mb_frame::CONFIG_GET, &[])
            .await
            .unwrap();
        let _ = s.finish();
        let (rft, rp) = read_mb_frame(&mut r).await.unwrap();
        assert_eq!(rft, mb_frame::CONFIG);
        assert_eq!(SignedConfig::decode(&rp).unwrap(), signed_cfg);

        conn.close(0u32.into(), b"done");
        client_ep.close().await;
        server.shutdown().await;
        std::thread::spawn(move || drop(relay)).join().unwrap();
    }

    #[test]
    fn signed_config_serving_and_removed_group_chain_frames_are_malformed() {
        let clock = Arc::new(FakeClock::new(20_500));
        let signed_cfg =
            SignedConfig::sign(&[0x77u8; 32], 20_500, 20_530, 10 * 1024 * 1024).unwrap();
        let mut eng = MailboxEngine::with_clock(Some(signed_cfg), clock).unwrap();
        let (ft, cp) = eng.handle_frame(mb_frame::CONFIG_GET, &[]);
        assert_eq!(ft, mb_frame::CONFIG);
        assert_eq!(SignedConfig::decode(&cp).unwrap(), signed_cfg);
        // The group-chain store is gone: its frame types get MALFORMED and store nothing.
        for old in [0x01u8, 0x02, 0x03, 0x04, 0x05] {
            assert_eq!(
                eng.handle_frame(old, &[0u8; 64]),
                (mb_frame::STATUS, vec![mb_status::MALFORMED])
            );
        }
        assert_eq!(eng.device_inbox_count(), 0);
    }

    #[test]
    fn per_peer_rate_limits_cover_inbox_frames() {
        use voidwire_core::envelope::{HEADER, OVERHEAD, PAD_BUCKETS};
        use voidwire_core::ids::GroupId;
        use voidwire_core::keys::ReceiveKeypair;
        let mut env = vec![0xABu8; PAD_BUCKETS[0] + OVERHEAD];
        env[..4].copy_from_slice(&HEADER);
        let clock = Arc::new(FakeClock::new(20_600));
        let limits = MailboxLimits {
            per_ip_reads_per_min: 2,
            per_ip_appends_per_min: 2,
            ..Default::default()
        };
        let mut eng = MailboxEngine::with_limits_and_clock(None, limits, clock).unwrap();
        let peer = DeviceKeypair::generate().device_id();
        let other = DeviceKeypair::generate().device_id();
        let gs = EpochSecret::from_bytes([0x61; 32]);
        let rx = ReceiveKeypair::generate();
        let keys = gs.derive_device_inbox_keys(&GroupId([0x62; 32]), 0, &other, &rx.public());
        let put = |i: u8| keys.build_put_req([i; 16], env.clone()).unwrap().encode();
        assert_eq!(
            eng.handle_frame_from_peer(Some(peer), mb_frame::INBOX_PUT, &put(1))
                .1,
            vec![mb_status::OK]
        );
        assert_eq!(
            eng.handle_frame_from_peer(Some(peer), mb_frame::INBOX_PUT, &put(2))
                .1,
            vec![mb_status::OK]
        );
        assert_eq!(
            eng.handle_frame_from_peer(Some(peer), mb_frame::INBOX_PUT, &put(3))
                .1,
            vec![mb_status::RATE_LIMITED],
            "a third write from one peer within a minute is refused"
        );
        assert_eq!(
            eng.handle_frame_from_peer(Some(other), mb_frame::INBOX_PUT, &put(3))
                .1,
            vec![mb_status::OK]
        );
        for _ in 0..2 {
            assert_ne!(
                eng.handle_frame_from_peer(Some(peer), mb_frame::CONFIG_GET, &[])
                    .1,
                vec![mb_status::RATE_LIMITED]
            );
        }
        assert_eq!(
            eng.handle_frame_from_peer(Some(peer), mb_frame::CONFIG_GET, &[])
                .1,
            vec![mb_status::RATE_LIMITED],
            "a third read from one peer within a minute is refused"
        );
    }

    #[test]
    fn ram_device_inbox_zero_disk_writes_quota_ttl_and_ack_zeroization() {
        use voidwire_core::envelope::{HEADER, MAX_PADDED_LEN, OVERHEAD, PAD_BUCKETS};
        use voidwire_core::ids::GroupId;
        use voidwire_core::keys::ReceiveKeypair;

        fn make_env(bucket: usize, tag: u8) -> Vec<u8> {
            let mut v = vec![tag; bucket + OVERHEAD];
            v[..4].copy_from_slice(&HEADER);
            v
        }
        let small_env_len = PAD_BUCKETS[0] + OVERHEAD;
        let _ = MAX_PADDED_LEN;

        let clock = Arc::new(FakeClock::new(20_650));
        let limits = MailboxLimits {
            inbox_max_items: 4,
            inbox_ttl_secs: 600,
            inbox_max_total_bytes: 65_536,
            max_relay_file_bytes: 12 * 1024 * 1024,
            ..MailboxLimits::default()
        };
        let mut eng =
            MailboxEngine::with_limits_and_clock(None, limits, clock.clone()).expect("init engine");

        let gs = EpochSecret::from_bytes([0x61; 32]);
        let gid = GroupId([0x62; 32]);
        let phone_id = DeviceKeypair::generate().device_id();
        let phone_rx = ReceiveKeypair::generate();
        let keys = gs.derive_device_inbox_keys(&gid, 0, &phone_id, &phone_rx.public());
        let peer = Some(DeviceKeypair::generate().device_id());

        // Enqueue 4 items (up to inbox_max_items = 4)
        let mut item_ids = Vec::new();
        for idx in 0..4u8 {
            let item_id = [idx + 1; 16];
            item_ids.push(item_id);
            let env = make_env(PAD_BUCKETS[0], idx);
            let put = keys.build_put_req(item_id, env).unwrap();
            assert_eq!(
                eng.handle_frame_from_peer(peer, mb_frame::INBOX_PUT, &put.encode()),
                (mb_frame::STATUS, vec![mb_status::OK]),
                "put item {idx}"
            );
        }
        assert_eq!(eng.device_inbox_count(), 1);
        assert_eq!(eng.device_inbox_item_count(&keys.inbox_id), 4);
        assert_eq!(eng.device_inbox_total_bytes(), 4 * small_env_len);

        // Idempotent retry of an existing item_id with identical payload succeeds with OK
        let retry_env = make_env(PAD_BUCKETS[0], 0);
        let retry_put = keys.build_put_req(item_ids[0], retry_env).unwrap();
        assert_eq!(
            eng.handle_frame_from_peer(peer, mb_frame::INBOX_PUT, &retry_put.encode()),
            (mb_frame::STATUS, vec![mb_status::OK])
        );

        // 5th distinct item must be rejected with QUOTA_EXCEEDED without overwriting existing 4
        let fifth_put = keys
            .build_put_req([0x99; 16], make_env(PAD_BUCKETS[0], 0xEE))
            .unwrap();
        assert_eq!(
            eng.handle_frame_from_peer(peer, mb_frame::INBOX_PUT, &fifth_put.encode()),
            (mb_frame::STATUS, vec![mb_status::QUOTA_EXCEEDED])
        );
        assert_eq!(eng.device_inbox_item_count(&keys.inbox_id), 4);

        // Wrong write_key must be rejected with BAD_AUTH
        let wrong_keys = EpochSecret::from_bytes([0x63; 32]).derive_device_inbox_keys(
            &gid,
            0,
            &phone_id,
            &phone_rx.public(),
        );
        let mut forged_put = wrong_keys
            .build_put_req([0x77; 16], make_env(PAD_BUCKETS[0], 0x11))
            .unwrap();
        forged_put.inbox_id = keys.inbox_id;
        assert_eq!(
            eng.handle_frame_from_peer(peer, mb_frame::INBOX_PUT, &forged_put.encode()),
            (mb_frame::STATUS, vec![mb_status::BAD_AUTH])
        );

        // Advance 100s and pull all 4 items
        clock.advance_mono_ms(100_000);
        let pull_req = keys.build_pull_req([0x11; 16]);
        let (rft, rbytes) =
            eng.handle_frame_from_peer(peer, mb_frame::INBOX_PULL, &pull_req.encode());
        assert_eq!(rft, mb_frame::INBOX_PULL_OK);
        let (pulled, caps) = InboxPullResp::decode_with_caps(&rbytes).unwrap();
        assert_eq!(pulled.items.len(), 4);
        for (i, item) in pulled.items.iter().enumerate() {
            assert_eq!(item.item_id, item_ids[i]);
            assert_eq!(item.remaining_ttl_secs, 500);
            assert_eq!(item.envelope[4], i as u8);
        }
        let adv = caps.expect("server advertises inbox caps");
        assert_eq!(adv.max_relay_file_bytes, 12 * 1024 * 1024);
        assert_eq!(adv.inbox_max_items, 4);
        assert_eq!(adv.inbox_ttl_secs, 600);

        // Wrong read_key on INBOX_PULL must fail with BAD_AUTH
        let mut bad_pull = wrong_keys.build_pull_req([0x12; 16]);
        bad_pull.inbox_id = keys.inbox_id;
        assert_eq!(
            eng.handle_frame_from_peer(peer, mb_frame::INBOX_PULL, &bad_pull.encode()),
            (mb_frame::STATUS, vec![mb_status::BAD_AUTH])
        );

        // ACK first 2 items -> 2 remain
        let ack1 = keys.build_ack_req(vec![item_ids[0], item_ids[1]]).unwrap();
        assert_eq!(
            eng.handle_frame_from_peer(peer, mb_frame::INBOX_ACK, &ack1.encode()),
            (mb_frame::STATUS, vec![mb_status::OK])
        );
        assert_eq!(eng.device_inbox_item_count(&keys.inbox_id), 2);
        assert_eq!(eng.device_inbox_total_bytes(), 2 * small_env_len);

        // ACK remaining 2 items -> RamDeviceInbox is completely removed from RAM
        let ack2 = keys.build_ack_req(vec![item_ids[2], item_ids[3]]).unwrap();
        assert_eq!(
            eng.handle_frame_from_peer(peer, mb_frame::INBOX_ACK, &ack2.encode()),
            (mb_frame::STATUS, vec![mb_status::OK])
        );
        assert_eq!(eng.device_inbox_count(), 0);
        assert_eq!(eng.device_inbox_total_bytes(), 0);

        // Enqueue 1 item and advance past 600s TTL -> automatically purged on next pull
        let ttl_put = keys
            .build_put_req([0x55; 16], make_env(PAD_BUCKETS[0], 0xCC))
            .unwrap();
        assert_eq!(
            eng.handle_frame_from_peer(peer, mb_frame::INBOX_PUT, &ttl_put.encode()),
            (mb_frame::STATUS, vec![mb_status::OK])
        );
        assert_eq!(eng.device_inbox_count(), 1);
        clock.advance_mono_ms(600_000);
        let pull_after_ttl = keys.build_pull_req([0x13; 16]);
        let (rft2, rbytes2) =
            eng.handle_frame_from_peer(peer, mb_frame::INBOX_PULL, &pull_after_ttl.encode());
        assert_eq!(rft2, mb_frame::INBOX_PULL_OK);
        let (pulled2, _) = InboxPullResp::decode_with_caps(&rbytes2).unwrap();
        assert!(pulled2.items.is_empty());
        assert_eq!(eng.device_inbox_count(), 0);
        assert_eq!(eng.device_inbox_total_bytes(), 0);
    }

    #[test]
    fn ram_device_inbox_global_ceiling_evicts_oldest_first() {
        use voidwire_core::envelope::{HEADER, MAX_ENVELOPE_LEN, MAX_PADDED_LEN, OVERHEAD};
        use voidwire_core::ids::GroupId;
        use voidwire_core::keys::ReceiveKeypair;

        fn make_large_env(tag: u8) -> Vec<u8> {
            let mut v = vec![tag; MAX_PADDED_LEN + OVERHEAD];
            v[..4].copy_from_slice(&HEADER);
            v
        }

        let clock = Arc::new(FakeClock::new(20_650));
        // 65,536 bytes holds at most 7 MAX_ENVELOPE_LEN (8,500 B) envelopes (7 * 8500 = 59,500 <= 65,536; 8 * 8500 = 68,000 > 65,536).
        let limits = MailboxLimits {
            inbox_max_items: 4,
            inbox_ttl_secs: 3_600,
            inbox_max_total_bytes: 65_536,
            ..MailboxLimits::default()
        };
        let mut eng = MailboxEngine::with_limits_and_clock(None, limits, clock.clone()).unwrap();

        let gs = EpochSecret::from_bytes([0x71; 32]);
        let gid = GroupId([0x72; 32]);
        let peer = Some(DeviceKeypair::generate().device_id());

        let mut all_keys = Vec::new();
        for dev_idx in 0..3u8 {
            let dev_id = DeviceKeypair::generate().device_id();
            let dev_rx = ReceiveKeypair::generate();
            let k = gs.derive_device_inbox_keys(&gid, 0, &dev_id, &dev_rx.public());
            for item_idx in 0..3u8 {
                let item_id = [dev_idx * 10 + item_idx + 1; 16];
                let put = k.build_put_req(item_id, make_large_env(dev_idx)).unwrap();
                assert_eq!(
                    eng.handle_frame_from_peer(peer, mb_frame::INBOX_PUT, &put.encode()),
                    (mb_frame::STATUS, vec![mb_status::OK])
                );
                clock.advance_mono_ms(10);
            }
            all_keys.push((dev_idx, k));
        }

        // 9 items * 8,500 B = 76,500 B > 65,536 B, so the 2 oldest items from dev 0 must have been evicted!
        assert!(eng.device_inbox_total_bytes() <= 65_536);
        assert_eq!(eng.device_inbox_total_bytes(), 7 * MAX_ENVELOPE_LEN);
        assert_eq!(eng.device_inbox_item_count(&all_keys[0].1.inbox_id), 1);
        assert_eq!(eng.device_inbox_item_count(&all_keys[1].1.inbox_id), 3);
        assert_eq!(eng.device_inbox_item_count(&all_keys[2].1.inbox_id), 3);
    }
    #[test]
    fn ram_device_inbox_new_inbox_flood_cannot_starve_existing_inbox_put() {
        use voidwire_core::envelope::{HEADER, OVERHEAD, PAD_BUCKETS};
        use voidwire_core::ids::GroupId;
        use voidwire_core::keys::ReceiveKeypair;

        let mut valid_env = vec![0xABu8; PAD_BUCKETS[0] + OVERHEAD];
        valid_env[..4].copy_from_slice(&HEADER);

        let clock = Arc::new(FakeClock::new(20_700));
        let limits = MailboxLimits {
            per_ip_reads_per_min: 100,
            per_ip_appends_per_min: 100,
            global_reads_per_min: 50,
            global_appends_per_min: 10,
            appends_per_min: 20,
            append_burst: 20,
            ..Default::default()
        };
        let mut eng =
            MailboxEngine::with_limits_and_clock(None, limits, clock.clone()).expect("init engine");

        // Pre-create a legitimate inbox, then let the buckets refill completely.
        let gs0 = EpochSecret::from_bytes([0x52; 32]);
        let owner = DeviceKeypair::generate().device_id();
        let owner_rx = ReceiveKeypair::generate();
        let keys0 =
            gs0.derive_device_inbox_keys(&GroupId([0x53; 32]), 0, &owner, &owner_rx.public());
        let put0 = keys0.build_put_req([0xE1; 16], valid_env.clone()).unwrap();
        assert_eq!(
            eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::INBOX_PUT,
                &put0.encode(),
            )
            .1,
            vec![mb_status::OK]
        );
        clock.advance_mono_ms(60_000);

        // Flood 10 INBOX_PUT requests for 10 brand-new random inbox_ids.
        // global_appends_per_min = 10 -> global_create_bucket cap is 5.
        // Only the first 5 new device inboxes may be created; the remaining 5 must
        // be rejected with RATE_LIMITED without draining the remaining 5 tokens in
        // global_append_bucket.
        let mut created = 0usize;
        let mut rate_limited = 0usize;
        for i in 0u8..10u8 {
            let fake_gs = EpochSecret::from_bytes([0x80 + i; 32]);
            let gid = GroupId([0x70 + i; 32]);
            let target = DeviceKeypair::generate().device_id();
            let target_rx = ReceiveKeypair::generate();
            let ik = fake_gs.derive_device_inbox_keys(&gid, 0, &target, &target_rx.public());
            let put = ik.build_put_req([i + 1; 16], valid_env.clone()).unwrap();
            let (_, reply) = eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::INBOX_PUT,
                &put.encode(),
            );
            if reply == vec![mb_status::OK] {
                created += 1;
            } else if reply == vec![mb_status::RATE_LIMITED] {
                rate_limited += 1;
            } else {
                panic!("unexpected reply: {reply:?}");
            }
        }
        assert_eq!(
            created, 5,
            "new INBOX_PUT creations must be capped at global_create_bucket (5)"
        );
        assert_eq!(rate_limited, 5);

        // A put to the existing inbox still succeeds.
        let put1 = keys0.build_put_req([0xE2; 16], valid_env.clone()).unwrap();
        assert_eq!(
            eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::INBOX_PUT,
                &put1.encode(),
            )
            .1,
            vec![mb_status::OK],
            "an existing inbox's INBOX_PUT must not be starved by a new-inbox flood"
        );
    }
}
