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
use std::path::{Path, PathBuf};
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
    mb_frame, mb_status, AdvertisedInboxCaps, AppendMailboxReq, CreateMailboxReq, DeviceInboxId,
    InboxAckReq, InboxPullItem, InboxPullReq, InboxPullResp, InboxPutReq, MailboxId, MailboxRecord,
    MailboxSeal, ReadMailboxReq, ReadMailboxResp, RotateMailboxReq, SealMailboxReq, SignedConfig,
    MAX_MAILBOX_RECORDS, MAX_MAILBOX_RECORD_BYTES, MAX_MAILBOX_TOTAL_BYTES,
};
use voidwire_core::net::{build_relay_mode, default_net_report_config, DEFAULT_RELAY_URL};
use voidwire_core::protocol::ALPN_MAILBOX;
use voidwire_core::ratelimit::{RateLimit, TokenBucket};
use voidwire_core::time::MonoMillis;
use voidwire_core::time::{Clock, Now, SystemClock};
use zeroize::{Zeroize, Zeroizing};

/// Strict no-logs default (`privacy-no-default-logs`).
pub const DEFAULT_LOG_LEVEL: &str = "off";

/// Loopback healthcheck bind address (`docs/M2-PLAN.md` §3.2).
pub const DEFAULT_HEALTHZ_ADDR: &str = "127.0.0.1:48486";

/// Whole-mailbox inactivity expiry in UTC days (`docs/PROTOCOL.md` §7.1(d)).
pub const MAILBOX_EXPIRY_DAYS: u32 = 180;

/// Maximum records returned in a single `READ_OK` response.
pub const MAX_READ_BATCH: usize = 64;

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
/// Default maximum stored mailboxes on disk/index (`10,000`).
pub const DEFAULT_MAX_MAILBOXES: usize = 10_000;
/// Maximum full `StoredMailbox` entries cached in RAM when `data_dir` is backed by disk
/// (`M2-H2`: bounds worst-case RAM well below `MemoryMax=200M`).
pub const MAX_RAM_CACHED_MAILBOXES: usize = 64;
/// Maximum entries in any RAM rate-limit table before oldest-entry eviction (`M2-M3`).
pub const MAX_RATE_BUCKETS: usize = 4_096;

const DISK_MAGIC: &[u8; 6] = b"VWMBX\x01";
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Configurable quotas, retention, and rate limits for [`MailboxEngine`] (`M2-H2`, `M2-M4`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxLimits {
    pub max_mailbox_bytes: usize,
    pub max_records: usize,
    pub max_record_bytes: usize,
    pub appends_per_min: u32,
    pub append_burst: u32,
    pub retention_days: u32,
    pub per_ip_reads_per_min: u32,
    pub per_ip_appends_per_min: u32,
    pub global_reads_per_min: u32,
    pub global_appends_per_min: u32,
    pub max_mailboxes: usize,
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
            max_mailbox_bytes: MAX_MAILBOX_TOTAL_BYTES,
            max_records: MAX_MAILBOX_RECORDS,
            max_record_bytes: MAX_MAILBOX_RECORD_BYTES,
            appends_per_min: MAILBOX_APPEND_LIMIT.per_minute,
            append_burst: MAILBOX_APPEND_LIMIT.burst,
            retention_days: MAILBOX_EXPIRY_DAYS,
            per_ip_reads_per_min: DEFAULT_PER_IP_READS_PER_MIN,
            per_ip_appends_per_min: DEFAULT_PER_IP_APPENDS_PER_MIN,
            global_reads_per_min: DEFAULT_GLOBAL_READS_PER_MIN,
            global_appends_per_min: DEFAULT_GLOBAL_APPENDS_PER_MIN,
            max_mailboxes: DEFAULT_MAX_MAILBOXES,
            max_relay_file_bytes: voidwire_core::file_transfer::DEFAULT_RELAY_FILE_CAP_BYTES,
            inbox_max_items: DEFAULT_INBOX_MAX_ITEMS,
            inbox_ttl_secs: DEFAULT_INBOX_TTL_SECS,
            inbox_max_total_bytes: DEFAULT_INBOX_MAX_TOTAL_BYTES,
        }
    }
}

/// Convert a [`Now`] reading to a coarse UTC day number (`unix_secs / 86_400`).
/// Sub-day precision is discarded immediately (`docs/M2-PLAN.md` §2.3).
pub fn utc_day(now: Now) -> u32 {
    ((now.wall.0 / 1000) / 86_400) as u32
}

/// Configuration for [`MailboxServer`].
#[derive(Debug, Clone)]
pub struct MailboxServerConfig {
    pub secret_key: [u8; 32],
    pub relay_url: String,
    pub data_dir: Option<PathBuf>,
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
            data_dir: None,
            healthz_addr: Some(DEFAULT_HEALTHZ_ADDR.parse().expect("valid loopback addr")),
            signed_config: None,
            limits: MailboxLimits::default(),
            log: DEFAULT_LOG_LEVEL.to_owned(),
        }
    }
}

/// Lightweight metadata kept in RAM for every stored mailbox (`~112 B` per mailbox).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxMeta {
    pub mailbox_id: MailboxId,
    pub epoch: u64,
    pub write_verifier: [u8; 32],
    pub seal_verifier: [u8; 32],
    pub last_access_day: u32,
    pub record_count: u16,
    pub sealed: bool,
    pub next_mailbox_id: Option<MailboxId>,
}

/// One epoch mailbox stored by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMailbox {
    pub mailbox_id: MailboxId,
    pub epoch: u64,
    pub write_verifier: [u8; 32],
    pub seal_verifier: [u8; 32],
    /// Coarse UTC day number (`unix_secs / 86_400`), never a fine-grained timestamp.
    pub last_access_day: u32,
    pub records: Vec<MailboxRecord>,
    pub total_bytes: usize,
    pub seal: Option<MailboxSeal>,
}

impl StoredMailbox {
    pub fn meta(&self) -> MailboxMeta {
        MailboxMeta {
            mailbox_id: self.mailbox_id,
            epoch: self.epoch,
            write_verifier: self.write_verifier,
            seal_verifier: self.seal_verifier,
            last_access_day: self.last_access_day,
            record_count: self.records.len().min(u16::MAX as usize) as u16,
            sealed: self.seal.is_some(),
            next_mailbox_id: self.seal.as_ref().map(|s| s.next_mailbox_id),
        }
    }

    pub fn next_seq(&self) -> u64 {
        (self.records.len() as u64) + 1
    }

    pub fn is_sealed(&self) -> bool {
        self.seal.is_some()
    }

    pub fn encode_disk(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(DISK_MAGIC);
        out.extend_from_slice(&self.mailbox_id.0);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.write_verifier);
        out.extend_from_slice(&self.seal_verifier);
        out.extend_from_slice(&self.last_access_day.to_be_bytes());
        out.extend_from_slice(&(self.records.len() as u16).to_be_bytes());
        for r in &self.records {
            let b = r.encode();
            out.extend_from_slice(&(b.len() as u16).to_be_bytes());
            out.extend_from_slice(&b);
        }
        match &self.seal {
            Some(s) => {
                out.push(1);
                let sb = s.encode();
                out.extend_from_slice(&(sb.len() as u16).to_be_bytes());
                out.extend_from_slice(&sb);
            }
            None => out.push(0),
        }
        out
    }

    pub fn decode_disk(b: &[u8]) -> Option<Self> {
        if b.len() < 6 + 32 + 8 + 32 + 32 + 4 + 2 + 1 {
            return None;
        }
        if &b[..6] != DISK_MAGIC {
            return None;
        }
        let mailbox_id = MailboxId(b[6..38].try_into().ok()?);
        let epoch = u64::from_be_bytes(b[38..46].try_into().ok()?);
        let write_verifier: [u8; 32] = b[46..78].try_into().ok()?;
        let seal_verifier: [u8; 32] = b[78..110].try_into().ok()?;
        let last_access_day = u32::from_be_bytes(b[110..114].try_into().ok()?);
        let count = u16::from_be_bytes([b[114], b[115]]) as usize;
        if count > MAX_MAILBOX_RECORDS + 1 {
            return None;
        }
        let mut o = 116;
        let mut records = Vec::with_capacity(count);
        let mut total_bytes = 0usize;
        for _ in 0..count {
            if o + 2 > b.len() {
                return None;
            }
            let rlen = u16::from_be_bytes([b[o], b[o + 1]]) as usize;
            o += 2;
            if o + rlen > b.len() {
                return None;
            }
            let rec = MailboxRecord::decode(&b[o..o + rlen]).ok()?;
            total_bytes = total_bytes.saturating_add(rec.encoded_len());
            records.push(rec);
            o += rlen;
        }
        if o >= b.len() || total_bytes > MAX_MAILBOX_TOTAL_BYTES + MAX_MAILBOX_RECORD_BYTES {
            return None;
        }
        let has_seal = b[o];
        o += 1;
        let seal = match has_seal {
            0 => {
                if o != b.len()
                    || count > MAX_MAILBOX_RECORDS
                    || total_bytes > MAX_MAILBOX_TOTAL_BYTES
                {
                    return None;
                }
                None
            }
            1 => {
                if o + 2 > b.len() {
                    return None;
                }
                let slen = u16::from_be_bytes([b[o], b[o + 1]]) as usize;
                o += 2;
                if o + slen != b.len() {
                    return None;
                }
                Some(MailboxSeal::decode(&b[o..o + slen]).ok()?)
            }
            _ => return None,
        };
        Some(StoredMailbox {
            mailbox_id,
            epoch,
            write_verifier,
            seal_verifier,
            last_access_day,
            records,
            total_bytes,
            seal,
        })
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
    index: HashMap<MailboxId, MailboxMeta>,
    mailboxes: HashMap<MailboxId, StoredMailbox>,
    cache_order: std::collections::VecDeque<MailboxId>,
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
    data_dir: Option<PathBuf>,
    signed_config: Option<SignedConfig>,
    clock: Arc<dyn Clock + Send + Sync>,
}

impl MailboxEngine {
    pub fn new(
        data_dir: Option<PathBuf>,
        signed_config: Option<SignedConfig>,
    ) -> Result<Self, String> {
        Self::with_limits_and_clock(
            data_dir,
            signed_config,
            MailboxLimits::default(),
            Arc::new(SystemClock),
        )
    }

    pub fn with_clock(
        data_dir: Option<PathBuf>,
        signed_config: Option<SignedConfig>,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Result<Self, String> {
        Self::with_limits_and_clock(data_dir, signed_config, MailboxLimits::default(), clock)
    }

    pub fn with_limits_and_clock(
        data_dir: Option<PathBuf>,
        signed_config: Option<SignedConfig>,
        limits: MailboxLimits,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Result<Self, String> {
        limits.validate()?;
        let mut engine = Self {
            index: HashMap::new(),
            mailboxes: HashMap::new(),
            cache_order: std::collections::VecDeque::new(),
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
            data_dir: data_dir.clone(),
            signed_config,
            clock,
        };
        if let Some(ref dir) = data_dir {
            voidwire_core::net::state::private_dir(dir)
                .map_err(|e| format!("mailbox data_dir: {e}"))?;
            let entries = std::fs::read_dir(dir).map_err(|e| format!("read_dir: {e}"))?;
            for entry in entries.flatten() {
                if engine.index.len() >= engine.limits.max_mailboxes {
                    break;
                }
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("mbx") {
                    continue;
                }
                let Ok(meta) = std::fs::metadata(&path) else {
                    continue;
                };
                if meta.len() > (MAX_MAILBOX_WIRE_FRAME as u64) {
                    continue;
                }
                if let Ok(bytes) = std::fs::read(&path) {
                    if let Some(mb) = StoredMailbox::decode_disk(&bytes) {
                        engine.index.insert(mb.mailbox_id, mb.meta());
                        engine.cache_mailbox(mb);
                    }
                }
            }
        }
        let today = utc_day(engine.clock.now());
        engine.purge_expired(today);
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

    pub fn mailbox_count(&self) -> usize {
        self.index.len()
    }

    pub fn ram_cached_mailbox_count(&self) -> usize {
        self.mailboxes.len()
    }

    pub fn get_mailbox(&self, id: &MailboxId) -> Option<&StoredMailbox> {
        self.mailboxes.get(id)
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

    fn cache_mailbox(&mut self, mb: StoredMailbox) {
        let id = mb.mailbox_id;
        self.index.insert(id, mb.meta());
        self.cache_order.retain(|x| *x != id);
        self.cache_order.push_back(id);
        self.mailboxes.insert(id, mb);
        if self.data_dir.is_some() {
            while self.mailboxes.len() > MAX_RAM_CACHED_MAILBOXES {
                if let Some(oldest) = self.cache_order.pop_front() {
                    self.mailboxes.remove(&oldest);
                } else {
                    break;
                }
            }
        }
    }

    fn load_mailbox(&mut self, id: &MailboxId) -> Option<StoredMailbox> {
        if let Some(mb) = self.mailboxes.get(id).cloned() {
            self.cache_order.retain(|x| x != id);
            self.cache_order.push_back(*id);
            return Some(mb);
        }
        if !self.index.contains_key(id) {
            return None;
        }
        let dir = self.data_dir.as_ref()?;
        let bytes = std::fs::read(Self::mbx_path(dir, id)).ok()?;
        let mb = StoredMailbox::decode_disk(&bytes)?;
        self.cache_mailbox(mb.clone());
        Some(mb)
    }

    pub fn purge_expired(&mut self, today: u32) -> usize {
        let retention = self.limits.retention_days;
        let expired: Vec<MailboxId> = self
            .index
            .iter()
            .filter(|(_, m)| today.saturating_sub(m.last_access_day) > retention)
            .map(|(id, _)| *id)
            .collect();
        let count = expired.len();
        for id in expired {
            self.index.remove(&id);
            self.mailboxes.remove(&id);
            self.cache_order.retain(|x| *x != id);
            self.append_buckets.remove(&id);
            if let Some(ref dir) = self.data_dir {
                let _ = std::fs::remove_file(Self::mbx_path(dir, &id));
            }
        }
        count
    }

    fn mbx_path(dir: &Path, id: &MailboxId) -> PathBuf {
        dir.join(format!("{}.mbx", id.to_hex()))
    }

    fn persist_mailbox(&self, mb: &StoredMailbox) -> Result<(), u8> {
        let Some(ref dir) = self.data_dir else {
            return Ok(());
        };
        let target = Self::mbx_path(dir, &mb.mailbox_id);
        let tmp = dir.join(format!(".{}.mbx.tmp", mb.mailbox_id.to_hex()));
        let bytes = mb.encode_disk();
        std::fs::write(&tmp, &bytes).map_err(|_| mb_status::MALFORMED)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &target).map_err(|_| mb_status::MALFORMED)?;
        Ok(())
    }

    fn validate_records_sequence(
        &self,
        mailbox_id: &MailboxId,
        write_verifier: &[u8; 32],
        start_seq: u64,
        current_count: usize,
        current_bytes: usize,
        records: &[MailboxRecord],
    ) -> Result<usize, u8> {
        if current_count + records.len() > self.limits.max_records {
            return Err(mb_status::QUOTA_EXCEEDED);
        }
        let mut total_bytes = current_bytes;
        for (expected_seq, rec) in (start_seq..).zip(records.iter()) {
            let rlen = rec.encoded_len();
            if rlen > self.limits.max_record_bytes {
                return Err(mb_status::QUOTA_EXCEEDED);
            }
            total_bytes = total_bytes.saturating_add(rlen);
            if total_bytes > self.limits.max_mailbox_bytes {
                return Err(mb_status::QUOTA_EXCEEDED);
            }
            if rec.seq != expected_seq {
                return Err(mb_status::BAD_SEQ);
            }
            rec.verify_write(mailbox_id, write_verifier)
                .map_err(|_| mb_status::BAD_AUTH)?;
        }
        Ok(total_bytes)
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

    /// Evict at most one safe slot during `ROTATE` when `index.len() >= max_mailboxes` (`M26-M1`).
    ///
    /// Security invariants:
    /// - NEVER evicts an active unsealed mailbox (`!m.sealed && m.record_count > 0`).
    /// - NEVER evicts another group's sealed redirect mailbox or any sealed mailbox accessed today
    ///   (except the rotating chain's own direct predecessor stub whose `next_mailbox_id == Some(*protect_old)`).
    /// - Priority 0: empty unsealed mailbox (`!m.sealed && m.record_count == 0`), oldest `last_access_day` first.
    /// - Priority 1: this chain's own direct predecessor sealed stub (`m.sealed && m.next_mailbox_id == Some(*protect_old)`).
    fn evict_one_for_rotate(&mut self, protect_old: &MailboxId, protect_new: &MailboxId) {
        let victim = self
            .index
            .iter()
            .filter(|(id, _)| *id != protect_old && *id != protect_new)
            .filter_map(|(id, m)| {
                if !m.sealed && m.record_count == 0 {
                    Some((*id, (0u8, m.last_access_day)))
                } else if m.sealed && m.next_mailbox_id == Some(*protect_old) {
                    Some((*id, (1u8, m.last_access_day)))
                } else {
                    None
                }
            })
            .min_by_key(|(_, key)| *key)
            .map(|(id, _)| id);

        if let Some(victim) = victim {
            self.index.remove(&victim);
            self.mailboxes.remove(&victim);
            self.cache_order.retain(|x| *x != victim);
            self.append_buckets.remove(&victim);
            if let Some(ref dir) = self.data_dir {
                let _ = std::fs::remove_file(Self::mbx_path(dir, &victim));
            }
        }
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
        let today = utc_day(now);
        self.purge_expired(today);
        self.purge_expired_inboxes(now.mono);

        if let Some(peer_id) = peer {
            let allowed = match frame_type {
                mb_frame::READ
                | mb_frame::CONFIG_GET
                | mb_frame::INBOX_PULL
                | mb_frame::INBOX_ACK => self.allow_peer_read(peer_id, now.mono),
                mb_frame::CREATE
                | mb_frame::APPEND
                | mb_frame::SEAL
                | mb_frame::ROTATE
                | mb_frame::INBOX_PUT => self.allow_peer_append(peer_id, now.mono),
                _ => true,
            };
            if !allowed {
                return Self::status_reply(mb_status::RATE_LIMITED);
            }
        }

        match frame_type {
            mb_frame::CREATE => {
                let Ok(req) = CreateMailboxReq::decode(payload) else {
                    return Self::status_reply(mb_status::MALFORMED);
                };
                if let Some(mut existing) = self.load_mailbox(&req.mailbox_id) {
                    if existing.epoch == req.epoch
                        && existing.write_verifier == req.write_verifier
                        && existing.seal_verifier == req.seal_verifier
                    {
                        if let Some(first) = req.initial_records.first() {
                            if first
                                .verify_write(&req.mailbox_id, &existing.write_verifier)
                                .is_err()
                            {
                                return Self::status_reply(mb_status::BAD_AUTH);
                            }
                        } else if !existing.records.is_empty() {
                            return Self::status_reply(mb_status::BAD_AUTH);
                        }
                        if !self.allow_append(req.mailbox_id, now.mono)
                            || !self.allow_global_append(now.mono)
                        {
                            return Self::status_reply(mb_status::RATE_LIMITED);
                        }
                        if existing.last_access_day != today {
                            existing.last_access_day = today;
                            let _ = self.persist_mailbox(&existing);
                            self.cache_mailbox(existing);
                        }
                        return Self::status_reply(mb_status::OK);
                    }
                    return Self::status_reply(mb_status::ALREADY_EXISTS);
                }
                if self.index.len() >= self.limits.max_mailboxes {
                    return Self::status_reply(mb_status::QUOTA_EXCEEDED);
                }
                let total_bytes = match self.validate_records_sequence(
                    &req.mailbox_id,
                    &req.write_verifier,
                    1,
                    0,
                    0,
                    &req.initial_records,
                ) {
                    Ok(tb) => tb,
                    Err(code) => return Self::status_reply(code),
                };
                if !self.allow_append(req.mailbox_id, now.mono)
                    || !self.allow_global_create(now.mono)
                    || !self.allow_global_append(now.mono)
                {
                    return Self::status_reply(mb_status::RATE_LIMITED);
                }
                let mb = StoredMailbox {
                    mailbox_id: req.mailbox_id,
                    epoch: req.epoch,
                    write_verifier: req.write_verifier,
                    seal_verifier: req.seal_verifier,
                    last_access_day: today,
                    records: req.initial_records,
                    total_bytes,
                    seal: None,
                };
                if let Err(code) = self.persist_mailbox(&mb) {
                    return Self::status_reply(code);
                }
                self.cache_mailbox(mb);
                Self::status_reply(mb_status::OK)
            }
            mb_frame::APPEND => {
                let Ok(req) = AppendMailboxReq::decode(payload) else {
                    return Self::status_reply(mb_status::MALFORMED);
                };
                let Some(existing) = self.load_mailbox(&req.mailbox_id) else {
                    return Self::status_reply(mb_status::NOT_FOUND);
                };
                if existing.is_sealed() {
                    return Self::status_reply(mb_status::SEALED);
                }
                if req
                    .record
                    .verify_write(&req.mailbox_id, &existing.write_verifier)
                    .is_err()
                {
                    return Self::status_reply(mb_status::BAD_AUTH);
                }
                if !self.allow_append(req.mailbox_id, now.mono)
                    || !self.allow_global_append(now.mono)
                {
                    return Self::status_reply(mb_status::RATE_LIMITED);
                }
                let new_total = match self.validate_records_sequence(
                    &req.mailbox_id,
                    &existing.write_verifier,
                    existing.next_seq(),
                    existing.records.len(),
                    existing.total_bytes,
                    std::slice::from_ref(&req.record),
                ) {
                    Ok(tb) => tb,
                    Err(code) => return Self::status_reply(code),
                };
                let mut updated = existing;
                updated.records.push(req.record);
                updated.total_bytes = new_total;
                updated.last_access_day = today;
                if let Err(code) = self.persist_mailbox(&updated) {
                    return Self::status_reply(code);
                }
                self.cache_mailbox(updated);
                Self::status_reply(mb_status::OK)
            }
            mb_frame::READ => {
                let Ok(req) = ReadMailboxReq::decode(payload) else {
                    return Self::status_reply(mb_status::MALFORMED);
                };
                let Some(mut existing) = self.load_mailbox(&req.mailbox_id) else {
                    return Self::status_reply(mb_status::NOT_FOUND);
                };
                if !self.allow_global_read(now.mono) {
                    return Self::status_reply(mb_status::RATE_LIMITED);
                }
                let day_changed = existing.last_access_day != today;
                existing.last_access_day = today;
                let records: Vec<MailboxRecord> = existing
                    .records
                    .iter()
                    .filter(|r| r.seq >= req.from_seq)
                    .take(MAX_READ_BATCH)
                    .cloned()
                    .collect();
                let resp = ReadMailboxResp {
                    epoch: existing.epoch,
                    records,
                    seal: existing.seal.clone(),
                };
                if day_changed {
                    let _ = self.persist_mailbox(&existing);
                    self.cache_mailbox(existing);
                }
                (
                    mb_frame::READ_OK,
                    resp.encode_with_cap(self.limits.max_relay_file_bytes),
                )
            }
            mb_frame::SEAL => {
                let Ok(req) = SealMailboxReq::decode(payload) else {
                    return Self::status_reply(mb_status::MALFORMED);
                };
                let Some(existing) = self.load_mailbox(&req.mailbox_id) else {
                    return Self::status_reply(mb_status::NOT_FOUND);
                };
                if existing.is_sealed() {
                    return Self::status_reply(mb_status::SEALED);
                }
                if req.seal.epoch != existing.epoch {
                    return Self::status_reply(mb_status::BAD_SEQ);
                }
                if req
                    .seal
                    .verify(&req.mailbox_id, &existing.seal_verifier)
                    .is_err()
                {
                    return Self::status_reply(mb_status::BAD_AUTH);
                }
                if !self.allow_append(req.mailbox_id, now.mono)
                    || !self.allow_global_append(now.mono)
                {
                    return Self::status_reply(mb_status::RATE_LIMITED);
                }
                let mut updated = existing;
                updated.seal = Some(req.seal);
                updated.last_access_day = today;
                if let Err(code) = self.persist_mailbox(&updated) {
                    return Self::status_reply(code);
                }
                self.cache_mailbox(updated);
                Self::status_reply(mb_status::OK)
            }
            mb_frame::ROTATE => {
                let Ok(req) = RotateMailboxReq::decode(payload) else {
                    return Self::status_reply(mb_status::MALFORMED);
                };
                if req.old_mailbox_id == req.create_new.mailbox_id {
                    return Self::status_reply(mb_status::MALFORMED);
                }
                let Some(old_mb) = self.load_mailbox(&req.old_mailbox_id) else {
                    return Self::status_reply(mb_status::NOT_FOUND);
                };
                if old_mb.is_sealed() {
                    return Self::status_reply(mb_status::SEALED);
                }
                if self.index.contains_key(&req.create_new.mailbox_id) {
                    return Self::status_reply(mb_status::ALREADY_EXISTS);
                }
                if req.seal.epoch != old_mb.epoch
                    || req.seal.next_mailbox_id != req.create_new.mailbox_id
                    || req.create_new.epoch != old_mb.epoch.saturating_add(1)
                {
                    return Self::status_reply(mb_status::BAD_SEQ);
                }
                if req
                    .seal
                    .verify(&req.old_mailbox_id, &old_mb.seal_verifier)
                    .is_err()
                {
                    return Self::status_reply(mb_status::BAD_AUTH);
                }
                let mut updated_old = old_mb.clone();
                if let Some(ref final_rec) = req.final_old_record {
                    let rlen = final_rec.encoded_len();
                    if rlen > self.limits.max_record_bytes {
                        return Self::status_reply(mb_status::QUOTA_EXCEEDED);
                    }
                    if final_rec.seq != old_mb.next_seq() {
                        return Self::status_reply(mb_status::BAD_SEQ);
                    }
                    if final_rec
                        .verify_write(&req.old_mailbox_id, &old_mb.write_verifier)
                        .is_err()
                    {
                        return Self::status_reply(mb_status::BAD_AUTH);
                    }
                    updated_old.records.push(final_rec.clone());
                    updated_old.total_bytes = old_mb.total_bytes.saturating_add(rlen);
                }
                updated_old.seal = Some(req.seal);
                updated_old.last_access_day = today;

                let new_total = match self.validate_records_sequence(
                    &req.create_new.mailbox_id,
                    &req.create_new.write_verifier,
                    1,
                    0,
                    0,
                    &req.create_new.initial_records,
                ) {
                    Ok(tb) => tb,
                    Err(code) => return Self::status_reply(code),
                };
                if !self.allow_append(req.old_mailbox_id, now.mono)
                    || !self.allow_global_append(now.mono)
                {
                    return Self::status_reply(mb_status::RATE_LIMITED);
                }
                // Carry the rate-limit bucket state from old_mailbox_id to the rotated
                // new_mailbox_id so rotating in a loop shares the same per-chain budget (`M26-M1`).
                if let Some(bucket_state) = self.append_buckets.get(&req.old_mailbox_id).cloned() {
                    self.append_buckets
                        .insert(req.create_new.mailbox_id, bucket_state);
                }
                let new_mb = StoredMailbox {
                    mailbox_id: req.create_new.mailbox_id,
                    epoch: req.create_new.epoch,
                    write_verifier: req.create_new.write_verifier,
                    seal_verifier: req.create_new.seal_verifier,
                    last_access_day: today,
                    records: req.create_new.initial_records,
                    total_bytes: new_total,
                    seal: None,
                };

                if let Err(code) = self.persist_mailbox(&new_mb) {
                    return Self::status_reply(code);
                }
                if let Err(code) = self.persist_mailbox(&updated_old) {
                    if let Some(ref dir) = self.data_dir {
                        let _ = std::fs::remove_file(Self::mbx_path(dir, &new_mb.mailbox_id));
                    }
                    return Self::status_reply(code);
                }
                self.cache_mailbox(updated_old);
                if self.index.len() >= self.limits.max_mailboxes {
                    self.evict_one_for_rotate(&req.old_mailbox_id, &new_mb.mailbox_id);
                }
                self.cache_mailbox(new_mb);
                Self::status_reply(mb_status::OK)
            }
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
            cfg.data_dir.clone(),
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
    use voidwire_core::mailbox::{EpochSecret, OwnerSealRoot, SEAL_REKEY_SEQ};
    use voidwire_core::net::test_relay::TestRelay;
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

        fn advance_days(&self, d: u32) {
            self.wall_ms
                .fetch_add((d as u64) * 86_400 * 1000, Ordering::SeqCst);
            self.mono_ms
                .fetch_add((d as u64) * 86_400 * 1000, Ordering::SeqCst);
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

    #[test]
    fn quotas_signatures_seal_immutability_and_atomic_rotate() {
        let clock = Arc::new(FakeClock::new(20_000));
        let mut eng = MailboxEngine::with_clock(None, None, clock.clone()).unwrap();

        let gs0 = EpochSecret::from_bytes([0x11; 32]);
        let keys0 = gs0.derive_keys();
        let osr = OwnerSealRoot::from_bytes([0x22; 32]);
        let seal_key0 = osr.derive_seal_key(0);

        // 1. Create mailbox 0
        let create0 = CreateMailboxReq {
            mailbox_id: keys0.mailbox_id,
            epoch: 0,
            write_verifier: keys0.write_verifier,
            seal_verifier: seal_key0.verifier,
            initial_records: Vec::new(),
        };
        let (ft, p) = eng.handle_frame(mb_frame::CREATE, &create0.encode());
        assert_eq!((ft, p.as_slice()), (mb_frame::STATUS, &[mb_status::OK][..]));

        // 2. Append valid record seq 1
        let rec1 = MailboxRecord::seal(&keys0, 1, b"op-1-bytes").unwrap();
        let app1 = AppendMailboxReq {
            mailbox_id: keys0.mailbox_id,
            record: rec1.clone(),
        };
        assert_eq!(
            eng.handle_frame(mb_frame::APPEND, &app1.encode()),
            (mb_frame::STATUS, vec![mb_status::OK])
        );

        // 3. Reject out-of-order seq (seq 1 again or seq 3)
        assert_eq!(
            eng.handle_frame(mb_frame::APPEND, &app1.encode()),
            (mb_frame::STATUS, vec![mb_status::BAD_SEQ])
        );
        let rec3 = MailboxRecord::seal(&keys0, 3, b"op-3").unwrap();
        assert_eq!(
            eng.handle_frame(
                mb_frame::APPEND,
                &AppendMailboxReq {
                    mailbox_id: keys0.mailbox_id,
                    record: rec3,
                }
                .encode()
            ),
            (mb_frame::STATUS, vec![mb_status::BAD_SEQ])
        );

        // 4. Reject record signed with wrong write key
        let wrong_keys = EpochSecret::from_bytes([0x99; 32]).derive_keys();
        let bad_rec = MailboxRecord::seal(&wrong_keys, 2, b"forged").unwrap();
        assert_eq!(
            eng.handle_frame(
                mb_frame::APPEND,
                &AppendMailboxReq {
                    mailbox_id: keys0.mailbox_id,
                    record: bad_rec,
                }
                .encode()
            ),
            (mb_frame::STATUS, vec![mb_status::BAD_AUTH])
        );

        // 5. Rate limit: 20 appends/min burst 20 (checked after write signature verification).
        // 4 authenticated writes above (1 CREATE + 3 valid-sig APPENDs) consumed 4 tokens;
        // 16 more succeed (seq 2..=17), then seq 18 is RATE_LIMITED.
        for seq in 2..=17 {
            let r = MailboxRecord::seal(&keys0, seq, b"op").unwrap();
            assert_eq!(
                eng.handle_frame(
                    mb_frame::APPEND,
                    &AppendMailboxReq {
                        mailbox_id: keys0.mailbox_id,
                        record: r,
                    }
                    .encode()
                ),
                (mb_frame::STATUS, vec![mb_status::OK])
            );
        }
        let r18 = MailboxRecord::seal(&keys0, 18, b"op-18").unwrap();
        assert_eq!(
            eng.handle_frame(
                mb_frame::APPEND,
                &AppendMailboxReq {
                    mailbox_id: keys0.mailbox_id,
                    record: r18,
                }
                .encode()
            ),
            (mb_frame::STATUS, vec![mb_status::RATE_LIMITED])
        );

        // Advance monotonic clock by 60s -> token bucket refills
        clock.advance_mono_ms(60_000);

        // 6. Atomic ROTATE (epoch 0 -> epoch 1):
        let gs1 = EpochSecret::from_bytes([0x33; 32]);
        let keys1 = gs1.derive_keys();
        let seal_key1 = osr.derive_seal_key(1);
        let remove_rec = MailboxRecord::seal(&keys0, 18, b"signed-remove-op").unwrap();
        let _ = SEAL_REKEY_SEQ;
        let seal0 =
            MailboxSeal::create(&keys0, &seal_key0, keys1.mailbox_id, b"signed-rekey-op").unwrap();
        let init_new_rec = MailboxRecord::seal(&keys1, 1, b"epoch1-checkpoint").unwrap();

        // First test atomic rollback: if seal has wrong epoch or bad signature, neither old nor new changes.
        let mut bad_seal = seal0.clone();
        bad_seal.sig_seal[0] ^= 0xFF;
        let bad_rotate = RotateMailboxReq {
            old_mailbox_id: keys0.mailbox_id,
            final_old_record: Some(remove_rec.clone()),
            seal: bad_seal,
            create_new: CreateMailboxReq {
                mailbox_id: keys1.mailbox_id,
                epoch: 1,
                write_verifier: keys1.write_verifier,
                seal_verifier: seal_key1.verifier,
                initial_records: vec![init_new_rec.clone()],
            },
        };
        assert_eq!(
            eng.handle_frame(mb_frame::ROTATE, &bad_rotate.encode()),
            (mb_frame::STATUS, vec![mb_status::BAD_AUTH])
        );
        assert!(!eng.get_mailbox(&keys0.mailbox_id).unwrap().is_sealed());
        assert!(eng.get_mailbox(&keys1.mailbox_id).is_none());

        // Now valid atomic ROTATE:
        let good_rotate = RotateMailboxReq {
            old_mailbox_id: keys0.mailbox_id,
            final_old_record: Some(remove_rec),
            seal: seal0.clone(),
            create_new: CreateMailboxReq {
                mailbox_id: keys1.mailbox_id,
                epoch: 1,
                write_verifier: keys1.write_verifier,
                seal_verifier: seal_key1.verifier,
                initial_records: vec![init_new_rec],
            },
        };
        assert_eq!(
            eng.handle_frame(mb_frame::ROTATE, &good_rotate.encode()),
            (mb_frame::STATUS, vec![mb_status::OK])
        );

        // 7. Seal immutability: old mailbox is now sealed; APPEND, SEAL, and ROTATE on old mailbox fail with SEALED.
        let r22 = MailboxRecord::seal(&keys0, 19, b"after-seal").unwrap();
        assert_eq!(
            eng.handle_frame(
                mb_frame::APPEND,
                &AppendMailboxReq {
                    mailbox_id: keys0.mailbox_id,
                    record: r22,
                }
                .encode()
            ),
            (mb_frame::STATUS, vec![mb_status::SEALED])
        );
        assert_eq!(
            eng.handle_frame(
                mb_frame::SEAL,
                &SealMailboxReq {
                    mailbox_id: keys0.mailbox_id,
                    seal: seal0.clone(),
                }
                .encode()
            ),
            (mb_frame::STATUS, vec![mb_status::SEALED])
        );

        // 8. READ old mailbox returns record 21 + seal0 pointing to keys1.mailbox_id:
        let (rft, rp) = eng.handle_frame(
            mb_frame::READ,
            &ReadMailboxReq {
                mailbox_id: keys0.mailbox_id,
                from_seq: 18,
            }
            .encode(),
        );
        assert_eq!(rft, mb_frame::READ_OK);
        let read_resp = ReadMailboxResp::decode(&rp).unwrap();
        assert_eq!(read_resp.epoch, 0);
        assert_eq!(read_resp.records.len(), 1);
        assert_eq!(
            read_resp.records[0].open(&keys0).unwrap(),
            b"signed-remove-op"
        );
        assert_eq!(read_resp.seal, Some(seal0));
    }

    #[test]
    fn day_granularity_expiry_and_signed_config_serving() {
        let dir = std::env::temp_dir().join(format!(
            "vw-mbx-test-{}",
            DeviceKeypair::generate().device_id().short()
        ));
        let clock = Arc::new(FakeClock::new(20_500));
        let cfg_sk = [0x77u8; 32];
        let signed_cfg = SignedConfig::sign(&cfg_sk, 20_500, 20_530, 10 * 1024 * 1024).unwrap();

        let mut eng =
            MailboxEngine::with_clock(Some(dir.clone()), Some(signed_cfg), clock.clone()).unwrap();

        let gs = EpochSecret::from_bytes([0x55; 32]);
        let keys = gs.derive_keys();
        let osr = OwnerSealRoot::from_bytes([0x66; 32]);
        let seal_key = osr.derive_seal_key(0);

        assert_eq!(
            eng.handle_frame(
                mb_frame::CREATE,
                &CreateMailboxReq {
                    mailbox_id: keys.mailbox_id,
                    epoch: 0,
                    write_verifier: keys.write_verifier,
                    seal_verifier: seal_key.verifier,
                    initial_records: Vec::new(),
                }
                .encode()
            ),
            (mb_frame::STATUS, vec![mb_status::OK])
        );

        // Verify disk file stores only the 4-byte UTC day number (20_500), never the raw wall_ms timestamp!
        let disk_bytes =
            std::fs::read(dir.join(format!("{}.mbx", keys.mailbox_id.to_hex()))).unwrap();
        let wall_ms_bytes = clock.now().wall.0.to_be_bytes();
        assert!(
            !disk_bytes.windows(8).any(|w| w == wall_ms_bytes),
            "fine-grained timestamp must never be written to .mbx file"
        );
        assert_eq!(
            eng.get_mailbox(&keys.mailbox_id).unwrap().last_access_day,
            20_500
        );

        // Advance 180 days: still alive (180 <= MAILBOX_EXPIRY_DAYS)
        clock.advance_days(180);
        let (ft, cp) = eng.handle_frame(mb_frame::CONFIG_GET, &[]);
        assert_eq!(ft, mb_frame::CONFIG);
        assert_eq!(SignedConfig::decode(&cp).unwrap(), signed_cfg);
        assert_eq!(eng.mailbox_count(), 1);

        // Advance 1 more day (181 days total without access): purged from memory and disk!
        clock.advance_days(1);
        let _ = eng.handle_frame(mb_frame::CONFIG_GET, &[]);
        assert_eq!(eng.mailbox_count(), 0);
        assert!(!dir
            .join(format!("{}.mbx", keys.mailbox_id.to_hex()))
            .exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn server_binds_zero_udp_sockets_and_serves_over_relay_with_throwaway_client() {
        let relay = std::thread::spawn(TestRelay::start).join().unwrap();
        let cfg_sk = [0x88u8; 32];
        let signed_cfg = SignedConfig::sign(&cfg_sk, 20_000, 20_010, 25 * 1024 * 1024).unwrap();

        let server = MailboxServer::start(MailboxServerConfig {
            secret_key: [0x44u8; 32],
            relay_url: relay.url(),
            data_dir: None,
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

        let gs = EpochSecret::from_bytes([0xAB; 32]);
        let keys = gs.derive_keys();
        let osr = OwnerSealRoot::from_bytes([0xCD; 32]);
        let seal_key = osr.derive_seal_key(0);
        let rec1 = MailboxRecord::seal(&keys, 1, b"hello-over-relay").unwrap();

        // Send CREATE with initial record
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        write_mb_frame(
            &mut s,
            mb_frame::CREATE,
            &CreateMailboxReq {
                mailbox_id: keys.mailbox_id,
                epoch: 0,
                write_verifier: keys.write_verifier,
                seal_verifier: seal_key.verifier,
                initial_records: vec![rec1],
            }
            .encode(),
        )
        .await
        .unwrap();
        let _ = s.finish();
        let (rft, rp) = read_mb_frame(&mut r).await.unwrap();
        assert_eq!(rft, mb_frame::STATUS);
        assert_eq!(rp[0], mb_status::OK);
        assert_eq!(
            u64::from_be_bytes(rp[1..9].try_into().unwrap()),
            voidwire_core::file_transfer::DEFAULT_RELAY_FILE_CAP_BYTES
        );

        // Send READ
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        write_mb_frame(
            &mut s,
            mb_frame::READ,
            &ReadMailboxReq {
                mailbox_id: keys.mailbox_id,
                from_seq: 1,
            }
            .encode(),
        )
        .await
        .unwrap();
        let _ = s.finish();
        let (rft, rp) = read_mb_frame(&mut r).await.unwrap();
        assert_eq!(rft, mb_frame::READ_OK);
        let read_ok = ReadMailboxResp::decode(&rp).unwrap();
        assert_eq!(read_ok.records.len(), 1);
        assert_eq!(read_ok.records[0].open(&keys).unwrap(), b"hello-over-relay");

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
    fn m2_h2_m3_per_peer_rate_limits_bounded_cache_and_idempotent_create() {
        let dir = std::env::temp_dir().join(format!(
            "vw-mbx-h2m3-{}",
            DeviceKeypair::generate().device_id().short()
        ));
        let clock = Arc::new(FakeClock::new(21_000));
        let limits = MailboxLimits {
            per_ip_reads_per_min: 3,
            per_ip_appends_per_min: 2,
            max_mailboxes: 80,
            ..Default::default()
        };

        let mut eng =
            MailboxEngine::with_limits_and_clock(Some(dir.clone()), None, limits, clock.clone())
                .unwrap();

        let peer_a = DeviceKeypair::generate().device_id();
        let gs = EpochSecret::from_bytes([0x71; 32]);
        let keys = gs.derive_keys();
        let osr = OwnerSealRoot::from_bytes([0x72; 32]);
        let seal_key = osr.derive_seal_key(0);
        let rec1 = MailboxRecord::seal(&keys, 1, b"rec-1").unwrap();

        let create_req = CreateMailboxReq {
            mailbox_id: keys.mailbox_id,
            epoch: 0,
            write_verifier: keys.write_verifier,
            seal_verifier: seal_key.verifier,
            initial_records: vec![rec1.clone()],
        };
        assert_eq!(
            eng.handle_frame_from_peer(Some(peer_a), mb_frame::CREATE, &create_req.encode()),
            (mb_frame::STATUS, vec![mb_status::OK])
        );

        let empty_create = CreateMailboxReq {
            mailbox_id: keys.mailbox_id,
            epoch: 0,
            write_verifier: keys.write_verifier,
            seal_verifier: seal_key.verifier,
            initial_records: Vec::new(),
        };
        assert_eq!(
            eng.handle_frame_from_peer(Some(peer_a), mb_frame::CREATE, &empty_create.encode()),
            (mb_frame::STATUS, vec![mb_status::BAD_AUTH])
        );

        assert_eq!(
            eng.handle_frame_from_peer(Some(peer_a), mb_frame::CREATE, &create_req.encode()),
            (mb_frame::STATUS, vec![mb_status::RATE_LIMITED])
        );
        clock.advance_mono_ms(60_000);

        let mbx_file = dir.join(format!("{}.mbx", keys.mailbox_id.to_hex()));
        let mtime_before = std::fs::metadata(&mbx_file).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            eng.handle_frame_from_peer(Some(peer_a), mb_frame::CREATE, &create_req.encode()),
            (mb_frame::STATUS, vec![mb_status::OK])
        );
        let mtime_after = std::fs::metadata(&mbx_file).unwrap().modified().unwrap();
        assert_eq!(mtime_before, mtime_after);

        let read_req = ReadMailboxReq {
            mailbox_id: keys.mailbox_id,
            from_seq: 1,
        }
        .encode();
        for _ in 0..3 {
            let (ft, _) = eng.handle_frame_from_peer(Some(peer_a), mb_frame::READ, &read_req);
            assert_eq!(ft, mb_frame::READ_OK);
        }
        assert_eq!(
            eng.handle_frame_from_peer(Some(peer_a), mb_frame::READ, &read_req),
            (mb_frame::STATUS, vec![mb_status::RATE_LIMITED])
        );

        for i in 1..80u8 {
            clock.advance_mono_ms(60_000);
            let ki = EpochSecret::from_bytes([i; 32]).derive_keys();
            let req = CreateMailboxReq {
                mailbox_id: ki.mailbox_id,
                epoch: 0,
                write_verifier: ki.write_verifier,
                seal_verifier: seal_key.verifier,
                initial_records: Vec::new(),
            };
            assert_eq!(
                eng.handle_frame(mb_frame::CREATE, &req.encode()),
                (mb_frame::STATUS, vec![mb_status::OK])
            );
        }
        assert_eq!(eng.mailbox_count(), 80);
        assert!(eng.ram_cached_mailbox_count() <= MAX_RAM_CACHED_MAILBOXES);

        clock.advance_mono_ms(60_000);
        let gs_over = EpochSecret::from_bytes([0xFE; 32]).derive_keys();
        assert_eq!(
            eng.handle_frame(
                mb_frame::CREATE,
                &CreateMailboxReq {
                    mailbox_id: gs_over.mailbox_id,
                    epoch: 0,
                    write_verifier: gs_over.write_verifier,
                    seal_verifier: seal_key.verifier,
                    initial_records: Vec::new(),
                }
                .encode()
            ),
            (mb_frame::STATUS, vec![mb_status::QUOTA_EXCEEDED])
        );

        clock.advance_mono_ms(60_000);
        let (ft, rp) = eng.handle_frame(mb_frame::READ, &read_req);
        assert_eq!(ft, mb_frame::READ_OK);
        assert_eq!(ReadMailboxResp::decode(&rp).unwrap().records.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn m2_h3_client_pagination_past_64_records_across_sync_rotate_and_pull_chain() {
        use voidwire_core::grouplog::{sign_new_entries, GroupReplica, Membership};
        use voidwire_core::ids::GroupId;
        use voidwire_core::keys::{DeviceCert, Platform, ReceiveKeypair};
        use voidwire_core::mailbox::{wrap_epoch_secret, RekeyPayload};
        use voidwire_core::net::mailbox_client::{
            owner_rotate_mailbox, owner_sync_or_reseed_mailbox, pull_mailbox_chain,
        };
        use voidwire_core::roster::{OpKind, Roster};
        use voidwire_core::time::UnixMillis;

        let relay = std::thread::spawn(TestRelay::start).join().unwrap();
        let relay_url = relay.url();
        let limits = MailboxLimits {
            per_ip_reads_per_min: 1_000,
            per_ip_appends_per_min: 1_000,
            appends_per_min: 1_000,
            append_burst: 1_000,
            ..Default::default()
        };

        let server = MailboxServer::start(MailboxServerConfig {
            secret_key: [0x51u8; 32],
            relay_url: relay_url.clone(),
            data_dir: None,
            healthz_addr: None,
            signed_config: None,
            limits,
            log: "off".into(),
        })
        .await
        .unwrap();
        let mb_peer = server.device_id();
        for _ in 0..200 {
            if relay.has_peer(&mb_peer) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let owner_kp = DeviceKeypair::generate();
        let owner_rx = ReceiveKeypair::generate();
        let owner_cert = DeviceCert::issue(
            &owner_kp,
            owner_rx.public(),
            "Owner PC",
            Platform::Linux,
            UnixMillis(1_000),
        )
        .unwrap();
        let group_id = GroupId([0x77; 32]);
        let mut roster = Roster::genesis_with_cert(group_id, owner_cert);

        let keep_phone_kp = DeviceKeypair::generate();
        let keep_phone_rx = ReceiveKeypair::generate();
        let keep_cert = DeviceCert::issue(
            &keep_phone_kp,
            keep_phone_rx.public(),
            "Phone Keep",
            Platform::Android,
            UnixMillis(2_000),
        )
        .unwrap();
        roster.apply(
            OpKind::AddDevice,
            keep_phone_kp.device_id(),
            "Phone Keep".into(),
            Some(keep_cert),
        );

        let mut last_added_id = None;
        for i in 0..69 {
            let dk = DeviceKeypair::generate();
            let drx = ReceiveKeypair::generate();
            let dc = DeviceCert::issue(
                &dk,
                drx.public(),
                &format!("Temp {i}"),
                Platform::Android,
                UnixMillis(3_000 + i),
            )
            .unwrap();
            roster.apply(
                OpKind::AddDevice,
                dk.device_id(),
                format!("Temp {i}"),
                Some(dc),
            );
            if i < 68 {
                roster.remove_device(&dk.device_id());
            } else {
                last_added_id = Some(dk.device_id());
            }
        }

        let mut ops = Vec::new();
        sign_new_entries(&roster, &owner_kp, &mut ops, UnixMillis(5_000));
        assert_eq!(ops.len(), 139);

        let gs0 = EpochSecret::from_bytes([0xA0; 32]);
        let keys0 = gs0.derive_keys();
        let osr = OwnerSealRoot::from_bytes([0xB0; 32]);
        let seal_key0 = osr.derive_seal_key(0);

        owner_sync_or_reseed_mailbox(
            &mb_peer,
            &relay_url,
            0,
            &keys0,
            seal_key0.verifier,
            &ops[..100],
        )
        .await
        .expect("seed first 100 ops");

        owner_sync_or_reseed_mailbox(&mb_peer, &relay_url, 0, &keys0, seal_key0.verifier, &ops)
            .await
            .expect("paginate & append remaining 39 ops past 64-record batch boundary");

        let victim_id = last_added_id.unwrap();
        roster.remove_device(&victim_id);
        let gs1 = EpochSecret::from_bytes([0xA1; 32]);
        let keys1 = gs1.derive_keys();
        let seal_key1 = osr.derive_seal_key(1);
        let wrapped = wrap_epoch_secret(
            &keep_phone_kp.device_id(),
            &keep_phone_rx.public(),
            &group_id,
            1,
            &gs1,
        )
        .unwrap();
        let rekey_payload = RekeyPayload {
            new_epoch: 1,
            removed: victim_id,
            wrapped_keys: vec![wrapped],
        };
        assert!(roster.rekey(rekey_payload));
        sign_new_entries(&roster, &owner_kp, &mut ops, UnixMillis(6_000));
        assert_eq!(ops.len(), 141);
        let rem_final = ops[139].clone();
        let rekey_op = ops[140].clone();

        owner_rotate_mailbox(
            &mb_peer,
            &relay_url,
            0,
            &keys0,
            &seal_key0,
            1,
            &keys1,
            seal_key1.verifier,
            &rem_final,
            &rekey_op,
            &ops,
        )
        .await
        .expect("owner_rotate_mailbox across >64 records");

        let (_eph, cur_epoch, cur_gs, pulled_ops) = pull_mailbox_chain(
            &mb_peer,
            &relay_url,
            &keep_phone_kp.device_id(),
            &keep_phone_rx,
            &group_id,
            0,
            &gs0,
        )
        .await
        .expect("pull_mailbox_chain across >64 records in both epoch 0 and epoch 1");

        assert_eq!(cur_epoch, 1);
        assert_eq!(cur_gs.as_bytes(), gs1.as_bytes());
        let mut replica = GroupReplica::new(owner_kp.device_id(), ops[..2].to_vec()).unwrap();
        for op in pulled_ops {
            let _ = replica.apply_op(op).unwrap();
        }
        assert_eq!(
            replica.membership(&keep_phone_kp.device_id()),
            Membership::Member
        );
        assert_eq!(replica.membership(&victim_id), Membership::Removed);
        assert_eq!(replica.epoch(), 1);
        assert_eq!(replica.head(), roster.head());

        server.shutdown().await;
        std::thread::spawn(move || drop(relay)).join().unwrap();
    }

    #[test]
    fn m2_r2_rotate_succeeds_at_max_mailboxes_and_global_rate_limit_bounds_throwaway_peers() {
        let clock = Arc::new(FakeClock::new(20_500));
        let limits = MailboxLimits {
            max_mailboxes: 3,
            per_ip_reads_per_min: 100,
            per_ip_appends_per_min: 100,
            global_reads_per_min: 4,
            global_appends_per_min: 5,
            ..Default::default()
        };

        let mut eng = MailboxEngine::with_limits_and_clock(None, None, limits, clock.clone())
            .expect("init engine");

        let gs0 = EpochSecret::from_bytes([0x10; 32]);
        let keys0 = gs0.derive_keys();
        let osr = OwnerSealRoot::from_bytes([0x20; 32]);
        let seal0 = osr.derive_seal_key(0);
        let rec1 = MailboxRecord::seal(&keys0, 1, b"active-group-op-1").unwrap();

        assert_eq!(
            eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::CREATE,
                &CreateMailboxReq {
                    mailbox_id: keys0.mailbox_id,
                    epoch: 0,
                    write_verifier: keys0.write_verifier,
                    seal_verifier: seal0.verifier,
                    initial_records: vec![rec1],
                }
                .encode(),
            ),
            (mb_frame::STATUS, vec![mb_status::OK])
        );

        let filler_a = EpochSecret::from_bytes([0x11; 32]).derive_keys();
        let filler_b = EpochSecret::from_bytes([0x12; 32]).derive_keys();
        for fk in [&filler_a, &filler_b] {
            assert_eq!(
                eng.handle_frame_from_peer(
                    Some(DeviceKeypair::generate().device_id()),
                    mb_frame::CREATE,
                    &CreateMailboxReq {
                        mailbox_id: fk.mailbox_id,
                        epoch: 0,
                        write_verifier: fk.write_verifier,
                        seal_verifier: seal0.verifier,
                        initial_records: Vec::new(),
                    }
                    .encode(),
                ),
                (mb_frame::STATUS, vec![mb_status::OK])
            );
        }
        assert_eq!(eng.mailbox_count(), 3);

        let gs1 = EpochSecret::from_bytes([0x13; 32]);
        let keys1 = gs1.derive_keys();
        let seal1 = osr.derive_seal_key(1);
        let final_old = MailboxRecord::seal(&keys0, 2, b"remove-device-op").unwrap();
        let seal = MailboxSeal::create(&keys0, &seal0, keys1.mailbox_id, b"rekey-epoch-1").unwrap();
        let new_rec1 = MailboxRecord::seal(&keys1, 1, b"epoch-1-genesis").unwrap();
        let rot_req = RotateMailboxReq {
            old_mailbox_id: keys0.mailbox_id,
            final_old_record: Some(final_old),
            seal,
            create_new: CreateMailboxReq {
                mailbox_id: keys1.mailbox_id,
                epoch: 1,
                write_verifier: keys1.write_verifier,
                seal_verifier: seal1.verifier,
                initial_records: vec![new_rec1],
            },
        };
        assert_eq!(
            eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::ROTATE,
                &rot_req.encode(),
            ),
            (mb_frame::STATUS, vec![mb_status::OK])
        );
        assert_eq!(eng.mailbox_count(), 3);

        let app_req = AppendMailboxReq {
            mailbox_id: keys1.mailbox_id,
            record: MailboxRecord::seal(&keys1, 2, b"epoch-1-op-2").unwrap(),
        }
        .encode();
        assert_eq!(
            eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::APPEND,
                &app_req,
            ),
            (mb_frame::STATUS, vec![mb_status::OK])
        );
        assert_eq!(
            eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::APPEND,
                &app_req,
            ),
            (mb_frame::STATUS, vec![mb_status::RATE_LIMITED]),
            "6th write within 1 min across distinct throwaway peers must hit global_appends_per_min=5"
        );

        let read_old = ReadMailboxReq {
            mailbox_id: keys0.mailbox_id,
            from_seq: 1,
        }
        .encode();
        let read_new = ReadMailboxReq {
            mailbox_id: keys1.mailbox_id,
            from_seq: 1,
        }
        .encode();
        let (ft_old, p_old) = eng.handle_frame_from_peer(
            Some(DeviceKeypair::generate().device_id()),
            mb_frame::READ,
            &read_old,
        );
        assert_eq!(ft_old, mb_frame::READ_OK);
        let resp_old = ReadMailboxResp::decode(&p_old).unwrap();
        assert_eq!(resp_old.records.len(), 2);
        assert!(resp_old.seal.is_some());

        let (ft_new, p_new) = eng.handle_frame_from_peer(
            Some(DeviceKeypair::generate().device_id()),
            mb_frame::READ,
            &read_new,
        );
        assert_eq!(ft_new, mb_frame::READ_OK);
        let resp_new = ReadMailboxResp::decode(&p_new).unwrap();
        assert_eq!(resp_new.records.len(), 2);

        for _ in 0..2 {
            let (ft, _) = eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::READ,
                &read_new,
            );
            assert_eq!(ft, mb_frame::READ_OK);
        }
        assert_eq!(
            eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::READ,
                &read_new,
            ),
            (mb_frame::STATUS, vec![mb_status::RATE_LIMITED]),
            "5th read within 1 min across distinct throwaway peers must hit global_reads_per_min=4"
        );
    }

    #[tokio::test]
    async fn m2_r3_512_record_mailbox_sealed_with_513th_record_returns_all_513_records() {
        use voidwire_core::grouplog::{sign_new_entries, GroupReplica, Membership};
        use voidwire_core::ids::GroupId;
        use voidwire_core::keys::{DeviceCert, Platform, ReceiveKeypair};
        use voidwire_core::mailbox::{wrap_epoch_secret, RekeyPayload};
        use voidwire_core::net::mailbox_client::{
            owner_rotate_mailbox, owner_sync_or_reseed_mailbox, pull_mailbox_chain,
            read_all_mailbox_records, ThrowawaySession,
        };
        use voidwire_core::roster::{OpKind, Roster};
        use voidwire_core::time::UnixMillis;

        let relay = std::thread::spawn(TestRelay::start).join().unwrap();
        let relay_url = relay.url();
        let limits = MailboxLimits {
            per_ip_reads_per_min: 5_000,
            per_ip_appends_per_min: 5_000,
            global_reads_per_min: 10_000,
            global_appends_per_min: 10_000,
            appends_per_min: 5_000,
            append_burst: 5_000,
            ..Default::default()
        };

        let server = MailboxServer::start(MailboxServerConfig {
            secret_key: [0x61u8; 32],
            relay_url: relay_url.clone(),
            data_dir: None,
            healthz_addr: None,
            signed_config: None,
            limits,
            log: "off".into(),
        })
        .await
        .unwrap();
        let mb_peer = server.device_id();
        for _ in 0..200 {
            if relay.has_peer(&mb_peer) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let owner_kp = DeviceKeypair::generate();
        let owner_rx = ReceiveKeypair::generate();
        let owner_cert = DeviceCert::issue(
            &owner_kp,
            owner_rx.public(),
            "Owner PC",
            Platform::Linux,
            UnixMillis(1_000),
        )
        .unwrap();
        let group_id = GroupId([0x88; 32]);
        let mut roster = Roster::genesis_with_cert(group_id, owner_cert);

        let keep_phone_kp = DeviceKeypair::generate();
        let keep_phone_rx = ReceiveKeypair::generate();
        let keep_cert = DeviceCert::issue(
            &keep_phone_kp,
            keep_phone_rx.public(),
            "Phone Keep",
            Platform::Android,
            UnixMillis(2_000),
        )
        .unwrap();
        roster.apply(
            OpKind::AddDevice,
            keep_phone_kp.device_id(),
            "Phone Keep".into(),
            Some(keep_cert),
        );

        for i in 0..253u64 {
            let dk = DeviceKeypair::generate();
            let drx = ReceiveKeypair::generate();
            let dc = DeviceCert::issue(
                &dk,
                drx.public(),
                &format!("Churn {i}"),
                Platform::Android,
                UnixMillis(3_000 + i),
            )
            .unwrap();
            roster.apply(
                OpKind::AddDevice,
                dk.device_id(),
                format!("Churn {i}"),
                Some(dc),
            );
            roster.remove_device(&dk.device_id());
        }
        let victim_kp = DeviceKeypair::generate();
        let victim_rx = ReceiveKeypair::generate();
        let victim_cert = DeviceCert::issue(
            &victim_kp,
            victim_rx.public(),
            "Victim 512",
            Platform::Android,
            UnixMillis(9_000),
        )
        .unwrap();
        let victim_id = victim_kp.device_id();
        roster.apply(
            OpKind::AddDevice,
            victim_id,
            "Victim 512".into(),
            Some(victim_cert),
        );
        let extra_kp = DeviceKeypair::generate();
        let extra_rx = ReceiveKeypair::generate();
        let extra_cert = DeviceCert::issue(
            &extra_kp,
            extra_rx.public(),
            "Extra 512",
            Platform::Android,
            UnixMillis(9_001),
        )
        .unwrap();
        roster.apply(
            OpKind::AddDevice,
            extra_kp.device_id(),
            "Extra 512".into(),
            Some(extra_cert),
        );

        let mut ops = Vec::new();
        sign_new_entries(&roster, &owner_kp, &mut ops, UnixMillis(10_000));
        assert_eq!(ops.len(), 510);

        let mut seeded_512 = ops.clone();
        seeded_512.push(ops[509].clone());
        seeded_512.push(ops[509].clone());
        assert_eq!(seeded_512.len(), MAX_MAILBOX_RECORDS);

        let gs0 = EpochSecret::from_bytes([0xC0; 32]);
        let keys0 = gs0.derive_keys();
        let osr = OwnerSealRoot::from_bytes([0xD0; 32]);
        let seal_key0 = osr.derive_seal_key(0);

        owner_sync_or_reseed_mailbox(
            &mb_peer,
            &relay_url,
            0,
            &keys0,
            seal_key0.verifier,
            &seeded_512,
        )
        .await
        .expect("seed 512 records into epoch 0 mailbox");

        roster.remove_device(&victim_id);
        let gs1 = EpochSecret::from_bytes([0xC1; 32]);
        let keys1 = gs1.derive_keys();
        let seal_key1 = osr.derive_seal_key(1);
        let wrapped = wrap_epoch_secret(
            &keep_phone_kp.device_id(),
            &keep_phone_rx.public(),
            &group_id,
            1,
            &gs1,
        )
        .unwrap();
        let rekey_payload = RekeyPayload {
            new_epoch: 1,
            removed: victim_id,
            wrapped_keys: vec![wrapped],
        };
        assert!(roster.rekey(rekey_payload));
        sign_new_entries(&roster, &owner_kp, &mut ops, UnixMillis(11_000));
        assert_eq!(ops.len(), 512);
        let rem_final_513 = ops[510].clone();
        let rekey_op_514 = ops[511].clone();

        owner_rotate_mailbox(
            &mb_peer,
            &relay_url,
            0,
            &keys0,
            &seal_key0,
            1,
            &keys1,
            seal_key1.verifier,
            &rem_final_513,
            &rekey_op_514,
            &ops,
        )
        .await
        .expect("rotate 512-record mailbox with 513th sealing RemoveDevice record");

        let sess = ThrowawaySession::connect(&mb_peer, &relay_url)
            .await
            .unwrap();
        let resp0 = read_all_mailbox_records(&sess, keys0.mailbox_id, 1)
            .await
            .unwrap()
            .expect("epoch 0 mailbox exists");
        sess.close().await;
        assert_eq!(
            resp0.records.len(),
            513,
            "read_all_mailbox_records must return all 513 records (512 + quota-exempt 513th sealing record)"
        );
        assert_eq!(resp0.records.last().unwrap().seq, 513);
        assert_eq!(
            resp0.records.last().unwrap().open(&keys0).unwrap(),
            rem_final_513.as_bytes()
        );
        assert!(resp0.seal.is_some());

        let (_eph, cur_epoch, cur_gs, pulled_ops) = pull_mailbox_chain(
            &mb_peer,
            &relay_url,
            &keep_phone_kp.device_id(),
            &keep_phone_rx,
            &group_id,
            0,
            &gs0,
        )
        .await
        .expect("pull_mailbox_chain across 513-record sealed mailbox");
        assert_eq!(cur_epoch, 1);
        assert_eq!(cur_gs.as_bytes(), gs1.as_bytes());
        assert_eq!(pulled_ops.len(), 512);

        let mut replica = GroupReplica::new(owner_kp.device_id(), ops[..2].to_vec()).unwrap();
        for op in pulled_ops {
            let _ = replica.apply_op(op).unwrap();
        }
        assert_eq!(replica.membership(&victim_id), Membership::Removed);
        assert_eq!(replica.epoch(), 1);
        assert_eq!(replica.head(), roster.head());

        server.shutdown().await;
        std::thread::spawn(move || drop(relay)).join().unwrap();
    }

    #[test]
    fn m26_h3_and_m1_unauth_flood_does_not_drain_global_buckets_and_rotate_preserves_other_groups()
    {
        let clock = Arc::new(FakeClock::new(20_600));
        let limits = MailboxLimits {
            max_mailboxes: 3,
            per_ip_reads_per_min: 100,
            per_ip_appends_per_min: 100,
            global_reads_per_min: 6,
            global_appends_per_min: 8,
            appends_per_min: 20,
            append_burst: 20,
            ..Default::default()
        };

        let mut eng = MailboxEngine::with_limits_and_clock(None, None, limits, clock.clone())
            .expect("init engine");

        let osr_a = OwnerSealRoot::from_bytes([0x30; 32]);
        let gs_a0 = EpochSecret::from_bytes([0x31; 32]);
        let keys_a0 = gs_a0.derive_keys();
        let seal_a0 = osr_a.derive_seal_key(0);
        let rec_a0 = MailboxRecord::seal(&keys_a0, 1, b"group-a-op1").unwrap();

        let osr_b = OwnerSealRoot::from_bytes([0x40; 32]);
        let gs_b0 = EpochSecret::from_bytes([0x41; 32]);
        let keys_b0 = gs_b0.derive_keys();
        let seal_b0 = osr_b.derive_seal_key(0);
        let rec_b0 = MailboxRecord::seal(&keys_b0, 1, b"group-b-op1").unwrap();

        // Create Group A and Group B mailboxes on Day 20600.
        for (k, s, r) in [(&keys_a0, &seal_a0, rec_a0), (&keys_b0, &seal_b0, rec_b0)] {
            assert_eq!(
                eng.handle_frame_from_peer(
                    Some(DeviceKeypair::generate().device_id()),
                    mb_frame::CREATE,
                    &CreateMailboxReq {
                        mailbox_id: k.mailbox_id,
                        epoch: 0,
                        write_verifier: k.write_verifier,
                        seal_verifier: s.verifier,
                        initial_records: vec![r],
                    }
                    .encode(),
                ),
                (mb_frame::STATUS, vec![mb_status::OK])
            );
        }

        // Rotate Group B on Day 20600 (so Group B has a sealed epoch-0 stub + active epoch-1).
        let gs_b1 = EpochSecret::from_bytes([0x42; 32]);
        let keys_b1 = gs_b1.derive_keys();
        let seal_b1 = osr_b.derive_seal_key(1);
        let b_seal =
            MailboxSeal::create(&keys_b0, &seal_b0, keys_b1.mailbox_id, b"b-rekey-1").unwrap();
        let rec_b1 = MailboxRecord::seal(&keys_b1, 1, b"group-b-e1-op1").unwrap();
        assert_eq!(
            eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::ROTATE,
                &RotateMailboxReq {
                    old_mailbox_id: keys_b0.mailbox_id,
                    final_old_record: None,
                    seal: b_seal,
                    create_new: CreateMailboxReq {
                        mailbox_id: keys_b1.mailbox_id,
                        epoch: 1,
                        write_verifier: keys_b1.write_verifier,
                        seal_verifier: seal_b1.verifier,
                        initial_records: vec![rec_b1],
                    },
                }
                .encode(),
            ),
            (mb_frame::STATUS, vec![mb_status::OK])
        );
        assert_eq!(eng.mailbox_count(), 3); // keys_a0 (active), keys_b0 (sealed), keys_b1 (active)

        // Advance 1 day and replenish rate-limit buckets.
        clock.advance_days(1);

        // M26-H3: Flood 200 malformed frames, NOT_FOUND probes, and BAD_AUTH APPENDs/SEALs
        // from distinct throwaway peers. None of these may drain global_read_bucket or global_append_bucket!
        let wrong_keys = EpochSecret::from_bytes([0x99; 32]).derive_keys();
        let bad_append = AppendMailboxReq {
            mailbox_id: keys_a0.mailbox_id,
            record: MailboxRecord::seal(&wrong_keys, 2, b"forged").unwrap(),
        }
        .encode();
        let not_found_read = ReadMailboxReq {
            mailbox_id: wrong_keys.mailbox_id,
            from_seq: 1,
        }
        .encode();
        for _ in 0..50 {
            let p = Some(DeviceKeypair::generate().device_id());
            assert_eq!(
                eng.handle_frame_from_peer(p, mb_frame::APPEND, &[0xff]),
                (mb_frame::STATUS, vec![mb_status::MALFORMED])
            );
            assert_eq!(
                eng.handle_frame_from_peer(p, mb_frame::READ, &[0xff]),
                (mb_frame::STATUS, vec![mb_status::MALFORMED])
            );
            assert_eq!(
                eng.handle_frame_from_peer(p, mb_frame::APPEND, &bad_append),
                (mb_frame::STATUS, vec![mb_status::BAD_AUTH])
            );
            assert_eq!(
                eng.handle_frame_from_peer(p, mb_frame::READ, &not_found_read),
                (mb_frame::STATUS, vec![mb_status::NOT_FOUND])
            );
        }

        // Legitimate Group A can still APPEND and READ without hitting RATE_LIMITED!
        let legit_append = AppendMailboxReq {
            mailbox_id: keys_a0.mailbox_id,
            record: MailboxRecord::seal(&keys_a0, 2, b"group-a-op2").unwrap(),
        }
        .encode();
        assert_eq!(
            eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::APPEND,
                &legit_append,
            ),
            (mb_frame::STATUS, vec![mb_status::OK])
        );

        // M26-M1: Group A rotates twice (a0 -> a1 -> a2) while server is at max_mailboxes=3.
        // Neither Group B's sealed epoch-0 mailbox (keys_b0) nor Group B's active epoch-1
        // mailbox (keys_b1) may be evicted!
        let gs_a1 = EpochSecret::from_bytes([0x32; 32]);
        let keys_a1 = gs_a1.derive_keys();
        let seal_a1 = osr_a.derive_seal_key(1);
        let a_seal0 =
            MailboxSeal::create(&keys_a0, &seal_a0, keys_a1.mailbox_id, b"a-rekey-1").unwrap();
        let rec_a1 = MailboxRecord::seal(&keys_a1, 1, b"group-a-e1-op1").unwrap();
        assert_eq!(
            eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::ROTATE,
                &RotateMailboxReq {
                    old_mailbox_id: keys_a0.mailbox_id,
                    final_old_record: None,
                    seal: a_seal0,
                    create_new: CreateMailboxReq {
                        mailbox_id: keys_a1.mailbox_id,
                        epoch: 1,
                        write_verifier: keys_a1.write_verifier,
                        seal_verifier: seal_a1.verifier,
                        initial_records: vec![rec_a1],
                    },
                }
                .encode(),
            ),
            (mb_frame::STATUS, vec![mb_status::OK])
        );

        let gs_a2 = EpochSecret::from_bytes([0x33; 32]);
        let keys_a2 = gs_a2.derive_keys();
        let seal_a2 = osr_a.derive_seal_key(2);
        let a_seal1 =
            MailboxSeal::create(&keys_a1, &seal_a1, keys_a2.mailbox_id, b"a-rekey-2").unwrap();
        let rec_a2 = MailboxRecord::seal(&keys_a2, 1, b"group-a-e2-op1").unwrap();
        assert_eq!(
            eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::ROTATE,
                &RotateMailboxReq {
                    old_mailbox_id: keys_a1.mailbox_id,
                    final_old_record: None,
                    seal: a_seal1,
                    create_new: CreateMailboxReq {
                        mailbox_id: keys_a2.mailbox_id,
                        epoch: 2,
                        write_verifier: keys_a2.write_verifier,
                        seal_verifier: seal_a2.verifier,
                        initial_records: vec![rec_a2],
                    },
                }
                .encode(),
            ),
            (mb_frame::STATUS, vec![mb_status::OK])
        );

        // Verify Group B's sealed epoch-0 mailbox AND active epoch-1 mailbox are both intact!
        for bid in [keys_b0.mailbox_id, keys_b1.mailbox_id, keys_a2.mailbox_id] {
            let (ft, _) = eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::READ,
                &ReadMailboxReq {
                    mailbox_id: bid,
                    from_seq: 1,
                }
                .encode(),
            );
            assert_eq!(ft, mb_frame::READ_OK, "mailbox {bid:?} must not be evicted");
        }
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

        let dir = std::env::temp_dir().join(format!(
            "vw-ram-inbox-test-{}",
            DeviceKeypair::generate().device_id().short()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let clock = Arc::new(FakeClock::new(20_650));
        let limits = MailboxLimits {
            inbox_max_items: 4,
            inbox_ttl_secs: 600,
            inbox_max_total_bytes: 65_536,
            max_relay_file_bytes: 12 * 1024 * 1024,
            ..MailboxLimits::default()
        };
        let mut eng =
            MailboxEngine::with_limits_and_clock(Some(dir.clone()), None, limits, clock.clone())
                .expect("init engine");

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

        // Verify ZERO files were written to data_dir!
        let disk_entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert!(
            disk_entries.is_empty(),
            "RAM-only device inbox must NEVER write files to disk, found: {disk_entries:?}"
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

        let _ = std::fs::remove_dir_all(&dir);
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
        let mut eng =
            MailboxEngine::with_limits_and_clock(None, None, limits, clock.clone()).unwrap();

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
    fn ram_device_inbox_new_inbox_flood_cannot_starve_existing_mailbox_append() {
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
        let mut eng = MailboxEngine::with_limits_and_clock(None, None, limits, clock.clone())
            .expect("init engine");

        // Pre-create a legitimate group-log mailbox and advance 60s so buckets refill completely.
        let osr = OwnerSealRoot::from_bytes([0x51; 32]);
        let gs0 = EpochSecret::from_bytes([0x52; 32]);
        let keys0 = gs0.derive_keys();
        let seal0 = osr.derive_seal_key(0);
        let rec1 = MailboxRecord::seal(&keys0, 1, b"group-op-1").unwrap();
        assert_eq!(
            eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::CREATE,
                &CreateMailboxReq {
                    mailbox_id: keys0.mailbox_id,
                    epoch: 0,
                    write_verifier: keys0.write_verifier,
                    seal_verifier: seal0.verifier,
                    initial_records: vec![rec1],
                }
                .encode(),
            ),
            (mb_frame::STATUS, vec![mb_status::OK])
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

        // Legitimate APPEND to the existing group-log mailbox still succeeds!
        let rec2 = MailboxRecord::seal(&keys0, 2, b"group-op-2").unwrap();
        assert_eq!(
            eng.handle_frame_from_peer(
                Some(DeviceKeypair::generate().device_id()),
                mb_frame::APPEND,
                &AppendMailboxReq {
                    mailbox_id: keys0.mailbox_id,
                    record: rec2,
                }
                .encode(),
            ),
            (mb_frame::STATUS, vec![mb_status::OK]),
            "existing group-log APPEND must not be starved by new-inbox INBOX_PUT flood"
        );
    }
}
