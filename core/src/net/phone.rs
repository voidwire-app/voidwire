//! The phone side: QR pairing (joiner) and sending links to paired PCs.
//! Blocking API (an internal tokio runtime); the Android app calls it from a
//! background thread through UniFFI (`crate::ffi`).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use iroh::endpoint::{presets, Connection};
use iroh::{Endpoint, EndpointAddr, SecretKey};

use super::links::{PairLink, PeerLog};
use super::state::{read_secret, Reader, StateStore, Writer};
use super::{
    close_code, conn_error, endpoint_id_of, frame, parse_error, read_frame, write_frame, NetError,
    SendOutcome, ALPN_APP, ALPN_PAIR, IO_TIMEOUT, MDNS_SERVICE,
};
use crate::envelope;
use crate::ids::{DeviceId, MsgId};
use crate::keys::{valid_device_name, DeviceCert, DeviceKeypair, Platform};
use crate::reject::RejectReason;
use crate::time::{Clock, MonoMillis, SystemClock};
use crate::wire::{encode_signed, Outgoing};

/// State format v3: no per-PC roster entries, mailbox sections or saved
/// relay list. Older formats are not read: the phone starts fresh (new
/// identity, nothing reused) and shows "This pairing is from an older
/// Voidwire. Pair again."
const STATE_MAGIC: &[u8] = b"VWPH3\n";
const OLD_STATE_MAGICS: &[&[u8]] = &[b"VWPH2\n"];
/// State flags byte (after the name). Unknown bits mean damaged.
const FLAG_OLD_PAIRINGS_DROPPED: u8 = 1;
/// Connect timeout (LAN: direct hints first, mDNS in parallel).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// At most this many PCs per phone (M1).
pub const MAX_PCS: usize = 16;

pub struct PhoneConfig {
    pub state: Arc<dyn StateStore>,
    /// Used until the user names the device.
    pub default_name: String,
    pub platform: Platform,
    /// Resolve PCs with mDNS/DNS-SD (we never advertise).
    pub mdns: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedPc {
    pub id: DeviceId,
    pub name: String,
    pub addrs: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendReport {
    pub outcome: SendOutcome,
    /// From the call to the PC's answer (opened or prompt shown), including
    /// connect and sync. Microseconds.
    pub latency_us: u64,
}

const STATE_SECTION_RELAY: u8 = 1;
const STATE_SECTION_FILE_STATS: u8 = 4;
const STATE_SECTION_CUSTOM_MAILBOX: u8 = 5;
const STATE_SECTION_SEEN_IDS: u8 = 6;
/// v2: pairings and relay settings (`net::pairings_state`).
const STATE_SECTION_PAIRWISE: u8 = 7;

/// Report from [`PhoneClient::send_file`] / [`PhoneClient::send_file_bytes`] (`M2.6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilePayloadSource<'a> {
    Bytes(&'a [u8]),
    Path(&'a std::path::Path),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSendReport {
    pub transfer_id: crate::file_transfer::TransferId,
    pub filename: String,
    pub size: u64,
    pub blake3_root: [u8; 32],
    pub chunks_sent: u64,
    pub resumed_from_chunk: u64,
    pub path_kind: crate::file_transfer::TransportPathKind,
    pub latency_us: u64,
}

/// Kind of incoming item received on a phone (`M3.1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncomingItemKind {
    Url,
    ClipboardText,
}

/// A verified link or clipboard text item received on the phone (`M3.1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingPhoneItem {
    pub item_id: u64,
    pub sender_id: DeviceId,
    pub sender_name: String,
    pub kind: IncomingItemKind,
    pub payload_text: String,
    pub host_display: Option<String>,
    pub sensitive_hint: bool,
    pub received_at: crate::time::UnixMillis,
    pub delivery_path: super::DeliveryPath,
}

/// An incoming file offer (live or from a `FileWake` inbox pointer) on the phone (`M3.1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingPhoneFileOffer {
    pub transfer_id: crate::file_transfer::TransferId,
    pub sender_id: DeviceId,
    pub sender_name: String,
    pub filename: String,
    pub mime: String,
    pub size: u64,
    pub chunk_count: u64,
    pub chunks_received: u64,
    pub blake3_root: [u8; 32],
    pub expires_at: crate::time::UnixMillis,
    pub is_executable: bool,
    pub accepted: bool,
    pub completed_path: Option<std::path::PathBuf>,
    pub relayed: bool,
    pub via_file_wake: bool,
}

/// Snapshot of pending incoming items and file offers on the phone (`M3.1`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IncomingPhoneBatch {
    pub items: Vec<IncomingPhoneItem>,
    pub files: Vec<IncomingPhoneFileOffer>,
}

struct IncomingPhoneFileSession {
    transfer_id: crate::file_transfer::TransferId,
    sender_id: DeviceId,
    sender_name: String,
    filename: String,
    mime: String,
    size: u64,
    chunk_count: u64,
    blake3_root: [u8; 32],
    expires_at: crate::time::UnixMillis,
    is_executable: bool,
    relayed: bool,
    via_file_wake: bool,
    offer: Option<crate::file_transfer::FileOffer>,
    k_file: Option<crate::file_transfer::FileTransferKey>,
    receiver: Option<crate::file_transfer::PartFileReceiver>,
    accepted: bool,
    target_dir: Option<std::path::PathBuf>,
    completed_path: Option<std::path::PathBuf>,
    last_activity: crate::time::UnixMillis,
}

struct PcEntry {
    replica: PeerLog,
    addrs: Vec<SocketAddr>,
    relay_url: Option<String>,
    mailbox_peer: Option<DeviceId>,
}

struct PhoneState {
    identity: DeviceKeypair,
    name: String,
    pcs: Vec<PcEntry>,
    relay_url: Option<String>,
    custom_mailbox_peer: Option<Option<DeviceId>>,
    relay_policy: crate::file_transfer::RelayTransferPolicy,
    conn_stats: crate::file_transfer::ConnectionStatsStore,
    seen_ids:
        std::collections::HashMap<DeviceId, Vec<(crate::replay::SeenKey, crate::time::UnixMillis)>>,
    /// State v2 (M4.1) as last loaded; [`PhoneState::pairwise`] re-derives
    /// the legacy pairings from `pcs` on every read and save.
    pairings: crate::pairwise::PairingSet,
    relay_settings: crate::pairwise::RelaySettings,
    /// Unpair notices not yet delivered (M4.3; persisted).
    outbox: super::outbox::Outbox,
    /// Away-relay endpoints (M4.4); `None` until the client is up.
    away: Option<Arc<super::away::Away>>,
    /// M4.4: old relay inboxes still pulled after a pairing moved.
    drains: Vec<super::relay_change::Drain>,
    /// Renames signed this run and not sent yet (RAM only).
    unsent_ops: super::pair_ops::Unsent,
    /// Pairings from an older Voidwire were dropped (state reset, or old
    /// pairing records): "This pairing is from an older Voidwire. Pair again."
    old_pairings_dropped: bool,
}

impl PhoneState {
    /// Pairings and relay settings, with the home relay entry in step with
    /// the configured relay.
    fn pairwise(&self) -> (crate::pairwise::PairingSet, crate::pairwise::RelaySettings) {
        let (p, mut r) = (self.pairings.clone(), self.relay_settings.clone());
        r.sync_home(super::pairings_state::relay_ref(
            self.relay_url.as_deref(),
            self.custom_mailbox_peer.flatten(),
        ));
        (p, r)
    }

    /// The state blob holds the identity secret key: wiped when dropped.
    fn encode(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut w = Writer::new(STATE_MAGIC);
        w.raw(&self.identity.secret_bytes()[..]);
        w.bytes8(self.name.as_bytes());
        w.u8(if self.old_pairings_dropped {
            FLAG_OLD_PAIRINGS_DROPPED
        } else {
            0
        });
        w.u8(STATE_SECTION_RELAY);
        w.bytes16(self.relay_url.as_deref().unwrap_or("").as_bytes());
        w.u8(STATE_SECTION_FILE_STATS);
        w.raw(&self.relay_policy.user_cap_bytes().to_be_bytes());
        let stats_bytes = self.conn_stats.to_bytes();
        w.bytes16(&stats_bytes);
        if let Some(ref mb_opt) = self.custom_mailbox_peer {
            w.u8(STATE_SECTION_CUSTOM_MAILBOX);
            match mb_opt {
                Some(mp) => {
                    w.u8(1);
                    w.raw(mp.as_bytes());
                }
                None => {
                    w.u8(0);
                }
            }
        }
        if !self.seen_ids.is_empty() {
            w.u8(STATE_SECTION_SEEN_IDS);
            let num_pcs = self.seen_ids.len().min(u8::MAX as usize);
            w.u8(num_pcs as u8);
            for (pc_id, entries) in self.seen_ids.iter().take(num_pcs) {
                w.raw(pc_id.as_bytes());
                let count = entries.len().min(u16::MAX as usize);
                w.raw(&(count as u16).to_be_bytes());
                for &(key, forget_after) in entries.iter().take(count) {
                    w.raw(&key);
                    w.raw(&forget_after.0.to_be_bytes());
                }
            }
        }
        let (pairings, relays) = self.pairwise();
        w.u8(STATE_SECTION_PAIRWISE);
        let body = super::pairings_state::encode_section(
            &pairings,
            &relays,
            &self.outbox,
            &Default::default(),
            &self.identity.secret_bytes(),
        );
        w.bytes32(&body);
        zeroize::Zeroizing::new(w.0)
    }

    fn decode(b: &[u8]) -> Option<PhoneState> {
        let mut r = Reader::new(b);
        let magic = r.take(STATE_MAGIC.len())?;
        if magic != STATE_MAGIC {
            return None;
        }
        let id_sk = read_secret(&mut r)?;
        let name = std::str::from_utf8(r.bytes8()?).ok()?.to_owned();
        let flags = r.u8()?;
        if flags & !FLAG_OLD_PAIRINGS_DROPPED != 0 {
            return None;
        }
        let mut relay_url = super::resolve_relay_url(None);
        let mut custom_mailbox_peer: Option<Option<DeviceId>> = None;
        let mut relay_policy = crate::file_transfer::RelayTransferPolicy::new();
        let mut conn_stats = crate::file_transfer::ConnectionStatsStore::new();
        let mut seen_ids: std::collections::HashMap<
            DeviceId,
            Vec<(crate::replay::SeenKey, crate::time::UnixMillis)>,
        > = std::collections::HashMap::new();
        let mut pairwise = None;
        while !r.is_empty() {
            match r.u8()? {
                STATE_SECTION_PAIRWISE => {
                    let body = r.bytes32()?;
                    pairwise = Some(super::pairings_state::decode_section(body, &id_sk)?);
                }
                STATE_SECTION_RELAY => {
                    let s = std::str::from_utf8(r.bytes16()?).ok()?;
                    relay_url = if s.is_empty() {
                        None
                    } else {
                        Some(s.to_owned())
                    };
                }
                STATE_SECTION_FILE_STATS => {
                    let cb = r.take(8)?;
                    let raw_cap = u64::from_be_bytes(cb.try_into().expect("8"));
                    let cap = match raw_cap {
                        c if c == 5 * 1024 * 1024
                            || c == 25 * 1024 * 1024
                            || c == 100 * 1024 * 1024
                            || c == 500 * 1024 * 1024 =>
                        {
                            crate::file_transfer::MAX_FILE_SIZE
                        }
                        other => other,
                    };
                    let _ = relay_policy.set_user_cap_bytes(cap);
                    let sb = r.bytes16()?;
                    conn_stats = crate::file_transfer::ConnectionStatsStore::from_bytes(sb)?;
                }
                STATE_SECTION_CUSTOM_MAILBOX => match r.u8()? {
                    1 => {
                        let id = DeviceId::from_bytes(r.arr32()?).ok()?;
                        custom_mailbox_peer = Some(Some(id));
                    }
                    0 => {
                        custom_mailbox_peer = Some(None);
                    }
                    _ => return None,
                },
                STATE_SECTION_SEEN_IDS => {
                    let num_pcs = r.u8()? as usize;
                    for _ in 0..num_pcs {
                        let pc_id = DeviceId::from_bytes(r.arr32()?).ok()?;
                        let cb = r.take(2)?;
                        let count = u16::from_be_bytes(cb.try_into().expect("2")) as usize;
                        let mut entries = Vec::with_capacity(count.min(1024));
                        for _ in 0..count {
                            let key_slice = r.take(16)?;
                            let mut key = [0u8; 16];
                            key.copy_from_slice(key_slice);
                            let wb = r.take(8)?;
                            let forget_after = crate::time::UnixMillis(u64::from_be_bytes(
                                wb.try_into().expect("8"),
                            ));
                            entries.push((key, forget_after));
                        }
                        seen_ids.insert(pc_id, entries);
                    }
                }
                _ => return None,
            }
        }
        let (pairings, relay_settings, outbox, _) = pairwise.unwrap_or_else(|| {
            (
                crate::pairwise::PairingSet::new(),
                crate::pairwise::RelaySettings::new(super::pairings_state::builtin_relay()),
                super::outbox::Outbox::default(),
                Default::default(),
            )
        });
        let mut st = PhoneState {
            identity: DeviceKeypair::from_secret_bytes(&id_sk),
            name,
            pcs: Vec::new(),
            relay_url,
            custom_mailbox_peer,
            relay_policy,
            conn_stats,
            seen_ids,
            pairings,
            relay_settings,
            outbox,
            away: None,
            drains: Vec::new(),
            unsent_ops: Default::default(),
            old_pairings_dropped: false,
        };
        st.old_pairings_dropped =
            flags & FLAG_OLD_PAIRINGS_DROPPED != 0 || st.pairings.old_dropped();
        st.rebuild_links();
        Some(st)
    }

    /// M4.2: one entry per v2 pairing (any peer, PC or phone). A v2 pairing
    /// replaces a legacy group entry for the same peer.
    fn rebuild_links(&mut self) {
        let me = self.identity.device_id();
        let links = super::links::links_of(&me, &self.pairings);
        let mut addrs: std::collections::HashMap<DeviceId, Vec<SocketAddr>> =
            std::collections::HashMap::new();
        for p in self.pcs.drain(..) {
            addrs.insert(p.replica.owner(), p.addrs);
        }
        for (peer, link) in links {
            let mut e = pc_entry_for_link(link);
            e.addrs = addrs.remove(&peer).unwrap_or_default();
            self.pcs.push(e);
        }
        self.sync_away();
    }

    /// Pairing relays other than home, most-used first.
    fn away_wanted(&self) -> Vec<String> {
        super::pc::away_wanted_of(
            self.relay_url.as_deref(),
            self.pcs
                .iter()
                .map(|p| p.replica.link())
                .filter_map(|l| l.relay.as_ref()),
        )
    }

    fn sync_away(&self) {
        if let Some(a) = &self.away {
            a.set_urls(self.away_wanted());
        }
    }

    /// `Some(pairing relay)` when live traffic with `peer` goes through an
    /// away endpoint.
    fn away_route_for(&self, peer: &DeviceId) -> Option<String> {
        let link = self.pc(peer)?.replica.link();
        super::pc::away_route(
            self.relay_url.as_deref(),
            link.relay.as_ref().map(|r| r.url.as_str()),
        )
    }

    fn pc(&self, id: &DeviceId) -> Option<&PcEntry> {
        self.pcs.iter().find(|p| p.replica.owner() == *id)
    }

    fn pc_mut(&mut self, id: &DeviceId) -> Option<&mut PcEntry> {
        self.pcs.iter_mut().find(|p| p.replica.owner() == *id)
    }

    fn cert(&self, platform: Platform) -> Result<DeviceCert, RejectReason> {
        DeviceCert::issue(&self.identity, &self.name, platform, SystemClock.now().wall)
    }
}

/// Drop a peer and everything received from it. A v2 peer's pairing is
/// erased with it (its secrets are wiped on drop). Saved first; on failure
/// nothing changes (QA 10-13).
fn erase_peer(inner: &Inner, pc: &DeviceId) -> Result<bool, NetError> {
    let mut st = inner.lock();
    let Some(idx) = st.pcs.iter().position(|p| p.replica.owner() == *pc) else {
        return Ok(false);
    };
    let entry = st.pcs.remove(idx);
    let removed_pairing = st.pairings.remove(&entry.replica.link().pairing_id);
    st.conn_stats.forget_peer(pc);
    if let Err(e) = inner.save(&st) {
        if let Some(p) = removed_pairing {
            let _ = st.pairings.add(p);
        }
        st.pcs.insert(idx, entry);
        return Err(e);
    }
    st.seen_ids.remove(pc);
    drop(st);
    inner
        .inboxes
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(pc);
    inner
        .incoming_items
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .retain(|i| i.sender_id != *pc);
    {
        let mut files = inner
            .incoming_files
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let to_remove: Vec<crate::file_transfer::TransferId> = files
            .iter()
            .filter_map(|(k, v)| (v.sender_id == *pc).then_some(*k))
            .collect();
        for tid in to_remove {
            if let Some(sess) = files.remove(&tid) {
                if let Some(rcv) = sess.receiver {
                    rcv.cancel_and_delete();
                }
            }
        }
    }
    if let Some(c) = inner
        .conns
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(pc)
    {
        c.close(0u32.into(), b"");
    }
    Ok(true)
}

/// A sealed unpair notice and where to deliver it (after the local erase).
struct UnpairNotice {
    env: Vec<u8>,
    /// The durable copy for the peer's inbox (`net::outbox`).
    item: Option<super::outbox::OutboxItem>,
    addrs: Vec<SocketAddr>,
    relay_url: Option<String>,
}

/// Send the unpair notices that are due (all of them when `force`). Only
/// from events that reach a relay anyway (start, pulls, network change);
/// failures back off on the supervisor schedule (`net::outbox`).
async fn flush_outbox_phone(inner: &Inner, force: bool) {
    let due = inner.lock().outbox.due(SystemClock.now().wall, force);
    if due.is_empty() {
        return;
    }
    let res = super::outbox::send(due).await;
    let mut st = inner.lock();
    let t = SystemClock.now().wall;
    for (item, ok) in res {
        if ok {
            st.outbox.delivered(&item);
        } else {
            st.outbox.failed(&item, t);
        }
    }
    let _ = inner.save(&st);
}

/// A verified pair notice from `peer`. Only an unpair of our pairing with
/// it, signed by it, is acted on: the pairing is erased here too (M4.2).
fn on_pair_notice_phone(inner: &Inner, peer: &DeviceId, n: &crate::verify::VerifiedPairNotice) {
    let Ok(op) = crate::pairwise::PairOp::decode(n.op_bytes()) else {
        return;
    };
    let pairing_id = {
        let st = inner.lock();
        let Some(e) = st.pc(peer) else {
            return;
        };
        e.replica.group()
    };
    if n.sender() != *peer || !op.is_unpair_by(peer, &pairing_id) {
        return;
    }
    let _ = erase_peer(inner, peer);
}

/// The peer could not be reached (as opposed to refusing the message).
fn is_offline(e: &NetError) -> bool {
    matches!(
        e,
        NetError::Unreachable(_) | NetError::Timeout | NetError::Protocol(_)
    )
}

fn pc_entry_for_link(link: PairLink) -> PcEntry {
    let mailbox_peer = link.relay.as_ref().and_then(|r| r.mailbox_id);
    PcEntry {
        replica: PeerLog::new(link),
        addrs: Vec::new(),
        // Live dials go through the pairing relay: our home endpoint when
        // it is our home relay, else an away endpoint (`away_route_for`).
        relay_url: None,
        mailbox_peer,
    }
}

type CachedFileHashMap =
    std::collections::HashMap<crate::file_transfer::TransferId, (u64, [u8; 32], Vec<[u8; 32]>)>;

/// Event-driven inbox pulls hit each relay at most this often (M4.1).
pub const EVENT_PULL_MIN_GAP_MS: u64 = 5 * 60_000;

struct Inner {
    rt: tokio::runtime::Runtime,
    endpoint: Mutex<Endpoint>,
    state: Mutex<PhoneState>,
    store: Arc<dyn StateStore>,
    platform: Platform,
    /// mDNS lookup is available (fresh-discovery fallback, see `get_conn`).
    mdns: bool,
    conns: Mutex<std::collections::HashMap<DeviceId, Connection>>,
    mailbox_peer: Mutex<(Option<DeviceId>, bool)>,
    last_throwaway_id: Mutex<Option<DeviceId>>,
    force_relay_at_chunk_for_test: Mutex<Option<u64>>,
    drop_conn_once_at_chunk_for_test: Mutex<Option<u64>>,
    fail_reconnects_for_test: Mutex<u32>,
    direct_first_wait_ms: Mutex<Option<u64>>,
    cached_file_hashes: Mutex<CachedFileHashMap>,
    prompt_accepted_transfers: Mutex<std::collections::HashSet<crate::file_transfer::TransferId>>,
    cancelled_transfers: Mutex<std::collections::VecDeque<crate::file_transfer::TransferId>>,
    accept_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    relay_watch: Mutex<Option<super::relay_watch::RelayWatch>>,
    /// The app UI is open (false: only the background service runs).
    app_foreground: std::sync::atomic::AtomicBool,
    /// Last event-driven inbox pull per relay (M4.1: at most every 5 min).
    last_event_pull: Mutex<std::collections::HashMap<String, crate::time::MonoMillis>>,
    /// Test seam: unpair saves the notice but doesn't send it (the app
    /// "killed" right after the erase).
    hold_unpair_send: std::sync::atomic::AtomicBool,
    /// Test seam: added to the event-pull gate's clock (0 in the app).
    event_skew_ms: std::sync::atomic::AtomicU64,
    /// Inbox pulls started (tests and diagnostics; no private data).
    inbox_pulls: std::sync::atomic::AtomicU64,
    inboxes: Mutex<std::collections::HashMap<DeviceId, crate::verify::Inbox>>,
    incoming_items: Mutex<Vec<IncomingPhoneItem>>,
    next_incoming_item_id: std::sync::atomic::AtomicU64,
    incoming_files: Mutex<
        std::collections::HashMap<crate::file_transfer::TransferId, IncomingPhoneFileSession>,
    >,
    declined_incoming_files:
        Mutex<std::collections::VecDeque<(crate::file_transfer::TransferId, DeviceId)>>,
    data_dir: Mutex<Option<std::path::PathBuf>>,
    pending_seen_sync: Arc<Mutex<Vec<(DeviceId, crate::replay::SeenKey, crate::time::UnixMillis)>>>,
    download_dir: Mutex<std::path::PathBuf>,
    /// Woken when an incoming file chunk lands or a transfer ends, so an
    /// accept waiting on it can tell a slow transfer from a dead one.
    file_progress: tokio::sync::Notify,
    auto_accept_files: std::sync::atomic::AtomicBool,
    background_listening: std::sync::atomic::AtomicBool,
    accept_incoming_enabled: std::sync::atomic::AtomicBool,
    /// M4.3: the live v2 invite this phone shows (QR or code).
    host2: Mutex<super::pair2::Host>,
    /// M4.3: a v2 invite this phone is joining.
    join2: Mutex<super::pair2::JoinSlot>,
    /// M4.4: relay-change proposals (RAM only).
    relay_change: Mutex<super::relay_change::Slots>,
}

impl super::pair2::Node2 for Inner {
    fn host(&self) -> MutexGuard<'_, super::pair2::Host> {
        self.host2.lock().unwrap_or_else(|p| p.into_inner())
    }
    fn join_slot(&self) -> MutexGuard<'_, super::pair2::JoinSlot> {
        self.join2.lock().unwrap_or_else(|p| p.into_inner())
    }
    fn identity(&self) -> Result<(DeviceKeypair, DeviceCert), RejectReason> {
        let st = self.lock();
        Ok((
            DeviceKeypair::from_secret_bytes(&st.identity.secret_bytes()),
            st.cert(self.platform)?,
        ))
    }
    fn relay_view(&self) -> super::pair2::RelayView {
        let (pairings, settings) = self.lock().pairwise();
        super::pair2::RelayView {
            in_use: settings.in_use(&pairings),
            pairing_room: pairings.has_room(),
            settings,
        }
    }
    fn save_relay(&self, e: crate::pairwise::RelayEntry) -> Result<(), NetError> {
        let mut st = self.lock();
        st.relay_settings.add(e).map_err(|e| {
            NetError::Rejected(match e {
                crate::pairwise::PairError::LimitReached => RejectReason::RelayLimitReached,
                _ => RejectReason::MalformedFrame,
            })
        })?;
        self.save(&st)
    }
    fn keep(&self, p: crate::pairwise::Pairing, addrs: Vec<SocketAddr>) -> Result<bool, NetError> {
        let mut st = self.lock();
        let peer = p.peer.id;
        let new_id = p.pairing_id;
        let old_addrs = st.pc(&peer).map(|e| e.addrs.clone());
        let replaced = super::pair2::replace_pairing(&mut st.pairings, p)?;
        st.rebuild_links();
        if let Some(e) = st.pc_mut(&peer) {
            e.addrs = addrs;
        }
        if let Err(e) = self.save(&st) {
            // Not saved: the old pairing (keys, inbox, relay) stays as it was.
            super::pair2::undo_replace(&mut st.pairings, &new_id, replaced);
            st.rebuild_links();
            if let (Some(a), Some(pc)) = (old_addrs, st.pc_mut(&peer)) {
                pc.addrs = a;
            }
            return Err(e);
        }
        drop(st);
        self.inboxes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&peer);
        Ok(!replaced.is_empty())
    }
    fn changed(&self) {}
}

impl super::pair_ops::Host for Inner {
    fn po_me(&self) -> DeviceKeypair {
        DeviceKeypair::from_secret_bytes(&self.lock().identity.secret_bytes())
    }
    fn po_with(
        &self,
        f: &mut dyn FnMut(&mut crate::pairwise::PairingSet, &mut super::pair_ops::Unsent) -> bool,
    ) {
        let mut st = self.lock();
        let st2 = &mut *st;
        if !f(&mut st2.pairings, &mut st2.unsent_ops) {
            return;
        }
        st.rebuild_links();
        // Not saved: RAM is ahead and the next save catches up.
        let _ = self.save(&st);
    }
}

impl super::relay_change::Host for Inner {
    fn rc_me(&self) -> DeviceKeypair {
        DeviceKeypair::from_secret_bytes(&self.lock().identity.secret_bytes())
    }
    fn rc_log(&self, peer: &DeviceId) -> Option<(crate::pairwise::PairLog, String)> {
        let st = self.lock();
        st.pc(peer)?;
        super::relay_change::log_of(&st.pairings, peer)
    }
    fn rc_room(&self, peer: &DeviceId, relay: &crate::pairwise::RelayRef) -> bool {
        let (p, r) = self.lock().pairwise();
        super::relay_change::room(&p, &r, peer, relay)
    }
    fn rc_is_saved(&self, url: &str) -> bool {
        super::relay_change::is_saved(&self.lock().relay_settings, url)
    }
    fn rc_commit(&self, peer: &DeviceId, log: crate::pairwise::PairLog) -> Result<(), NetError> {
        let (g, explicit) = *self.mailbox_peer.lock().unwrap_or_else(|p| p.into_inner());
        let mut st = self.lock();
        let old = st.pc(peer).and_then(|e| {
            let home = e.relay_url.clone().or_else(|| st.relay_url.clone());
            e.replica
                .link()
                .place(home.as_deref(), g.map(|m| (m, explicit)))
        });
        let st2 = &mut *st;
        super::relay_change::apply_commit(
            &mut st2.pairings,
            &mut st2.relay_settings,
            &mut st2.drains,
            peer,
            log,
            old,
        )?;
        st.rebuild_links();
        self.save(&st)?;
        drop(st);
        // New sends dial on the new relay.
        self.conns
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(peer);
        Ok(())
    }
    fn rc_slots(&self) -> MutexGuard<'_, super::relay_change::Slots> {
        self.relay_change.lock().unwrap_or_else(|p| p.into_inner())
    }
    fn rc_changed(&self) {}
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, PhoneState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
    fn save(&self, st: &PhoneState) -> Result<(), NetError> {
        self.store.save(&st.encode()).map_err(NetError::Storage)
    }
    fn mark_transfer_cancelled(&self, tid: crate::file_transfer::TransferId) {
        {
            let mut q = self
                .cancelled_transfers
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if !q.contains(&tid) {
                if q.len() >= 64 {
                    q.pop_front();
                }
                q.push_back(tid);
            }
        }
        self.cached_file_hashes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&tid);
        self.prompt_accepted_transfers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&tid);
    }
    fn is_transfer_cancelled(&self, tid: &crate::file_transfer::TransferId) -> bool {
        self.cancelled_transfers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(tid)
    }
}

/// The phone's network client. Cheap to clone (shared inner).
#[derive(Clone)]
pub struct PhoneClient {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for PhoneClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhoneClient").finish_non_exhaustive()
    }
}

/// L3: how long the mDNS fallback waits for an answer before dialling.
pub const MDNS_FALLBACK_WAIT: Duration = Duration::from_secs(2);
/// L3: at most this many dials after the mDNS answer...
const MDNS_FALLBACK_DIALS: u32 = 8;
/// ...and no new dial after this long (a slow failure isn't retried).
const MDNS_FALLBACK_REDIAL_BUDGET_MS: u64 = 1500;

/// L3: wait up to `wait` for the address lookup (mDNS) to report `pc`, and
/// return its direct addresses (empty on timeout or no lookup). Returns as
/// soon as the first answer with addresses arrives.
/// `mdns`: this device uses mDNS at all (a phone without a standing lookup
/// asks once, for this call).
pub(crate) async fn discover_addrs(
    endpoint: &Endpoint,
    pc: &DeviceId,
    wait: Duration,
    mdns: bool,
) -> Vec<SocketAddr> {
    use n0_future::StreamExt;
    let Ok(id) = endpoint_id_of(pc) else {
        return Vec::new();
    };
    let Ok(services) = endpoint.address_lookup() else {
        return Vec::new();
    };
    if services.is_empty() {
        if !mdns {
            return Vec::new();
        }
        // The phone (0.8.2): no standing mDNS lookup, because it queried the
        // LAN every 0.7 s for as long as the app process lived, background
        // included (~35 MB/day on Wi-Fi). It asks only now, for this dial,
        // and the lookup (socket and task) is gone when this returns.
        return lan_lookup_once(endpoint, id, wait).await;
    }
    let mut answers = std::pin::pin!(services.resolve(id));
    let first = async {
        while let Some(r) = answers.next().await {
            match r {
                Ok(Ok(item)) => {
                    let a: Vec<SocketAddr> = item.endpoint_info().ip_addrs().copied().collect();
                    if !a.is_empty() {
                        return a;
                    }
                }
                Ok(Err(_)) => continue,
                Err(_) => break,
            }
        }
        Vec::new()
    };
    tokio::time::timeout(wait, first).await.unwrap_or_default()
}

/// One mDNS question for `id`, asked by a lookup that lives only for this
/// call (it doesn't advertise this device).
async fn lan_lookup_once(
    endpoint: &Endpoint,
    id: iroh::EndpointId,
    wait: Duration,
) -> Vec<SocketAddr> {
    use iroh::address_lookup::AddressLookup;
    use n0_future::StreamExt;
    let Ok(mdns) = iroh_mdns_address_lookup::MdnsAddressLookup::builder()
        .service_name(MDNS_SERVICE)
        .advertise(false)
        .build(endpoint.id())
    else {
        return Vec::new();
    };
    let Some(mut answers) = mdns.resolve(id) else {
        return Vec::new();
    };
    let first = async {
        while let Some(r) = answers.next().await {
            if let Ok(item) = r {
                let a: Vec<SocketAddr> = item.endpoint_info().ip_addrs().copied().collect();
                if !a.is_empty() {
                    return a;
                }
            }
        }
        Vec::new()
    };
    let found = tokio::time::timeout(wait, first).await.unwrap_or_default();
    drop(answers);
    drop(mdns);
    found
}

async fn connect(
    endpoint: &Endpoint,
    pc: &DeviceId,
    addrs: &[SocketAddr],
    relay_url: Option<&str>,
    alpn: &[u8],
) -> Result<Connection, NetError> {
    let ep_id = endpoint_id_of(pc)?;
    let parsed_relay = relay_url.and_then(|r| {
        let trimmed = r.trim();
        (!trimmed.is_empty())
            .then(|| trimmed.parse::<iroh::RelayUrl>().ok())
            .flatten()
    });
    let relay_is_local_test = parsed_relay.as_ref().is_some_and(|u| {
        let s = u.as_str();
        s.contains("127.0.0.1") || s.contains("localhost")
    });
    let has_loopback_addr = addrs.iter().any(|a| a.ip().is_loopback());
    let should_use_relay =
        parsed_relay.is_some() && (relay_is_local_test || addrs.is_empty() || !has_loopback_addr);

    if should_use_relay {
        let _ = tokio::time::timeout(Duration::from_millis(2500), endpoint.online()).await;
    }

    let mut addr = EndpointAddr::new(ep_id);
    for a in addrs {
        addr = addr.with_ip_addr(*a);
    }
    if let Some(ref u) = parsed_relay {
        addr = addr.with_relay_url(u.clone());
    }
    let first_res = match tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(addr, alpn)).await
    {
        Ok(Ok(c)) => return Ok(c),
        Ok(Err(e)) => Err(NetError::Unreachable(e.to_string())),
        Err(_) => Err(NetError::Unreachable("no answer from the PC".into())),
    };

    // M2.8: If dialing with cached private LAN addresses (`192.168.x.x`) failed or timed out
    // while a relay URL is configured, immediately retry a relay-only dial without the stale
    // LAN socket addresses (which fail on cellular / different networks).
    if !addrs.is_empty() && should_use_relay {
        if let Some(u) = parsed_relay {
            endpoint.network_change().await;
            let _ = tokio::time::timeout(Duration::from_millis(2500), endpoint.online()).await;
            let relay_only_addr = EndpointAddr::new(ep_id).with_relay_url(u);
            if let Ok(Ok(c)) =
                tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(relay_only_addr, alpn)).await
            {
                return Ok(c);
            }
        }
    }
    first_res
}

/// One request/response on a fresh bidirectional stream.
async fn request(
    conn: &Connection,
    t: u8,
    payload: &[u8],
    expect: u8,
) -> Result<Vec<u8>, NetError> {
    let (mut s, mut r) = conn.open_bi().await.map_err(|e| conn_error(conn, e))?;
    if write_frame(&mut s, t, payload).await.is_err() {
        return Err(conn_error(conn, "write failed"));
    }
    let _ = s.finish();
    match read_frame(&mut r, IO_TIMEOUT).await {
        Ok((frame::ERROR, p)) => Err(parse_error(&p)),
        Ok((rt, p)) if rt == expect => Ok(p),
        Ok(_) => Err(NetError::Protocol("unexpected frame".into())),
        Err(NetError::Protocol(m)) => Err(match conn.close_reason() {
            Some(_) => conn_error(conn, m),
            None => NetError::Protocol(m),
        }),
        Err(e) => Err(e),
    }
}

fn bind_phone_endpoint(
    rt: &tokio::runtime::Runtime,
    sk: SecretKey,
    mdns: bool,
    relay_url: Option<&str>,
) -> Result<Endpoint, NetError> {
    let (relay_mode, _) = super::build_relay_mode(relay_url)?;
    rt.block_on(async move {
        let b = Endpoint::builder(presets::Minimal)
            .secret_key(sk)
            // M4.3: ALPN_PAIR for a code this phone shows; refused at once
            // when no code is showing.
            .alpns(vec![ALPN_APP.to_vec(), ALPN_PAIR.to_vec()])
            .relay_mode(relay_mode)
            .clear_address_lookup()
            .net_report_config(super::default_net_report_config());
        // `mdns`: asked per dial (`discover_addrs`), never a standing
        // lookup: that one multicast a query every 0.7 s, all day, in the
        // background too (0.8.1 field test).
        let _ = mdns;
        b.bind()
            .await
            .map_err(|e| NetError::Unreachable(format!("bind: {e}")))
    })
}

impl PhoneClient {
    pub fn new(cfg: PhoneConfig) -> Result<PhoneClient, NetError> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("voidwire-net")
            .enable_all()
            .build()
            .map_err(|e| NetError::Protocol(format!("runtime: {e}")))?;
        let state = match cfg
            .state
            .load()
            .map_err(NetError::Storage)?
            .map(zeroize::Zeroizing::new)
        {
            Some(b) if !OLD_STATE_MAGICS.iter().any(|m| b.starts_with(m)) => PhoneState::decode(&b)
                .ok_or_else(|| {
                    NetError::Storage("state is damaged or from another version".into())
                })?,
            // No state, or an older Voidwire's: start fresh. The save below
            // replaces the old file (temp + rename), so no old secret stays.
            old => {
                let from_old = old.is_some();
                let name = if valid_device_name(&cfg.default_name) {
                    cfg.default_name.clone()
                } else {
                    "Phone".to_owned()
                };
                let st = PhoneState {
                    identity: DeviceKeypair::generate(),
                    name,
                    pcs: Vec::new(),
                    relay_url: super::resolve_relay_url(None),
                    custom_mailbox_peer: None,
                    relay_policy: crate::file_transfer::RelayTransferPolicy::new(),
                    conn_stats: crate::file_transfer::ConnectionStatsStore::new(),
                    seen_ids: std::collections::HashMap::new(),
                    pairings: crate::pairwise::PairingSet::new(),
                    relay_settings: crate::pairwise::RelaySettings::new(
                        super::pairings_state::builtin_relay(),
                    ),
                    outbox: super::outbox::Outbox::default(),
                    away: None,
                    drains: Vec::new(),
                    unsent_ops: Default::default(),
                    old_pairings_dropped: from_old,
                };
                cfg.state.save(&st.encode()).map_err(NetError::Storage)?;
                st
            }
        };
        let sk = SecretKey::from_bytes(&state.identity.secret_bytes());
        let mdns = cfg.mdns;
        let endpoint =
            bind_phone_endpoint(&rt, sk, mdns, state.relay_url.as_deref().or(Some("off")))?;
        let env_mb_explicit = std::env::var(super::mailbox_client::ENV_MAILBOX_ID).is_ok();
        let initial_mb = if !env_mb_explicit {
            if let Some(custom) = state.custom_mailbox_peer {
                let is_custom =
                    custom.is_some_and(|p| p != super::mailbox_client::default_mailbox_device_id());
                (custom, is_custom)
            } else {
                (super::mailbox_client::resolve_mailbox_id(None), false)
            }
        } else {
            (super::mailbox_client::resolve_mailbox_id(None), true)
        };
        let initial_data_dir = cfg.state.data_dir();
        let default_dl_dir = match initial_data_dir {
            Some(ref d) => d.join("incoming-staging"),
            None => std::env::temp_dir().join(format!(
                "voidwire-phone-dl-{}",
                state.identity.device_id().short()
            )),
        };
        let ep_for_accept = endpoint.clone();
        let inner = Arc::new(Inner {
            rt,
            endpoint: Mutex::new(endpoint),
            state: Mutex::new(state),
            store: cfg.state,
            platform: cfg.platform,
            mdns,
            conns: Mutex::new(Default::default()),
            mailbox_peer: Mutex::new(initial_mb),
            last_throwaway_id: Mutex::new(None),
            force_relay_at_chunk_for_test: Mutex::new(None),
            drop_conn_once_at_chunk_for_test: Mutex::new(None),
            fail_reconnects_for_test: Mutex::new(0),
            direct_first_wait_ms: Mutex::new(None),
            cached_file_hashes: Mutex::new(std::collections::HashMap::new()),
            prompt_accepted_transfers: Mutex::new(std::collections::HashSet::new()),
            cancelled_transfers: Mutex::new(std::collections::VecDeque::new()),
            accept_task: Mutex::new(None),
            relay_watch: Mutex::new(None),
            app_foreground: std::sync::atomic::AtomicBool::new(true),
            last_event_pull: Mutex::new(std::collections::HashMap::new()),
            hold_unpair_send: std::sync::atomic::AtomicBool::new(false),
            event_skew_ms: std::sync::atomic::AtomicU64::new(0),
            inbox_pulls: std::sync::atomic::AtomicU64::new(0),
            inboxes: Mutex::new(std::collections::HashMap::new()),
            incoming_items: Mutex::new(Vec::new()),
            next_incoming_item_id: std::sync::atomic::AtomicU64::new(1),
            incoming_files: Mutex::new(std::collections::HashMap::new()),
            declined_incoming_files: Mutex::new(std::collections::VecDeque::new()),
            data_dir: Mutex::new(initial_data_dir),
            pending_seen_sync: Arc::new(Mutex::new(Vec::new())),
            download_dir: Mutex::new(default_dl_dir),
            file_progress: tokio::sync::Notify::new(),
            auto_accept_files: std::sync::atomic::AtomicBool::new(false),
            background_listening: std::sync::atomic::AtomicBool::new(false),
            accept_incoming_enabled: std::sync::atomic::AtomicBool::new(true),
            host2: Mutex::new(Default::default()),
            join2: Mutex::new(Default::default()),
            relay_change: Mutex::new(Default::default()),
        });
        let task =
            spawn_phone_accept_loop(&inner.rt, Arc::downgrade(&inner), ep_for_accept.clone());
        *inner.accept_task.lock().unwrap_or_else(|p| p.into_inner()) = Some(task);
        let client = PhoneClient { inner };
        client.restart_relay_watch(&ep_for_accept);
        {
            let weak = Arc::downgrade(&client.inner);
            let serve: super::away::Serve = Arc::new(move |incoming| {
                let weak = weak.clone();
                tokio::spawn(async move {
                    let Ok(accepting) = incoming.accept() else {
                        return;
                    };
                    let Ok(conn) = accepting.await else { return };
                    if conn.alpn() != ALPN_APP {
                        conn.close(close_code(RejectReason::MalformedFrame), b"alpn");
                        return;
                    }
                    serve_app_conn(weak, conn).await;
                });
            });
            let weak = Arc::downgrade(&client.inner);
            let busy: super::away::Busy = Arc::new(move || {
                weak.upgrade().is_some_and(|i| {
                    !i.incoming_files
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .is_empty()
                        || !i
                            .cached_file_hashes
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .is_empty()
                })
            });
            let secret = *client.inner.lock().identity.secret_bytes();
            let away =
                super::away::Away::new(client.inner.rt.handle().clone(), secret, serve, busy);
            // Not foreground until the app UI says so: a process started by
            // the background service never holds an away relay.
            away.set_mode(crate::relay_supervisor::DeviceMode::PhoneBackground);
            let mut st = client.inner.lock();
            st.away = Some(away);
            st.sync_away();
        }
        // Event: start. Unpair notices a previous run couldn't deliver.
        if !client.inner.lock().outbox.is_empty() {
            let inner = client.inner.clone();
            client.inner.rt.spawn(async move {
                flush_outbox_phone(&inner, false).await;
            });
        }
        Ok(client)
    }

    fn away(&self) -> Option<Arc<super::away::Away>> {
        self.inner.lock().away.clone()
    }

    fn supervisor_mode(&self) -> crate::relay_supervisor::DeviceMode {
        if self
            .inner
            .app_foreground
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            crate::relay_supervisor::DeviceMode::PhoneForeground
        } else {
            crate::relay_supervisor::DeviceMode::PhoneBackground
        }
    }

    fn restart_relay_watch(&self, ep: &Endpoint) {
        let relay = self.inner.lock().relay_url.clone();
        let w = super::relay_watch::for_app_endpoint(
            self.inner.rt.handle(),
            ep,
            relay.as_deref().or(Some("off")),
            self.supervisor_mode(),
        );
        *self
            .inner
            .relay_watch
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = w;
    }

    fn with_relay_watch(&self, f: impl FnOnce(&super::relay_watch::RelayWatch)) {
        if let Some(w) = self
            .inner
            .relay_watch
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
        {
            f(w);
        }
    }

    /// The app UI opened (`true`) or closed (`false`). Phones keep only their
    /// home relay while closed; opening retries parked relays at once.
    pub fn set_app_foreground(&self, foreground: bool) {
        self.inner
            .app_foreground
            .store(foreground, std::sync::atomic::Ordering::SeqCst);
        let mode = self.supervisor_mode();
        self.with_relay_watch(|w| {
            w.set_mode(mode);
            if foreground {
                w.retry_now();
            }
        });
        if let Some(a) = self.away() {
            a.set_mode(mode);
            if foreground {
                a.retry_now(false);
            }
        }
    }

    /// The OS reported a network change: retry parked relays now.
    pub fn network_changed(&self) {
        self.with_relay_watch(|w| w.network_change());
        if let Some(a) = self.away() {
            a.retry_now(true);
        }
        // A new network is worth one more try for waiting unpair notices.
        if !self.inner.lock().outbox.is_empty() {
            let inner = self.inner.clone();
            self.inner.rt.spawn(async move {
                flush_outbox_phone(&inner, true).await;
            });
        }
    }

    /// Unpair notices saved but not yet delivered (tests, diagnostics).
    pub fn pending_unpair_notices(&self) -> usize {
        self.inner.lock().outbox.len()
    }

    /// Test seam: unpairing saves the notice but doesn't send it, like an
    /// app killed right after the erase.
    #[cfg(feature = "test-util")]
    pub fn hold_unpair_send_for_tests(&self, hold: bool) {
        self.inner
            .hold_unpair_send
            .store(hold, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test seam: move the event-pull gate's clock forward by `ms`.
    #[cfg(feature = "test-util")]
    pub fn advance_event_clock_for_tests(&self, ms: u64) {
        self.inner
            .event_skew_ms
            .fetch_add(ms, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test seam: inbox pulls actually started (gated ones don't count).
    #[cfg(feature = "test-util")]
    pub fn inbox_pulls_for_tests(&self) -> u64 {
        self.inner
            .inbox_pulls
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Relay supervisor counters (tests and diagnostics; no private data).
    pub fn relay_watch_stats(&self) -> Option<Arc<super::relay_watch::WatchStats>> {
        let mut out = None;
        self.with_relay_watch(|w| out = Some(w.stats()));
        out
    }

    /// Event-driven inbox pull (unlock, network change): skipped when the
    /// same relay was pulled less than [`EVENT_PULL_MIN_GAP_MS`] ago. App
    /// open passes `force = true` and always pulls. Never timer-driven.
    pub fn pull_device_inbox_on_event(&self, force: bool) -> Result<usize, NetError> {
        let skew = self
            .inner
            .event_skew_ms
            .load(std::sync::atomic::Ordering::SeqCst);
        let t = SystemClock.now().mono.saturating_add(skew);
        self.pull_inbox_gated(if force { None } else { Some(t) }, t)
    }

    /// Away relays open now: (url, held) (tests).
    #[cfg(feature = "test-util")]
    pub fn away_relays_for_tests(&self) -> Vec<(String, bool)> {
        self.inner
            .lock()
            .away
            .clone()
            .map(|a| {
                a.open_relays()
                    .into_iter()
                    .map(|i| (i.url, i.held))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Away endpoints opened since start (tests).
    #[cfg(feature = "test-util")]
    pub fn away_opened_for_tests(&self) -> u64 {
        self.inner
            .lock()
            .away
            .clone()
            .map(|a| a.opened())
            .unwrap_or(0)
    }

    /// Event pulls per relay since this process started (tests).
    pub fn event_pulled_relays(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .inner
            .last_event_pull
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .cloned()
            .collect();
        v.sort();
        v
    }

    pub fn device_id(&self) -> DeviceId {
        self.inner.lock().identity.device_id()
    }

    pub fn device_name(&self) -> String {
        self.inner.lock().name.clone()
    }

    /// Name shown on PCs we pair with from now on.
    pub fn set_device_name(&self, name: &str) -> Result<(), NetError> {
        let name = name.trim();
        if !valid_device_name(name) {
            return Err(NetError::Rejected(RejectReason::BadDeviceName));
        }
        let mut st = self.inner.lock();
        if st.name == name {
            return Ok(());
        }
        let (name_before, pairings_before, unsent_before) =
            (st.name.clone(), st.pairings.clone(), st.unsent_ops.clone());
        st.name = name.to_owned();
        // M4.5: a signed rename for each v2 peer, sent on a connection that
        // is up now or the next one that comes up.
        let st2 = &mut *st;
        let peers = super::pair_ops::rename_all(
            &mut st2.pairings,
            &mut st2.unsent_ops,
            &st2.identity,
            SystemClock.now().wall,
            name,
        );
        st.rebuild_links();
        if let Err(e) = self.inner.save(&st) {
            st.name = name_before;
            st.pairings = pairings_before;
            st.unsent_ops = unsent_before;
            st.rebuild_links();
            return Err(e);
        }
        drop(st);
        for peer in peers {
            let live = self
                .inner
                .conns
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&peer)
                .filter(|c| c.close_reason().is_none())
                .cloned();
            if let Some(conn) = live {
                self.inner
                    .rt
                    .spawn(super::pair_ops::flush(self.inner.clone(), conn, peer));
            }
        }
        Ok(())
    }

    /// Configured default relay URL (`Some("https://relay.voidwire.app")` by default).
    pub fn relay_url(&self) -> Option<String> {
        self.inner.lock().relay_url.clone()
    }

    /// Set or reset the relay URL (`None` or empty string resets to `DEFAULT_RELAY_URL`;
    /// `"off"` / `"none"` / `"disabled"` disables the relay), validating the URL and
    /// rebinding the active endpoint without blocking on the old endpoint teardown (`M2.9`).
    pub fn set_relay_url(&self, relay_url: Option<String>) -> Result<(), NetError> {
        let normalized = match relay_url.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(s) => Some(s),
        };
        let (_, parsed) = super::build_relay_mode(normalized)?;
        let resolved = parsed.map(|u| u.as_str().trim_end_matches('/').to_owned());
        let sk = {
            let mut st = self.inner.lock();
            st.relay_url = resolved.clone();
            st.relay_policy
                .set_server_cap_bytes(crate::file_transfer::DEFAULT_RELAY_FILE_CAP_BYTES);
            for pc in &mut st.pcs {
                pc.relay_url = resolved.clone();
            }
            st.sync_away();
            self.inner.save(&st)?;
            SecretKey::from_bytes(&st.identity.secret_bytes())
        };
        for (_, c) in self.conns().drain() {
            c.close(0u32.into(), b"relay_changed");
        }
        let new_ep = bind_phone_endpoint(
            &self.inner.rt,
            sk,
            self.inner.mdns,
            resolved.as_deref().or(Some("off")),
        )?;
        let ep_for_accept = new_ep.clone();
        self.restart_relay_watch(&new_ep);
        let old_ep = std::mem::replace(
            &mut *self
                .inner
                .endpoint
                .lock()
                .unwrap_or_else(|p| p.into_inner()),
            new_ep,
        );
        {
            let mut guard = self
                .inner
                .accept_task
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(old_task) = guard.take() {
                old_task.abort();
            }
            *guard = Some(spawn_phone_accept_loop(
                &self.inner.rt,
                Arc::downgrade(&self.inner),
                ep_for_accept,
            ));
        }
        self.inner.rt.spawn(async move {
            old_ep.close().await;
        });
        Ok(())
    }

    /// M4.3: the saved relays (for the relay picker on invites).
    pub fn saved_relays(&self) -> Vec<super::pair2::SavedRelay> {
        super::pair2::saved_relays(&*self.inner)
    }

    /// M4.3: show a `v=2` QR and a code for another device to join, over
    /// `relay_url` (a saved relay; `None`: this phone's relay). The app
    /// asks for the screen lock first.
    pub fn pair2_show(&self, relay_url: Option<&str>) -> Result<super::pair2::ShowInfo, NetError> {
        let dial = self.inner.lock().relay_url.clone();
        let ep = self
            .inner
            .endpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let addrs: Vec<SocketAddr> = ep
            .addr()
            .ip_addrs()
            .copied()
            .filter(|a| !a.ip().is_loopback() || cfg!(any(test, feature = "test-util")))
            .collect();
        let inner = self.inner.clone();
        let relay = relay_url.map(str::to_owned);
        self.inner.rt.block_on(async move {
            super::pair2::show(
                &*inner,
                relay.as_deref(),
                dial.as_deref(),
                &addrs,
                SystemClock.now(),
            )
            .await
        })
    }

    /// Test harness (M4.3): save a relay (with its mailbox) for the picker.
    #[cfg(feature = "test-util")]
    pub fn add_saved_relay_for_tests(
        &self,
        relay: crate::pairwise::RelayRef,
    ) -> Result<(), NetError> {
        super::pair2::Node2::save_relay(
            &*self.inner,
            crate::pairwise::RelayEntry {
                nickname: super::pair2::relay_host(&relay.url),
                relay,
                source: crate::pairwise::RelaySource::Manual,
                no_udp: false,
                token: None,
            },
        )
    }

    /// Test harness (M4.3): show a code issued `age_ms` ago (expiry tests).
    #[cfg(feature = "test-util")]
    pub fn pair2_show_aged_for_tests(
        &self,
        relay_url: Option<&str>,
        age_ms: u64,
    ) -> Result<super::pair2::ShowInfo, NetError> {
        let n = SystemClock.now();
        let then = crate::time::Now {
            wall: crate::time::UnixMillis(n.wall.0.saturating_sub(age_ms)),
            mono: crate::time::MonoMillis(n.mono.0.saturating_sub(age_ms)),
        };
        let inner = self.inner.clone();
        let relay = relay_url.map(str::to_owned);
        // On the node's own runtime, so the card's later deletion runs.
        self.inner.rt.block_on(async move {
            super::pair2::show(&*inner, relay.as_deref(), None, &[], then).await
        })
    }

    /// M4.3: the showing screen's state.
    pub fn pair2_status(&self) -> super::pair2::HostStatus {
        super::pair2::Node2::host(&*self.inner).status(SystemClock.now())
    }

    /// M4.3: the user typed the 6-digit code the other device shows.
    pub fn pair2_submit_code(&self, sas: &str) -> Result<super::pair2::Paired2, NetError> {
        super::pair2::host_submit(&*self.inner, sas, SystemClock.now())
    }

    /// M4.3: close the pairing screen (a showing code stops working).
    pub fn pair2_cancel(&self) {
        super::pair2::Node2::host(&*self.inner).cancel(SystemClock.now());
        super::pair2::join_cancel(&*self.inner);
    }

    /// M4.3: open a typed code, fetched from `relay_url` (a saved relay;
    /// `None`: the public relay).
    pub fn pair2_open_code(
        &self,
        code: &str,
        relay_url: Option<&str>,
    ) -> Result<super::pair2::Opened, NetError> {
        let inner = self.inner.clone();
        let (code, relay) = (code.to_owned(), relay_url.map(str::to_owned));
        self.inner.rt.block_on(async move {
            super::pair2::open_code(&*inner, &code, relay.as_deref(), SystemClock.now()).await
        })
    }

    /// M4.3: open a scanned `v=2` pairing QR.
    pub fn pair2_open_qr(&self, uri: &str) -> Result<super::pair2::Opened, NetError> {
        super::pair2::open_qr(&*self.inner, uri, SystemClock.now())
    }

    /// M4.3: the user chose [Add and pair] for the invite's relay.
    pub fn pair2_add_relay(&self) -> Result<(), NetError> {
        super::pair2::add_pending_relay(&*self.inner)
    }

    /// M4.3: connect to the inviter; returns the 6-digit code to show.
    pub fn pair2_join(&self) -> Result<String, NetError> {
        let inner = self.inner.clone();
        let ep = self
            .inner
            .endpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        self.inner
            .rt
            .block_on(async move { super::pair2::join_begin(&*inner, &ep).await })
    }

    /// M4.3: wait until the other device's user typed our code.
    pub fn pair2_join_wait(&self) -> Result<super::pair2::Paired2, NetError> {
        let inner = self.inner.clone();
        self.inner
            .rt
            .block_on(async move { super::pair2::join_wait(&*inner).await })
    }

    // ---- M4.4 relays ----

    fn relay_status(&self, url: &str, used: bool) -> super::relays::RelayStatus {
        use super::relays::RelayStatus;
        let (home, away) = {
            let st = self.inner.lock();
            (
                st.relay_url
                    .as_deref()
                    .is_some_and(|h| super::away::same_relay(h, url)),
                st.away.clone(),
            )
        };
        let stats = if home {
            self.inner
                .relay_watch
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .map(|w| w.stats())
        } else {
            away.and_then(|a| {
                a.open_relays()
                    .into_iter()
                    .find(|i| super::away::same_relay(&i.url, url))
                    .map(|i| i.stats)
            })
        };
        match stats {
            Some(s) if s.is_parked() => RelayStatus::Unreachable {
                since_ms: s.down_since().unwrap_or(0),
            },
            Some(_) => RelayStatus::Connected,
            None if home && used => RelayStatus::Connected,
            None => RelayStatus::Idle,
        }
    }

    /// Settings → Relays.
    pub fn relays(&self) -> Vec<super::relays::RelayInfo> {
        let (p, rs) = self.inner.lock().pairwise();
        let pr = super::relay_change::pairing_relays(&p, None);
        super::relays::list(&rs, &pr, |u, used| self.relay_status(u, used))
    }

    fn edit_relays(
        &self,
        f: impl FnOnce(
            &mut crate::pairwise::RelaySettings,
            &[Option<String>],
        ) -> Result<(), super::relays::RelayError>,
    ) -> Result<(), super::relays::RelayError> {
        let mut st = self.inner.lock();
        let (p, mut rs) = st.pairwise();
        let pr = super::relay_change::pairing_relays(&p, None);
        f(&mut rs, &pr)?;
        st.relay_settings = rs;
        self.inner.save(&st)?;
        Ok(())
    }

    /// Save a relay from a `voidwire:relay?…` link.
    pub fn add_relay_link(&self, link: &str) -> Result<(), super::relays::RelayError> {
        let k = super::relays::parse_link(link)?;
        self.edit_relays(|rs, _| {
            super::relays::add(
                rs,
                k.relay,
                &k.nickname,
                crate::pairwise::RelaySource::Manual,
                k.no_udp,
                k.token,
            )
        })
    }

    /// Save a relay typed by hand (`mailbox_hex` may be empty).
    pub fn add_relay(
        &self,
        url: &str,
        mailbox_hex: &str,
        nickname: &str,
    ) -> Result<(), super::relays::RelayError> {
        let r = super::relays::relay_ref(url, mailbox_hex)?;
        self.edit_relays(|rs, _| {
            super::relays::add(
                rs,
                r,
                nickname,
                crate::pairwise::RelaySource::Manual,
                false,
                None,
            )
        })
    }

    pub fn remove_relay(&self, url: &str) -> Result<(), super::relays::RelayError> {
        self.edit_relays(|rs, pr| super::relays::remove(rs, url, pr))?;
        if let Some(a) = self.inner.lock().away.clone() {
            a.forget(url);
        }
        Ok(())
    }

    pub fn rename_relay(&self, url: &str, nickname: &str) -> Result<(), super::relays::RelayError> {
        self.edit_relays(|rs, _| super::relays::rename(rs, url, nickname))
    }

    /// Settings → Relays → Retry.
    pub fn retry_relay(&self, url: &str) {
        let (home, away) = {
            let st = self.inner.lock();
            (
                st.relay_url
                    .as_deref()
                    .is_some_and(|h| super::away::same_relay(h, url)),
                st.away.clone(),
            )
        };
        if home {
            if let Some(w) = self
                .inner
                .relay_watch
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
            {
                w.retry_now();
            }
        } else if let Some(a) = away {
            a.retry_relay(url);
        }
    }

    fn peer_name(&self, peer: &DeviceId) -> String {
        use super::relay_change::Host;
        self.inner
            .rc_log(peer)
            .map(|(_, n)| n)
            .unwrap_or_else(|| peer.short())
    }

    /// Propose moving the pairing with `peer` to the saved relay `url`
    /// (the other device's user must allow it).
    pub fn change_pairing_relay(
        &self,
        peer: &DeviceId,
        url: &str,
    ) -> Result<(), super::relays::RelayError> {
        use super::relay_change as rc;
        let relay = {
            let st = self.inner.lock();
            st.relay_settings
                .relays
                .iter()
                .find(|e| super::away::same_relay(&e.relay.url, url))
                .map(|e| e.relay.clone())
                .ok_or(super::relays::RelayError::NotFound)?
        };
        let name = self.peer_name(peer);
        let op = rc::propose(&*self.inner, peer, relay)?;
        let inner = self.inner.clone();
        let p = *peer;
        let res = self.inner.rt.block_on(async move {
            let conn = Self::get_conn(&inner, &p, false).await?;
            rc::request(&conn, frame::RELAY_PROPOSE, &op.encode()).await
        });
        match res {
            Ok(rc::ack::OK) => Ok(()),
            Ok(rc::ack::NO_ROOM) => {
                rc::mark_no_room(&*self.inner, peer);
                Err(super::relays::RelayError::Other(format!(
                    "{name} has no room for another relay."
                )))
            }
            Ok(_) => {
                rc::forget_outgoing(&*self.inner, peer);
                Err(super::relays::RelayError::Other(format!(
                    "{name} refused the change. Make sure both devices are up to date."
                )))
            }
            Err(_) => {
                rc::forget_outgoing(&*self.inner, peer);
                Err(rc::offline_error(&name))
            }
        }
    }

    pub fn relay_change_requests(&self) -> Vec<super::relay_change::RelayChangeRequest> {
        super::relay_change::requests(&*self.inner)
    }

    pub fn relay_change_statuses(&self) -> Vec<super::relay_change::RelayChangeStatus> {
        super::relay_change::statuses(&*self.inner)
    }

    /// Allow (co-sign and switch) or decline a request from `peer`.
    pub fn answer_relay_change(
        &self,
        peer: &DeviceId,
        allow: bool,
    ) -> Result<(), super::relays::RelayError> {
        use super::relay_change::{self as rc, Host};
        let name = self.peer_name(peer);
        let inner = self.inner.clone();
        let p = *peer;
        if !allow {
            if let Some(h) = rc::finish_incoming(&*self.inner, peer) {
                let _ = self.inner.rt.block_on(async move {
                    let conn = Self::get_conn(&inner, &p, false).await?;
                    rc::request(&conn, frame::RELAY_DECLINE, &h.0).await
                });
            }
            return Ok(());
        }
        let (log, op) = rc::cosign(&*self.inner, peer)?;
        let res = self.inner.rt.block_on(async move {
            let conn = Self::get_conn(&inner, &p, false).await?;
            rc::request(&conn, frame::RELAY_ACCEPT, &op.encode()).await
        });
        match res {
            Ok(rc::ack::OK) => {
                self.inner.rc_commit(peer, log)?;
                rc::finish_incoming(&*self.inner, peer);
                // Drain the old relay inbox once now.
                let _ = self.pull_device_inbox_now();
                Ok(())
            }
            Ok(_) => {
                rc::finish_incoming(&*self.inner, peer);
                Err(super::relays::RelayError::Other(format!(
                    "{name} no longer wants this change."
                )))
            }
            Err(_) => Err(rc::offline_error(&name)),
        }
    }

    /// This phone's pairings (state v2, M4.1): one per paired PC.
    pub fn pairings(&self) -> Vec<super::pairings_state::PairingSummary> {
        super::pairings_state::summaries(&self.inner.lock().pairwise().0)
    }

    pub fn paired_pcs(&self) -> Vec<PairedPc> {
        let st = self.inner.lock();
        st.pcs
            .iter()
            .map(|p| PairedPc {
                id: p.replica.owner(),
                name: p.replica.link().name(),
                // An unpair erases the pairing, so a listed PC is paired.
                addrs: p.addrs.clone(),
            })
            .collect()
    }

    /// Remove a peer from this phone. A legacy PC is dropped locally only. A
    /// v2 pairing is erased first (spec §6: saved, else nothing changes and
    /// nothing is sent), then the peer is sent a signed unpair notice in the
    /// background, best effort: live, else into its pairing inbox (M4.2).
    pub fn forget_pc(&self, pc: &DeviceId) -> Result<bool, NetError> {
        let notice = if self.is_link_peer(pc) {
            self.prepare_unpair_notice(pc)
        } else {
            None
        };
        // Durable: the notice is saved with the erase and sent even if the
        // app is killed right after.
        let item = notice.as_ref().and_then(|n| n.item.clone());
        if let Some(i) = &item {
            self.inner.lock().outbox.push(i.clone());
        }
        let erased = match erase_peer(&self.inner, pc) {
            Ok(e) => e,
            Err(e) => {
                if let Some(i) = &item {
                    self.inner.lock().outbox.delivered(i);
                }
                return Err(e);
            }
        };
        if let Some(n) = notice {
            if self
                .inner
                .hold_unpair_send
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Ok(erased);
            }
            let inner = self.inner.clone();
            let ep = self
                .inner
                .endpoint
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            let peer = *pc;
            self.inner.rt.spawn(async move {
                let live =
                    match connect(&ep, &peer, &n.addrs, n.relay_url.as_deref(), ALPN_APP).await {
                        Ok(c) => {
                            let ok = Self::send_on(&c, &n.env).await.is_ok();
                            c.close(0u32.into(), b"");
                            ok
                        }
                        Err(_) => false,
                    };
                if live {
                    if let Some(i) = &n.item {
                        let mut st = inner.lock();
                        st.outbox.delivered(i);
                        let _ = inner.save(&st);
                    }
                } else {
                    flush_outbox_phone(&inner, false).await;
                }
            });
        }
        Ok(erased)
    }

    /// The signed unpair op for a v2 peer, sealed as a pair notice, with
    /// where to send it. Signed on a copy of the log: the stored pairing is
    /// untouched until the erase is saved.
    fn prepare_unpair_notice(&self, peer: &DeviceId) -> Option<UnpairNotice> {
        let home_mb = self.effective_mailbox_peer(peer);
        let st = self.inner.lock();
        let entry = st.pc(peer)?;
        let link = entry.replica.link();
        let (pairing_id, rk) = (link.pairing_id, link.peer_rx);
        let home_url = entry.relay_url.clone().or_else(|| st.relay_url.clone());
        let target = link.peer_inbox(home_url.as_deref(), home_mb);
        let addrs = entry.addrs.clone();
        let ts = SystemClock.now().wall;
        let op = st
            .pairings
            .get(&pairing_id)?
            .log
            .clone()
            .unpair(&st.identity, ts)
            .ok()?;
        let body = crate::wire::encode_signed_pair_notice(
            &st.identity,
            &crate::wire::OutgoingPairNotice {
                group: pairing_id,
                recipient: *peer,
                msg_id: MsgId::random(),
                timestamp: ts,
                op: &op.encode(),
            },
        )
        .ok()?;
        let env = envelope::seal(peer, &rk, &body).ok()?;
        Some(UnpairNotice {
            item: target
                .as_ref()
                .and_then(|t| super::outbox::OutboxItem::new(t, env.clone(), ts)),
            env,
            addrs,
            relay_url: home_url,
        })
    }

    fn conns(&self) -> MutexGuard<'_, std::collections::HashMap<DeviceId, Connection>> {
        self.inner.conns.lock().unwrap_or_else(|p| p.into_inner())
    }

    async fn get_conn(
        inner: &Arc<Inner>,
        pc: &DeviceId,
        fresh: bool,
    ) -> Result<Connection, NetError> {
        if fresh {
            if let Some(old) = inner
                .conns
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(pc)
            {
                old.close(0u32.into(), b"reconnect");
            }
            let mut fail_rem = inner
                .fail_reconnects_for_test
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if *fail_rem > 0 {
                *fail_rem -= 1;
                return Err(NetError::Unreachable("simulated reconnect failure".into()));
            }
        } else {
            let cached = inner
                .conns
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(pc)
                .cloned();
            if let Some(c) = cached {
                if c.close_reason().is_none() {
                    return Ok(c);
                }
            }
        }
        let (addrs, relay_url, away) = {
            let st = inner.lock();
            let p = st.pc(pc).ok_or(NetError::UnknownDevice)?;
            let away = st
                .away_route_for(pc)
                .and_then(|u| st.away.clone().map(|a| (u, a)));
            (
                p.addrs.clone(),
                p.relay_url.clone().or_else(|| st.relay_url.clone()),
                away,
            )
        };
        let ep = inner
            .endpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if fresh {
            ep.network_change().await;
        }
        if let Some((url, away)) = away {
            let c = super::away::dial_via(&away, &ep, inner.mdns, pc, &addrs, &url, true).await?;
            inner
                .conns
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(*pc, c.clone());
            spawn_pc_conn_reader(&inner.rt, Arc::downgrade(inner), *pc, c.clone());
            return Ok(c);
        }
        let c = match connect(&ep, pc, &addrs, relay_url.as_deref(), ALPN_APP).await {
            Ok(c) => c,
            // The cached address failed (stale, or answered with the wrong
            // identity): one retry on a fresh mDNS lookup. In a cold process
            // (the share sheet) mDNS has no answers yet, so first wait a
            // bounded time for one (L3) and dial what it found. The TLS
            // identity is still checked, so this can't reach the wrong PC.
            //
            // When another device answered at the cached address, iroh keeps
            // that path for this PC and races it against the mDNS one, so a
            // single redial can still lose to the fast identity failure. Those
            // failures take milliseconds: redial a few times within a small
            // bounded budget (each dial still checks the PC's identity).
            Err(first) if inner.mdns && !addrs.is_empty() => {
                let found = discover_addrs(&ep, pc, MDNS_FALLBACK_WAIT, true).await;
                let start = SystemClock.now().mono;
                let mut attempt = 0;
                loop {
                    attempt += 1;
                    match connect(&ep, pc, &found, relay_url.as_deref(), ALPN_APP).await {
                        Ok(c) => break c,
                        Err(_)
                            if attempt < MDNS_FALLBACK_DIALS
                                && SystemClock.now().mono.0.saturating_sub(start.0)
                                    < MDNS_FALLBACK_REDIAL_BUDGET_MS =>
                        {
                            tokio::time::sleep(Duration::from_millis(25)).await;
                        }
                        Err(_) => return Err(first),
                    }
                }
            }
            Err(e) => return Err(e),
        };
        if inner.mdns {
            // Keep the cache on the path that actually worked (mDNS may have
            // found the PC somewhere other than the cached address).
            Self::learn_addrs(inner, pc, &c);
        }
        inner
            .conns
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(*pc, c.clone());
        spawn_pc_conn_reader(&inner.rt, Arc::downgrade(inner), *pc, c.clone());
        Ok(c)
    }

    /// Replace a PC's cached addresses with the direct paths of a working
    /// connection (after the mDNS fallback), and persist.
    fn learn_addrs(inner: &Inner, pc: &DeviceId, conn: &Connection) {
        let mut fresh: Vec<SocketAddr> = conn
            .paths()
            .iter()
            .filter_map(|p| match p.remote_addr() {
                iroh::TransportAddr::Ip(a) => Some(*a),
                _ => None,
            })
            .collect();
        fresh.dedup();
        fresh.truncate(crate::pairing::MAX_QR_ADDRS);
        if fresh.is_empty() {
            return;
        }
        let mut st = inner.lock();
        if let Some(e) = st.pc_mut(pc) {
            if e.addrs == fresh {
                return;
            }
            e.addrs = fresh;
            let _ = inner.save(&st);
        }
    }

    /// Configure the blind mailbox service `DeviceId` (or `None` to disable).
    pub fn set_mailbox_peer(&self, peer: Option<DeviceId>) {
        let is_explicit = peer != Some(super::mailbox_client::default_mailbox_device_id());
        *self
            .inner
            .mailbox_peer
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = (peer, is_explicit);
        let mut st = self.inner.lock();
        st.custom_mailbox_peer = Some(peer);
        if let Some(mp) = peer {
            for pc in &mut st.pcs {
                pc.mailbox_peer = Some(mp);
            }
        }
        let _ = self.inner.save(&st);
    }

    /// Alias for [`PhoneClient::mailbox_peer`] (`M2.8`).
    pub fn mailbox_id(&self) -> Option<DeviceId> {
        self.mailbox_peer()
    }

    /// Set or reset the blind mailbox endpoint `DeviceId` and persist in `phone-state.bin` (`M2.8`).
    pub fn set_mailbox_id(&self, peer: Option<DeviceId>) -> Result<(), NetError> {
        let is_explicit = peer != Some(super::mailbox_client::default_mailbox_device_id());
        *self
            .inner
            .mailbox_peer
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = (peer, is_explicit);
        let mut st = self.inner.lock();
        st.custom_mailbox_peer = Some(peer);
        if let Some(mp) = peer {
            for pc in &mut st.pcs {
                pc.mailbox_peer = Some(mp);
            }
        }
        self.inner.save(&st)
    }

    /// Configured blind mailbox service `DeviceId`.
    pub fn mailbox_peer(&self) -> Option<DeviceId> {
        let (global_peer, explicit) = *self
            .inner
            .mailbox_peer
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if explicit {
            return global_peer;
        }
        let st = self.inner.lock();
        if let Some(pc_mp) = st.pcs.iter().find_map(|p| p.mailbox_peer) {
            return Some(pc_mp);
        }
        global_peer
    }

    fn effective_mailbox_peer(&self, pc: &DeviceId) -> Option<(DeviceId, bool)> {
        let (global_peer, explicit) = *self
            .inner
            .mailbox_peer
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if explicit {
            return global_peer.map(|p| (p, true));
        }
        let st = self.inner.lock();
        if let Some(mp) = st.pc(pc).and_then(|e| e.mailbox_peer) {
            let is_custom = mp != super::mailbox_client::default_mailbox_device_id();
            return Some((mp, is_custom));
        }
        global_peer.map(|p| (p, false))
    }

    /// Ephemeral `DeviceId` used on the most recent throwaway mailbox session.
    pub fn last_throwaway_id(&self) -> Option<DeviceId> {
        *self
            .inner
            .last_throwaway_id
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Check that `pc` is still paired and reachable: `Removed` once its
    /// unpair notice was applied (the pairing is gone), else a live dial.
    /// Pairings from an older Voidwire were dropped: show "This pairing is
    /// from an older Voidwire. Pair again."
    pub fn old_pairings_dropped(&self) -> bool {
        self.inner.lock().old_pairings_dropped
    }

    /// Connect to `pc`; `Ok(false)` when it is no longer paired.
    pub fn sync(&self, pc: &DeviceId) -> Result<bool, NetError> {
        if Self::require_pair(&self.inner, pc).is_err() {
            return Ok(false);
        }
        let inner = self.inner.clone();
        let pc_id = *pc;
        self.inner
            .rt
            .block_on(async move { Self::get_conn(&inner, &pc_id, true).await })?;
        Ok(true)
    }

    /// `pc` is a v2 pairing of this phone.
    fn require_pair(inner: &Inner, pc: &DeviceId) -> Result<(), NetError> {
        match inner.lock().pc(pc) {
            Some(_) => Ok(()),
            None => Err(NetError::UnknownDevice),
        }
    }

    /// Send one link. Checks it locally first (same policy as the PC), and
    /// performs pull-before-trust (`docs/PROTOCOL.md` §7.1(e)) when a mailbox is configured.
    pub fn send_url(&self, pc: &DeviceId, url: &str) -> Result<SendReport, NetError> {
        let canonical = crate::url_policy::check_url(url)?;
        let started = crate::time::Stopwatch::start();
        Self::require_pair(&self.inner, pc)?;
        let inner = self.inner.clone();
        let pc = *pc;
        let url = canonical.as_str().to_owned();
        let url_q = url.clone();
        let res =
            self.inner.rt.block_on(async move {
                let mut fresh = false;
                loop {
                    let conn = Self::get_conn(&inner, &pc, fresh).await?;
                    let r = async {
                        let env = Self::seal_for(&inner, &pc, &url)?;
                        let out = Self::send_on(&conn, &env).await?;
                        let path_kind = Self::conn_path_kind(&inner, &pc, &conn);
                        {
                            let mut st = inner.lock();
                            if st.conn_stats.is_enabled() {
                                st.conn_stats.record_transfer(
                                    &pc,
                                    path_kind,
                                    env.len() as u64,
                                    SystemClock.now().wall,
                                );
                                let _ = inner.save(&st);
                            }
                        }
                        Ok(out)
                    }
                    .await;
                    match r {
                        // A cached connection may have gone stale (PC restarted,
                        // Wi-Fi/cellular changed): retry once on a fresh one.
                        Err(
                            NetError::Protocol(_) | NetError::Timeout | NetError::Unreachable(_),
                        ) if !fresh => fresh = true,
                        // The PC dropped our connection because it forgot us:
                        // fetch the signed remove op so the UI can say so.
                        other => return other,
                    }
                }
            });
        let outcome = match res {
            Err(e) if is_offline(&e) && self.is_link_peer(&pc) => {
                let env = Self::seal_for(&self.inner, &pc, &url_q)?;
                self.queue_in_pair_inbox(&pc, env)?;
                SendOutcome::Prompted
            }
            r => r?,
        };
        Ok(SendReport {
            outcome,
            latency_us: started.elapsed_us(),
        })
    }

    /// The peer is a v2 link (M4.2).
    fn is_link_peer(&self, peer: &DeviceId) -> bool {
        self.inner.lock().pc(peer).is_some()
    }

    /// Put a sealed envelope into a v2 peer's inbox on the pairing relay
    /// (the peer is offline, M4.2).
    fn queue_in_pair_inbox(&self, peer: &DeviceId, env: Vec<u8>) -> Result<(), NetError> {
        let home_mb = self.effective_mailbox_peer(peer);
        let target = {
            let st = self.inner.lock();
            let entry = st.pc(peer).ok_or(NetError::UnknownDevice)?;
            let link = entry.replica.link();
            let home_url = entry.relay_url.clone().or_else(|| st.relay_url.clone());
            link.peer_inbox(home_url.as_deref(), home_mb)
                .ok_or_else(|| NetError::Unreachable("no relay for this pairing".into()))?
        };
        let mut item_id = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut item_id);
        let (eph, _cap) = self
            .inner
            .rt
            .block_on(super::links::put_one(&target, item_id, env))?;
        *self
            .inner
            .last_throwaway_id
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(eph);
        Ok(())
    }

    fn seal_for(inner: &Inner, pc: &DeviceId, url: &str) -> Result<Vec<u8>, NetError> {
        let st = inner.lock();
        let entry = st.pc(pc).ok_or(NetError::UnknownDevice)?;
        let rk = entry.replica.seal_key();
        let body = encode_signed(
            &st.identity,
            &Outgoing {
                group: entry.replica.group(),
                recipient: *pc,
                msg_id: MsgId::random(),
                timestamp: SystemClock.now().wall,
                url,
            },
        )?;
        Ok(envelope::seal(pc, &rk, &body)?)
    }

    async fn send_on(conn: &Connection, env: &[u8]) -> Result<SendOutcome, NetError> {
        let p = request(conn, frame::SEND, env, frame::RESULT).await?;
        if p.len() != 3 {
            return Err(NetError::Protocol("bad result".into()));
        }
        let code = u16::from_be_bytes([p[0], p[1]]);
        if code != 0 {
            return Err(NetError::Rejected(RejectReason::from_code(code)));
        }
        SendOutcome::from_u8(p[2]).ok_or_else(|| NetError::Protocol("bad outcome".into()))
    }

    /// Test harness: a `FakePeer` holding this phone's real key and its view
    /// of `pc` (group, head, receive key), to craft hostile envelopes.
    #[cfg(feature = "test-util")]
    pub fn fake_peer_for_tests(&self, pc: &DeviceId) -> Option<crate::test_util::FakePeer> {
        let st = self.inner.lock();
        let e = st.pc(pc)?;
        Some(crate::test_util::FakePeer {
            key: DeviceKeypair::from_secret_bytes(&st.identity.secret_bytes()),
            group: e.replica.group(),
            recipient: *pc,
            seal_to: e.replica.seal_key(),
        })
    }

    /// Test harness: send arbitrary envelope bytes over the real connection
    /// (no local checks, no sync).
    #[cfg(feature = "test-util")]
    pub fn send_envelope_for_tests(
        &self,
        pc: &DeviceId,
        env: &[u8],
    ) -> Result<SendReport, NetError> {
        let started = crate::time::Stopwatch::start();
        let inner = self.inner.clone();
        let pc = *pc;
        let env = env.to_vec();
        let outcome = self.inner.rt.block_on(async move {
            let conn = Self::get_conn(&inner, &pc, false).await?;
            Self::send_on(&conn, &env).await
        })?;
        Ok(SendReport {
            outcome,
            latency_us: started.elapsed_us(),
        })
    }

    /// Test harness: send a raw frame (any type/length header) and return
    /// the reply frame type and payload.
    #[cfg(feature = "test-util")]
    pub fn raw_request_for_tests(
        &self,
        pc: &DeviceId,
        bytes: &[u8],
    ) -> Result<(u8, Vec<u8>), NetError> {
        let inner = self.inner.clone();
        let pc = *pc;
        let bytes = bytes.to_vec();
        self.inner.rt.block_on(async move {
            let conn = Self::get_conn(&inner, &pc, false).await?;
            let (mut s, mut r) = conn.open_bi().await.map_err(|e| conn_error(&conn, e))?;
            s.write_all(&bytes)
                .await
                .map_err(|e| NetError::Protocol(e.to_string()))?;
            let _ = s.finish();
            read_frame(&mut r, IO_TIMEOUT).await
        })
    }

    /// Test harness (M4.2): this phone's identity and certificate, to make
    /// a v2 pairing with [`crate::net::pair_v2_for_tests`].
    #[cfg(feature = "test-util")]
    pub fn v2_identity_for_tests(&self) -> (DeviceKeypair, crate::keys::DeviceCert) {
        let st = self.inner.lock();
        let kp = DeviceKeypair::from_secret_bytes(&st.identity.secret_bytes());
        let cert = st.cert(self.inner.platform).expect("cert");
        (kp, cert)
    }

    /// Test harness (M4.2): (our inbox keys, the peer's inbox keys) on the
    /// v2 pairing with `peer`.
    #[cfg(feature = "test-util")]
    pub fn pairing_inbox_keys_for_tests(
        &self,
        peer: &DeviceId,
    ) -> Option<(
        crate::mailbox::DeviceInboxKeys,
        crate::mailbox::DeviceInboxKeys,
    )> {
        let st = self.inner.lock();
        let me = st.identity.device_id();
        Some(st.pc(peer)?.replica.link().inbox_keys_for_tests(&me))
    }

    /// Test harness (M4.3): the inbox derivation inputs of the v2 pairing
    /// with `peer`.
    #[cfg(feature = "test-util")]
    pub fn pairing_inbox_inputs_for_tests(
        &self,
        peer: &DeviceId,
    ) -> Option<super::PairingInboxInputs> {
        let st = self.inner.lock();
        Some(st.pc(peer)?.replica.link().inbox_inputs_for_tests())
    }

    /// Test harness (M4.2): take a v2 pairing made outside the pairing
    /// flows (those arrive in M4.3). `addrs`: the peer's direct addresses.
    #[cfg(feature = "test-util")]
    pub fn adopt_v2_pairing_for_tests(
        &self,
        p: crate::pairwise::Pairing,
        addrs: Vec<SocketAddr>,
    ) -> Result<(), NetError> {
        let mut st = self.inner.lock();
        let me = st.identity.device_id();
        let peer = p.log.peer_of(&me).ok_or(NetError::UnknownDevice)?;
        st.pairings
            .add(p)
            .map_err(|_| NetError::Rejected(RejectReason::BadLogOp))?;
        st.rebuild_links();
        if let Some(e) = st.pc_mut(&peer) {
            e.addrs = addrs;
        }
        self.inner.save(&st)?;
        drop(st);
        self.inner
            .inboxes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&peer);
        Ok(())
    }

    /// Test harness: overwrite the cached addresses of `pc` (stale or
    /// poisoned-address tests).
    #[cfg(feature = "test-util")]
    pub fn set_pc_addrs_for_tests(&self, pc: &DeviceId, addrs: Vec<SocketAddr>) {
        if let Some(e) = self.inner.lock().pc_mut(pc) {
            e.addrs = addrs;
        }
        if let Some(c) = self.conns().remove(pc) {
            c.close(0u32.into(), b"");
        }
    }

    /// Test harness: the L3 bounded mDNS wait, on this phone's endpoint.
    #[cfg(feature = "test-util")]
    pub fn discover_for_tests(&self, pc: &DeviceId, wait: Duration) -> Vec<SocketAddr> {
        let ep = self
            .inner
            .endpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let pc = *pc;
        let mdns = self.inner.mdns;
        self.inner
            .rt
            .block_on(async move { discover_addrs(&ep, &pc, wait, mdns).await })
    }

    /// Test harness: standing address lookups on this phone's endpoint
    /// (none: mDNS is asked per dial, so an idle phone sends nothing).
    #[cfg(feature = "test-util")]
    pub fn standing_lookups_for_tests(&self) -> usize {
        let ep = self
            .inner
            .endpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        ep.address_lookup().map(|s| s.len()).unwrap_or(0)
    }

    /// Test harness: the UDP sockets this phone's endpoint is bound to.
    #[cfg(feature = "test-util")]
    pub fn bound_sockets_for_tests(&self) -> Vec<SocketAddr> {
        self.inner
            .endpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .bound_sockets()
    }

    fn conn_path_kind(
        inner: &Inner,
        pc: &DeviceId,
        conn: &Connection,
    ) -> crate::file_transfer::TransportPathKind {
        let has_known_direct_addrs = inner
            .lock()
            .pc(pc)
            .map(|e| !e.addrs.is_empty())
            .unwrap_or(false);
        if !has_known_direct_addrs && !inner.mdns {
            return crate::file_transfer::TransportPathKind::Relayed;
        }
        let has_ip = conn
            .paths()
            .iter()
            .any(|p| p.is_selected() && matches!(p.remote_addr(), iroh::TransportAddr::Ip(_)));
        if has_ip {
            crate::file_transfer::TransportPathKind::Direct
        } else {
            crate::file_transfer::TransportPathKind::Relayed
        }
    }

    pub(crate) fn decode_file_ack(
        b: &[u8],
    ) -> Result<(u8, crate::file_transfer::TransferId, u64, String), NetError> {
        if b.len() < 1 + 16 + 8 + 2 {
            return Err(NetError::Protocol("short file ack".into()));
        }
        let status = b[0];
        let mut tid_b = [0u8; 16];
        tid_b.copy_from_slice(&b[1..17]);
        let tid = crate::file_transfer::TransferId::from_bytes(tid_b);
        let val = u64::from_be_bytes(b[17..25].try_into().expect("8"));
        let msg_len = u16::from_be_bytes([b[25], b[26]]) as usize;
        if b.len() < 27 + msg_len {
            return Err(NetError::Protocol("truncated file ack msg".into()));
        }
        let msg = String::from_utf8_lossy(&b[27..27 + msg_len]).into_owned();
        Ok((status, tid, val, msg))
    }

    /// Current relay file-transfer policy (`M2.6` §6a.1 & §6b).
    pub fn relay_policy(&self) -> crate::file_transfer::RelayTransferPolicy {
        self.inner.lock().relay_policy
    }

    /// Server-advertised relay file size cap (`25 MiB` default, `0` = unlimited up to 2 GiB, `M2.9`).
    pub fn relay_server_cap_bytes(&self) -> u64 {
        self.inner.lock().relay_policy.server_cap_bytes()
    }

    /// Update the server-advertised relay file size cap (`M2.9`).
    pub fn set_relay_server_cap_bytes(&self, cap_bytes: u64) -> Result<(), NetError> {
        let mut st = self.inner.lock();
        st.relay_policy.set_server_cap_bytes(cap_bytes);
        self.inner.save(&st)
    }

    /// Whether "Never send files over relay" is enabled (`false` by default, `M2.8`).
    pub fn never_send_files_over_relay(&self) -> bool {
        self.inner.lock().relay_policy.never_send_files_over_relay()
    }

    /// Enable or disable "Never send files over relay" (`M2.8`, persisted in `phone-state.bin`).
    pub fn set_never_send_files_over_relay(&self, never: bool) -> Result<(), NetError> {
        let mut st = self.inner.lock();
        st.relay_policy.set_never_send_files_over_relay(never);
        self.inner.save(&st)
    }

    /// Set the user's local relay file size cap (`0..=500 MB`, persisted in `state.bin`).
    pub fn set_user_relay_cap_bytes(&self, cap: u64) -> Result<(), NetError> {
        let mut st = self.inner.lock();
        st.relay_policy
            .set_user_cap_bytes(cap)
            .map_err(|e| NetError::Protocol(e.to_string()))?;
        self.inner.save(&st)
    }

    /// Apply a verified `SignedConfig` from the mailbox/config server (`M2.6` §6b).
    pub fn apply_signed_config(
        &self,
        cfg: &crate::mailbox::SignedConfig,
        expected_pubkey: &[u8; 32],
    ) -> Result<u64, NetError> {
        let mut st = self.inner.lock();
        st.relay_policy
            .apply_signed_config(cfg, expected_pubkey)
            .map_err(|e| NetError::Protocol(e.to_string()))?;
        Ok(st.relay_policy.effective_cap_bytes())
    }

    /// Evaluate the relay data-minimization policy for `file_size` over `path_kind`.
    pub fn evaluate_file_relay_policy(
        &self,
        file_size: u64,
        path_kind: crate::file_transfer::TransportPathKind,
        prompt_decision: Option<crate::file_transfer::RelayPromptDecision>,
    ) -> crate::file_transfer::RelayPolicyOutcome {
        self.inner
            .lock()
            .relay_policy
            .evaluate(file_size, path_kind, prompt_decision)
    }

    /// Whether on-device connection stats are enabled (`false` by default, `M2.6` §6a.3).
    pub fn connection_stats_enabled(&self) -> bool {
        self.inner.lock().conn_stats.is_enabled()
    }

    /// Enable or disable on-device connection stats. Disabling immediately deletes
    /// all stored stats in memory and on disk (`M2.6` §6a.3).
    pub fn set_connection_stats_enabled(&self, enabled: bool) -> Result<(), NetError> {
        let mut st = self.inner.lock();
        st.conn_stats.set_enabled(enabled);
        self.inner.save(&st)
    }

    /// Snapshot of on-device day-granularity connection stats (`M2.6` §6a.3).
    pub fn connection_stats(&self) -> Vec<(DeviceId, crate::file_transfer::PeerDayStats)> {
        self.inner.lock().conn_stats.entries()
    }

    /// Cancel an in-progress or pending file transfer on `pc`, recording local
    /// cancellation (`M28-L2`) so any active `send_file` loop aborts immediately with
    /// [`NetError::Cancelled`] and deleting `<id>.part` / `<id>.part.meta` on the
    /// receiver (`M2.6` / `M28-N1` fresh-connection fallback).
    pub fn cancel_file_transfer(
        &self,
        pc: &DeviceId,
        transfer_id: &crate::file_transfer::TransferId,
    ) -> Result<(), NetError> {
        self.inner.mark_transfer_cancelled(*transfer_id);
        let inner = self.inner.clone();
        let pc = *pc;
        let payload = transfer_id.as_bytes().to_vec();
        self.inner.rt.block_on(async move {
            let first = async {
                let conn = Self::get_conn(&inner, &pc, false).await?;
                request(&conn, frame::FILE_CANCEL, &payload, frame::FILE_CANCEL).await
            }
            .await;
            match first {
                Ok(_) => Ok(()),
                Err(_) => {
                    let conn = Self::get_conn(&inner, &pc, true).await?;
                    let _ =
                        request(&conn, frame::FILE_CANCEL, &payload, frame::FILE_CANCEL).await?;
                    Ok(())
                }
            }
        })
    }

    /// Test hook: close the cached connection for `pc` without removing it from `conns`
    /// so the next cached operation fails and exercises the fresh-connection fallback (`M28-N1`).
    pub fn poison_cached_conn_for_test(&self, pc: &DeviceId) {
        if let Some(c) = self
            .inner
            .conns
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(pc)
            .cloned()
        {
            c.close(0u32.into(), b"poisoned_for_test");
        }
    }

    /// Test hook: simulate a one-time transient connection drop right before `chunk_idx`
    /// and optionally fail the first `fail_reconnects` fresh `get_conn(..., true)` calls (`M28-L1`).
    pub fn set_transient_drop_for_test(&self, chunk_idx: Option<u64>, fail_reconnects: u32) {
        *self
            .inner
            .drop_conn_once_at_chunk_for_test
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = chunk_idx;
        *self
            .inner
            .fail_reconnects_for_test
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = fail_reconnects;
    }

    /// Configure a test hook that forces `conn_path_kind` to report `Relayed` starting at
    /// `chunk_idx` during `send_file` (`M26-M4` §6a.1 rule 4 mid-stream relay fallback test).
    pub fn set_force_relay_at_chunk_for_test(&self, chunk_idx: Option<u64>) {
        *self
            .inner
            .force_relay_at_chunk_for_test
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = chunk_idx;
    }

    /// Override the 5-second direct-first polling window before prompting on large relay transfers.
    pub fn set_direct_first_wait_ms(&self, ms: Option<u64>) {
        *self
            .inner
            .direct_first_wait_ms
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = ms;
    }

    /// Send a file from disk (`path`) to `pc` (`M2.6` / `M26-H2`), streaming hashes and
    /// 256 KiB chunks directly from `std::fs::File` without reading the entire file into RAM.
    pub fn send_file(
        &self,
        pc: &DeviceId,
        path: &std::path::Path,
        mime: &str,
        prompt_decision: Option<crate::file_transfer::RelayPromptDecision>,
    ) -> Result<FileSendReport, NetError> {
        let tid = crate::file_transfer::TransferId::random();
        self.send_file_with_transfer_id(pc, tid, path, mime, prompt_decision)
    }

    /// Send or resume a file from disk (`path`) with an explicit `TransferId` (`M26-H2`).
    pub fn send_file_with_transfer_id(
        &self,
        pc: &DeviceId,
        transfer_id: crate::file_transfer::TransferId,
        path: &std::path::Path,
        mime: &str,
        prompt_decision: Option<crate::file_transfer::RelayPromptDecision>,
    ) -> Result<FileSendReport, NetError> {
        let raw_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file.bin");
        self.send_file_source_with_options(
            pc,
            transfer_id,
            raw_name,
            mime,
            FilePayloadSource::Path(path),
            prompt_decision,
            None,
            None,
            None,
        )
    }

    /// Send or resume a file from disk (`path`) while polling up to `max_accept_polls`
    /// times (sleeping `poll_interval` between polls) while the recipient has not yet
    /// clicked Accept (`M27-H1` & `M27-M1`). Hashes the file from disk once and runs
    /// mailbox pull + log sync once per session.
    #[allow(clippy::too_many_arguments)]
    pub fn send_file_awaiting_accept(
        &self,
        pc: &DeviceId,
        transfer_id: crate::file_transfer::TransferId,
        path: &std::path::Path,
        mime: &str,
        prompt_decision: Option<crate::file_transfer::RelayPromptDecision>,
        max_accept_polls: u32,
        poll_interval: Duration,
    ) -> Result<FileSendReport, NetError> {
        let raw_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file.bin");
        self.send_file_source_with_options(
            pc,
            transfer_id,
            raw_name,
            mime,
            FilePayloadSource::Path(path),
            prompt_decision,
            None,
            None,
            Some((max_accept_polls, poll_interval)),
        )
    }

    /// Send an in-memory file payload to `pc` with an explicit `TransferId` (allowing
    /// deterministic resume across reconnects, `M2.6`).
    pub fn send_file_bytes(
        &self,
        pc: &DeviceId,
        transfer_id: crate::file_transfer::TransferId,
        filename: &str,
        mime: &str,
        data: &[u8],
        prompt_decision: Option<crate::file_transfer::RelayPromptDecision>,
    ) -> Result<FileSendReport, NetError> {
        self.send_file_bytes_with_options(
            pc,
            transfer_id,
            filename,
            mime,
            data,
            prompt_decision,
            None,
            None,
        )
    }

    /// Send a file payload with optional test hooks (`stop_after_chunks` to simulate a
    /// mid-stream network drop after N chunks, or `tamper_chunk` to flip a byte in chunk M).
    #[allow(clippy::too_many_arguments)]
    pub fn send_file_bytes_with_options(
        &self,
        pc: &DeviceId,
        transfer_id: crate::file_transfer::TransferId,
        filename: &str,
        mime: &str,
        data: &[u8],
        prompt_decision: Option<crate::file_transfer::RelayPromptDecision>,
        stop_after_chunks: Option<u64>,
        tamper_chunk: Option<u64>,
    ) -> Result<FileSendReport, NetError> {
        self.send_file_source_with_options(
            pc,
            transfer_id,
            filename,
            mime,
            FilePayloadSource::Bytes(data),
            prompt_decision,
            stop_after_chunks,
            tamper_chunk,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn send_file_source_with_options(
        &self,
        pc: &DeviceId,
        transfer_id: crate::file_transfer::TransferId,
        filename: &str,
        mime: &str,
        source: FilePayloadSource<'_>,
        prompt_decision: Option<crate::file_transfer::RelayPromptDecision>,
        stop_after_chunks: Option<u64>,
        tamper_chunk: Option<u64>,
        wait_for_accept: Option<(u32, Duration)>,
    ) -> Result<FileSendReport, NetError> {
        // M27-M1 & M28-L2: Short-circuit Cancel (or prior cancel_file_transfer) before hashing or dialing QUIC.
        if matches!(
            prompt_decision,
            Some(crate::file_transfer::RelayPromptDecision::Cancel)
        ) || self.inner.is_transfer_cancelled(&transfer_id)
        {
            self.inner.mark_transfer_cancelled(transfer_id);
            return Err(NetError::Cancelled);
        }

        let (size, root, chunk_hashes, mut disk_file) = match source {
            FilePayloadSource::Bytes(data) => {
                let sz = data.len() as u64;
                if sz > crate::file_transfer::MAX_FILE_SIZE {
                    return Err(NetError::Protocol(format!(
                        "file exceeds 2 GiB cap ({sz} B)"
                    )));
                }
                let (r, ch) = crate::file_transfer::compute_file_hashes(data);
                (sz, r, ch, None)
            }
            FilePayloadSource::Path(path) => {
                let meta_len = std::fs::metadata(path)
                    .map_err(|e| NetError::Storage(e.to_string()))?
                    .len();
                let cached = self
                    .inner
                    .cached_file_hashes
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(&transfer_id)
                    .and_then(|(sz, r, ch)| {
                        if *sz == meta_len {
                            Some((*sz, *r, ch.clone()))
                        } else {
                            None
                        }
                    });
                let (sz, r, ch) = match cached {
                    Some(hit) => hit,
                    None => {
                        let computed = crate::file_transfer::compute_file_hashes_streaming(path)
                            .map_err(|e| NetError::Storage(e.to_string()))?;
                        let mut cache = self
                            .inner
                            .cached_file_hashes
                            .lock()
                            .unwrap_or_else(|p| p.into_inner());
                        if cache.len() >= 16 {
                            cache.clear();
                        }
                        cache.insert(transfer_id, (computed.0, computed.1, computed.2.clone()));
                        computed
                    }
                };
                let f = std::fs::File::open(path).map_err(|e| NetError::Storage(e.to_string()))?;
                (sz, r, ch, Some(f))
            }
        };
        let bytes_slice = match source {
            FilePayloadSource::Bytes(d) => Some(d),
            FilePayloadSource::Path(_) => None,
        };

        let started = crate::time::Stopwatch::start();
        Self::require_pair(&self.inner, pc)?;
        let inner = self.inner.clone();
        let pc_id = *pc;
        let filename_str = filename.to_owned();
        let mime_str = mime.to_owned();
        self.inner.rt.block_on(async move {
            let mut conn = Self::get_conn(&inner, &pc_id, false).await?;
            let mut path_kind = Self::conn_path_kind(&inner, &pc_id, &conn);
            // M26-M4 (§6a.1 Rule 1): 5s direct-first window before prompting on large relay transfers.
            if path_kind == crate::file_transfer::TransportPathKind::Relayed
                && size > crate::file_transfer::DEFAULT_SMALL_ITEM_CAP_BYTES
                && prompt_decision.is_none()
            {
                let has_direct_candidate = inner
                    .lock()
                    .pc(&pc_id)
                    .map(|e| !e.addrs.is_empty())
                    .unwrap_or(false)
                    || inner.mdns;
                let wait_ms = inner
                    .direct_first_wait_ms
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .unwrap_or(if has_direct_candidate { 5_000 } else { 0 });
                let steps = wait_ms / 100;
                for _ in 0..steps {
                    if inner.is_transfer_cancelled(&transfer_id) {
                        return Err(NetError::Cancelled);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    if inner.is_transfer_cancelled(&transfer_id) {
                        return Err(NetError::Cancelled);
                    }
                    path_kind = Self::conn_path_kind(&inner, &pc_id, &conn);
                    if path_kind == crate::file_transfer::TransportPathKind::Direct {
                        break;
                    }
                }
            }
            let outcome = {
                let mut st = inner.lock();
                let out = st.relay_policy.evaluate(size, path_kind, prompt_decision);
                match out {
                    crate::file_transfer::RelayPolicyOutcome::PromptSender { .. } => {
                        st.conn_stats
                            .record_prompt_shown(&pc_id, SystemClock.now().wall);
                        let _ = inner.save(&st);
                    }
                    crate::file_transfer::RelayPolicyOutcome::ProceedViaRelay
                        if matches!(
                            prompt_decision,
                            Some(crate::file_transfer::RelayPromptDecision::SendViaRelay)
                        ) =>
                    {
                        let first_record = {
                            let mut set = inner
                                .prompt_accepted_transfers
                                .lock()
                                .unwrap_or_else(|p| p.into_inner());
                            if set.len() >= 64 {
                                set.clear();
                            }
                            set.insert(transfer_id)
                        };
                        if first_record {
                            st.conn_stats
                                .record_prompt_accepted(&pc_id, SystemClock.now().wall);
                            let _ = inner.save(&st);
                        }
                    }
                    _ => {}
                }
                out
            };
            match outcome {
                crate::file_transfer::RelayPolicyOutcome::ProceedDirect
                | crate::file_transfer::RelayPolicyOutcome::ProceedViaRelay => {}
                crate::file_transfer::RelayPolicyOutcome::PromptSender {
                    size: file_size,
                    effective_cap,
                } => {
                    return Err(NetError::Protocol(format!(
                        "relay_prompt_required: size={file_size} cap={effective_cap}"
                    )));
                }
                crate::file_transfer::RelayPolicyOutcome::WaitForDirect => {
                    return Err(NetError::Protocol("waiting_for_direct_path".into()));
                }
                crate::file_transfer::RelayPolicyOutcome::Cancelled => {
                    return Err(NetError::Cancelled);
                }
                crate::file_transfer::RelayPolicyOutcome::NeverSendOverRelay => {
                    return Err(NetError::Protocol(format!(
                        "exceeds_relay_cap: never_send_files_over_relay: size={size} cap=0"
                    )));
                }
                crate::file_transfer::RelayPolicyOutcome::ExceedsRelayCap {
                    size: file_size,
                    effective_cap,
                } => {
                    return Err(NetError::Protocol(format!(
                        "exceeds_relay_cap: size={file_size} cap={effective_cap}"
                    )));
                }
            }

            let (offer, envelope, k_file) = {
                let st = inner.lock();
                let entry = st.pc(&pc_id).ok_or(NetError::UnknownDevice)?;
                let rk = entry
                    .replica
            .seal_key();
                let grp = entry.replica.group();
                let ts = SystemClock.now().wall;
                let expires = crate::time::UnixMillis(ts.0 + 3_600_000);
                let offer = crate::file_transfer::FileOffer::new(
                    grp,
                    st.identity.device_id(),
                    pc_id,
                    transfer_id,
                    &filename_str,
                    &mime_str,
                    size,
                    root,
                    chunk_hashes,
                    ts,
                    expires,
                )
                .map_err(NetError::Rejected)?;
                let (env, k_file) =
                    crate::file_transfer::seal_file_offer(&offer, &st.identity, &rk)
                        .map_err(NetError::Rejected)?;
                (offer, env, k_file)
            };

            let mut poll_attempts = 0u32;
            let mut initial_resumed_from_chunk: Option<u64> = None;
            let mut chunks_sent = 0u64;
            let retry_backoffs_ms: [u64; 3] = [500, 1500, 3000];
            let mut retry_count = 0usize;

            loop {
                let attempt_res: Result<(), NetError> = async {
                    let next_chunk = loop {
                        if inner.is_transfer_cancelled(&transfer_id) {
                            return Err(NetError::Cancelled);
                        }
                        let ack_bytes =
                            request(&conn, frame::FILE_OFFER, &envelope, frame::FILE_OFFER_ACK)
                                .await?;
                        let (status, _tid, nc, msg) = Self::decode_file_ack(&ack_bytes)?;
                        match status {
                            0 | 2 => break nc,
                            1 => {
                                if let Some((max_polls, interval)) = wait_for_accept {
                                    if poll_attempts < max_polls {
                                        poll_attempts += 1;
                                        let total_ms = interval.as_millis() as u64;
                                        let mut slept_ms = 0u64;
                                        while slept_ms < total_ms {
                                            if inner.is_transfer_cancelled(&transfer_id) {
                                                return Err(NetError::Cancelled);
                                            }
                                            let step = (total_ms - slept_ms).min(50);
                                            tokio::time::sleep(Duration::from_millis(step)).await;
                                            slept_ms += step;
                                        }
                                        if inner.is_transfer_cancelled(&transfer_id) {
                                            return Err(NetError::Cancelled);
                                        }
                                        continue;
                                    }
                                }
                                return Err(NetError::Protocol(format!(
                                    "file_offer_pending_accept: next_chunk={nc}"
                                )));
                            }
                            _ => {
                                inner
                                    .cached_file_hashes
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .remove(&transfer_id);
                                inner
                                    .prompt_accepted_transfers
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .remove(&transfer_id);
                                let detail =
                                    if msg.contains("exceeds_relay_cap") && !msg.contains("cap=") {
                                        format!("{msg}: cap={nc}")
                                    } else {
                                        msg
                                    };
                                return Err(NetError::Protocol(format!(
                                    "file_offer_rejected: {detail}"
                                )));
                            }
                        }
                    };

                    if initial_resumed_from_chunk.is_none() {
                        initial_resumed_from_chunk = Some(next_chunk);
                    }
                    let mut relay_policy_checked =
                        path_kind == crate::file_transfer::TransportPathKind::Relayed;
                    for idx in next_chunk..offer.chunk_count {
                        if inner.is_transfer_cancelled(&transfer_id) {
                            return Err(NetError::Cancelled);
                        }
                        if let Some(limit) = stop_after_chunks {
                            if chunks_sent >= limit {
                                conn.close(0u32.into(), b"simulated_drop");
                                return Err(NetError::Unreachable(
                                    "simulated_mid_stream_drop".into(),
                                ));
                            }
                        }
                        let drop_once = {
                            let mut d = inner
                                .drop_conn_once_at_chunk_for_test
                                .lock()
                                .unwrap_or_else(|p| p.into_inner());
                            if *d == Some(idx) {
                                *d = None;
                                true
                            } else {
                                false
                            }
                        };
                        if drop_once {
                            conn.close(0u32.into(), b"transient_drop");
                            return Err(NetError::Unreachable(
                                "transient_mid_stream_drop".into(),
                            ));
                        }
                        // M26-M4 (§6a.1 Rule 4): re-check transport path at chunk boundaries.
                        let forced_relay = inner
                            .force_relay_at_chunk_for_test
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .is_some_and(|fc| idx >= fc);
                        let cur_path = if forced_relay {
                            crate::file_transfer::TransportPathKind::Relayed
                        } else {
                            Self::conn_path_kind(&inner, &pc_id, &conn)
                        };
                        if cur_path == crate::file_transfer::TransportPathKind::Relayed {
                            path_kind = crate::file_transfer::TransportPathKind::Relayed;
                        }
                        let remaining_bytes = offer
                            .size
                            .saturating_sub(idx * (crate::file_transfer::FILE_CHUNK_SIZE as u64));
                        if !relay_policy_checked
                            && cur_path == crate::file_transfer::TransportPathKind::Relayed
                            && remaining_bytes
                                > crate::file_transfer::DEFAULT_SMALL_ITEM_CAP_BYTES
                        {
                            let mid_outcome = {
                                let mut st = inner.lock();
                                let out = st.relay_policy.evaluate(
                                    offer.size,
                                    cur_path,
                                    prompt_decision,
                                );
                                match out {
                                    crate::file_transfer::RelayPolicyOutcome::ProceedViaRelay
                                        if matches!(
                                            prompt_decision,
                                            Some(
                                                crate::file_transfer::RelayPromptDecision::SendViaRelay
                                            )
                                        ) =>
                                    {
                                        st.conn_stats.record_prompt_accepted(
                                            &pc_id,
                                            SystemClock.now().wall,
                                        );
                                        let _ = inner.save(&st);
                                    }
                                    crate::file_transfer::RelayPolicyOutcome::PromptSender {
                                        ..
                                    } => {
                                        st.conn_stats.record_prompt_shown(
                                            &pc_id,
                                            SystemClock.now().wall,
                                        );
                                        let _ = inner.save(&st);
                                    }
                                    _ => {}
                                }
                                out
                            };
                            match mid_outcome {
                                crate::file_transfer::RelayPolicyOutcome::ProceedDirect
                                | crate::file_transfer::RelayPolicyOutcome::ProceedViaRelay => {
                                    relay_policy_checked = true;
                                }
                                crate::file_transfer::RelayPolicyOutcome::PromptSender { .. }
                                | crate::file_transfer::RelayPolicyOutcome::WaitForDirect => {
                                    return Err(NetError::Protocol(format!(
                                        "relay_prompt_required: mid_stream_chunk={idx} outcome={mid_outcome:?}"
                                    )));
                                }
                                crate::file_transfer::RelayPolicyOutcome::Cancelled => {
                                    return Err(NetError::Cancelled);
                                }
                                crate::file_transfer::RelayPolicyOutcome::NeverSendOverRelay => {
                                    return Err(NetError::Protocol(format!(
                                        "exceeds_relay_cap: never_send_files_over_relay: size={} cap=0",
                                        offer.size
                                    )));
                                }
                                crate::file_transfer::RelayPolicyOutcome::ExceedsRelayCap {
                                    size: file_size,
                                    effective_cap,
                                } => {
                                    return Err(NetError::Protocol(format!(
                                        "exceeds_relay_cap: size={file_size} cap={effective_cap}"
                                    )));
                                }
                            }
                        }

                        let is_final = idx + 1 == offer.chunk_count;
                        let mut ct = if let Some(ref mut f) = disk_file {
                            crate::file_transfer::read_and_encrypt_file_chunk(
                                f,
                                offer.size,
                                offer.chunk_count,
                                &k_file,
                                &transfer_id,
                                idx,
                            )
                            .map_err(|e| NetError::Protocol(e.to_string()))?
                        } else {
                            let data = bytes_slice.expect("Bytes source");
                            let start_off =
                                (idx as usize) * crate::file_transfer::FILE_CHUNK_SIZE;
                            let end_off =
                                ((idx as usize + 1) * crate::file_transfer::FILE_CHUNK_SIZE)
                                    .min(data.len());
                            let slice = if start_off < data.len() {
                                &data[start_off..end_off]
                            } else {
                                &[][..]
                            };
                            crate::file_transfer::encrypt_chunk(
                                &k_file,
                                &transfer_id,
                                idx,
                                is_final,
                                slice,
                            )
                            .map_err(|e| NetError::Protocol(e.to_string()))?
                        };
                        if tamper_chunk == Some(idx) && !ct.is_empty() {
                            ct[0] ^= 0xff;
                        }
                        let mut frame_payload = Vec::with_capacity(16 + 8 + 1 + ct.len());
                        frame_payload.extend_from_slice(transfer_id.as_bytes());
                        frame_payload.extend_from_slice(&idx.to_be_bytes());
                        frame_payload.push(u8::from(is_final));
                        frame_payload.extend_from_slice(&ct);

                        let c_ack = request(
                            &conn,
                            frame::FILE_CHUNK,
                            &frame_payload,
                            frame::FILE_CHUNK_ACK,
                        )
                        .await?;
                        let (c_status, _, c_next, c_msg) = Self::decode_file_ack(&c_ack)?;
                        match c_status {
                            0 | 2 => {
                                chunks_sent += 1;
                            }
                            _ => {
                                if c_msg.contains("canceled_by_recipient")
                                    || c_msg.contains("declined")
                                {
                                    inner
                                        .cached_file_hashes
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner())
                                        .remove(&transfer_id);
                                    inner
                                        .prompt_accepted_transfers
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner())
                                        .remove(&transfer_id);
                                    return Err(NetError::Protocol(format!(
                                        "file_chunk_failed: canceled_by_recipient ({c_msg})"
                                    )));
                                }
                                let c_detail = if c_msg.contains("exceeds_relay_cap")
                                    && !c_msg.contains("cap=")
                                {
                                    format!("{c_msg}: cap={c_next}")
                                } else {
                                    c_msg
                                };
                                return Err(NetError::Protocol(format!(
                                    "file_chunk_rejected({idx}): {c_detail}"
                                )));
                            }
                        }
                    }
                    Ok(())
                }
                .await;

                match attempt_res {
                    Ok(()) => break,
                    Err(mut err) => {
                        if inner.is_transfer_cancelled(&transfer_id) {
                            err = NetError::Cancelled;
                        }
                        let is_transient = match &err {
                            NetError::Timeout => true,
                            NetError::Unreachable(msg) => msg != "simulated_mid_stream_drop",
                            NetError::Protocol(msg) => {
                                !msg.starts_with("file_offer_rejected:")
                                    && !msg.starts_with("file_offer_pending_accept:")
                                    && !msg.starts_with("relay_prompt_required:")
                                    && !msg.starts_with("waiting_for_direct_path")
                                    && !msg.starts_with("exceeds_relay_cap:")
                                    && !msg.starts_with("file_chunk_rejected(")
                                    && !msg.starts_with("file_chunk_failed:")
                            }
                            _ => false,
                        };
                        if is_transient && retry_count < retry_backoffs_ms.len() {
                            let mut reconnected = None;
                            while retry_count < retry_backoffs_ms.len() {
                                if inner.is_transfer_cancelled(&transfer_id) {
                                    err = NetError::Cancelled;
                                    break;
                                }
                                let backoff_ms = retry_backoffs_ms[retry_count];
                                retry_count += 1;
                                let mut slept_ms = 0u64;
                                while slept_ms < backoff_ms {
                                    if inner.is_transfer_cancelled(&transfer_id) {
                                        break;
                                    }
                                    let step = (backoff_ms - slept_ms).min(50);
                                    tokio::time::sleep(Duration::from_millis(step)).await;
                                    slept_ms += step;
                                }
                                if inner.is_transfer_cancelled(&transfer_id) {
                                    err = NetError::Cancelled;
                                    break;
                                }
                                if let Ok(reconn) = Self::get_conn(&inner, &pc_id, true).await {
                                    reconnected = Some(reconn);
                                    break;
                                }
                            }
                            if let Some(reconn) = reconnected {
                                conn = reconn;
                                path_kind = Self::conn_path_kind(&inner, &pc_id, &conn);
                                continue;
                            }
                        }
                        if matches!(err, NetError::Cancelled)
                            || (is_transient && retry_count >= retry_backoffs_ms.len())
                        {
                            let cancel_payload = transfer_id.as_bytes().to_vec();
                            let _ = tokio::time::timeout(
                                Duration::from_millis(500),
                                request(
                                    &conn,
                                    frame::FILE_CANCEL,
                                    &cancel_payload,
                                    frame::FILE_CANCEL,
                                ),
                            )
                            .await;
                        }
                        return Err(err);
                    }
                }
            }
            let resumed_from_chunk = initial_resumed_from_chunk.unwrap_or(0);

            {
                let mut st = inner.lock();
                if st.conn_stats.is_enabled() {
                    st.conn_stats.record_transfer(
                        &pc_id,
                        path_kind,
                        offer.size,
                        SystemClock.now().wall,
                    );
                    let _ = inner.save(&st);
                }
            }

            inner
                .cached_file_hashes
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&transfer_id);
            inner
                .prompt_accepted_transfers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&transfer_id);

            Ok(FileSendReport {
                transfer_id,
                filename: offer.filename,
                size: offer.size,
                blake3_root: offer.blake3_root,
                chunks_sent,
                resumed_from_chunk,
                path_kind,
                latency_us: started.elapsed_us(),
            })
        })
    }

    /// Send UTF-8 clipboard text to `pc` (`M3.1`).
    /// Inline text (`<= 7,680 B`) is sealed in a `512 B` / `8,448 B` HPKE envelope;
    /// larger text (`<= 10 MiB`) streams via `send_file_bytes` with `CLIPBOARD_STREAM_MIME`.
    pub fn send_clipboard_text(&self, pc: &DeviceId, text: &str) -> Result<SendReport, NetError> {
        if text.is_empty() || text.len() > crate::limits::MAX_STREAMED_CLIPBOARD_BYTES {
            return Err(NetError::Rejected(RejectReason::UrlTooLong));
        }
        let started = crate::time::Stopwatch::start();
        if text.len() > crate::limits::MAX_INLINE_CLIPBOARD_BYTES {
            let tid = crate::file_transfer::TransferId::random();
            let _rep = self.send_file_bytes(
                pc,
                tid,
                "clipboard.txt",
                crate::clipboard::CLIPBOARD_STREAM_MIME,
                text.as_bytes(),
                None,
            )?;
            return Ok(SendReport {
                outcome: SendOutcome::Prompted,
                latency_us: started.elapsed_us(),
            });
        }
        Self::require_pair(&self.inner, pc)?;
        let inner = self.inner.clone();
        let pc = *pc;
        let text_owned = text.to_owned();
        let text_q = text_owned.clone();
        let sensitive = crate::clipboard::looks_sensitive_clipboard(&text_owned);
        let res = self.inner.rt.block_on(async move {
            let mut fresh = false;
            loop {
                let conn = Self::get_conn(&inner, &pc, fresh).await?;
                let r = async {
                    let env = Self::seal_clipboard_for(&inner, &pc, &text_owned, sensitive)?;
                    let out = Self::send_on(&conn, &env).await?;
                    let path_kind = Self::conn_path_kind(&inner, &pc, &conn);
                    {
                        let mut st = inner.lock();
                        if st.conn_stats.is_enabled() {
                            st.conn_stats.record_transfer(
                                &pc,
                                path_kind,
                                env.len() as u64,
                                SystemClock.now().wall,
                            );
                            let _ = inner.save(&st);
                        }
                    }
                    Ok(out)
                }
                .await;
                match r {
                    Err(NetError::Protocol(_) | NetError::Timeout | NetError::Unreachable(_))
                        if !fresh =>
                    {
                        fresh = true;
                    }
                    other => return other,
                }
            }
        });
        let outcome = match res {
            Err(e) if is_offline(&e) && self.is_link_peer(&pc) => {
                let env = Self::seal_clipboard_for(&self.inner, &pc, &text_q, sensitive)?;
                self.queue_in_pair_inbox(&pc, env)?;
                SendOutcome::Prompted
            }
            r => r?,
        };
        Ok(SendReport {
            outcome,
            latency_us: started.elapsed_us(),
        })
    }

    /// Auto-detect whether `raw_text` is a single `http`/`https` URL or clipboard
    /// text and send it to `pc` (`M3.1`).
    pub fn send_text_or_url(&self, pc: &DeviceId, raw_text: &str) -> Result<SendReport, NetError> {
        match crate::clipboard::classify_shared_text(raw_text)? {
            crate::clipboard::SharedContentKind::Url { url } => self.send_url(pc, &url),
            crate::clipboard::SharedContentKind::InlineClipboard { text, .. }
            | crate::clipboard::SharedContentKind::StreamedClipboard { text, .. } => {
                self.send_clipboard_text(pc, &text)
            }
        }
    }

    fn seal_clipboard_for(
        inner: &Inner,
        pc: &DeviceId,
        text: &str,
        sensitive_hint: bool,
    ) -> Result<Vec<u8>, NetError> {
        let st = inner.lock();
        let entry = st.pc(pc).ok_or(NetError::UnknownDevice)?;
        let rk = entry.replica.seal_key();
        let body = crate::wire::encode_signed_clipboard(
            &st.identity,
            &crate::wire::OutgoingClipboard {
                group: entry.replica.group(),
                recipient: *pc,
                msg_id: MsgId::random(),
                timestamp: SystemClock.now().wall,
                text,
                sensitive: sensitive_hint,
            },
        )?;
        Ok(envelope::seal(pc, &rk, &body)?)
    }

    /// Configured download directory for incoming files on the phone (`M3.1`).
    pub fn download_dir(&self) -> std::path::PathBuf {
        self.inner
            .download_dir
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Set the download directory for incoming files on the phone (`M3.1`).
    pub fn set_download_dir(&self, dir: std::path::PathBuf) {
        *self
            .inner
            .download_dir
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = dir;
    }

    /// Configure the phone's private data directory (used for `FileSeenIdStore` replay
    /// persistence and default `incoming-staging` download staging on Android).
    pub fn set_data_dir(&self, dir: std::path::PathBuf) {
        let _ = std::fs::create_dir_all(&dir);
        let staging = dir.join("incoming-staging");
        let _ = std::fs::create_dir_all(&staging);
        *self
            .inner
            .data_dir
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(dir);
        *self
            .inner
            .download_dir
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = staging;
        self.inner
            .inboxes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    /// Whether incoming file offers from paired PCs are auto-accepted (`false` by default, `M3.1`).
    pub fn auto_accept_files(&self) -> bool {
        self.inner
            .auto_accept_files
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Enable or disable auto-accepting incoming file offers from paired PCs (`M3.1`).
    pub fn set_auto_accept_files(&self, enabled: bool) {
        self.inner
            .auto_accept_files
            .store(enabled, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether background listening mode is enabled (`false` by default, `M3.1`).
    pub fn background_listening(&self) -> bool {
        self.inner
            .background_listening
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Enable or disable background listening mode (`M3.1`).
    /// Never performs blocking network I/O on the caller's thread (`M3.1.1`).
    pub fn set_background_listening(&self, enabled: bool) -> Result<(), NetError> {
        self.inner
            .background_listening
            .store(enabled, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Simulate offline / background-closed state in tests (`M3.1`).
    /// When `offline == true`, closes active connections and refuses incoming `ALPN_APP`
    /// dials so the PC falls back to queueing in the RAM-only blind device inbox.
    pub fn set_offline_for_tests(&self, offline: bool) {
        self.inner
            .accept_incoming_enabled
            .store(!offline, std::sync::atomic::Ordering::SeqCst);
        if offline {
            for (_, c) in self.conns().drain() {
                c.close(0u32.into(), b"offline_for_test");
            }
            // Offline means unreachable on away relays too.
            if let Some(a) = self.away() {
                a.close_all();
            }
        } else {
            self.inner.lock().sync_away();
        }
    }

    /// Pull and acknowledge all pending envelopes from this phone's RAM-only blind
    /// device inboxes: the per-pairing inbox of each v2 peer (`M3.1`,
    /// M4.2). One throwaway
    /// session per relay. Call it on events (start, network change,
    /// foreground, a wake push); it never schedules itself.
    /// Returns the number of newly verified items/offers added to the phone's incoming queues.
    pub fn pull_device_inbox_now(&self) -> Result<usize, NetError> {
        self.pull_inbox_gated(None, SystemClock.now().mono)
    }

    /// Pull our inboxes. With `gate = Some(now)` (an event: unlock, network
    /// change) each relay is skipped if it was pulled less than
    /// [`EVENT_PULL_MIN_GAP_MS`] ago; `None` pulls all (app open, Retry).
    /// Throwaway sessions only: no away endpoint is involved.
    fn pull_inbox_gated(&self, gate: Option<MonoMillis>, t: MonoMillis) -> Result<usize, NetError> {
        let norm = |u: &str| u.trim().trim_end_matches('/').to_ascii_lowercase();
        let last_pull = self
            .inner
            .last_event_pull
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let allowed = |u: &str| match gate {
            None => true,
            Some(now) => last_pull
                .get(&norm(u))
                .is_none_or(|prev| now.saturating_sub(*prev) >= EVENT_PULL_MIN_GAP_MS),
        };
        let home_relay = self.inner.lock().relay_url.clone().unwrap_or_default();
        let home_allowed = allowed(&home_relay);
        let drains: Vec<super::relay_change::Drain> =
            super::relay_change::live_drains(&mut self.inner.lock().drains)
                .into_iter()
                .filter(|d| allowed(&d.relay_url))
                .collect();
        let any_allowed = home_allowed || !drains.is_empty() || {
            let st = self.inner.lock();
            st.pcs
                .iter()
                .map(|p| p.replica.link())
                .filter_map(|l| l.relay.as_ref())
                .any(|r| allowed(&r.url))
        };
        if !any_allowed {
            return Ok(0);
        }
        self.inner
            .inbox_pulls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let inner = self.inner.clone();
        self.inner
            .rt
            .block_on(async move { flush_outbox_phone(&inner, false).await });
        let peers: Vec<DeviceId> = self
            .inner
            .lock()
            .pcs
            .iter()
            .map(|p| p.replica.owner())
            .collect();
        let mut targets: Vec<super::links::InboxTarget> = Vec::new();
        for peer in peers {
            let home_mb = self.effective_mailbox_peer(&peer);
            let st = self.inner.lock();
            let my_id = st.identity.device_id();
            let Some(entry) = st.pc(&peer) else {
                continue;
            };
            let home_url = entry.relay_url.clone().or_else(|| st.relay_url.clone());
            {
                let link = entry.replica.link();
                if let Some(t) = link.my_inbox(&my_id, home_url.as_deref(), home_mb) {
                    if allowed(&t.relay_url) {
                        targets.push(t);
                    }
                }
            }
        }
        {
            let st = self.inner.lock();
            let me = st.identity.device_id();
            for d in drains {
                if let Some(l) = st.pc(&d.peer).map(|e| e.replica.link()) {
                    targets.push(l.my_inbox_at(&me, d.relay_url, d.mailbox));
                }
            }
        }
        {
            let mut last = self
                .inner
                .last_event_pull
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if home_allowed {
                last.insert(norm(&home_relay), t);
            }
            for tg in &targets {
                last.insert(norm(&tg.relay_url), t);
            }
        }
        if targets.is_empty() {
            return Ok(0);
        }
        let inbox_ttl_secs = self.inner.lock().relay_policy.inbox_ttl_secs();
        let mut total_delivered = 0usize;
        let inner = &self.inner;
        let out =
            self.inner
                .rt
                .block_on(super::links::pull_batched(targets, |peer, item, caps| {
                    let eff_ttl = caps.map(|c| c.inbox_ttl_secs).unwrap_or(inbox_ttl_secs);
                    let n = SystemClock.now();
                    let verified = with_phone_inbox(inner, peer, |inbox, _| {
                        inbox.receive_from_device_inbox(&item.envelope, u64::from(eff_ttl), n)
                    });
                    if let Some((Ok(msg), sender_name)) = verified {
                        if enqueue_verified_on_phone(
                            inner,
                            peer,
                            &sender_name,
                            msg,
                            super::DeliveryPath::QueuedInDeviceInbox,
                            n.wall,
                        ) {
                            total_delivered += 1;
                        }
                    }
                }));
        if let Some(eph) = out.last_session {
            *self
                .inner
                .last_throwaway_id
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(eph);
        }
        if let Some(caps) = out.caps {
            let mut st = self.inner.lock();
            st.relay_policy
                .set_server_cap_bytes(caps.max_relay_file_bytes);
            st.relay_policy
                .set_inbox_limits(caps.inbox_max_items, caps.inbox_ttl_secs);
        }
        if total_delivered == 0 {
            if let Some(e) = out.last_err {
                return Err(e);
            }
        }
        Ok(total_delivered)
    }

    /// Snapshot of pending incoming items (links and clipboard text) and file offers (`M3.1`).
    pub fn poll_incoming(&self) -> IncomingPhoneBatch {
        let now_wall = SystemClock.now().wall;
        let items = self
            .inner
            .incoming_items
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut files_guard = self
            .inner
            .incoming_files
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        files_guard.retain(|_, f| f.completed_path.is_some() || now_wall.0 < f.expires_at.0);
        let mut files: Vec<IncomingPhoneFileOffer> = files_guard
            .values()
            .map(|f| IncomingPhoneFileOffer {
                transfer_id: f.transfer_id,
                sender_id: f.sender_id,
                sender_name: f.sender_name.clone(),
                filename: f.filename.clone(),
                mime: f.mime.clone(),
                size: f.size,
                chunk_count: f.chunk_count,
                chunks_received: f.receiver.as_ref().map(|r| r.next_chunk()).unwrap_or(
                    if f.completed_path.is_some() {
                        f.chunk_count
                    } else {
                        0
                    },
                ),
                blake3_root: f.blake3_root,
                expires_at: f.expires_at,
                is_executable: f.is_executable,
                accepted: f.accepted,
                completed_path: f.completed_path.clone(),
                relayed: f.relayed,
                via_file_wake: f.via_file_wake,
            })
            .collect();
        files.sort_by_key(|f| *f.transfer_id.as_bytes());
        IncomingPhoneBatch { items, files }
    }

    /// Dismiss/acknowledge a received link or clipboard item from the phone's incoming list (`M3.1`).
    pub fn dismiss_incoming_item(&self, item_id: u64) -> bool {
        let mut items = self
            .inner
            .incoming_items
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let before = items.len();
        items.retain(|i| i.item_id != item_id);
        items.len() < before
    }

    /// Accept an incoming file offer (either received live or via a `FileWake` inbox pointer)
    /// and stream/finalize it into `dest_dir` (or [`PhoneClient::download_dir`] when `None`, `M3.1`).
    pub fn accept_incoming_file(
        &self,
        transfer_id: &crate::file_transfer::TransferId,
        dest_dir: Option<&std::path::Path>,
        prompt_decision: Option<crate::file_transfer::RelayPromptDecision>,
    ) -> Result<std::path::PathBuf, NetError> {
        if matches!(
            prompt_decision,
            Some(crate::file_transfer::RelayPromptDecision::Cancel)
        ) {
            let _ = self.cancel_incoming_file(transfer_id);
            return Err(NetError::Cancelled);
        }
        let target_dir = dest_dir
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| self.download_dir());
        std::fs::create_dir_all(&target_dir).map_err(|e| NetError::Storage(e.to_string()))?;
        crate::file_transfer::purge_expired_parts(&target_dir, SystemClock.now().wall);

        let (sender_id, file_size, already_completed) = {
            let mut files = self
                .inner
                .incoming_files
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let sess = files
                .get_mut(transfer_id)
                .ok_or_else(|| NetError::Protocol("unknown_or_expired_transfer".into()))?;
            if let Some(ref p) = sess.completed_path {
                return Ok(p.clone());
            }
            sess.accepted = true;
            sess.target_dir = Some(target_dir.clone());
            sess.last_activity = SystemClock.now().wall;
            if sess.receiver.is_none() {
                if let (Some(ref offer), Some(ref k_file)) = (&sess.offer, &sess.k_file) {
                    let rcv = crate::file_transfer::PartFileReceiver::open_or_resume(
                        offer.clone(),
                        k_file.clone(),
                        &target_dir,
                        SystemClock.now().wall,
                    )
                    .map_err(|e| NetError::Storage(e.to_string()))?;
                    sess.receiver = Some(rcv);
                }
            }
            (sess.sender_id, sess.size, sess.completed_path.clone())
        };
        if let Some(p) = already_completed {
            return Ok(p);
        }

        // v0.7.1: a phone sender pushes the file itself once it sees the
        // accept (its re-offer loop); it serves no FILE_PULL. Pulling from a
        // phone got "unknown frame" back, shown as a pairing-QR error.
        let sender_is_phone = self
            .inner
            .lock()
            .pc(&sender_id)
            .is_some_and(|e| e.replica.peer_is_mobile());
        if sender_is_phone {
            let res = self.wait_for_pushed_file(transfer_id);
            if let Err(ref e) = res {
                self.fail_incoming_file(transfer_id, e);
            }
            return res;
        }

        let inner = self.inner.clone();
        let tid = *transfer_id;
        let pull_res: Result<std::path::PathBuf, NetError> = self.inner.rt.block_on(async move {
            let conn = Self::get_conn(&inner, &sender_id, false).await?;
            let path_kind = Self::conn_path_kind(&inner, &sender_id, &conn);
            if path_kind == crate::file_transfer::TransportPathKind::Relayed {
                let outcome =
                    inner
                        .lock()
                        .relay_policy
                        .evaluate(file_size, path_kind, prompt_decision);
                match outcome {
                    crate::file_transfer::RelayPolicyOutcome::ProceedDirect
                    | crate::file_transfer::RelayPolicyOutcome::ProceedViaRelay => {}
                    crate::file_transfer::RelayPolicyOutcome::PromptSender {
                        size,
                        effective_cap,
                    } => {
                        return Err(NetError::Protocol(format!(
                            "relay_prompt_required: size={size} cap={effective_cap}"
                        )));
                    }
                    crate::file_transfer::RelayPolicyOutcome::WaitForDirect => {
                        return Err(NetError::Protocol("waiting_for_direct_path".into()));
                    }
                    crate::file_transfer::RelayPolicyOutcome::Cancelled => {
                        return Err(NetError::Cancelled);
                    }
                    crate::file_transfer::RelayPolicyOutcome::NeverSendOverRelay => {
                        return Err(NetError::Protocol(format!(
                            "exceeds_relay_cap: never_send_files_over_relay: size={file_size} cap=0"
                        )));
                    }
                    crate::file_transfer::RelayPolicyOutcome::ExceedsRelayCap {
                        size,
                        effective_cap,
                    } => {
                        return Err(NetError::Protocol(format!(
                            "exceeds_relay_cap: size={size} cap={effective_cap}"
                        )));
                    }
                }
            }

            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .map_err(|e| super::conn_error(&conn, e))?;
            write_frame(&mut send, frame::FILE_PULL, tid.as_bytes()).await?;
            let _ = send.finish();

            // Wait for FILE_OFFER_ACK on the FILE_PULL control stream while chunks arrive
            // on parallel bi-streams. As long as `last_activity` advances within IO_TIMEOUT,
            // keep waiting so multi-megabyte transfers never time out mid-stream (`M3.1.1`).
            let read_fut = async {
                let mut hdr = [0u8; 5];
                recv.read_exact(&mut hdr)
                    .await
                    .map_err(|e| super::conn_error(&conn, e))?;
                let t = hdr[0];
                let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
                if len > super::frame_cap(t) {
                    return Err(NetError::Rejected(RejectReason::MalformedFrame));
                }
                let mut payload = vec![0u8; len];
                recv.read_exact(&mut payload)
                    .await
                    .map_err(|e| super::conn_error(&conn, e))?;
                Ok((t, payload))
            };
            tokio::pin!(read_fut);
            let (rt, ack_bytes) = loop {
                tokio::select! {
                    res = &mut read_fut => break res?,
                    _ = tokio::time::sleep(Duration::from_secs(3)) => {
                        let idle_ms = {
                            let files = inner
                                .incoming_files
                                .lock()
                                .unwrap_or_else(|p| p.into_inner());
                            files
                                .get(&tid)
                                .map(|s| SystemClock.now().wall.0.saturating_sub(s.last_activity.0))
                                .unwrap_or(u64::MAX)
                        };
                        if idle_ms > IO_TIMEOUT.as_millis() as u64 {
                            return Err(NetError::Timeout);
                        }
                    }
                }
            };
            if rt == frame::ERROR {
                return Err(super::parse_error(&ack_bytes));
            }
            if rt != frame::FILE_OFFER_ACK {
                return Err(NetError::Protocol("unexpected file pull reply".into()));
            }
            let (status, _t, nc, msg) = Self::decode_file_ack(&ack_bytes)?;
            if status >= 3 {
                let detail = if msg.contains("exceeds_relay_cap") && !msg.contains("cap=") {
                    format!("{msg}: cap={nc}")
                } else {
                    msg
                };
                return Err(NetError::Protocol(format!("file_offer_rejected: {detail}")));
            }
            let completed = inner
                .incoming_files
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&tid)
                .and_then(|s| s.completed_path);
            completed.ok_or_else(|| {
                NetError::Protocol("file pull finished without completed path".into())
            })
        });
        if let Err(ref e) = pull_res {
            self.fail_incoming_file(transfer_id, e);
        }
        pull_res
    }

    /// An accepted transfer failed. A relay question for the user keeps it
    /// (they answer and accept again); anything else forgets it and deletes
    /// its `.part` and `.part.meta` (v0.7.1: they used to be left behind).
    fn fail_incoming_file(&self, transfer_id: &crate::file_transfer::TransferId, e: &NetError) {
        let keep = matches!(e, NetError::Protocol(m)
            if m.starts_with("relay_prompt_required") || m.starts_with("waiting_for_direct_path"));
        let mut files = self
            .inner
            .incoming_files
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if keep {
            if let Some(sess) = files.get_mut(transfer_id) {
                sess.accepted = false;
            }
            return;
        }
        if let Some(sess) = files.remove(transfer_id) {
            if let Some(rcv) = sess.receiver {
                rcv.cancel_and_delete();
            }
        }
    }

    /// Wait for a phone sender to push an accepted file: done when the last
    /// chunk lands, failed when the transfer goes away or no chunk has
    /// landed for `IO_TIMEOUT` (woken by each chunk, no polling).
    fn wait_for_pushed_file(
        &self,
        transfer_id: &crate::file_transfer::TransferId,
    ) -> Result<std::path::PathBuf, NetError> {
        let inner = self.inner.clone();
        let tid = *transfer_id;
        self.inner.rt.block_on(async move {
            loop {
                let progressed = inner.file_progress.notified();
                tokio::pin!(progressed);
                progressed.as_mut().enable();
                {
                    let mut files = inner
                        .incoming_files
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    match files.get(&tid) {
                        None => {
                            return Err(NetError::Protocol(
                                "the transfer stopped before the end".into(),
                            ))
                        }
                        Some(s) if s.completed_path.is_some() => {
                            let s = files.remove(&tid).expect("present");
                            return Ok(s.completed_path.expect("checked"));
                        }
                        Some(_) => {}
                    }
                }
                if tokio::time::timeout(IO_TIMEOUT, progressed).await.is_err() {
                    return Err(NetError::Timeout);
                }
            }
        })
    }

    /// Decline or cancel an incoming file offer on the phone, deleting any `.part` state
    /// and sending a best-effort `FILE_CANCEL` to the sender PC (`M3.1`).
    pub fn cancel_incoming_file(&self, transfer_id: &crate::file_transfer::TransferId) -> bool {
        let removed = {
            let mut files = self
                .inner
                .incoming_files
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let sess = files.remove(transfer_id);
            if let Some(ref s) = sess {
                let mut dec = self
                    .inner
                    .declined_incoming_files
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                if dec.len() >= 64 {
                    dec.pop_front();
                }
                dec.push_back((*transfer_id, s.sender_id));
            }
            sess
        };
        if let Some(sess) = removed {
            if let Some(rcv) = sess.receiver {
                rcv.cancel_and_delete();
            }
            self.inner.file_progress.notify_waiters();
            let inner = self.inner.clone();
            let sender_id = sess.sender_id;
            let payload = transfer_id.as_bytes().to_vec();
            self.inner.rt.block_on(async move {
                let first_ok = match Self::get_conn(&inner, &sender_id, false).await {
                    Ok(conn) => matches!(
                        tokio::time::timeout(
                            Duration::from_secs(3),
                            request(&conn, frame::FILE_CANCEL, &payload, frame::FILE_CANCEL),
                        )
                        .await,
                        Ok(Ok(_))
                    ),
                    Err(_) => false,
                };
                if !first_ok {
                    if let Ok(conn) = Self::get_conn(&inner, &sender_id, true).await {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(3),
                            request(&conn, frame::FILE_CANCEL, &payload, frame::FILE_CANCEL),
                        )
                        .await;
                    }
                }
            });
            true
        } else {
            false
        }
    }

    /// Alias for [`PhoneClient::cancel_incoming_file`] (`M3.1`).
    pub fn decline_incoming_file(&self, transfer_id: &crate::file_transfer::TransferId) -> bool {
        self.cancel_incoming_file(transfer_id)
    }
}

fn spawn_phone_accept_loop(
    rt: &tokio::runtime::Runtime,
    weak_inner: std::sync::Weak<Inner>,
    endpoint: Endpoint,
) -> tokio::task::JoinHandle<()> {
    rt.spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let Some(inner) = weak_inner.upgrade() else {
                break;
            };
            if !inner
                .accept_incoming_enabled
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                drop(incoming);
                continue;
            }
            let weak_conn = weak_inner.clone();
            tokio::spawn(async move {
                let Ok(mut accepting) = incoming.accept() else {
                    return;
                };
                let Ok(alpn) = accepting.alpn().await else {
                    return;
                };
                if alpn.as_slice() == ALPN_PAIR {
                    let Some(inner) = weak_conn.upgrade() else {
                        return;
                    };
                    if !super::pair2::Node2::host(&*inner).showing(SystemClock.now()) {
                        drop(accepting);
                        return;
                    }
                    let Ok(conn) = accepting.await else {
                        return;
                    };
                    let Ok(Ok((send, mut recv))) =
                        tokio::time::timeout(IO_TIMEOUT, conn.accept_bi()).await
                    else {
                        return;
                    };
                    match read_frame(&mut recv, IO_TIMEOUT).await {
                        Ok((super::frame::HELLO, p)) => match super::pair2::is_v2_hello(&p) {
                            Some(sid) => super::pair2::serve(&*inner, conn, send, recv, sid).await,
                            None => {
                                let mut send = send;
                                super::pair2::send_err(&mut send, RejectReason::UnsupportedVersion)
                                    .await
                            }
                        },
                        _ => conn.close(close_code(RejectReason::MalformedFrame), b""),
                    }
                    return;
                }
                if alpn.as_slice() != ALPN_APP {
                    return;
                }
                let Ok(conn) = accepting.await else {
                    return;
                };
                serve_app_conn(weak_conn, conn).await;
            });
        }
    })
}

/// An authenticated ALPN_APP connection from a peer (main or away
/// endpoint): membership check, then its streams.
async fn serve_app_conn(weak_conn: std::sync::Weak<Inner>, conn: Connection) {
    let Some(inner) = weak_conn.upgrade() else {
        return;
    };
    if !inner
        .accept_incoming_enabled
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        conn.close(close_code(RejectReason::Internal), b"offline");
        return;
    }
    let Ok(peer) = super::device_id_of(&conn.remote_id()) else {
        conn.close(close_code(RejectReason::MalformedFrame), b"");
        return;
    };
    {
        if inner.lock().pc(&peer).is_none() {
            conn.close(close_code(RejectReason::NotPaired), b"not paired");
            return;
        }
    }
    PhoneClient::learn_addrs(&inner, &peer, &conn);
    inner
        .conns
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(peer, conn.clone());
    drop(inner);
    handle_pc_conn_streams(weak_conn, peer, conn).await;
}

fn spawn_pc_conn_reader(
    rt: &tokio::runtime::Runtime,
    weak_inner: std::sync::Weak<Inner>,
    pc: DeviceId,
    conn: Connection,
) {
    rt.spawn(async move {
        handle_pc_conn_streams(weak_inner, pc, conn).await;
    });
}

async fn handle_pc_conn_streams(
    weak_inner: std::sync::Weak<Inner>,
    pc: DeviceId,
    conn: Connection,
) {
    // Renames waiting for this peer go out on this connection.
    if let Some(inner) = weak_inner.upgrade() {
        if inner.lock().pc(&pc).is_some() {
            tokio::spawn(super::pair_ops::flush(inner, conn.clone(), pc));
        }
    }
    loop {
        let Ok((mut send, mut recv)) = conn.accept_bi().await else {
            break;
        };
        crate::probe::app_stream_accepted();
        let Some(inner) = weak_inner.upgrade() else {
            break;
        };
        if !inner
            .accept_incoming_enabled
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            conn.close(close_code(RejectReason::Internal), b"offline");
            break;
        }
        let (t, payload) = match read_frame(&mut recv, IO_TIMEOUT).await {
            Ok(x) => x,
            Err(NetError::Rejected(r)) => {
                let _ = write_frame(&mut send, frame::ERROR, &super::error_payload(r)).await;
                let _ = send.finish();
                continue;
            }
            Err(_) => continue,
        };
        match t {
            frame::RELAY_PROPOSE | frame::RELAY_ACCEPT | frame::RELAY_DECLINE => {
                let is_pair = inner.lock().pc(&pc).is_some();
                let status = if is_pair {
                    super::relay_change::serve_frame(&*inner, &pc, t, &payload)
                } else {
                    None
                };
                let status = status.unwrap_or(super::relay_change::ack::REFUSED);
                let _ = write_frame(&mut send, frame::RELAY_ACK, &[status]).await;
                let _ = send.finish();
                let _ = tokio::time::timeout(Duration::from_secs(3), send.stopped()).await;
            }
            frame::PAIR_OPS => {
                let is_pair = inner.lock().pc(&pc).is_some();
                let (status, resend) = if is_pair {
                    super::pair_ops::serve_frame(&*inner, &pc, SystemClock.now().wall, &payload)
                } else {
                    (super::pair_ops::status::REFUSED, false)
                };
                let _ = write_frame(&mut send, frame::PAIR_OPS_ACK, &[status]).await;
                let _ = send.finish();
                if resend {
                    tokio::spawn(super::pair_ops::flush(inner.clone(), conn.clone(), pc));
                }
            }
            frame::SEND => {
                let path_kind = PhoneClient::conn_path_kind(&inner, &pc, &conn);
                let delivery_path = if path_kind == crate::file_transfer::TransportPathKind::Relayed
                {
                    super::DeliveryPath::Relayed
                } else {
                    super::DeliveryPath::Direct
                };
                let res = on_phone_send(&inner, &pc, &payload, delivery_path, path_kind);
                let mut out = [0u8; 3];
                match res {
                    Ok(o) => out[2] = o as u8,
                    Err(r) => out[..2].copy_from_slice(&r.code().to_be_bytes()),
                }
                let _ = write_frame(&mut send, frame::RESULT, &out).await;
                let _ = send.finish();
            }
            frame::FILE_OFFER => {
                let path_kind = PhoneClient::conn_path_kind(&inner, &pc, &conn);
                let is_relayed = path_kind == crate::file_transfer::TransportPathKind::Relayed;
                let reply = on_phone_file_offer(&inner, &pc, &payload, is_relayed);
                let _ = write_frame(&mut send, frame::FILE_OFFER_ACK, &reply).await;
                let _ = send.finish();
            }
            frame::FILE_CHUNK => {
                let path_kind = PhoneClient::conn_path_kind(&inner, &pc, &conn);
                let is_relayed = path_kind == crate::file_transfer::TransportPathKind::Relayed;
                let reply = on_phone_file_chunk(&inner, &pc, &payload, is_relayed);
                inner.file_progress.notify_waiters();
                let _ = write_frame(&mut send, frame::FILE_CHUNK_ACK, &reply).await;
                let _ = send.finish();
            }
            frame::FILE_CANCEL => {
                let reply = on_phone_file_cancel(&inner, &pc, &payload);
                inner.file_progress.notify_waiters();
                let _ = write_frame(&mut send, frame::FILE_CANCEL, &reply).await;
                let _ = send.finish();
            }
            _ => {
                let _ = write_frame(
                    &mut send,
                    frame::ERROR,
                    &super::error_payload(RejectReason::MalformedFrame),
                )
                .await;
                let _ = send.finish();
            }
        }
    }
}

struct PhoneSeenIdStore {
    pc: DeviceId,
    /// The replay file could not be opened: refuse everything (B13).
    unopenable: bool,
    file_store: Option<crate::replay::FileSeenIdStore>,
    state_entries: Vec<(crate::replay::SeenKey, crate::time::UnixMillis)>,
    pending_sync: Arc<Mutex<Vec<(DeviceId, crate::replay::SeenKey, crate::time::UnixMillis)>>>,
}

impl crate::replay::SeenIdStore for PhoneSeenIdStore {
    fn persist(
        &mut self,
        key: &crate::replay::SeenKey,
        forget_after: crate::time::UnixMillis,
    ) -> std::io::Result<()> {
        self.persist_with_retention(key, forget_after, crate::limits::REPLAY_RETENTION_MS)
    }

    fn persist_with_retention(
        &mut self,
        key: &crate::replay::SeenKey,
        forget_after: crate::time::UnixMillis,
        retention_ms: u64,
    ) -> std::io::Result<()> {
        if self.unopenable {
            return Err(std::io::Error::other("replay file could not be opened"));
        }
        if let Some(ref mut fs) = self.file_store {
            fs.persist_with_retention(key, forget_after, retention_ms)?;
        }
        self.pending_sync
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((self.pc, *key, forget_after));
        Ok(())
    }

    fn load(&mut self) -> Vec<(crate::replay::SeenKey, crate::time::UnixMillis)> {
        let mut map = std::collections::HashMap::new();
        for &(k, w) in &self.state_entries {
            map.entry(k)
                .and_modify(|cur: &mut crate::time::UnixMillis| *cur = (*cur).max(w))
                .or_insert(w);
        }
        if let Some(ref mut fs) = self.file_store {
            for (k, w) in fs.load() {
                map.entry(k)
                    .and_modify(|cur| *cur = (*cur).max(w))
                    .or_insert(w);
            }
        }
        map.into_iter().collect()
    }
}

fn with_phone_inbox<R, F>(inner: &Inner, pc: &DeviceId, f: F) -> Option<(R, String)>
where
    F: FnOnce(&mut crate::verify::Inbox, &str) -> R,
{
    let (binding, rx_kp, sender_name, state_seen) = {
        let st = inner.lock();
        let entry = st.pc(pc)?;
        let rx_kp = entry.replica.my_rx();
        let sender_name = entry.replica.link().name();
        let state_seen = st.seen_ids.get(pc).cloned().unwrap_or_default();
        (
            entry.replica.link().binding(),
            rx_kp,
            sender_name,
            state_seen,
        )
    };
    let data_dir = inner
        .data_dir
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let out = {
        let mut inboxes = inner.inboxes.lock().unwrap_or_else(|p| p.into_inner());
        let inbox = inboxes.entry(*pc).or_insert_with(|| {
            let now = SystemClock.now();
            // B13: a data dir whose replay file can't be opened fails closed.
            let on_disk = data_dir.is_some();
            let file_store = data_dir.and_then(|dir| {
                let _ = std::fs::create_dir_all(&dir);
                let path = dir.join(format!("seen-{}.bin", pc.to_hex()));
                crate::replay::FileSeenIdStore::open(path, now, false).ok()
            });
            let unopenable = on_disk && file_store.is_none();
            let store = PhoneSeenIdStore {
                pc: *pc,
                unopenable,
                file_store,
                state_entries: state_seen,
                pending_sync: inner.pending_seen_sync.clone(),
            };
            crate::verify::Inbox::for_link(
                binding,
                rx_kp,
                crate::verify::InboxConfig::default(),
                Box::new(store),
            )
            .expect("default InboxConfig valid")
        });
        inbox.rebind(binding);
        f(inbox, &sender_name)
    };
    let drained: Vec<(DeviceId, crate::replay::SeenKey, crate::time::UnixMillis)> = {
        let mut q = inner
            .pending_seen_sync
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        std::mem::take(&mut *q)
    };
    if !drained.is_empty() {
        let now_wall = SystemClock.now().wall;
        let mut st = inner.lock();
        for (pc_id, key, forget_after) in drained {
            let list = st.seen_ids.entry(pc_id).or_default();
            list.retain(|(k, w)| *w > now_wall && *k != key);
            list.push((key, forget_after));
        }
        let _ = inner.save(&st);
    }
    Some((out, sender_name))
}

fn on_phone_send(
    inner: &Inner,
    pc: &DeviceId,
    envelope: &[u8],
    delivery_path: super::DeliveryPath,
    path_kind: crate::file_transfer::TransportPathKind,
) -> Result<SendOutcome, RejectReason> {
    let n = SystemClock.now();
    let (res, sender_name) = with_phone_inbox(inner, pc, |inbox, _name| {
        inbox.receive_message(pc, envelope, n)
    })
    .ok_or(RejectReason::NotPaired)?;
    let msg = res?;
    {
        let mut st = inner.lock();
        if st.conn_stats.is_enabled() {
            st.conn_stats
                .record_transfer(pc, path_kind, envelope.len() as u64, n.wall);
            let _ = inner.save(&st);
        }
    }
    let _ = enqueue_verified_on_phone(inner, pc, &sender_name, msg, delivery_path, n.wall);
    Ok(SendOutcome::Prompted)
}

fn enqueue_verified_on_phone(
    inner: &Inner,
    pc: &DeviceId,
    sender_name: &str,
    msg: crate::verify::VerifiedMessage,
    delivery_path: super::DeliveryPath,
    received_at: crate::time::UnixMillis,
) -> bool {
    match msg {
        crate::verify::VerifiedMessage::Url(u) => {
            let item_id = inner
                .next_incoming_item_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let host = u.host_for_display().to_owned();
            let mut items = inner
                .incoming_items
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if items.len() >= 64 {
                items.remove(0);
            }
            items.push(IncomingPhoneItem {
                item_id,
                sender_id: *pc,
                sender_name: sender_name.to_owned(),
                kind: IncomingItemKind::Url,
                payload_text: u.as_str().to_owned(),
                host_display: Some(host),
                sensitive_hint: false,
                received_at,
                delivery_path,
            });
            true
        }
        crate::verify::VerifiedMessage::Clipboard(clip) => {
            let item_id = inner
                .next_incoming_item_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let text = clip.as_str().to_owned();
            let sensitive =
                clip.is_sensitive() || crate::clipboard::looks_sensitive_clipboard(&text);
            let mut items = inner
                .incoming_items
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if items.len() >= 64 {
                items.remove(0);
            }
            items.push(IncomingPhoneItem {
                item_id,
                sender_id: *pc,
                sender_name: sender_name.to_owned(),
                kind: IncomingItemKind::ClipboardText,
                payload_text: text,
                host_display: None,
                sensitive_hint: sensitive,
                received_at,
                delivery_path,
            });
            true
        }
        crate::verify::VerifiedMessage::FileWake(wake) => {
            let tid = crate::file_transfer::TransferId::from_bytes(wake.transfer_id());
            if received_at.0 >= wake.expires_at().0 {
                return false;
            }
            let declined = inner
                .declined_incoming_files
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|(dtid, s)| *dtid == tid && *s == *pc);
            if declined {
                return false;
            }
            let mut files = inner
                .incoming_files
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if files.contains_key(&tid) {
                return false;
            }
            let is_exec = wake.is_executable()
                || crate::file_transfer::is_executable_filename(wake.filename());
            let chunk_count = wake
                .size_bytes()
                .div_ceil(crate::file_transfer::FILE_CHUNK_SIZE as u64)
                .max(1);
            files.insert(
                tid,
                IncomingPhoneFileSession {
                    transfer_id: tid,
                    sender_id: *pc,
                    sender_name: sender_name.to_owned(),
                    filename: wake.filename().to_owned(),
                    mime: "application/octet-stream".into(),
                    size: wake.size_bytes(),
                    chunk_count,
                    blake3_root: [0u8; 32],
                    expires_at: wake.expires_at(),
                    is_executable: is_exec,
                    relayed: delivery_path == super::DeliveryPath::Relayed,
                    via_file_wake: true,
                    offer: None,
                    k_file: None,
                    receiver: None,
                    accepted: false,
                    target_dir: None,
                    completed_path: None,
                    last_activity: received_at,
                },
            );
            true
        }
        crate::verify::VerifiedMessage::PairNotice(n) => {
            on_pair_notice_phone(inner, pc, &n);
            false
        }
    }
}

fn encode_phone_file_ack(
    status: u8,
    tid: &crate::file_transfer::TransferId,
    val: u64,
    msg: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 8 + 2 + msg.len());
    out.push(status);
    out.extend_from_slice(tid.as_bytes());
    out.extend_from_slice(&val.to_be_bytes());
    let mb = msg.as_bytes();
    let len = mb.len().min(200);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&mb[..len]);
    out
}

fn on_phone_file_offer(inner: &Inner, pc: &DeviceId, envelope: &[u8], is_relayed: bool) -> Vec<u8> {
    let zero_tid = crate::file_transfer::TransferId::from_bytes([0u8; 16]);
    let n = SystemClock.now();
    let default_dir = inner
        .download_dir
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let _ = std::fs::create_dir_all(&default_dir);

    let active_in_mem: Vec<(
        crate::file_transfer::TransferId,
        DeviceId,
        u64,
        u64,
        [u8; 32],
    )> = inner
        .incoming_files
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .values()
        .map(|inc| {
            (
                inc.transfer_id,
                inc.sender_id,
                inc.size,
                inc.chunk_count,
                inc.blake3_root,
            )
        })
        .collect();
    let declined_in_mem: Vec<(crate::file_transfer::TransferId, DeviceId)> = inner
        .declined_incoming_files
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .copied()
        .collect();

    let Some((verified, sender_name)) = with_phone_inbox(inner, pc, |inbox, _name| {
        inbox.verify_file_offer(
            pc,
            envelope,
            |offer| {
                if active_in_mem.iter().any(|(tid, s, sz, cc, root)| {
                    *tid == offer.transfer_id
                        && *s == offer.sender
                        && *sz == offer.size
                        && *cc == offer.chunk_count
                        && (*root == offer.blake3_root || *root == [0u8; 32])
                }) {
                    return true;
                }
                if declined_in_mem
                    .iter()
                    .any(|(tid, s)| *tid == offer.transfer_id && *s == offer.sender)
                {
                    return true;
                }
                false
            },
            n,
        )
    }) else {
        return encode_phone_file_ack(
            3,
            &zero_tid,
            RejectReason::NotPaired.code() as u64,
            "not_paired",
        );
    };
    let (offer, k_file) = match verified {
        Ok(x) => x,
        Err(r) => return encode_phone_file_ack(3, &zero_tid, r.code() as u64, r.label()),
    };
    let tid = offer.transfer_id;
    let is_clipboard_stream = offer.mime == crate::clipboard::CLIPBOARD_STREAM_MIME
        && offer.size <= crate::limits::MAX_STREAMED_CLIPBOARD_BYTES as u64;
    if offer.mime == crate::clipboard::CLIPBOARD_STREAM_MIME
        && offer.size > crate::limits::MAX_STREAMED_CLIPBOARD_BYTES as u64
    {
        return encode_phone_file_ack(3, &tid, 0, "clipboard_too_large");
    }

    if is_relayed {
        let eff_cap = inner.lock().relay_policy.effective_cap_bytes();
        if eff_cap == 0 || offer.size > eff_cap {
            return encode_phone_file_ack(3, &tid, eff_cap, "exceeds_relay_cap");
        }
    }

    if declined_in_mem
        .iter()
        .any(|(dtid, s)| *dtid == tid && *s == *pc)
    {
        return encode_phone_file_ack(3, &tid, 0, "canceled_by_recipient");
    }

    let auto_accept_clipboard_stream =
        is_clipboard_stream && offer.size <= crate::file_transfer::DEFAULT_SMALL_ITEM_CAP_BYTES;
    let auto_accept = inner
        .auto_accept_files
        .load(std::sync::atomic::Ordering::SeqCst)
        || auto_accept_clipboard_stream;

    let mut files = inner
        .incoming_files
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(existing) = files.get_mut(&tid) {
        let root_matches = existing.blake3_root == offer.blake3_root
            || (existing.offer.is_none() && existing.via_file_wake);
        if existing.sender_id != *pc
            || !root_matches
            || existing.size != offer.size
            || existing.chunk_count != offer.chunk_count
        {
            return encode_phone_file_ack(3, &tid, 0, "resume_metadata_mismatch");
        }
        existing.blake3_root = offer.blake3_root;
        existing.mime = offer.mime.clone();
        existing.offer = Some(offer.clone());
        existing.k_file = Some(k_file.clone());
        existing.relayed = is_relayed;
        existing.last_activity = n.wall;
        if existing.accepted || auto_accept {
            existing.accepted = true;
            let dir = existing
                .target_dir
                .clone()
                .unwrap_or_else(|| default_dir.clone());
            let _ = std::fs::create_dir_all(&dir);
            if let Some(ref mut rcv) = existing.receiver {
                rcv.update_file_key(k_file);
            } else {
                match crate::file_transfer::PartFileReceiver::open_or_resume(
                    offer, k_file, &dir, n.wall,
                ) {
                    Ok(rcv) => existing.receiver = Some(rcv),
                    Err(e) => return encode_phone_file_ack(3, &tid, 0, &e.to_string()),
                }
            }
            let nc = existing
                .receiver
                .as_ref()
                .map(|r| r.next_chunk())
                .unwrap_or(0);
            return encode_phone_file_ack(0, &tid, nc, "");
        }
        return encode_phone_file_ack(1, &tid, 0, "awaiting_accept");
    }

    let (receiver, accepted, next_chunk) = if auto_accept {
        match crate::file_transfer::PartFileReceiver::open_or_resume(
            offer.clone(),
            k_file.clone(),
            &default_dir,
            n.wall,
        ) {
            Ok(rcv) => {
                let nc = rcv.next_chunk();
                (Some(rcv), true, nc)
            }
            Err(e) => return encode_phone_file_ack(3, &tid, 0, &e.to_string()),
        }
    } else {
        if let Err(e) = crate::file_transfer::check_offer_acceptable(&offer, &default_dir, n.wall) {
            return encode_phone_file_ack(3, &tid, 0, &e.to_string());
        }
        (None, false, 0)
    };

    let is_exec = crate::file_transfer::is_executable_filename(&offer.filename);
    files.insert(
        tid,
        IncomingPhoneFileSession {
            transfer_id: tid,
            sender_id: *pc,
            sender_name,
            filename: offer.filename.clone(),
            mime: offer.mime.clone(),
            size: offer.size,
            chunk_count: offer.chunk_count,
            blake3_root: offer.blake3_root,
            expires_at: offer.expires_at,
            is_executable: is_exec,
            relayed: is_relayed,
            via_file_wake: false,
            offer: Some(offer),
            k_file: Some(k_file),
            receiver,
            accepted,
            target_dir: Some(default_dir),
            completed_path: None,
            last_activity: n.wall,
        },
    );
    let status = if accepted { 0 } else { 1 };
    encode_phone_file_ack(status, &tid, next_chunk, "")
}

fn on_phone_file_chunk(inner: &Inner, pc: &DeviceId, payload: &[u8], is_relayed: bool) -> Vec<u8> {
    let zero_tid = crate::file_transfer::TransferId::from_bytes([0u8; 16]);
    if payload.len() < 16 + 8 + 1 {
        return encode_phone_file_ack(3, &zero_tid, 0, "short_chunk_frame");
    }
    let mut tid_b = [0u8; 16];
    tid_b.copy_from_slice(&payload[..16]);
    let tid = crate::file_transfer::TransferId::from_bytes(tid_b);
    let chunk_index = u64::from_be_bytes(payload[16..24].try_into().expect("8"));
    let is_final = payload[24] == 1;
    let ciphertext = &payload[25..];

    let eff_cap = inner.lock().relay_policy.effective_cap_bytes();
    let was_declined = inner
        .declined_incoming_files
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .any(|(dtid, s)| *dtid == tid && *s == *pc);

    let mut files = inner
        .incoming_files
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let Some(sess) = files.get_mut(&tid) else {
        let reason = if was_declined {
            "canceled_by_recipient"
        } else {
            "unknown_transfer"
        };
        return encode_phone_file_ack(3, &tid, 0, reason);
    };
    if sess.sender_id != *pc {
        return encode_phone_file_ack(3, &tid, 0, "sender_mismatch");
    }
    sess.relayed = is_relayed;
    if is_relayed && (eff_cap == 0 || sess.size > eff_cap) {
        if let Some(failed) = files.remove(&tid) {
            if let Some(rcv) = failed.receiver {
                rcv.cancel_and_delete();
            }
        }
        return encode_phone_file_ack(3, &tid, eff_cap, "exceeds_relay_cap");
    }
    if !sess.accepted || sess.receiver.is_none() {
        let nc = sess.receiver.as_ref().map(|r| r.next_chunk()).unwrap_or(0);
        return encode_phone_file_ack(1, &tid, nc, "awaiting_accept");
    }
    if is_final != (chunk_index + 1 == sess.chunk_count) {
        if let Some(failed) = files.remove(&tid) {
            if let Some(rcv) = failed.receiver {
                rcv.cancel_and_delete();
            }
        }
        return encode_phone_file_ack(3, &tid, chunk_index, "is_final_mismatch");
    }
    sess.last_activity = SystemClock.now().wall;
    let rcv = sess.receiver.as_mut().expect("checked is_some");
    if let Err(e) = rcv.write_encrypted_chunk(chunk_index, ciphertext) {
        let msg = e.to_string();
        if let Some(failed) = files.remove(&tid) {
            if let Some(r) = failed.receiver {
                r.cancel_and_delete();
            }
        }
        return encode_phone_file_ack(3, &tid, chunk_index, &msg);
    }
    let next_chunk = rcv.next_chunk();
    if rcv.is_complete() {
        let rcv_owned = sess.receiver.take().expect("complete");
        match rcv_owned.finalize() {
            Ok(completed) => {
                let final_path = completed.path;
                let file_size = sess.size;
                let is_clipboard_stream = sess.mime == crate::clipboard::CLIPBOARD_STREAM_MIME;
                let sender_name = sess.sender_name.clone();
                sess.completed_path = Some(final_path.clone());
                if is_clipboard_stream {
                    files.remove(&tid);
                }
                drop(files);
                {
                    let mut st = inner.lock();
                    if st.conn_stats.is_enabled() {
                        let pk = if is_relayed {
                            crate::file_transfer::TransportPathKind::Relayed
                        } else {
                            crate::file_transfer::TransportPathKind::Direct
                        };
                        st.conn_stats
                            .record_transfer(pc, pk, file_size, SystemClock.now().wall);
                        let _ = inner.save(&st);
                    }
                }
                if is_clipboard_stream {
                    let bytes = std::fs::read(&final_path).unwrap_or_default();
                    let _ = std::fs::remove_file(&final_path);
                    match String::from_utf8(bytes) {
                        Ok(text)
                            if !text.is_empty()
                                && text.len() <= crate::limits::MAX_STREAMED_CLIPBOARD_BYTES =>
                        {
                            let item_id = inner
                                .next_incoming_item_id
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let sensitive = crate::clipboard::looks_sensitive_clipboard(&text);
                            let mut items = inner
                                .incoming_items
                                .lock()
                                .unwrap_or_else(|p| p.into_inner());
                            if items.len() >= 64 {
                                items.remove(0);
                            }
                            items.push(IncomingPhoneItem {
                                item_id,
                                sender_id: *pc,
                                sender_name,
                                kind: IncomingItemKind::ClipboardText,
                                payload_text: text,
                                host_display: None,
                                sensitive_hint: sensitive,
                                received_at: SystemClock.now().wall,
                                delivery_path: if is_relayed {
                                    super::DeliveryPath::Relayed
                                } else {
                                    super::DeliveryPath::Direct
                                },
                            });
                            encode_phone_file_ack(2, &tid, next_chunk, "completed")
                        }
                        _ => encode_phone_file_ack(3, &tid, next_chunk, "bad_clipboard_utf8"),
                    }
                } else {
                    encode_phone_file_ack(2, &tid, next_chunk, "completed")
                }
            }
            Err(e) => {
                let msg = e.to_string();
                files.remove(&tid);
                encode_phone_file_ack(3, &tid, next_chunk, &msg)
            }
        }
    } else {
        encode_phone_file_ack(0, &tid, next_chunk, "")
    }
}

fn on_phone_file_cancel(inner: &Inner, pc: &DeviceId, payload: &[u8]) -> Vec<u8> {
    let zero_tid = crate::file_transfer::TransferId::from_bytes([0u8; 16]);
    if payload.len() < 16 {
        return encode_phone_file_ack(3, &zero_tid, 0, "short_cancel");
    }
    let mut tid_b = [0u8; 16];
    tid_b.copy_from_slice(&payload[..16]);
    let tid = crate::file_transfer::TransferId::from_bytes(tid_b);
    let mut files = inner
        .incoming_files
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if files.get(&tid).is_some_and(|s| s.sender_id == *pc) {
        if let Some(sess) = files.remove(&tid) {
            if let Some(rcv) = sess.receiver {
                rcv.cancel_and_delete();
            }
        }
    }
    encode_phone_file_ack(4, &tid, 0, "cancelled")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::state::MemoryStateStore;

    #[test]
    fn set_relay_url_reset_restores_default_and_never_hangs() {
        let phone = PhoneClient::new(PhoneConfig {
            state: Arc::new(MemoryStateStore::default()),
            default_name: "Pixel".into(),
            platform: Platform::Android,
            mdns: false,
        })
        .expect("open phone");
        assert_eq!(
            phone.relay_url(),
            Some(crate::net::DEFAULT_RELAY_URL.to_owned())
        );

        let sw = crate::time::Stopwatch::start();
        phone
            .set_relay_url(Some("https://relay.example.com".into()))
            .expect("set custom relay");
        assert_eq!(
            phone.relay_url(),
            Some("https://relay.example.com".to_owned())
        );

        phone.set_relay_url(None).expect("reset relay via None");
        let elapsed_us = sw.elapsed_us();
        assert!(
            elapsed_us < 500_000,
            "set_relay_url took too long: {elapsed_us} us"
        );
        assert_eq!(
            phone.relay_url(),
            Some(crate::net::DEFAULT_RELAY_URL.to_owned())
        );

        phone
            .set_relay_url(Some("   ".into()))
            .expect("reset relay via blank string");
        assert_eq!(
            phone.relay_url(),
            Some(crate::net::DEFAULT_RELAY_URL.to_owned())
        );

        phone
            .set_relay_url(Some("off".into()))
            .expect("disable relay via off");
        assert_eq!(phone.relay_url(), None);
    }

    #[test]
    fn relay_url_off_and_reset_persist_across_reopen() {
        let store = Arc::new(MemoryStateStore::default());
        {
            let phone = PhoneClient::new(PhoneConfig {
                state: store.clone(),
                default_name: "Pixel".into(),
                platform: Platform::Android,
                mdns: false,
            })
            .expect("open phone");
            phone
                .set_relay_url(Some("off".into()))
                .expect("disable relay");
            assert_eq!(phone.relay_url(), None);
        }
        {
            let reopened = PhoneClient::new(PhoneConfig {
                state: store.clone(),
                default_name: "Pixel".into(),
                platform: Platform::Android,
                mdns: false,
            })
            .expect("reopen phone after off");
            assert_eq!(
                reopened.relay_url(),
                None,
                "disabled relay ('off') must persist across reopen"
            );
            reopened
                .set_relay_url(None)
                .expect("reset relay to default");
            assert_eq!(
                reopened.relay_url(),
                Some(crate::net::DEFAULT_RELAY_URL.to_owned())
            );
        }
        {
            let reopened2 = PhoneClient::new(PhoneConfig {
                state: store,
                default_name: "Pixel".into(),
                platform: Platform::Android,
                mdns: false,
            })
            .expect("reopen phone after reset");
            assert_eq!(
                reopened2.relay_url(),
                Some(crate::net::DEFAULT_RELAY_URL.to_owned()),
                "reset relay must persist DEFAULT_RELAY_URL across reopen"
            );
        }
    }
}
