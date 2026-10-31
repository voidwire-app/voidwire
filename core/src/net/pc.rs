//! The PC side: listener, pairing inviter, inbox, prompts. Headless (the
//! desktop app wraps it in Tauri windows; the e2e test drives it directly).

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use iroh::endpoint::{presets, Connection};
use iroh::{Endpoint, RelayMode, SecretKey};

use super::state::{read_ops, read_secret, write_ops, Reader, StateStore, Writer};
use super::{
    close_code, device_id_of, error_payload, frame, read_frame, write_frame, NetError, SendOutcome,
    ALPN_APP, ALPN_PAIR, IO_TIMEOUT, MDNS_SERVICE, PREFERRED_PORT,
};
use crate::grouplog::{self, SignedOp};
use crate::ids::{DeviceId, GroupId, LogHead};
use crate::keys::{DeviceCert, DeviceKeypair, Platform, ReceiveKeypair};
use crate::limits::PENDING_PROMPT_TTL_MS;
use crate::opener::{deliver, Delivery, OpenMode, PendingOpen, UrlOpener};
use crate::reject::RejectReason;
use crate::replay::{FileSeenIdStore, HighWater, NoPersistence, SeenIdStore, StoreHealth};
use crate::roster::Roster;
use crate::time::{Clock, MonoMillis, Now, SystemClock, UnixMillis};
use crate::verify::{Inbox, InboxConfig};

/// State format v2. Older formats are not read (nothing shipped them).
const STATE_MAGIC: &[u8] = b"VWPC2\n";

fn take_magic(r: &mut Reader<'_>) -> bool {
    matches!(r.take(STATE_MAGIC.len()), Some(m) if m == STATE_MAGIC)
}
/// At most this many prompts wait at once (oldest dropped).
pub const MAX_PENDING: usize = 20;

/// Events for the UI (never carry a URL; hosts only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcEvent {
    PendingOpen {
        id: u64,
        host: String,
        from: String,
    },
    Opened {
        host: String,
        from: String,
        device: DeviceId,
        /// `true`: opened without asking (no-prompt mode, via `deliver`).
        /// `false`: the user clicked Open on a prompt.
        without_prompt: bool,
    },
    Rejected {
        reason: RejectReason,
        from: Option<String>,
    },
    PairingChanged,
    DevicesChanged,
    /// M4.4: a paired device asks to move the pairing to another relay
    /// (see [`PcNode::relay_change_requests`]), or a proposal's state moved.
    RelayChangeChanged,
    FileOfferPending {
        transfer_id: crate::file_transfer::TransferId,
        filename: String,
        size: u64,
        from: String,
        allow_open: bool,
    },
    FileCompleted {
        transfer_id: crate::file_transfer::TransferId,
        filename: String,
        path: PathBuf,
        size: u64,
        from: String,
        allow_open: bool,
    },
    FileCancelled {
        transfer_id: crate::file_transfer::TransferId,
        reason: String,
    },
    ClipboardPending {
        id: u64,
        from: String,
        byte_len: usize,
        sensitive: bool,
    },
    ClipboardAutoCopied {
        from: String,
        device: DeviceId,
        text: String,
        byte_len: usize,
        sensitive: bool,
    },
    OutgoingFileUpdated {
        transfer_id: crate::file_transfer::TransferId,
        recipient: DeviceId,
        chunks_sent: u64,
        chunk_count: u64,
        completed: bool,
    },
}

pub type EventSink = Arc<dyn Fn(PcEvent) + Send + Sync>;

pub struct PcConfig {
    /// Name in our certificate (first run only; kept in state afterwards).
    pub device_name: String,
    pub state: Arc<dyn StateStore>,
    /// The fsync'd replay cache file (ENV-05). `None`: in memory (tests).
    pub seen_store_path: Option<PathBuf>,
    pub inbox: InboxConfig,
    pub opener: Arc<dyn UrlOpener + Send + Sync>,
    /// Advertise on mDNS/DNS-SD (`_voidwire._udp.local`).
    pub mdns: bool,
    /// `None`: try [`PREFERRED_PORT`], fall back to random. `Some(p)`: exactly
    /// `p` (0 = random).
    pub port: Option<u16>,
    /// Put 127.0.0.1 in the QR hints (headless tests on one box).
    pub advertise_loopback: bool,
    pub events: Option<EventSink>,
    /// Skip the one-inbox-per-process check (R1). Only honoured with the
    /// `test-util` feature; refused otherwise.
    pub unchecked_inbox_for_tests: bool,
    /// Use this group id for a brand-new PC's genesis instead of a random one
    /// (QA's PAIR-11 attacker model: a fake PC reusing a victim's group id).
    /// Only honoured with the `test-util` feature; refused otherwise.
    pub genesis_group_for_tests: Option<GroupId>,
    /// Unanswered prompts expire after this long (clamped to
    /// 1..=[`PENDING_PROMPT_TTL_MS`]; tests use a short one).
    pub prompt_ttl_ms: u64,
    /// Relay URL (`Some("https://relay.voidwire.app")` by default, `None` disables relay).
    pub relay_url: Option<String>,
    /// Directory where incoming file transfers (`.part`, `.part.meta`, and completed files)
    /// are saved by default. Defaults to `~/Downloads/Voidwire` (or `<data_dir>/downloads` with
    /// `0700` mode). A folder the user picked with `set_download_dir` (saved in state) wins.
    pub download_dir: Option<PathBuf>,
    /// Whether incoming file offers are accepted automatically (`false` by default in production;
    /// when `false`, no `.part` or `.part.meta` file is created on disk until `accept_file` is called).
    pub auto_accept_files: bool,
}

const MAX_CONCURRENT_INCOMING_FILES: usize = 16;
const MAX_COMPLETED_FILES_HISTORY: usize = 64;

impl PcConfig {
    pub fn new(
        device_name: impl Into<String>,
        state: Arc<dyn StateStore>,
        opener: Arc<dyn UrlOpener + Send + Sync>,
    ) -> Self {
        PcConfig {
            device_name: device_name.into(),
            state,
            seen_store_path: None,
            inbox: InboxConfig::default(),
            opener,
            mdns: true,
            port: None,
            advertise_loopback: false,
            events: None,
            unchecked_inbox_for_tests: false,
            genesis_group_for_tests: None,
            prompt_ttl_ms: PENDING_PROMPT_TTL_MS,
            relay_url: super::resolve_relay_url(None),
            download_dir: None,
            auto_accept_files: false,
        }
    }

    /// Override the relay URL (`None` disables relay transport).
    pub fn with_relay_url(mut self, relay_url: Option<String>) -> Self {
        self.relay_url = relay_url;
        self
    }

    /// Override the destination directory for incoming file transfers.
    pub fn with_download_dir(mut self, dir: PathBuf) -> Self {
        self.download_dir = Some(dir);
        self
    }

    /// Override whether incoming file offers are auto-accepted without user prompt.
    pub fn with_auto_accept_files(mut self, auto_accept: bool) -> Self {
        self.auto_accept_files = auto_accept;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub id: DeviceId,
    pub name: String,
    pub platform: Option<Platform>,
    pub paired_at: Option<UnixMillis>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingInfo {
    pub id: u64,
    pub host: String,
    pub from: String,
    pub received_at: UnixMillis,
}

/// A pending clipboard text item awaiting user confirmation on the PC (`M3.1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingClipboardInfo {
    pub id: u64,
    pub from: String,
    pub sender: DeviceId,
    pub text: String,
    pub byte_len: usize,
    pub sensitive: bool,
    pub received_at: UnixMillis,
}

/// Delivery report for a PC -> Phone link or clipboard send (`M3.1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcSendReport {
    pub outcome: SendOutcome,
    pub delivery_path: super::DeliveryPath,
    pub latency_us: u64,
}

/// Delivery report for a PC -> Phone file transfer or offline `FileWake` offer (`M3.1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcFileSendReport {
    pub transfer_id: crate::file_transfer::TransferId,
    pub filename: String,
    pub size: u64,
    pub blake3_root: [u8; 32],
    pub chunks_sent: u64,
    pub resumed_from_chunk: u64,
    pub delivery_path: super::DeliveryPath,
    pub awaiting_accept: bool,
    pub latency_us: u64,
}

/// Metadata for an active or queued PC -> Phone outgoing file transfer (`M3.1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingFileInfo {
    pub transfer_id: crate::file_transfer::TransferId,
    pub recipient: DeviceId,
    pub to: String,
    pub filename: String,
    pub mime: String,
    pub size: u64,
    pub chunk_count: u64,
    pub chunks_sent: u64,
    pub delivery_path: super::DeliveryPath,
    pub created_at: UnixMillis,
    pub expires_at: UnixMillis,
    /// `Some` for a transfer that just ended without finishing; it stays
    /// listed for [`OUTBOUND_ENDED_SHOW_MS`].
    pub ended: Option<OutboundEnd>,
}

/// Why an outgoing transfer ended without finishing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundEnd {
    /// The recipient declined (or cancelled) it.
    Declined,
    /// The recipient never accepted it before the pre-accept deadline.
    NotAccepted,
    /// Accepted, then no chunk went out for [`STALLED_ACCEPTED_FILE_TIMEOUT_MS`].
    Stalled,
}

/// How long an ended outgoing transfer stays in [`PcNode::outgoing_files`].
pub const OUTBOUND_ENDED_SHOW_MS: u64 = 10_000;

/// Metadata for a pending or active incoming file transfer on the PC (`M2.6`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingFileInfo {
    pub transfer_id: crate::file_transfer::TransferId,
    pub sender: DeviceId,
    pub from: String,
    pub filename: String,
    pub mime: String,
    pub size: u64,
    pub chunk_count: u64,
    pub next_chunk: u64,
    pub accepted: bool,
    pub allow_open: bool,
}

/// Completed incoming file record (`M2.6`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedFileInfo {
    pub transfer_id: crate::file_transfer::TransferId,
    pub sender: DeviceId,
    pub from: String,
    pub filename: String,
    pub path: PathBuf,
    pub size: u64,
    pub blake3_root: [u8; 32],
    pub allow_open: bool,
}

/// Stalled accepted file-transfer timeout (45 seconds without a chunk, `M2.8`).
pub const STALLED_ACCEPTED_FILE_TIMEOUT_MS: u64 = 45_000;
/// Stalled unaccepted file-offer timeout (120 seconds without user acceptance, `M2.8`).
pub const STALLED_UNACCEPTED_FILE_TIMEOUT_MS: u64 = 120_000;

struct IncomingFileSession {
    offer: crate::file_transfer::FileOffer,
    from: String,
    k_file: crate::file_transfer::FileTransferKey,
    receiver: Option<crate::file_transfer::PartFileReceiver>,
    accepted: bool,
    last_activity: UnixMillis,
}

struct Pending {
    open: PendingOpen,
    from: String,
    received_at: UnixMillis,
    /// Monotonic deadline: unanswered after this, the prompt is dropped.
    expires_mono: MonoMillis,
}

struct PendingClipboard {
    from: String,
    sender: DeviceId,
    text: zeroize::Zeroizing<String>,
    sensitive: bool,
    received_at: UnixMillis,
    expires_mono: MonoMillis,
}

#[derive(Clone)]
enum OutboundFileData {
    Bytes(Vec<u8>),
    Path(PathBuf),
}

#[derive(Clone)]
struct OutboundPendingFile {
    offer: crate::file_transfer::FileOffer,
    envelope: Vec<u8>,
    k_file: crate::file_transfer::FileTransferKey,
    data: OutboundFileData,
    to: String,
    chunks_sent: u64,
    delivery_path: super::DeliveryPath,
    created_at: UnixMillis,
    /// The recipient asked for the chunks (it accepted): the pre-accept
    /// deadline no longer applies.
    pulled: bool,
    /// When the last chunk went out (or the pull came): the in-flight stall
    /// deadline counts from here.
    last_activity: UnixMillis,
}

struct PcState {
    identity: DeviceKeypair,
    receive_secret: zeroize::Zeroizing<[u8; 32]>,
    inbox: Inbox,
    signed: Vec<SignedOp>,
    no_prompt: bool,
    pending: BTreeMap<u64, Pending>,
    next_pending: u64,
    conns: HashMap<DeviceId, Vec<Connection>>,
    prompt_ttl_ms: u64,
    /// L2: the high-water mark last written to state.bin.
    saved_hw: Option<HighWater>,
    /// Configured relay URL (`None` disables relay; persisted in state.bin).
    relay_url: Option<String>,
    mailbox_peer: Option<DeviceId>,
    mailbox_peer_explicit: bool,
    last_throwaway_id: Option<DeviceId>,
    download_dir: PathBuf,
    default_download_dir: PathBuf,
    custom_download_dir: Option<PathBuf>,
    keep_file_history: bool,
    relay_url_explicit: bool,
    auto_accept_files: bool,
    auto_copy_clipboard: bool,
    send_clipboard_shortcut: bool,
    send_clipboard_shortcut_accel: String,
    pending_clipboards: BTreeMap<u64, PendingClipboard>,
    phone_addrs: HashMap<DeviceId, Vec<SocketAddr>>,
    outbound_files: HashMap<crate::file_transfer::TransferId, OutboundPendingFile>,
    cancelled_outbound_files: std::collections::VecDeque<crate::file_transfer::TransferId>,
    incoming_files: HashMap<crate::file_transfer::TransferId, IncomingFileSession>,
    declined_files: std::collections::VecDeque<(crate::file_transfer::TransferId, DeviceId)>,
    /// Outgoing transfers that just ended without finishing (declined, or
    /// never accepted), kept in RAM for [`OUTBOUND_ENDED_SHOW_MS`] so the
    /// sender's list says why the row went away. Bounded; never stored.
    ended_outbound: std::collections::VecDeque<(OutgoingFileInfo, UnixMillis)>,
    completed_files: Vec<CompletedFileInfo>,
    relay_policy: crate::file_transfer::RelayTransferPolicy,
    conn_stats: crate::file_transfer::ConnectionStatsStore,
    /// State v2 (M4.1): one pairing per peer, split from the hub group.
    pairings: crate::pairwise::PairingSet,
    relay_settings: crate::pairwise::RelaySettings,
    /// M4.2: live v2 links (any peer), each with its own inbox.
    links: HashMap<DeviceId, LinkRt>,
    /// M4.4: old relay inboxes still pulled after a pairing moved.
    drains: Vec<super::relay_change::Drain>,
    /// Renames signed this run and not sent yet (RAM only).
    unsent_ops: super::pair_ops::Unsent,
    /// Legacy splits waiting for the phone's co-signature (RAM only; a
    /// restart just means the phone asks again).
    /// Last window-focus inbox pull (RAM only).
    last_focus_pull: Option<MonoMillis>,
    /// Unpair notices not yet delivered (M4.3; persisted).
    outbox: super::outbox::Outbox,
    /// Where per-link replay caches go (`None`: in memory).
    seen_dir: Option<PathBuf>,
    /// Limits for each pairing's inbox ([`PcConfig::inbox`]).
    link_inbox: InboxConfig,
    /// Each pairing's replay-file high-water mark as last saved (L2): a
    /// file that lost records, or went missing, fails closed at start.
    link_marks: super::pairings_state::ReplayMarks,
    /// Away-relay endpoints (M4.4); `None` until the node is up.
    away: Option<Arc<super::away::Away>>,
}

/// A v2 link and the inbox its messages are verified in.
struct LinkRt {
    link: super::links::PairLink,
    inbox: Inbox,
}

/// How to address one peer: through its v2 link, or the legacy hub group.
struct PeerCtx {
    group: GroupId,
    head: LogHead,
    rk: crate::keys::ReceivePublicKey,
}

struct Shared {
    state: Mutex<PcState>,
    store: Arc<dyn StateStore>,
    opener: Arc<dyn UrlOpener + Send + Sync>,
    events: Option<EventSink>,
    advertise_loopback: bool,
    mdns: bool,
    /// Test seam: unpair saves the notice but doesn't send it (the app
    /// "killed" right after the erase).
    hold_unpair_send: std::sync::atomic::AtomicBool,
    /// Test seam: the sender stops sending chunks while set (always false
    /// outside tests).
    hold_outbound_chunks: std::sync::atomic::AtomicBool,
    /// Test seam: added to the event-pull gate's clock (0 in the app).
    event_skew_ms: std::sync::atomic::AtomicU64,
    /// Inbox pulls started (tests and diagnostics; no private data).
    inbox_pulls: std::sync::atomic::AtomicU64,
    /// Stall watch (no timers when idle): notified when an incoming transfer
    /// starts or is accepted, or the watch stops. Waits on `state`.
    stall_cv: std::sync::Condvar,
    stall_stop: std::sync::atomic::AtomicBool,
    /// Times the stall watch woke (tests and diagnostics; no private data).
    stall_wakeups: std::sync::atomic::AtomicU64,
    /// M4.3: the live v2 invite this PC shows (code or QR).
    host2: Mutex<super::pair2::Host>,
    /// M4.3: a v2 invite this PC is joining (typed code or QR).
    join2: Mutex<super::pair2::JoinSlot>,
    /// Woken whenever an incoming file chunk lands, so a pull waiting for
    /// its final ack can tell a slow transfer from a dead one.
    file_progress: tokio::sync::Notify,
    /// M4.4: relay-change proposals (RAM only).
    relay_change: Mutex<super::relay_change::Slots>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, PcState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
    fn emit(&self, e: PcEvent) {
        if let Some(f) = &self.events {
            f(e);
        }
    }
}

fn now() -> Now {
    SystemClock.now()
}

fn stall_deadline_of(st: &PcState) -> Option<UnixMillis> {
    let incoming = st.incoming_files.values().map(|s| {
        let limit = if s.accepted {
            STALLED_ACCEPTED_FILE_TIMEOUT_MS
        } else {
            STALLED_UNACCEPTED_FILE_TIMEOUT_MS
        };
        UnixMillis(s.last_activity.0.saturating_add(limit))
    });
    let outgoing = st
        .outbound_files
        .values()
        .filter_map(|o| outbound_stall_deadline(st, o).map(|(d, _)| d));
    incoming.chain(outgoing).min()
}

/// The sender's stall deadline, the mirror of the receiver's watch. Only a
/// live offer (direct or relayed) has one; an offer queued in a device inbox
/// keeps its own expiry.
/// - Before accept (v0.9.0 test sheet step 13): an offer to a PC that the PC
///   leaves unaccepted for [`STALLED_UNACCEPTED_FILE_TIMEOUT_MS`]. A phone
///   may accept later, so an unaccepted offer to a phone has none.
/// - In flight (pulled, or a chunk sent), to any device: no chunk for
///   [`STALLED_ACCEPTED_FILE_TIMEOUT_MS`] since the last one. After that the
///   receiver has dropped its session too, so nothing can resume it.
fn outbound_stall_deadline(
    st: &PcState,
    o: &OutboundPendingFile,
) -> Option<(UnixMillis, OutboundEnd)> {
    let live = matches!(
        o.delivery_path,
        super::DeliveryPath::Direct | super::DeliveryPath::Relayed
    );
    if !live {
        return None;
    }
    if o.pulled || o.chunks_sent > 0 {
        let d = o
            .last_activity
            .0
            .saturating_add(STALLED_ACCEPTED_FILE_TIMEOUT_MS);
        return Some((UnixMillis(d), OutboundEnd::Stalled));
    }
    let to_pc = st
        .links
        .get(&o.offer.recipient)
        .is_some_and(|l| !l.link.peer_cert.platform().is_mobile());
    to_pc.then(|| {
        let d = o
            .created_at
            .0
            .saturating_add(STALLED_UNACCEPTED_FILE_TIMEOUT_MS);
        (UnixMillis(d), OutboundEnd::NotAccepted)
    })
}

fn outgoing_info(o: &OutboundPendingFile, ended: Option<OutboundEnd>) -> OutgoingFileInfo {
    OutgoingFileInfo {
        transfer_id: o.offer.transfer_id,
        recipient: o.offer.recipient,
        to: o.to.clone(),
        filename: o.offer.filename.clone(),
        mime: o.offer.mime.clone(),
        size: o.offer.size,
        chunk_count: o.offer.chunk_count,
        chunks_sent: o.chunks_sent,
        delivery_path: o.delivery_path,
        created_at: o.created_at,
        expires_at: o.offer.expires_at,
        ended,
    }
}

/// Keep an ended outgoing transfer listed for a moment, with why it ended.
fn end_outbound(st: &mut PcState, o: &OutboundPendingFile, why: OutboundEnd) {
    st.ended_outbound
        .retain(|(i, _)| i.transfer_id != o.offer.transfer_id);
    if st.ended_outbound.len() >= 16 {
        st.ended_outbound.pop_front();
    }
    st.ended_outbound
        .push_back((outgoing_info(o, Some(why)), now().wall));
}

impl super::pair2::Node2 for Shared {
    fn host(&self) -> MutexGuard<'_, super::pair2::Host> {
        self.host2.lock().unwrap_or_else(|p| p.into_inner())
    }
    fn join_slot(&self) -> MutexGuard<'_, super::pair2::JoinSlot> {
        self.join2.lock().unwrap_or_else(|p| p.into_inner())
    }
    fn identity(&self) -> Result<(DeviceKeypair, DeviceCert), RejectReason> {
        let st = self.lock();
        let me = st.identity.device_id();
        let cert = st
            .inbox
            .roster()
            .and_then(|r| r.device(&me))
            .and_then(|e| e.cert.clone())
            .ok_or(RejectReason::Internal)?;
        Ok((
            DeviceKeypair::from_secret_bytes(&st.identity.secret_bytes()),
            cert,
        ))
    }
    fn relay_view(&self) -> super::pair2::RelayView {
        let st = self.lock();
        super::pair2::RelayView {
            settings: st.relay_settings.clone(),
            in_use: st.relay_settings.in_use(&st.pairings),
            pairing_room: st.pairings.has_room(),
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
        st.commit(&*self.store)
    }
    fn keep(&self, p: crate::pairwise::Pairing, addrs: Vec<SocketAddr>) -> Result<bool, NetError> {
        let mut st = self.lock();
        let peer = p.peer.id;
        let new_id = p.pairing_id;
        let replaced = super::pair2::replace_pairing(&mut st.pairings, p)?;
        let old_addrs = st.phone_addrs.get(&peer).cloned();
        if !addrs.is_empty() {
            st.phone_addrs.insert(peer, addrs);
        }
        if let Err(e) = st.commit(&*self.store) {
            // Not saved: the old pairing (keys, inbox, relay) stays as it was.
            super::pair2::undo_replace(&mut st.pairings, &new_id, replaced);
            match old_addrs {
                Some(a) => st.phone_addrs.insert(peer, a),
                None => st.phone_addrs.remove(&peer),
            };
            st.rebuild_links();
            return Err(e);
        }
        // The replaced pairing's inbox replay file is no use any more.
        for old in &replaced {
            st.forget_seen_file(&old.pairing_id);
        }
        drop(st);
        self.emit(PcEvent::DevicesChanged);
        Ok(!replaced.is_empty())
    }
    fn changed(&self) {
        self.emit(PcEvent::PairingChanged);
    }
}

impl PcState {
    /// Something an inbox event should do: pull v2 inboxes or send unpair
    /// notices.
    fn has_inbox_work(&self) -> bool {
        !self.links.is_empty() || !self.outbox.is_empty()
    }

    /// The state blob holds both secret keys: wiped when dropped.
    fn encode(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut w = Writer::new(STATE_MAGIC);
        w.raw(&self.identity.secret_bytes()[..]);
        w.raw(&self.receive_secret[..]);
        w.u8(self.no_prompt as u8);
        write_ops(&mut w, &self.signed);
        // L2: optional trailing section, the seen-id high-water mark.
        if let Some(hw) = self.inbox.replay_high_water() {
            w.u8(STATE_SECTION_HIGH_WATER);
            w.raw(&hw.encode());
        }
        if let Some(ref r) = self.relay_url {
            w.u8(STATE_SECTION_RELAY);
            w.bytes16(r.as_bytes());
        }
        let id_sk = self.identity.secret_bytes();
        w.u8(STATE_SECTION_FILE_STATS);
        w.raw(&self.relay_policy.user_cap_bytes().to_be_bytes());
        let stats_bytes = self.conn_stats.to_bytes();
        w.bytes16(&stats_bytes);
        if self.keep_file_history
            || self.relay_url_explicit
            || self.mailbox_peer_explicit
            || self.custom_download_dir.is_some()
            || self.auto_copy_clipboard
            || self.send_clipboard_shortcut
            || self.send_clipboard_shortcut_accel != DEFAULT_SEND_CLIPBOARD_SHORTCUT_ACCEL
        {
            w.u8(STATE_SECTION_PREFS);
            let prefs_bytes = self.encode_prefs();
            w.bytes16(&prefs_bytes);
        }
        w.u8(STATE_SECTION_PAIRWISE);
        let body = super::pairings_state::encode_section(
            &self.pairings,
            &self.relay_settings,
            &self.outbox,
            &self.current_link_marks(),
            &id_sk,
        );
        w.bytes32(&body);
        zeroize::Zeroizing::new(w.0)
    }

    /// Keep the home relay entry in step with the configured relay.
    fn sync_home_relay(&mut self) {
        let relay = super::pairings_state::relay_ref(self.relay_url.as_deref(), self.mailbox_peer);
        self.relay_settings.sync_home(relay);
    }

    /// Each live pairing's replay high-water mark (the saved one until its
    /// inbox has seen something this run).
    fn current_link_marks(&self) -> super::pairings_state::ReplayMarks {
        self.links
            .values()
            .filter_map(|l| {
                let id = l.link.pairing_id;
                let hw = l
                    .inbox
                    .replay_high_water()
                    .or_else(|| self.link_marks.get(&id).copied())?;
                Some((id, hw))
            })
            .collect()
    }

    /// L2: re-save state.bin when a seen-id file's high-water mark moved
    /// (after its fsync'd append, before the sender hears back).
    fn save_high_water(&mut self, store: &dyn StateStore) {
        let hw = self.inbox.replay_high_water();
        let marks = self.current_link_marks();
        if hw != self.saved_hw || marks != self.link_marks {
            match store.save(&self.encode()) {
                Ok(()) => {
                    self.saved_hw = hw;
                    self.link_marks = marks;
                }
                // Lagging is detected (and fails closed) at the next start.
                Err(e) => eprintln!("voidwire: couldn't save the replay high-water mark: {e}"),
            }
        }
    }

    /// Drop prompts nobody answered in time. Returns how many were dropped.
    fn expire_prompts(&mut self, now: Now) -> usize {
        let before = self.pending.len() + self.pending_clipboards.len();
        self.pending.retain(|_, p| now.mono < p.expires_mono);
        self.pending_clipboards
            .retain(|_, p| now.mono < p.expires_mono);
        before - (self.pending.len() + self.pending_clipboards.len())
    }

    fn name_of(&self, id: &DeviceId) -> String {
        if let Some(l) = self.links.get(id) {
            return l.link.name();
        }
        // This PC's own name (its cert lives in the local roster).
        self.inbox
            .roster()
            .and_then(|r| r.device(id))
            .map(|e| e.name.clone())
            .unwrap_or_else(|| id.short())
    }

    fn encode_prefs(&self) -> Vec<u8> {
        let mut pw = Writer::new(&[1u8]);
        pw.u8(self.keep_file_history as u8);
        pw.u8(self.relay_url_explicit as u8);
        pw.bytes16(self.relay_url.as_deref().unwrap_or("").as_bytes());
        pw.u8(self.mailbox_peer_explicit as u8);
        match &self.mailbox_peer {
            Some(mp) => {
                pw.u8(1);
                pw.raw(mp.as_bytes());
            }
            None => {
                pw.u8(0);
            }
        }
        let dir_str = self
            .custom_download_dir
            .as_ref()
            .and_then(|d| d.to_str())
            .unwrap_or("");
        pw.bytes16(dir_str.as_bytes());
        pw.u8(self.auto_copy_clipboard as u8);
        pw.u8(self.send_clipboard_shortcut as u8);
        if self.send_clipboard_shortcut_accel != DEFAULT_SEND_CLIPBOARD_SHORTCUT_ACCEL {
            pw.bytes16(self.send_clipboard_shortcut_accel.as_bytes());
        }
        pw.0
    }

    /// Sign new roster entries and persist. Persist failure is reported.
    fn commit(&mut self, store: &dyn StateStore) -> Result<(), NetError> {
        let Some(roster) = self.inbox.roster() else {
            return Err(NetError::Protocol("hub inbox has no roster".into()));
        };
        grouplog::sign_new_entries(roster, &self.identity, &mut self.signed, now().wall);
        self.sync_home_relay();
        self.rebuild_links();
        store.save(&self.encode()).map_err(NetError::Storage)?;
        self.saved_hw = self.inbox.replay_high_water();
        self.link_marks = self.current_link_marks();
        Ok(())
    }

    /// A pairing is gone for good (saved): delete its inbox's replay file.
    fn forget_seen_file(&self, pairing_id: &GroupId) {
        if let Some(d) = &self.seen_dir {
            let _ = std::fs::remove_file(seen_file(d, pairing_id));
        }
    }

    /// Re-derive the live v2 links from the pairing set, keeping the inbox
    /// (and its replay state) of each pairing that is still there.
    fn rebuild_links(&mut self) {
        let me = self.identity.device_id();
        let fresh = super::links::links_of(&me, &self.pairings);
        let mut old = std::mem::take(&mut self.links);
        for (peer, link) in fresh {
            let inbox = match old.remove(&peer) {
                Some(rt) if rt.link.pairing_id == link.pairing_id => {
                    let mut inbox = rt.inbox;
                    inbox.rebind(link.binding());
                    inbox
                }
                _ => {
                    let seen: Box<dyn SeenIdStore + Send> = match &self.seen_dir {
                        Some(d) => {
                            let path = seen_file(d, &link.pairing_id);
                            // A saved mark means the file must be there
                            // and still hold its last record.
                            let mark = self.link_marks.get(&link.pairing_id).copied();
                            match FileSeenIdStore::open_checked(path, now(), mark.is_some(), mark) {
                                Ok(s) => Box::new(s),
                                Err(_) => Box::new(NoPersistence),
                            }
                        }
                        None => Box::new(NoPersistence),
                    };
                    match Inbox::for_link(link.binding(), link.rx(), self.link_inbox, seen) {
                        Ok(i) => i,
                        Err(_) => continue,
                    }
                }
            };
            self.links.insert(peer, LinkRt { link, inbox });
        }
        self.sync_away();
    }

    /// The relay a live dial to `peer` goes through: its pairing relay,
    /// else (legacy pairings, v2 ones on no particular relay) our home.
    fn live_relay_for(&self, peer: &DeviceId) -> Option<String> {
        match self.links.get(peer).and_then(|l| l.link.relay.as_ref()) {
            Some(r) => Some(r.url.clone()),
            None => self.relay_url.clone(),
        }
    }

    /// Pairing relays other than home, most-used first.
    fn away_wanted(&self) -> Vec<String> {
        away_wanted_of(
            self.relay_url.as_deref(),
            self.links.values().filter_map(|l| l.link.relay.as_ref()),
        )
    }

    fn sync_away(&self) {
        if let Some(a) = &self.away {
            a.set_urls(self.away_wanted());
        }
    }

    /// The inbox `peer`'s messages are verified in.
    fn inbox_for(&self, peer: &DeviceId) -> &Inbox {
        self.links.get(peer).map_or(&self.inbox, |l| &l.inbox)
    }

    fn inbox_for_mut(&mut self, peer: &DeviceId) -> &mut Inbox {
        match self.links.get_mut(peer) {
            Some(l) => &mut l.inbox,
            None => &mut self.inbox,
        }
    }

    /// The inbox a message from `peer` was verified in: the legacy group's
    /// for a mid-split peer still sending there, else its own.
    fn inbox_by_tag(&self, peer: &DeviceId, tag: crate::verify::InboxTag) -> &Inbox {
        if self.inbox.tag() == tag {
            &self.inbox
        } else {
            self.inbox_for(peer)
        }
    }

    fn is_link(&self, peer: &DeviceId) -> bool {
        self.links.contains_key(peer)
    }

    /// Group, head and seal key for a message to `peer` (v2 link first).
    fn peer_ctx(&self, peer: &DeviceId) -> Result<PeerCtx, NetError> {
        if *peer == self.identity.device_id() {
            return Err(NetError::UnknownDevice);
        }
        if let Some(l) = self.links.get(peer) {
            return Ok(PeerCtx {
                group: l.link.pairing_id,
                head: l.link.head(),
                rk: l.link.peer_rx,
            });
        }
        Err(NetError::UnknownDevice)
    }
}

/// state.bin trailing section tags (after the signed log).
const STATE_SECTION_HIGH_WATER: u8 = 1;
const STATE_SECTION_RELAY: u8 = 2;
const STATE_SECTION_MAILBOX: u8 = 3;
const STATE_SECTION_FILE_STATS: u8 = 4;
const STATE_SECTION_PREFS: u8 = 5;
/// v2: pairings and relay settings (`net::pairings_state`).
const STATE_SECTION_PAIRWISE: u8 = 6;

/// The running PC node. Dropping it closes the endpoint.
pub struct PcNode {
    rt: tokio::runtime::Runtime,
    endpoint: Mutex<Endpoint>,
    accept_task: Mutex<tokio::task::JoinHandle<()>>,
    relay_watch: Mutex<Option<super::relay_watch::RelayWatch>>,
    port: Option<u16>,
    mdns: bool,
    shared: Arc<Shared>,
    advertise_loopback: bool,
    replay_health: Option<StoreHealth>,
}

impl std::fmt::Debug for PcNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcNode").finish_non_exhaustive()
    }
}

/// Loaded (or new) PC state: keys, roster, signed log, no-prompt flag, and
/// whether it already existed on disk.
type Loaded = (
    DeviceKeypair,
    ReceiveKeypair,
    Roster,
    Vec<SignedOp>,
    bool,
    bool,
    Option<HighWater>,
);

fn load_or_create(cfg: &PcConfig) -> Result<Loaded, NetError> {
    let blob = cfg
        .state
        .load()
        .map_err(NetError::Storage)?
        .map(zeroize::Zeroizing::new);
    if let Some(blob) = blob {
        let mut r = Reader::new(&blob);
        let bad = || NetError::Storage("state file is damaged or from another version".into());
        if !take_magic(&mut r) {
            return Err(bad());
        }
        let id_sk = read_secret(&mut r).ok_or_else(bad)?;
        let rx_sk = read_secret(&mut r).ok_or_else(bad)?;
        let flags = r.u8().ok_or_else(bad)?;
        let ops = read_ops(&mut r).ok_or_else(bad)?;
        let mut high_water = None;
        while !r.is_empty() {
            match r.u8().ok_or_else(bad)? {
                STATE_SECTION_HIGH_WATER => {
                    let b = r.take(HighWater::ENCODED_LEN).ok_or_else(bad)?;
                    high_water = Some(HighWater::decode(b).ok_or_else(bad)?);
                }
                STATE_SECTION_RELAY => {
                    let b = r.bytes16().ok_or_else(bad)?;
                    std::str::from_utf8(b).map_err(|_| bad())?;
                }
                STATE_SECTION_MAILBOX => {
                    let _ = r
                        .take(8 + crate::mailbox::SEALED_STATE_SECRET_LEN * 2)
                        .ok_or_else(bad)?;
                    let n = r.u16().ok_or_else(bad)? as usize;
                    let _ = r
                        .take(n * (8 + crate::mailbox::SEALED_STATE_SECRET_LEN))
                        .ok_or_else(bad)?;
                }
                STATE_SECTION_FILE_STATS => {
                    let _ = r.take(8).ok_or_else(bad)?;
                    let sb = r.bytes16().ok_or_else(bad)?;
                    let _ = crate::file_transfer::ConnectionStatsStore::from_bytes(sb)
                        .ok_or_else(bad)?;
                }
                STATE_SECTION_PAIRWISE => {
                    let _ = r.bytes32().ok_or_else(bad)?;
                }
                STATE_SECTION_PREFS => {
                    let _ = r.bytes16().ok_or_else(bad)?;
                }
                _ => return Err(bad()),
            }
        }
        let identity = DeviceKeypair::from_secret_bytes(&id_sk);
        let receive = ReceiveKeypair::from_secret_bytes(&rx_sk).ok_or_else(bad)?;
        let roster = grouplog::replay(&identity.device_id(), &ops).map_err(|_| bad())?;
        let own = roster
            .device(&identity.device_id())
            .and_then(|e| e.cert.as_ref())
            .ok_or_else(bad)?;
        if own.receive_key() != receive.public() {
            return Err(bad());
        }
        // Saved state keeps the stored open mode. M1 state files can't tell
        // "never touched" from an explicit "ask first", so a stored 0 stays
        // "Ask before opening" (an explicit choice is never overridden).
        return Ok((
            identity,
            receive,
            roster,
            ops,
            flags & 1 == 1,
            true,
            high_water,
        ));
    }
    let identity = DeviceKeypair::generate();
    let receive = ReceiveKeypair::generate();
    let cert = DeviceCert::issue(
        &identity,
        receive.public(),
        &cfg.device_name,
        Platform::current(),
        now().wall,
    )?;
    let mut g = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut g);
    if let Some(forced) = cfg.genesis_group_for_tests {
        #[cfg(feature = "test-util")]
        {
            g = forced.0;
        }
        #[cfg(not(feature = "test-util"))]
        {
            let _ = forced;
            return Err(NetError::Protocol(
                "genesis_group_for_tests needs test-util".into(),
            ));
        }
    }
    let roster = Roster::genesis_with_cert(GroupId(g), cert);
    // Fresh state: no-prompt is the default. A saved
    // state keeps its stored choice (see the load branch above).
    Ok((identity, receive, roster, Vec::new(), true, false, None))
}

fn load_saved_relay(store: &dyn StateStore) -> Option<String> {
    let blob = store.load().ok()??;
    let mut r = Reader::new(&blob);
    if !take_magic(&mut r) {
        return None;
    }
    let _ = read_secret(&mut r)?;
    let _ = read_secret(&mut r)?;
    let _ = r.u8()?;
    let _ = read_ops(&mut r)?;
    let mut relay = None;
    while !r.is_empty() {
        match r.u8()? {
            STATE_SECTION_HIGH_WATER => {
                let _ = r.take(HighWater::ENCODED_LEN)?;
            }
            STATE_SECTION_RELAY => {
                let b = r.bytes16()?;
                let s = std::str::from_utf8(b).ok()?;
                if !s.is_empty() {
                    relay = Some(s.to_owned());
                }
            }
            STATE_SECTION_MAILBOX => {
                let _ = r.take(8 + crate::mailbox::SEALED_STATE_SECRET_LEN * 2)?;
                let n = r.u16()? as usize;
                let _ = r.take(n * (8 + crate::mailbox::SEALED_STATE_SECRET_LEN))?;
            }
            STATE_SECTION_FILE_STATS => {
                let _ = r.take(8)?;
                let _ = r.bytes16()?;
            }
            STATE_SECTION_PAIRWISE => {
                let _ = r.bytes32()?;
            }
            STATE_SECTION_PREFS => {
                let _ = r.bytes16()?;
            }
            _ => break,
        }
    }
    relay
}

fn load_file_stats_state(
    store: &dyn StateStore,
) -> (
    crate::file_transfer::RelayTransferPolicy,
    crate::file_transfer::ConnectionStatsStore,
) {
    let mut policy = crate::file_transfer::RelayTransferPolicy::new();
    let mut stats = crate::file_transfer::ConnectionStatsStore::new();
    let Some(blob) = store.load().ok().flatten() else {
        return (policy, stats);
    };
    let mut r = Reader::new(&blob);
    if !take_magic(&mut r) {
        return (policy, stats);
    }
    let _ = read_secret(&mut r);
    let _ = read_secret(&mut r);
    let _ = r.u8();
    let _ = read_ops(&mut r);
    while !r.is_empty() {
        let Some(tag) = r.u8() else { break };
        match tag {
            STATE_SECTION_HIGH_WATER => {
                let _ = r.take(HighWater::ENCODED_LEN);
            }
            STATE_SECTION_RELAY => {
                let _ = r.bytes16();
            }
            STATE_SECTION_MAILBOX => {
                let _ = r.take(8 + crate::mailbox::SEALED_STATE_SECRET_LEN * 2);
                let Some(n) = r.u16() else { break };
                let _ = r.take(n as usize * (8 + crate::mailbox::SEALED_STATE_SECRET_LEN));
            }
            STATE_SECTION_FILE_STATS => {
                if let Some(cb) = r.take(8) {
                    let raw_cap = u64::from_be_bytes(cb.try_into().expect("8"));
                    // M2.8: Migrate legacy v0.2.0-m2 UI preset caps (5/25/100/500 MiB) to MAX_FILE_SIZE
                    // while preserving 0 ("Never send files over relay") and explicit test caps.
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
                    let _ = policy.set_user_cap_bytes(cap);
                }
                if let Some(sb) = r.bytes16() {
                    if let Some(decoded) =
                        crate::file_transfer::ConnectionStatsStore::from_bytes(sb)
                    {
                        stats = decoded;
                    }
                }
            }
            STATE_SECTION_PAIRWISE => {
                if r.bytes32().is_none() {
                    break;
                }
            }
            STATE_SECTION_PREFS => {
                let _ = r.bytes16();
            }
            _ => break,
        }
    }
    (policy, stats)
}

/// State v2 pairings section, if present. A damaged section fails closed.
fn load_pairwise_state(
    store: &dyn StateStore,
    identity: &DeviceKeypair,
) -> Result<Option<super::pairings_state::Section>, NetError> {
    let bad = || NetError::Storage("state file pairings are damaged".into());
    let Some(blob) = store.load().map_err(NetError::Storage)? else {
        return Ok(None);
    };
    let blob = zeroize::Zeroizing::new(blob);
    let mut r = Reader::new(&blob);
    if !take_magic(&mut r) {
        return Ok(None);
    }
    let _ = read_secret(&mut r).ok_or_else(bad)?;
    let _ = read_secret(&mut r).ok_or_else(bad)?;
    let _ = r.u8().ok_or_else(bad)?;
    let _ = read_ops(&mut r).ok_or_else(bad)?;
    while !r.is_empty() {
        match r.u8().ok_or_else(bad)? {
            STATE_SECTION_HIGH_WATER => {
                let _ = r.take(HighWater::ENCODED_LEN).ok_or_else(bad)?;
            }
            STATE_SECTION_RELAY | STATE_SECTION_PREFS => {
                let _ = r.bytes16().ok_or_else(bad)?;
            }
            STATE_SECTION_MAILBOX => {
                let _ = r
                    .take(8 + crate::mailbox::SEALED_STATE_SECRET_LEN * 2)
                    .ok_or_else(bad)?;
                let n = r.u16().ok_or_else(bad)? as usize;
                let _ = r
                    .take(n * (8 + crate::mailbox::SEALED_STATE_SECRET_LEN))
                    .ok_or_else(bad)?;
            }
            STATE_SECTION_FILE_STATS => {
                let _ = r.take(8).ok_or_else(bad)?;
                let _ = r.bytes16().ok_or_else(bad)?;
            }
            STATE_SECTION_PAIRWISE => {
                let b = r.bytes32().ok_or_else(bad)?;
                let id_sk = identity.secret_bytes();
                return super::pairings_state::decode_section(b, &id_sk)
                    .map(Some)
                    .ok_or_else(bad);
            }
            _ => return Err(bad()),
        }
    }
    Ok(None)
}

/// Default global keyboard shortcut accelerator for sending the PC clipboard (`M3.1.1`).
pub const DEFAULT_SEND_CLIPBOARD_SHORTCUT_ACCEL: &str = "Ctrl+Shift+V";

#[derive(Default)]
struct LoadedPrefs {
    keep_file_history: bool,
    relay_url_explicit: bool,
    relay_url: Option<String>,
    mailbox_peer_explicit: bool,
    mailbox_peer: Option<Option<DeviceId>>,
    custom_download_dir: Option<PathBuf>,
    auto_copy_clipboard: bool,
    send_clipboard_shortcut: bool,
    send_clipboard_shortcut_accel: Option<String>,
}

fn load_prefs_state(store: &dyn StateStore) -> LoadedPrefs {
    let mut out = LoadedPrefs::default();
    let Some(blob) = store.load().ok().flatten() else {
        return out;
    };
    let mut r = Reader::new(&blob);
    if !take_magic(&mut r) {
        return out;
    }
    let _ = read_secret(&mut r);
    let _ = read_secret(&mut r);
    let _ = r.u8();
    let _ = read_ops(&mut r);
    while !r.is_empty() {
        let Some(tag) = r.u8() else { break };
        match tag {
            STATE_SECTION_HIGH_WATER => {
                let _ = r.take(HighWater::ENCODED_LEN);
            }
            STATE_SECTION_RELAY => {
                let _ = r.bytes16();
            }
            STATE_SECTION_MAILBOX => {
                let _ = r.take(8 + crate::mailbox::SEALED_STATE_SECRET_LEN * 2);
                let Some(n) = r.u16() else { break };
                let _ = r.take(n as usize * (8 + crate::mailbox::SEALED_STATE_SECRET_LEN));
            }
            STATE_SECTION_FILE_STATS => {
                let _ = r.take(8);
                let _ = r.bytes16();
            }
            STATE_SECTION_PAIRWISE => {
                if r.bytes32().is_none() {
                    break;
                }
            }
            STATE_SECTION_PREFS => {
                let Some(pb) = r.bytes16() else { break };
                let mut pr = Reader::new(pb);
                if pr.u8() != Some(1) {
                    break;
                }
                out.keep_file_history = pr.u8().unwrap_or(0) != 0;
                out.relay_url_explicit = pr.u8().unwrap_or(0) != 0;
                if let Some(rb) = pr.bytes16() {
                    if let Ok(rs) = std::str::from_utf8(rb) {
                        out.relay_url = if rs.is_empty() {
                            None
                        } else {
                            Some(rs.to_owned())
                        };
                    }
                }
                out.mailbox_peer_explicit = pr.u8().unwrap_or(0) != 0;
                match pr.u8() {
                    Some(1) => {
                        if let Some(arr) = pr.arr32() {
                            if let Ok(id) = DeviceId::from_bytes(arr) {
                                out.mailbox_peer = Some(Some(id));
                            }
                        }
                    }
                    Some(0) => {
                        out.mailbox_peer = Some(None);
                    }
                    _ => {}
                }
                if let Some(db) = pr.bytes16() {
                    if let Ok(ds) = std::str::from_utf8(db) {
                        if !ds.trim().is_empty() {
                            out.custom_download_dir = Some(PathBuf::from(ds));
                        }
                    }
                }
                if !pr.is_empty() {
                    out.auto_copy_clipboard = pr.u8().unwrap_or(0) != 0;
                }
                if !pr.is_empty() {
                    out.send_clipboard_shortcut = pr.u8().unwrap_or(0) != 0;
                }
                if !pr.is_empty() {
                    if let Some(ab) = pr.bytes16() {
                        if let Ok(s) = std::str::from_utf8(ab) {
                            let trimmed = s.trim();
                            if !trimmed.is_empty() {
                                out.send_clipboard_shortcut_accel = Some(trimmed.to_owned());
                            }
                        }
                    }
                }
            }
            _ => break,
        }
    }
    out
}

/// How often a PC sends its own mDNS query (0.8.1 field test: the 700 ms
/// default kept the LAN busy all day for nothing).
pub const PC_MDNS_CADENCE: Duration = Duration::from_secs(30);

async fn bind_endpoint(
    identity: &DeviceKeypair,
    port: Option<u16>,
    mdns: bool,
    relay_url: Option<&str>,
) -> Result<Endpoint, NetError> {
    let (relay_mode, _) = super::build_relay_mode(relay_url)?;
    let try_bind = |port: u16, relay_mode: RelayMode| async move {
        let mut b = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&identity.secret_bytes()))
            .alpns(vec![ALPN_PAIR.to_vec(), ALPN_APP.to_vec()])
            .relay_mode(relay_mode)
            .clear_address_lookup()
            .net_report_config(super::default_net_report_config())
            .bind_addr(SocketAddr::from(([0, 0, 0, 0], port)))
            .map_err(|e| NetError::Unreachable(format!("bind: {e}")))?;
        if mdns {
            b = b.address_lookup(
                iroh_mdns_address_lookup::MdnsAddressLookup::builder()
                    .service_name(MDNS_SERVICE)
                    .advertise(true)
                    // Queries from others are answered at once whatever
                    // the cadence; this only spaces out the PC's own
                    // queries (700 ms by default: needless LAN chatter).
                    .discovery_cadence(PC_MDNS_CADENCE),
            );
        }
        b.bind()
            .await
            .map_err(|e| NetError::Unreachable(format!("bind: {e}")))
    };
    match port {
        Some(p) => try_bind(p, relay_mode).await,
        None => match try_bind(PREFERRED_PORT, relay_mode.clone()).await {
            Ok(e) => Ok(e),
            Err(_) => try_bind(0, relay_mode).await,
        },
    }
}

fn spawn_accept_loop(
    rt: &tokio::runtime::Runtime,
    ep: Endpoint,
    sh: Arc<Shared>,
) -> tokio::task::JoinHandle<()> {
    rt.spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let sh = sh.clone();
            tokio::spawn(async move {
                let Ok(accepting) = incoming.accept() else {
                    return;
                };
                let Ok(conn) = accepting.await else { return };
                if conn.alpn() == ALPN_PAIR {
                    handle_pair(sh, conn).await;
                } else if conn.alpn() == ALPN_APP {
                    handle_app(sh, conn).await;
                } else {
                    conn.close(close_code(RejectReason::MalformedFrame), b"alpn");
                }
            });
        }
    })
}

impl PcNode {
    /// Load (or create) state, bind the listener, start accepting.
    pub fn start(cfg: PcConfig) -> Result<PcNode, NetError> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("voidwire-net")
            .enable_all()
            .build()
            .map_err(|e| NetError::Protocol(format!("runtime: {e}")))?;
        let (identity, receive, roster, signed, no_prompt, initialised, high_water) =
            load_or_create(&cfg)?;
        let receive_secret = receive.secret_bytes();
        let mut replay_health = None;
        let seen: Box<dyn SeenIdStore + Send> = match &cfg.seen_store_path {
            Some(p) => {
                if let Some(d) = p.parent() {
                    // 0700 / current-user-only DACL before any file is created.
                    super::state::private_dir(d)
                        .map_err(|e| NetError::Storage(format!("data dir: {e}")))?;
                }
                let store =
                    FileSeenIdStore::open_checked(p.clone(), now(), initialised, high_water)
                        .map_err(|e| NetError::Storage(format!("replay cache: {e}")))?;
                replay_health = Some(store.health());
                Box::new(store)
            }
            None => Box::new(NoPersistence),
        };
        let inbox = if cfg.unchecked_inbox_for_tests {
            #[cfg(feature = "test-util")]
            {
                Inbox::new_unchecked_for_tests(roster, receive, cfg.inbox, seen)
            }
            #[cfg(not(feature = "test-util"))]
            {
                return Err(NetError::Protocol("unchecked inbox needs test-util".into()));
            }
        } else {
            Inbox::with_store(roster, receive, cfg.inbox, seen)
        }
        .map_err(|e| NetError::Protocol(format!("inbox: {e}")))?;
        let (relay_policy, conn_stats) = load_file_stats_state(&*cfg.state);
        let prefs = load_prefs_state(&*cfg.state);
        let (pairings, relay_settings, outbox, link_marks) =
            match load_pairwise_state(&*cfg.state, &identity)? {
                Some(v) => v,
                // v1 file (v0.4.x) or a new device: split on the first commit.
                None => (
                    crate::pairwise::PairingSet::new(),
                    crate::pairwise::RelaySettings::new(super::pairings_state::builtin_relay()),
                    super::outbox::Outbox::default(),
                    Default::default(),
                ),
            };
        let default_download_dir = cfg.download_dir.clone().unwrap_or_else(|| {
            if let Some(parent) = cfg.seen_store_path.as_ref().and_then(|p| p.parent()) {
                return parent.join("downloads");
            }
            if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
                if !home.is_empty() {
                    return PathBuf::from(home).join("Downloads").join("Voidwire");
                }
            }
            std::env::temp_dir().join(format!("voidwire-files-{}", identity.device_id().short()))
        });
        // `cfg.download_dir` is only the default. The folder the user picked
        // (saved in state.bin) always wins: the app passes its default on
        // every start, and treating that as an override wiped the choice on
        // each restart and upgrade (v0.7.1).
        let custom_download_dir = prefs
            .custom_download_dir
            .clone()
            .filter(|d| *d != default_download_dir);
        let download_dir = custom_download_dir
            .clone()
            .unwrap_or_else(|| default_download_dir.clone());
        let _ = super::state::private_dir(&download_dir);
        // Nothing is in flight yet: whatever we left behind is stale.
        crate::file_transfer::purge_stale_parts(&download_dir);
        let default_cfg_relay = super::resolve_relay_url(None);
        let resolved_relay_url = if prefs.relay_url_explicit && cfg.relay_url == default_cfg_relay {
            prefs.relay_url.clone()
        } else {
            cfg.relay_url
                .clone()
                .or_else(|| load_saved_relay(&*cfg.state))
        };
        let (resolved_mb_peer, resolved_mb_explicit) = if prefs.mailbox_peer_explicit
            && std::env::var(super::mailbox_client::ENV_MAILBOX_ID).is_err()
        {
            (
                prefs
                    .mailbox_peer
                    .unwrap_or_else(|| super::mailbox_client::resolve_mailbox_id(None)),
                prefs
                    .mailbox_peer
                    .flatten()
                    .is_some_and(|p| p != super::mailbox_client::default_mailbox_device_id()),
            )
        } else {
            (
                super::mailbox_client::resolve_mailbox_id(None),
                std::env::var(super::mailbox_client::ENV_MAILBOX_ID).is_ok(),
            )
        };
        let mut state = PcState {
            identity,
            receive_secret,
            inbox,
            signed,
            no_prompt,
            pending: BTreeMap::new(),
            next_pending: 1,
            conns: HashMap::new(),
            prompt_ttl_ms: cfg.prompt_ttl_ms.clamp(1, PENDING_PROMPT_TTL_MS),
            saved_hw: None,
            relay_url: resolved_relay_url,
            mailbox_peer: resolved_mb_peer,
            mailbox_peer_explicit: resolved_mb_explicit,
            last_throwaway_id: None,
            download_dir,
            default_download_dir,
            custom_download_dir,
            keep_file_history: prefs.keep_file_history,
            relay_url_explicit: prefs.relay_url_explicit,
            auto_accept_files: cfg.auto_accept_files,
            auto_copy_clipboard: prefs.auto_copy_clipboard,
            send_clipboard_shortcut: prefs.send_clipboard_shortcut,
            send_clipboard_shortcut_accel: prefs
                .send_clipboard_shortcut_accel
                .unwrap_or_else(|| DEFAULT_SEND_CLIPBOARD_SHORTCUT_ACCEL.to_owned()),
            pending_clipboards: BTreeMap::new(),
            phone_addrs: HashMap::new(),
            outbound_files: HashMap::new(),
            cancelled_outbound_files: std::collections::VecDeque::new(),
            incoming_files: HashMap::new(),
            declined_files: std::collections::VecDeque::new(),
            ended_outbound: std::collections::VecDeque::new(),
            completed_files: Vec::new(),
            relay_policy,
            conn_stats,
            pairings,
            relay_settings,
            links: HashMap::new(),
            drains: Vec::new(),
            unsent_ops: Default::default(),
            last_focus_pull: None,
            outbox,
            seen_dir: cfg
                .seen_store_path
                .as_ref()
                .and_then(|p| p.parent())
                .map(|d| d.to_path_buf()),
            link_inbox: cfg.inbox,
            link_marks,
            away: None,
        };
        state.commit(&*cfg.state)?;
        let endpoint = rt.block_on(bind_endpoint(
            &state.identity,
            cfg.port,
            cfg.mdns,
            state.relay_url.as_deref().or(Some("off")),
        ))?;
        let shared = Arc::new(Shared {
            state: Mutex::new(state),
            store: cfg.state.clone(),
            opener: cfg.opener.clone(),
            events: cfg.events.clone(),
            advertise_loopback: cfg.advertise_loopback,
            mdns: cfg.mdns,
            hold_unpair_send: std::sync::atomic::AtomicBool::new(false),
            hold_outbound_chunks: std::sync::atomic::AtomicBool::new(false),
            event_skew_ms: std::sync::atomic::AtomicU64::new(0),
            inbox_pulls: std::sync::atomic::AtomicU64::new(0),
            stall_cv: std::sync::Condvar::new(),
            stall_stop: std::sync::atomic::AtomicBool::new(false),
            stall_wakeups: std::sync::atomic::AtomicU64::new(0),
            host2: Mutex::new(Default::default()),
            join2: Mutex::new(Default::default()),
            file_progress: tokio::sync::Notify::new(),
            relay_change: Mutex::new(Default::default()),
        });
        let accept_task = spawn_accept_loop(&rt, endpoint.clone(), shared.clone());
        {
            let weak = Arc::downgrade(&shared);
            let serve: super::away::Serve = Arc::new(move |incoming| {
                let weak = weak.clone();
                tokio::spawn(async move {
                    let Ok(accepting) = incoming.accept() else {
                        return;
                    };
                    let Ok(conn) = accepting.await else { return };
                    let Some(sh) = weak.upgrade() else { return };
                    if conn.alpn() == ALPN_APP {
                        handle_app(sh, conn).await;
                    } else {
                        conn.close(close_code(RejectReason::MalformedFrame), b"alpn");
                    }
                });
            });
            let busy: super::away::Busy = Arc::new(|| false);
            let secret = *shared.lock().identity.secret_bytes();
            let away = super::away::Away::new(rt.handle().clone(), secret, serve, busy);
            away.set_mode(crate::relay_supervisor::DeviceMode::Pc);
            let mut st = shared.lock();
            st.away = Some(away);
            st.sync_away();
        }
        let relay_watch = super::relay_watch::for_app_endpoint(
            rt.handle(),
            &endpoint,
            shared.lock().relay_url.as_deref().or(Some("off")),
            crate::relay_supervisor::DeviceMode::Pc,
        );
        let node = PcNode {
            rt,
            endpoint: Mutex::new(endpoint),
            accept_task: Mutex::new(accept_task),
            relay_watch: Mutex::new(relay_watch),
            port: cfg.port,
            mdns: cfg.mdns,
            shared,
            advertise_loopback: cfg.advertise_loopback,
            replay_health,
        };
        // Event: start. Anything v2 peers queued while we were off, and
        // unpair notices a previous run couldn't deliver.
        if node.shared.lock().has_inbox_work() {
            let sh = node.shared.clone();
            node.rt.spawn(async move {
                let _ = pull_link_inboxes(&sh).await;
            });
        }
        Ok(node)
    }

    pub fn device_id(&self) -> DeviceId {
        self.shared.lock().identity.device_id()
    }

    /// What the on-disk replay cache looked like at startup (`None`: in
    /// memory). `Missing`/`Corrupt` mean the startup guard is on.
    pub fn replay_cache_health(&self) -> Option<StoreHealth> {
        self.replay_health
    }

    pub fn device_name(&self) -> String {
        let st = self.shared.lock();
        st.name_of(&st.identity.device_id())
    }

    /// UDP sockets the listener is bound to.
    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.endpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .bound_sockets()
    }

    /// Direct-address hints for the QR: LAN interface addresses (and
    /// loopback when configured), with the bound port.
    pub fn direct_addrs(&self) -> Vec<SocketAddr> {
        let ep = self
            .endpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut v: Vec<SocketAddr> = ep
            .addr()
            .ip_addrs()
            .copied()
            .filter(|a| match a.ip() {
                std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
                std::net::IpAddr::V6(ip) => {
                    (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80
                }
            })
            .filter(|a| !a.ip().is_loopback())
            .collect();
        v.sort_by_key(|a| (a.is_ipv6(), *a));
        v.dedup();
        if self.advertise_loopback {
            for s in ep.bound_sockets() {
                if s.is_ipv4() {
                    v.insert(0, SocketAddr::from(([127, 0, 0, 1], s.port())));
                }
            }
        }
        v.truncate(crate::pairing::MAX_QR_ADDRS);
        v
    }

    // ---- pairing (the "Pair device" window) ----

    /// M4.3: the saved relays (for the relay picker on invites).
    pub fn saved_relays(&self) -> Vec<super::pair2::SavedRelay> {
        super::pair2::saved_relays(&*self.shared)
    }

    /// M4.3: show a code (and a `v=2` QR) for another device to join, over
    /// `relay_url` (a saved relay; `None`: this PC's relay). Replaces any
    /// code already showing.
    pub fn pair2_show(&self, relay_url: Option<&str>) -> Result<super::pair2::ShowInfo, NetError> {
        let addrs = self.direct_addrs();
        let dial = self.shared.lock().relay_url.clone();
        let sh = self.shared.clone();
        let relay = relay_url.map(str::to_owned);
        self.block_on_rt(async move {
            super::pair2::show(&*sh, relay.as_deref(), dial.as_deref(), &addrs, now()).await
        })
    }

    /// Test harness (M4.3): save a relay (with its mailbox) for the picker.
    #[cfg(feature = "test-util")]
    pub fn add_saved_relay_for_tests(
        &self,
        relay: crate::pairwise::RelayRef,
    ) -> Result<(), NetError> {
        super::pair2::Node2::save_relay(
            &*self.shared,
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
        let n = now();
        let then = Now {
            wall: crate::time::UnixMillis(n.wall.0.saturating_sub(age_ms)),
            mono: crate::time::MonoMillis(n.mono.0.saturating_sub(age_ms)),
        };
        let inner = self.shared.clone();
        let relay = relay_url.map(str::to_owned);
        // On the node's own runtime, so the card's later deletion runs.
        self.block_on_rt(async move {
            super::pair2::show(&*inner, relay.as_deref(), None, &[], then).await
        })
    }

    /// M4.3: the showing screen's state.
    pub fn pair2_status(&self) -> super::pair2::HostStatus {
        use super::pair2::Node2;
        self.shared.host().status(now())
    }

    /// M4.3: the user typed the 6-digit code the other device shows. One
    /// try; returns the new peer once both sides kept the pairing.
    pub fn pair2_submit_code(&self, sas: &str) -> Result<super::pair2::Paired2, NetError> {
        super::pair2::host_submit(&*self.shared, sas, now())
    }

    /// M4.3: close the showing screen (the code stops working).
    pub fn pair2_cancel(&self) {
        use super::pair2::Node2;
        self.shared.host().cancel(now());
        super::pair2::join_cancel(&*self.shared);
    }

    /// M4.3: open a typed code, fetched from `relay_url` (a saved relay;
    /// `None`: the public relay).
    pub fn pair2_open_code(
        &self,
        code: &str,
        relay_url: Option<&str>,
    ) -> Result<super::pair2::Opened, NetError> {
        let sh = self.shared.clone();
        let (code, relay) = (code.to_owned(), relay_url.map(str::to_owned));
        self.block_on_rt(async move {
            super::pair2::open_code(&*sh, &code, relay.as_deref(), now()).await
        })
    }

    /// M4.3: open a `v=2` pairing QR (pasted or scanned).
    pub fn pair2_open_qr(&self, uri: &str) -> Result<super::pair2::Opened, NetError> {
        super::pair2::open_qr(&*self.shared, uri, now())
    }

    /// M4.3: the user chose [Add and pair] for the invite's relay.
    pub fn pair2_add_relay(&self) -> Result<(), NetError> {
        super::pair2::add_pending_relay(&*self.shared)
    }

    /// M4.3: connect to the inviter; returns the 6-digit code to show.
    pub fn pair2_join(&self) -> Result<String, NetError> {
        let sh = self.shared.clone();
        let ep = self
            .endpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        self.block_on_rt(async move { super::pair2::join_begin(&*sh, &ep).await })
    }

    /// M4.3: wait until the other device's user typed our code.
    pub fn pair2_join_wait(&self) -> Result<super::pair2::Paired2, NetError> {
        let sh = self.shared.clone();
        self.block_on_rt(async move { super::pair2::join_wait(&*sh).await })
    }

    // ---- devices ----

    pub fn devices(&self) -> Vec<DeviceInfo> {
        let st = self.shared.lock();
        let mut v: Vec<DeviceInfo> = st.links.keys().map(|id| device_info(&st, id)).collect();
        v.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then(a.id.as_bytes().cmp(b.id.as_bytes()))
        });
        v
    }

    /// "Forget this device": local and immediate. Drops its connections and
    /// prompts; a signed remove op goes into the log (delivered to the
    /// device on its next sync).
    ///
    /// Save first, then act: if writing state fails, the removal is rolled
    /// back in memory, the device stays paired, and it is not told anything
    /// (QA 10-13: a failed save used to leave memory and disk diverged).
    pub fn forget_device(&self, id: &DeviceId) -> Result<bool, NetError> {
        let linked = self.shared.lock().is_link(id);
        if linked {
            self.unpair_link(id)?;
        }
        Ok(linked)
    }

    /// Unpair a v2 peer (M4.2, spec §6): erase the pairing at once, then
    /// send the signed unpair op in the background, best effort: live (an
    /// open connection or one dial), else into its pairing inbox. Forget
    /// returns without waiting on the network.
    fn unpair_link(&self, id: &DeviceId) -> Result<(), NetError> {
        let (env, target, conn, addrs, relay_url) = {
            let mut st = self.shared.lock();
            let st = &mut *st;
            let l = st.links.get(id).ok_or(NetError::UnknownDevice)?;
            let (pairing_id, head, rk) = (l.link.pairing_id, l.link.head(), l.link.peer_rx);
            let target = l.link.peer_inbox(st.relay_url.as_deref(), home_mailbox(st));
            let conn = st
                .conns
                .get(id)
                .and_then(|v| v.iter().rev().find(|c| c.close_reason().is_none()).cloned());
            let ts = now().wall;
            // Signed on a copy: the stored log is untouched if the erase
            // can't be saved.
            let op = st
                .pairings
                .get(&pairing_id)
                .and_then(|p| p.log.clone())
                .ok_or(NetError::UnknownDevice)?
                .unpair(&st.identity, ts)
                .map_err(|_| NetError::Rejected(RejectReason::BadLogOp))?;
            let body = crate::wire::encode_signed_pair_notice(
                &st.identity,
                &crate::wire::OutgoingPairNotice {
                    group: pairing_id,
                    recipient: *id,
                    log_head: head,
                    msg_id: crate::ids::MsgId::random(),
                    timestamp: ts,
                    op: &op.encode(),
                },
            )?;
            let addrs = st.phone_addrs.get(id).cloned().unwrap_or_default();
            let relay_url = st.live_relay_for(id);
            let env = crate::envelope::seal(id, &rk, &body)?;
            // Durable: saved with the erase, sent even if we're killed now.
            let item = target
                .as_ref()
                .and_then(|t| super::outbox::OutboxItem::new(t, env.clone(), ts));
            if let Some(i) = &item {
                st.outbox.push(i.clone());
            }
            (env, item, conn, addrs, relay_url)
        };
        if let Err(e) = erase_link(&self.shared, id, false) {
            if let Some(i) = &target {
                self.shared.lock().outbox.delivered(i);
            }
            return Err(e);
        }
        if self
            .shared
            .hold_unpair_send
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }
        let sh = self.shared.clone();
        let ep = self
            .endpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mdns = self.mdns;
        let peer = *id;
        self.rt.spawn(async move {
            let mut live = match &conn {
                Some(c) => send_notice_on(c, &env).await.is_ok(),
                None => false,
            };
            if !live {
                if let Ok(c) = dial_peer_raw(&sh, ep, mdns, peer, addrs, relay_url).await {
                    live = send_notice_on(&c, &env).await.is_ok();
                    c.close(0u32.into(), b"");
                }
            }
            if live {
                if let Some(i) = &target {
                    let mut st = sh.lock();
                    st.outbox.delivered(i);
                    let _ = st.commit(&*sh.store);
                }
            } else {
                flush_outbox(&sh, false).await;
            }
            let mut st = sh.lock();
            if !st.is_link(&peer) {
                st.phone_addrs.remove(&peer);
                for c in st.conns.remove(&peer).unwrap_or_default() {
                    c.close(close_code(RejectReason::Removed), b"removed");
                }
            }
        });
        Ok(())
    }

    /// Unpair notices saved but not yet delivered (tests, diagnostics).
    pub fn pending_unpair_notices(&self) -> usize {
        self.shared.lock().outbox.len()
    }

    /// Test seam: unpairing saves the notice but doesn't send it, like an
    /// app killed right after the erase.
    #[cfg(feature = "test-util")]
    pub fn hold_unpair_send_for_tests(&self, hold: bool) {
        self.shared
            .hold_unpair_send
            .store(hold, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test seam: the sender holds its chunks, like a transfer whose
    /// receiver went quiet after accepting.
    #[cfg(feature = "test-util")]
    pub fn hold_outbound_chunks_for_tests(&self, hold: bool) {
        self.shared
            .hold_outbound_chunks
            .store(hold, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test seam: move the event-pull gate's clock forward by `ms`.
    #[cfg(feature = "test-util")]
    pub fn advance_event_clock_for_tests(&self, ms: u64) {
        self.shared
            .event_skew_ms
            .fetch_add(ms, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test seam: inbox pulls actually started (gated ones don't count).
    #[cfg(feature = "test-util")]
    pub fn inbox_pulls_for_tests(&self) -> u64 {
        self.shared
            .inbox_pulls
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Test harness (M4.2): this PC's identity and certificate, to make a
    /// v2 pairing with [`crate::net::pair_v2_for_tests`].
    #[cfg(feature = "test-util")]
    pub fn v2_identity_for_tests(&self) -> (DeviceKeypair, DeviceCert) {
        let st = self.shared.lock();
        let me = st.identity.device_id();
        let kp = DeviceKeypair::from_secret_bytes(&st.identity.secret_bytes());
        let cert = st
            .inbox
            .roster()
            .and_then(|r| r.device(&me))
            .and_then(|e| e.cert.clone())
            .expect("own cert");
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
        let st = self.shared.lock();
        let me = st.identity.device_id();
        st.links.get(peer).map(|l| l.link.inbox_keys_for_tests(&me))
    }

    /// Test harness (M4.3): the inbox derivation inputs of the v2 pairing
    /// with `peer`.
    #[cfg(feature = "test-util")]
    pub fn pairing_inbox_inputs_for_tests(
        &self,
        peer: &DeviceId,
    ) -> Option<super::PairingInboxInputs> {
        let st = self.shared.lock();
        st.links.get(peer).map(|l| l.link.inbox_inputs_for_tests())
    }

    /// Test harness (M4.2): take a v2 pairing made outside the pairing
    /// flows (those arrive in M4.3). `addrs`: the peer's direct addresses.
    #[cfg(feature = "test-util")]
    pub fn adopt_v2_pairing_for_tests(
        &self,
        p: crate::pairwise::Pairing,
        addrs: Vec<SocketAddr>,
    ) -> Result<(), NetError> {
        let mut st = self.shared.lock();
        let me = st.identity.device_id();
        let peer = p
            .log
            .as_ref()
            .and_then(|l| l.peer_of(&me))
            .ok_or(NetError::UnknownDevice)?;
        st.pairings
            .add(p)
            .map_err(|_| NetError::Rejected(RejectReason::BadLogOp))?;
        if !addrs.is_empty() {
            st.phone_addrs.insert(peer, addrs);
        }
        st.commit(&*self.shared.store)
    }

    /// Pull this PC's v2 pairing inboxes now (M4.2; one session per relay).
    /// For events only (start, the window coming to the front); never
    /// called on a timer.
    pub fn pull_pairing_inboxes_now(&self) -> Result<usize, NetError> {
        let sh = self.shared.clone();
        self.block_on_rt(async move { pull_link_inboxes(&sh).await })
    }

    /// Pull the v2 pairing inboxes because the Devices window came to the
    /// front; skipped when the last such pull was under
    /// [`super::phone::EVENT_PULL_MIN_GAP_MS`] ago. Never timer-driven.
    pub fn pull_pairing_inboxes_on_focus(&self) -> Result<usize, NetError> {
        let skew = self
            .shared
            .event_skew_ms
            .load(std::sync::atomic::Ordering::SeqCst);
        let t = now().mono.saturating_add(skew);
        {
            let mut st = self.shared.lock();
            if !st.has_inbox_work() {
                return Ok(0);
            }
            if let Some(prev) = st.last_focus_pull {
                if t.saturating_sub(prev) < super::phone::EVENT_PULL_MIN_GAP_MS {
                    return Ok(0);
                }
            }
            st.last_focus_pull = Some(t);
        }
        self.pull_pairing_inboxes_now()
    }

    pub fn log_head(&self) -> LogHead {
        self.shared.lock().inbox.head()
    }

    /// Configure the blind mailbox service `DeviceId` (or `None` to disable).
    pub fn set_mailbox_peer(&self, peer: Option<DeviceId>) {
        let mut st = self.shared.lock();
        st.mailbox_peer = peer;
        st.mailbox_peer_explicit = true;
        let _ = st.commit(&*self.shared.store);
    }

    /// Configured blind mailbox endpoint `DeviceId` (`M2.8` alias for `mailbox_peer`).
    pub fn mailbox_id(&self) -> Option<DeviceId> {
        self.mailbox_peer()
    }

    /// Set or reset the blind mailbox endpoint `DeviceId` and persist in `state.bin` (`M2.8`).
    pub fn set_mailbox_id(&self, peer: Option<DeviceId>) -> Result<(), NetError> {
        let mut st = self.shared.lock();
        let is_default = peer == Some(super::mailbox_client::default_mailbox_device_id());
        st.mailbox_peer = peer;
        st.mailbox_peer_explicit = !is_default;
        st.commit(&*self.shared.store)
    }

    /// Configured blind mailbox service `DeviceId`.
    pub fn mailbox_peer(&self) -> Option<DeviceId> {
        self.shared.lock().mailbox_peer
    }

    /// Ephemeral `DeviceId` used on the most recent throwaway mailbox session.
    pub fn last_throwaway_id(&self) -> Option<DeviceId> {
        self.shared.lock().last_throwaway_id
    }

    fn block_on_rt<F>(&self, fut: F) -> F::Output
    where
        F: std::future::Future + Send,
        F::Output: Send,
    {
        if tokio::runtime::Handle::try_current().is_ok() {
            std::thread::scope(|s| {
                s.spawn(|| self.rt.block_on(fut))
                    .join()
                    .unwrap_or_else(|p| std::panic::resume_unwind(p))
            })
        } else {
            self.rt.block_on(fut)
        }
    }

    // ---- settings ----

    pub fn no_prompt(&self) -> bool {
        self.shared.lock().no_prompt
    }

    /// Open without asking. On by default for a fresh PC;
    /// `false` is the "Ask before opening" setting.
    pub fn set_no_prompt(&self, on: bool) -> Result<(), NetError> {
        let mut st = self.shared.lock();
        st.no_prompt = on;
        st.commit(&*self.shared.store)
    }

    /// Configured relay URL (`Some("https://relay.voidwire.app")` by default).
    pub fn relay_url(&self) -> Option<String> {
        self.shared.lock().relay_url.clone()
    }

    /// Set or reset the relay URL (`None` or empty string resets to `DEFAULT_RELAY_URL`;
    /// `"off"` / `"none"` / `"disabled"` disables the relay), validating the URL and
    /// rebinding the active endpoint without blocking indefinitely on teardown (`M2.9`).
    pub fn set_relay_url(&self, relay_url: Option<String>) -> Result<(), NetError> {
        let normalized = match relay_url.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(s) => Some(s),
        };
        let (_, parsed) = super::build_relay_mode(normalized)?;
        let resolved = parsed.map(|u| u.as_str().trim_end_matches('/').to_owned());
        let (identity, old_conns) = {
            let mut st = self.shared.lock();
            st.relay_url = resolved.clone();
            st.relay_url_explicit = normalized.is_some();
            st.sync_away();
            st.relay_policy
                .set_server_cap_bytes(crate::file_transfer::DEFAULT_RELAY_FILE_CAP_BYTES);
            st.commit(&*self.shared.store)?;
            let conns: Vec<_> = st.conns.drain().flat_map(|(_, v)| v).collect();
            (
                DeviceKeypair::from_secret_bytes(&st.identity.secret_bytes()),
                conns,
            )
        };
        for c in old_conns {
            c.close(0u32.into(), b"relay_changed");
        }
        self.accept_task
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .abort();
        if self.port.unwrap_or(0) != 0 {
            let ep_clone = self
                .endpoint
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            self.block_on_rt(async move {
                let _ = tokio::time::timeout(Duration::from_millis(100), ep_clone.close()).await;
            });
        }
        let new_ep = self.block_on_rt(bind_endpoint(
            &identity,
            self.port,
            self.mdns,
            resolved.as_deref().or(Some("off")),
        ))?;
        let new_task = spawn_accept_loop(&self.rt, new_ep.clone(), self.shared.clone());
        *self.relay_watch.lock().unwrap_or_else(|p| p.into_inner()) =
            super::relay_watch::for_app_endpoint(
                self.rt.handle(),
                &new_ep,
                resolved.as_deref().or(Some("off")),
                crate::relay_supervisor::DeviceMode::Pc,
            );
        let old_ep = std::mem::replace(
            &mut *self.endpoint.lock().unwrap_or_else(|p| p.into_inner()),
            new_ep,
        );
        *self.accept_task.lock().unwrap_or_else(|p| p.into_inner()) = new_task;
        self.rt.spawn(async move {
            old_ep.close().await;
        });
        Ok(())
    }

    // ---- M4.4 relays ----

    /// Away relays open now: (url, held) (tests).
    #[cfg(feature = "test-util")]
    pub fn away_relays_for_tests(&self) -> Vec<(String, bool)> {
        self.shared
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
        self.shared
            .lock()
            .away
            .clone()
            .map(|a| a.opened())
            .unwrap_or(0)
    }

    fn relay_status(&self, url: &str, used: bool) -> super::relays::RelayStatus {
        use super::relays::RelayStatus;
        let st = self.shared.lock();
        let home = st
            .relay_url
            .as_deref()
            .is_some_and(|h| super::away::same_relay(h, url));
        let stats = if home {
            self.relay_watch
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .map(|w| w.stats())
        } else {
            st.away.as_ref().and_then(|a| {
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
        let (rs, pr) = {
            let st = self.shared.lock();
            (
                st.relay_settings.clone(),
                super::relay_change::pairing_relays(&st.pairings, None),
            )
        };
        super::relays::list(&rs, &pr, |u, used| self.relay_status(u, used))
    }

    fn edit_relays(
        &self,
        f: impl FnOnce(
            &mut crate::pairwise::RelaySettings,
            &[Option<String>],
        ) -> Result<(), super::relays::RelayError>,
    ) -> Result<(), super::relays::RelayError> {
        {
            let mut st = self.shared.lock();
            let pr = super::relay_change::pairing_relays(&st.pairings, None);
            let mut rs = st.relay_settings.clone();
            f(&mut rs, &pr)?;
            st.relay_settings = rs;
            st.commit(&*self.shared.store)?;
        }
        self.shared.emit(PcEvent::DevicesChanged);
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
        if let Some(a) = self.shared.lock().away.clone() {
            a.forget(url);
        }
        Ok(())
    }

    pub fn rename_relay(&self, url: &str, nickname: &str) -> Result<(), super::relays::RelayError> {
        self.edit_relays(|rs, _| super::relays::rename(rs, url, nickname))
    }

    /// Settings → Relays → Retry: try a relay now, outside its backoff.
    pub fn retry_relay(&self, url: &str) {
        let home = self
            .shared
            .lock()
            .relay_url
            .as_deref()
            .is_some_and(|h| super::away::same_relay(h, url));
        if home {
            if let Some(w) = self
                .relay_watch
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
            {
                w.retry_now();
            }
        } else if let Some(a) = self.shared.lock().away.clone() {
            a.retry_relay(url);
        }
    }

    /// Propose moving the pairing with `peer` to the saved relay `url`.
    /// Both devices must be online; the other device's user must allow it
    /// (see [`PcNode::relay_change_statuses`]).
    pub fn change_pairing_relay(
        &self,
        peer: &DeviceId,
        url: &str,
    ) -> Result<(), super::relays::RelayError> {
        use super::relay_change as rc;
        let (relay, name) = {
            let st = self.shared.lock();
            let relay = st
                .relay_settings
                .relays
                .iter()
                .find(|e| super::away::same_relay(&e.relay.url, url))
                .map(|e| e.relay.clone())
                .ok_or(super::relays::RelayError::NotFound)?;
            (relay, st.name_of(peer))
        };
        let op = rc::propose(&*self.shared, peer, relay)?;
        let res = self.block_on_rt(async {
            let conn = self.get_phone_conn(peer, false).await?;
            rc::request(&conn, frame::RELAY_PROPOSE, &op.encode()).await
        });
        match res {
            Ok(rc::ack::OK) => Ok(()),
            Ok(rc::ack::NO_ROOM) => {
                rc::mark_no_room(&*self.shared, peer);
                Err(super::relays::RelayError::Other(format!(
                    "{name} has no room for another relay."
                )))
            }
            Ok(_) => {
                rc::forget_outgoing(&*self.shared, peer);
                Err(super::relays::RelayError::Other(format!(
                    "{name} refused the change. Make sure both devices are up to date."
                )))
            }
            Err(_) => {
                rc::forget_outgoing(&*self.shared, peer);
                Err(rc::offline_error(&name))
            }
        }
    }

    /// Requests from paired devices to move a pairing.
    pub fn relay_change_requests(&self) -> Vec<super::relay_change::RelayChangeRequest> {
        super::relay_change::requests(&*self.shared)
    }

    /// Where this PC's proposals stand.
    pub fn relay_change_statuses(&self) -> Vec<super::relay_change::RelayChangeStatus> {
        super::relay_change::statuses(&*self.shared)
    }

    /// Allow (co-sign and switch) or decline a request from `peer`.
    pub fn answer_relay_change(
        &self,
        peer: &DeviceId,
        allow: bool,
    ) -> Result<(), super::relays::RelayError> {
        use super::relay_change as rc;
        let name = self.shared.lock().name_of(peer);
        if !allow {
            if let Some(h) = rc::finish_incoming(&*self.shared, peer) {
                let _ = self.block_on_rt(async {
                    let conn = self.get_phone_conn(peer, false).await?;
                    rc::request(&conn, frame::RELAY_DECLINE, &h.0).await
                });
            }
            return Ok(());
        }
        let (log, op) = rc::cosign(&*self.shared, peer)?;
        let res = self.block_on_rt(async {
            let conn = self.get_phone_conn(peer, false).await?;
            rc::request(&conn, frame::RELAY_ACCEPT, &op.encode()).await
        });
        match res {
            Ok(rc::ack::OK) => {
                use super::relay_change::Host;
                self.shared.rc_commit(peer, log)?;
                rc::finish_incoming(&*self.shared, peer);
                self.after_relay_move();
                Ok(())
            }
            Ok(_) => {
                rc::finish_incoming(&*self.shared, peer);
                Err(super::relays::RelayError::Other(format!(
                    "{name} no longer wants this change."
                )))
            }
            Err(_) => Err(rc::offline_error(&name)),
        }
    }

    /// After a move: pull the old relay inbox once now (more on events
    /// for the next hour).
    fn after_relay_move(&self) {
        let sh = self.shared.clone();
        self.rt.spawn(async move {
            let _ = pull_link_inboxes(&sh).await;
        });
    }

    /// This PC's pairings (state v2, M4.1): one per paired device.
    pub fn pairings(&self) -> Vec<super::pairings_state::PairingSummary> {
        super::pairings_state::summaries(&self.shared.lock().pairings)
    }

    // ---- prompts ----

    /// Prompts still waiting (expired ones are dropped first).
    pub fn pending(&self) -> Vec<PendingInfo> {
        let mut st = self.shared.lock();
        st.expire_prompts(now());
        st.pending
            .iter()
            .map(|(id, p)| PendingInfo {
                id: *id,
                host: p.open.host_for_display().to_owned(),
                from: p.from.clone(),
                received_at: p.received_at,
            })
            .collect()
    }

    /// The user clicked Open (`open = true`) or Dismiss on prompt `id`.
    /// An unknown id is `NoSuchPrompt`; one that outlived its TTL is
    /// `PromptExpired` (and is never opened).
    pub fn decide(&self, id: u64, open: bool) -> Result<(), NetError> {
        let mut st = self.shared.lock();
        let n = now();
        let p = st
            .pending
            .remove(&id)
            .ok_or(NetError::Rejected(RejectReason::NoSuchPrompt))?;
        if n.mono >= p.expires_mono {
            st.expire_prompts(n);
            return Err(NetError::Rejected(RejectReason::PromptExpired));
        }
        if !open {
            return Ok(());
        }
        let host = p.open.host_for_display().to_owned();
        let from = p.from.clone();
        let device = p.open.sender();
        let tag = p.open.inbox_tag();
        match p
            .open
            .confirm(st.inbox_by_tag(&device, tag), &*self.shared.opener)
        {
            Ok(()) => {
                drop(st);
                self.shared.emit(PcEvent::Opened {
                    host,
                    from,
                    device,
                    without_prompt: false,
                });
                Ok(())
            }
            Err(crate::opener::OpenError::Policy(r)) => Err(NetError::Rejected(r)),
            Err(e) => Err(NetError::Protocol(e.to_string())),
        }
    }

    /// Accepted/rejected counts by reason label (diagnostics, tests).
    pub fn counters(&self) -> (u64, Vec<(String, u64)>) {
        let st = self.shared.lock();
        let c = st.inbox.counters();
        let mut v: Vec<(String, u64)> = c
            .rejected
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect();
        v.sort();
        (c.accepted, v)
    }

    // ---- M2.6 file transfer, relay policy & connection stats ----

    /// Rename this PC (`M2.8`), signing a new `OpKind::RenameDevice` log entry with a fresh
    /// `DeviceCert`, persisting `state.bin`, and syncing to the blind mailbox if configured.
    pub fn rename_device(&self, name: &str) -> Result<(), NetError> {
        let trimmed = name.trim();
        if !crate::keys::valid_device_name(trimmed) {
            return Err(NetError::Rejected(RejectReason::BadDeviceName));
        }
        {
            let mut st = self.shared.lock();
            let my_id = st.identity.device_id();
            if st.name_of(&my_id) == trimmed {
                return Ok(());
            }
            let cert = DeviceCert::issue(
                &st.identity,
                st.inbox.receive_public(),
                trimmed,
                Platform::current(),
                now().wall,
            )
            .map_err(NetError::Rejected)?;
            let signed_before = st.signed.len();
            if !st
                .inbox
                .rename_device(&my_id, trimmed.to_owned(), Some(cert))
            {
                return Err(NetError::Rejected(RejectReason::BadDeviceName));
            }
            // M4.5: a signed rename for each v2 peer, sent on a connection
            // that is up now or the next one that comes up.
            let (pairings_before, unsent_before) = (st.pairings.clone(), st.unsent_ops.clone());
            let st2 = &mut *st;
            let peers = super::pair_ops::rename_all(
                &mut st2.pairings,
                &mut st2.unsent_ops,
                &st2.identity,
                now().wall,
                trimmed,
            );
            if let Err(e) = st.commit(&*self.shared.store) {
                st.signed.truncate(signed_before);
                st.pairings = pairings_before;
                st.unsent_ops = unsent_before;
                return Err(e);
            }
            for peer in peers {
                let live = st.conns.get_mut(&peer).and_then(|list| {
                    list.retain(|c| c.close_reason().is_none());
                    list.last().cloned()
                });
                if let Some(conn) = live {
                    let sh = self.shared.clone();
                    self.rt
                        .spawn(async move { super::pair_ops::flush(sh, conn, peer).await });
                }
            }
        }
        self.shared.emit(PcEvent::DevicesChanged);
        Ok(())
    }

    /// Alias for [`PcNode::rename_device`] (`M2.8`).
    pub fn set_device_name(&self, name: &str) -> Result<(), NetError> {
        self.rename_device(name)
    }

    /// Destination directory where incoming file transfers are saved.
    pub fn download_dir(&self) -> PathBuf {
        self.shared.lock().download_dir.clone()
    }

    /// Default destination directory where incoming file transfers are saved (`~/Downloads/Voidwire`).
    pub fn default_download_dir(&self) -> PathBuf {
        self.shared.lock().default_download_dir.clone()
    }

    /// Set the destination directory for incoming file transfers and persist in `state.bin` (`M2.8`).
    pub fn set_download_dir(&self, dir: PathBuf) -> Result<(), NetError> {
        if dir.as_os_str().is_empty() {
            return Err(NetError::Storage(
                "download folder path cannot be empty".into(),
            ));
        }
        super::state::private_dir(&dir).map_err(|e| NetError::Storage(e.to_string()))?;
        crate::file_transfer::purge_expired_parts(&dir, now().wall);
        let mut st = self.shared.lock();
        if dir == st.default_download_dir {
            st.custom_download_dir = None;
        } else {
            st.custom_download_dir = Some(dir.clone());
        }
        st.download_dir = dir;
        st.commit(&*self.shared.store)
    }

    /// Reset the destination directory to the default (`~/Downloads/Voidwire`) and persist (`M2.8`).
    pub fn reset_download_dir(&self) -> Result<PathBuf, NetError> {
        let def = self.default_download_dir();
        super::state::private_dir(&def).map_err(|e| NetError::Storage(e.to_string()))?;
        crate::file_transfer::purge_expired_parts(&def, now().wall);
        let mut st = self.shared.lock();
        st.custom_download_dir = None;
        st.download_dir = def.clone();
        st.commit(&*self.shared.store)?;
        Ok(def)
    }

    /// Whether completed file transfers are kept in session history (`false` by default for privacy, `M2.8`).
    pub fn keep_file_history(&self) -> bool {
        self.shared.lock().keep_file_history
    }

    /// Enable or disable keeping completed file transfers in session history (`M2.8`).
    /// Turning this off immediately clears `completed_files`.
    pub fn set_keep_file_history(&self, keep: bool) -> Result<(), NetError> {
        let mut st = self.shared.lock();
        st.keep_file_history = keep;
        if !keep {
            st.completed_files.clear();
        }
        st.commit(&*self.shared.store)
    }

    /// Clear all completed file transfer records from memory (`M2.8`).
    pub fn clear_completed_files(&self) {
        self.shared.lock().completed_files.clear();
    }

    /// Sweep stalled incoming file transfers (`M2.8`):
    /// - Accepted transfers with no chunk activity for >= 45s (`STALLED_ACCEPTED_FILE_TIMEOUT_MS`)
    ///   are removed from `incoming_files` while preserving `<tid>.part` and `<tid>.part.meta` on disk
    ///   so a later retry with the same `TransferId` can resume cleanly.
    /// - Unaccepted file offers older than >= 120s (`STALLED_UNACCEPTED_FILE_TIMEOUT_MS`) are expired.
    pub fn sweep_stalled_transfers(
        &self,
        now_wall: UnixMillis,
    ) -> Vec<crate::file_transfer::TransferId> {
        let timed_out = {
            let mut st = self.shared.lock();
            let stalled_tids: Vec<crate::file_transfer::TransferId> = st
                .incoming_files
                .iter()
                .filter_map(|(tid, s)| {
                    let idle_ms = now_wall.0.saturating_sub(s.last_activity.0);
                    let limit_ms = if s.accepted {
                        STALLED_ACCEPTED_FILE_TIMEOUT_MS
                    } else {
                        STALLED_UNACCEPTED_FILE_TIMEOUT_MS
                    };
                    if idle_ms >= limit_ms {
                        Some(*tid)
                    } else {
                        None
                    }
                })
                .collect();
            let stalled_out: Vec<(crate::file_transfer::TransferId, OutboundEnd)> = st
                .outbound_files
                .iter()
                .filter_map(|(tid, o)| match outbound_stall_deadline(&st, o) {
                    Some((d, why)) if now_wall.0 >= d.0 => Some((*tid, why)),
                    _ => None,
                })
                .collect();
            let mut removed = Vec::with_capacity(stalled_tids.len() + stalled_out.len());
            for (tid, why) in stalled_out {
                if let Some(o) = st.outbound_files.remove(&tid) {
                    end_outbound(&mut st, &o, why);
                    removed.push(tid);
                }
            }
            for tid in stalled_tids {
                if let Some(mut sess) = st.incoming_files.remove(&tid) {
                    // v0.7.1: a timed-out transfer is over; nothing resumes it
                    // once its session is gone, so its .part and .part.meta go.
                    if let Some(rcv) = sess.receiver.take() {
                        rcv.cancel_and_delete();
                    }
                    removed.push(tid);
                }
            }
            removed
        };
        for tid in &timed_out {
            self.shared.emit(PcEvent::FileCancelled {
                transfer_id: *tid,
                reason: "stalled_timeout".into(),
            });
        }
        timed_out
    }

    /// Whether incoming file offers are accepted automatically (`false` by default in production;
    /// when `false`, offers wait for [`PcNode::accept_file`] or [`PcNode::cancel_file`] and
    /// never create `.part` or `.part.meta` files on disk prior to consent).
    pub fn auto_accept_files(&self) -> bool {
        self.shared.lock().auto_accept_files
    }

    pub fn set_auto_accept_files(&self, auto_accept: bool) {
        self.shared.lock().auto_accept_files = auto_accept;
    }

    /// The earliest moment an incoming transfer counts as stalled, or `None`
    /// when nothing is in flight.
    pub fn stall_deadline(&self) -> Option<UnixMillis> {
        stall_deadline_of(&self.shared.lock())
    }

    /// The stall watch: blocks until the earliest stall deadline passes, then
    /// sweeps and returns what timed out. With no transfer in flight it waits
    /// without a timeout, so an idle PC wakes for nothing; a new or accepted
    /// transfer notifies it. `None` once [`PcNode::stop_stall_watch`] ran.
    pub fn wait_stalled_transfers(&self) -> Option<Vec<crate::file_transfer::TransferId>> {
        use std::sync::atomic::Ordering;
        let sh = &self.shared;
        let mut st = sh.lock();
        loop {
            if sh.stall_stop.load(Ordering::SeqCst) {
                return None;
            }
            match stall_deadline_of(&st) {
                None => st = sh.stall_cv.wait(st).unwrap_or_else(|p| p.into_inner()),
                Some(d) => {
                    let now_ms = now().wall.0;
                    if now_ms >= d.0 {
                        drop(st);
                        return Some(self.sweep_stalled_transfers(now().wall));
                    }
                    st = match sh
                        .stall_cv
                        .wait_timeout(st, std::time::Duration::from_millis(d.0 - now_ms))
                    {
                        Ok((g, _)) => g,
                        Err(p) => p.into_inner().0,
                    };
                }
            }
            sh.stall_wakeups.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Ends [`PcNode::wait_stalled_transfers`] (tests; the app's watch lives
    /// as long as the process).
    pub fn stop_stall_watch(&self) {
        self.shared
            .stall_stop
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _g = self.shared.lock();
        self.shared.stall_cv.notify_all();
    }

    /// How often the stall watch woke (tests).
    pub fn stall_wakeups(&self) -> u64 {
        self.shared
            .stall_wakeups
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// List pending or active incoming file transfers.
    pub fn incoming_files(&self) -> Vec<IncomingFileInfo> {
        let _ = self.sweep_stalled_transfers(now().wall);
        let st = self.shared.lock();
        let mut out: Vec<IncomingFileInfo> = st
            .incoming_files
            .values()
            .map(|s| IncomingFileInfo {
                transfer_id: s.offer.transfer_id,
                sender: s.offer.sender,
                from: s.from.clone(),
                filename: s.offer.filename.clone(),
                mime: s.offer.mime.clone(),
                size: s.offer.size,
                chunk_count: s.offer.chunk_count,
                next_chunk: s.receiver.as_ref().map(|r| r.next_chunk()).unwrap_or(0),
                accepted: s.accepted,
                allow_open: s.offer.allow_open,
            })
            .collect();
        out.sort_by_key(|i| *i.transfer_id.as_bytes());
        out
    }

    /// List completed incoming file transfers.
    pub fn completed_files(&self) -> Vec<CompletedFileInfo> {
        self.shared.lock().completed_files.clone()
    }

    /// Accept a pending incoming file transfer offer (`M2.6` / `M26-H1`).
    /// Re-verifies the 2 GiB cap and `size + 64 MiB` free disk space and creates the
    /// `<transfer_id>.part` and `<transfer_id>.part.meta` files on disk only upon consent.
    pub fn accept_file(
        &self,
        transfer_id: &crate::file_transfer::TransferId,
    ) -> Result<u64, NetError> {
        let mut st = self.shared.lock();
        let dir = st.download_dir.clone();
        let n = now();
        let sess = st
            .incoming_files
            .get_mut(transfer_id)
            .ok_or(NetError::Rejected(RejectReason::NoSuchPrompt))?;
        if sess.receiver.is_none() {
            let rcv = crate::file_transfer::PartFileReceiver::open_or_resume(
                sess.offer.clone(),
                sess.k_file.clone(),
                &dir,
                n.wall,
            )
            .map_err(|e| NetError::Protocol(e.to_string()))?;
            sess.receiver = Some(rcv);
        } else {
            crate::file_transfer::check_offer_acceptable(&sess.offer, &dir, n.wall)
                .map_err(|e| NetError::Protocol(e.to_string()))?;
        }
        sess.accepted = true;
        sess.last_activity = n.wall;
        // The deadline moved (120 s unaccepted -> 45 s accepted).
        self.shared.stall_cv.notify_all();
        let next = sess.receiver.as_ref().map(|r| r.next_chunk()).unwrap_or(0);
        let sender = sess.offer.sender;
        // v0.7.1: a desktop sender keeps the file and waits to be pulled
        // (it has no re-offer loop, unlike a phone), so accepting has to
        // ask it for the chunks. Before this, PC->PC files sat at 0 bytes.
        let pull = st
            .links
            .get(&sender)
            .is_some_and(|l| !l.link.peer_cert.platform().is_mobile());
        drop(st);
        if pull {
            let sh = self.shared.clone();
            let ep = self
                .endpoint
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            let mdns = self.mdns;
            let tid = *transfer_id;
            self.rt.spawn(async move {
                let res = match peer_conn(&sh, ep, mdns, &sender, false).await {
                    Ok(conn) => pull_file_from_peer(&sh, &conn, &tid).await,
                    Err(e) => Err(e),
                };
                if let Err(e) = res {
                    fail_incoming_file(&sh, &tid, &file_failure_reason(&e));
                }
            });
        }
        Ok(next)
    }

    /// A declined or cancelled incoming file from another PC: tell that PC
    /// (FILE_CANCEL), so its outgoing row ends as declined instead of
    /// waiting to be pulled until the offer expires (v0.9.0 test sheet step
    /// 13). A phone sender re-offers and learns it from `declined_files`.
    /// Best effort, in the background: a live connection or one dial.
    fn tell_pc_sender_cancelled(&self, sender: DeviceId, tid: crate::file_transfer::TransferId) {
        let to_pc = self
            .shared
            .lock()
            .links
            .get(&sender)
            .is_some_and(|l| !l.link.peer_cert.platform().is_mobile());
        if !to_pc {
            return;
        }
        let sh = self.shared.clone();
        let ep = self
            .endpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mdns = self.mdns;
        self.rt.spawn(async move {
            let Ok(conn) = peer_conn(&sh, ep, mdns, &sender, false).await else {
                return;
            };
            if let Ok((mut s, mut r)) = conn.open_bi().await {
                if write_frame(&mut s, frame::FILE_CANCEL, tid.as_bytes())
                    .await
                    .is_ok()
                {
                    let _ = s.finish();
                    let _ = read_frame(&mut r, Duration::from_secs(2)).await;
                }
            }
        });
    }

    /// Alias for [`PcNode::cancel_file`] (`M2.9`).
    pub fn decline_file_offer(&self, transfer_id: &crate::file_transfer::TransferId) -> bool {
        self.cancel_file(transfer_id)
    }

    /// Cancel or reject an incoming file transfer, immediately deleting `<id>.part`
    /// and `<id>.part.meta` and zeroing `k_file` (`M2.6`).
    pub fn cancel_file(&self, transfer_id: &crate::file_transfer::TransferId) -> bool {
        let removed = {
            let mut st = self.shared.lock();
            let sess = st.incoming_files.remove(transfer_id);
            if let Some(ref s) = sess {
                if !st
                    .declined_files
                    .iter()
                    .any(|(tid, peer)| tid == transfer_id && *peer == s.offer.sender)
                {
                    if st.declined_files.len() >= 64 {
                        st.declined_files.pop_front();
                    }
                    st.declined_files.push_back((*transfer_id, s.offer.sender));
                }
            }
            sess
        };
        if let Some(sess) = removed {
            let sender = sess.offer.sender;
            if let Some(rcv) = sess.receiver {
                rcv.cancel_and_delete();
            }
            self.shared.emit(PcEvent::FileCancelled {
                transfer_id: *transfer_id,
                reason: "cancelled_by_receiver".into(),
            });
            self.tell_pc_sender_cancelled(sender, *transfer_id);
            true
        } else {
            // Also clean up any leftover .part files on disk if present.
            let dir = self.download_dir();
            let (part, meta) = crate::file_transfer::part_paths(&dir, transfer_id);
            let had = part.exists() || meta.exists();
            let _ = std::fs::remove_file(part);
            let _ = std::fs::remove_file(meta);
            had
        }
    }

    /// Current relay file-transfer policy (`M2.6` §6a.1 & §6b).
    pub fn relay_policy(&self) -> crate::file_transfer::RelayTransferPolicy {
        self.shared.lock().relay_policy
    }

    /// Server-advertised relay file size cap (`25 MiB` default, `0` = unlimited up to 2 GiB, `M2.9`).
    pub fn relay_server_cap_bytes(&self) -> u64 {
        self.shared.lock().relay_policy.server_cap_bytes()
    }

    /// Update the server-advertised relay file size cap (`M2.9`).
    pub fn set_relay_server_cap_bytes(&self, cap_bytes: u64) -> Result<(), NetError> {
        let mut st = self.shared.lock();
        st.relay_policy.set_server_cap_bytes(cap_bytes);
        st.commit(&*self.shared.store)
    }

    /// Whether "Never send files over relay" is enabled (`false` by default, `M2.8`).
    pub fn never_send_files_over_relay(&self) -> bool {
        self.shared
            .lock()
            .relay_policy
            .never_send_files_over_relay()
    }

    /// Enable or disable "Never send files over relay" (`M2.8`).
    pub fn set_never_send_files_over_relay(&self, never: bool) -> Result<(), NetError> {
        let mut st = self.shared.lock();
        st.relay_policy.set_never_send_files_over_relay(never);
        st.commit(&*self.shared.store)
    }

    /// Set the user's local relay file size cap (`0..=2 GiB`, persisted in `state.bin`).
    pub fn set_user_relay_cap_bytes(&self, cap: u64) -> Result<(), NetError> {
        let mut st = self.shared.lock();
        st.relay_policy
            .set_user_cap_bytes(cap)
            .map_err(|e| NetError::Protocol(e.to_string()))?;
        st.commit(&*self.shared.store)
    }

    /// Apply a verified `SignedConfig` from the mailbox/config server (`M2.6` §6b).
    pub fn apply_signed_config(
        &self,
        cfg: &crate::mailbox::SignedConfig,
        expected_pubkey: &[u8; 32],
    ) -> Result<u64, NetError> {
        let mut st = self.shared.lock();
        st.relay_policy
            .apply_signed_config(cfg, expected_pubkey)
            .map_err(|e| NetError::Protocol(e.to_string()))?;
        Ok(st.relay_policy.effective_cap_bytes())
    }

    /// Whether on-device connection stats are enabled (`false` by default, `M2.6` §6a.3).
    pub fn connection_stats_enabled(&self) -> bool {
        self.shared.lock().conn_stats.is_enabled()
    }

    /// Enable or disable on-device connection stats. Disabling immediately deletes
    /// all stored stats in memory and on disk (`M2.6` §6a.3).
    pub fn set_connection_stats_enabled(&self, enabled: bool) -> Result<(), NetError> {
        let mut st = self.shared.lock();
        st.conn_stats.set_enabled(enabled);
        st.commit(&*self.shared.store)
    }

    /// Snapshot of on-device day-granularity connection stats (`M2.6` §6a.3).
    pub fn connection_stats(&self) -> Vec<(DeviceId, crate::file_transfer::PeerDayStats)> {
        self.shared.lock().conn_stats.entries()
    }

    /// Whether incoming clipboard text from paired phones is automatically copied (`false` by default, `M3.1`).
    pub fn auto_copy_clipboard(&self) -> bool {
        self.shared.lock().auto_copy_clipboard
    }

    /// Enable or disable auto-copying incoming clipboard text from paired phones (`M3.1`).
    pub fn set_auto_copy_clipboard(&self, on: bool) -> Result<(), NetError> {
        let mut st = self.shared.lock();
        st.auto_copy_clipboard = on;
        st.commit(&*self.shared.store)
    }

    /// Whether the opt-in send-clipboard shortcut is enabled (`false` by default, `M3.1`).
    pub fn send_clipboard_shortcut(&self) -> bool {
        self.shared.lock().send_clipboard_shortcut
    }

    /// Enable or disable the opt-in send-clipboard shortcut (`M3.1`).
    pub fn set_send_clipboard_shortcut(&self, on: bool) -> Result<(), NetError> {
        let mut st = self.shared.lock();
        st.send_clipboard_shortcut = on;
        st.commit(&*self.shared.store)
    }

    /// Configured keyboard shortcut accelerator for sending the PC clipboard (`"Ctrl+Shift+V"` by default, `M3.1.1`).
    pub fn send_clipboard_shortcut_accel(&self) -> String {
        self.shared.lock().send_clipboard_shortcut_accel.clone()
    }

    /// Update and persist the keyboard shortcut accelerator for sending the PC clipboard (`M3.1.1`).
    pub fn set_send_clipboard_shortcut_accel(&self, accel: &str) -> Result<(), NetError> {
        let trimmed = accel.trim();
        if trimmed.is_empty() || trimmed.len() > 64 {
            return Err(NetError::Protocol("invalid shortcut accelerator".into()));
        }
        let mut st = self.shared.lock();
        st.send_clipboard_shortcut_accel = trimmed.to_owned();
        st.commit(&*self.shared.store)
    }

    /// Consume a pending clipboard prompt and save its UTF-8 text as a collision-safe `.txt`
    /// file in the configured download folder (`M3.1`).
    pub fn save_pending_clipboard_as_txt(&self, id: u64) -> Result<PathBuf, NetError> {
        let info = self
            .decide_clipboard(id, true)?
            .ok_or(NetError::Rejected(RejectReason::NoSuchPrompt))?;
        let dest_dir = self.download_dir();
        let filename_hint = format!("clipboard-{}.txt", info.received_at.0);
        crate::file_transfer::save_sanitized_text_file(
            &dest_dir,
            &filename_hint,
            info.text.as_bytes(),
        )
        .map_err(NetError::Storage)
    }

    /// Pending incoming clipboard text items waiting for user confirmation (`M3.1`).
    pub fn pending_clipboards(&self) -> Vec<PendingClipboardInfo> {
        let mut st = self.shared.lock();
        st.expire_prompts(now());
        st.pending_clipboards
            .iter()
            .map(|(id, c)| PendingClipboardInfo {
                id: *id,
                from: c.from.clone(),
                sender: c.sender,
                text: c.text.as_str().to_owned(),
                byte_len: c.text.len(),
                sensitive: c.sensitive,
                received_at: c.received_at,
            })
            .collect()
    }

    /// Accept (`accept = true`, returning the clipboard item to copy or save) or dismiss
    /// (`accept = false`) a pending clipboard prompt (`M3.1`).
    pub fn decide_clipboard(
        &self,
        id: u64,
        accept: bool,
    ) -> Result<Option<PendingClipboardInfo>, NetError> {
        let mut st = self.shared.lock();
        let n = now();
        let c = st
            .pending_clipboards
            .remove(&id)
            .ok_or(NetError::Rejected(RejectReason::NoSuchPrompt))?;
        if n.mono >= c.expires_mono {
            st.expire_prompts(n);
            return Err(NetError::Rejected(RejectReason::PromptExpired));
        }
        if !accept {
            return Ok(None);
        }
        Ok(Some(PendingClipboardInfo {
            id,
            from: c.from,
            sender: c.sender,
            text: c.text.as_str().to_owned(),
            byte_len: c.text.len(),
            sensitive: c.sensitive,
            received_at: c.received_at,
        }))
    }

    /// Read cached socket addresses for a paired phone (`M3.1.3` test helper).
    pub fn phone_addrs_for_tests(&self, phone: &DeviceId) -> Vec<SocketAddr> {
        self.shared
            .lock()
            .phone_addrs
            .get(phone)
            .cloned()
            .unwrap_or_default()
    }

    /// Override cached socket addresses for a paired phone (`M3.1` test helper).
    pub fn set_phone_addrs_for_tests(&self, phone: &DeviceId, addrs: Vec<SocketAddr>) {
        let mut st = self.shared.lock();
        if addrs.is_empty() {
            st.phone_addrs.remove(phone);
        } else {
            st.phone_addrs.insert(*phone, addrs);
        }
        for c in st.conns.remove(phone).unwrap_or_default() {
            c.close(0u32.into(), b"addr_override");
        }
    }

    /// Active or queued outgoing file transfers to paired phones (`M3.1`).
    pub fn outgoing_files(&self) -> Vec<OutgoingFileInfo> {
        let n = now().wall;
        let mut st = self.shared.lock();
        st.outbound_files.retain(|_, o| n.0 < o.offer.expires_at.0);
        st.ended_outbound
            .retain(|(_, at)| n.0 < at.0.saturating_add(OUTBOUND_ENDED_SHOW_MS));
        let mut out: Vec<OutgoingFileInfo> = st
            .outbound_files
            .values()
            .map(|o| outgoing_info(o, None))
            .collect();
        out.extend(st.ended_outbound.iter().map(|(i, _)| i.clone()));
        out.sort_by_key(|i| *i.transfer_id.as_bytes());
        out
    }

    /// Alias for [`PcNode::outgoing_files`] (`M3.1`).
    pub fn outgoing_file_offers(&self) -> Vec<OutgoingFileInfo> {
        self.outgoing_files()
    }

    /// Cancel an active or queued outgoing file transfer to a paired phone (`M3.1`).
    pub fn cancel_outgoing_file(&self, transfer_id: &crate::file_transfer::TransferId) -> bool {
        let removed = {
            let mut st = self.shared.lock();
            if !st.cancelled_outbound_files.contains(transfer_id) {
                if st.cancelled_outbound_files.len() >= 64 {
                    st.cancelled_outbound_files.pop_front();
                }
                st.cancelled_outbound_files.push_back(*transfer_id);
            }
            let out = st.outbound_files.remove(transfer_id);
            let live_conn = out
                .as_ref()
                .and_then(|o| st.conns.get(&o.offer.recipient))
                .and_then(|v| v.iter().rfind(|c| c.close_reason().is_none()).cloned());
            (out, live_conn)
        };
        if let (Some(_out), maybe_conn) = removed {
            if let Some(conn) = maybe_conn {
                let payload = transfer_id.as_bytes().to_vec();
                self.rt.spawn(async move {
                    if let Ok((mut s, mut r)) = conn.open_bi().await {
                        if write_frame(&mut s, frame::FILE_CANCEL, &payload)
                            .await
                            .is_ok()
                        {
                            let _ = s.finish();
                            let _ = read_frame(&mut r, Duration::from_secs(2)).await;
                        }
                    }
                });
            }
            self.shared.emit(PcEvent::FileCancelled {
                transfer_id: *transfer_id,
                reason: "cancelled_by_sender".into(),
            });
            true
        } else {
            false
        }
    }

    /// Send a validated `http`/`https` link to a paired phone (`M3.1`).
    /// Delivers live over `ALPN_APP` when the phone is reachable, or seals and queues
    /// the envelope in the phone's RAM-only blind device inbox on `voidwire-mailbox`
    /// when the phone is offline.
    pub fn send_url_to_phone(&self, phone: &DeviceId, url: &str) -> Result<PcSendReport, NetError> {
        let canonical = crate::url_policy::check_url(url)?;
        let started = crate::time::Stopwatch::start();
        self.send_sealed(phone, started, |st, PeerCtx { group, head, rk }| {
            let body = crate::wire::encode_signed(
                &st.identity,
                &crate::wire::Outgoing {
                    group,
                    recipient: *phone,
                    log_head: head,
                    msg_id: crate::ids::MsgId::random(),
                    timestamp: now().wall,
                    url: canonical.as_str(),
                },
            )?;
            Ok(crate::envelope::seal(phone, &rk, &body)?)
        })
    }

    /// Seal with `build` for `phone`'s pairing and deliver it.
    fn send_sealed(
        &self,
        phone: &DeviceId,
        started: crate::time::Stopwatch,
        build: impl Fn(&PcState, PeerCtx) -> Result<Vec<u8>, NetError>,
    ) -> Result<PcSendReport, NetError> {
        let envelope = {
            let st = self.shared.lock();
            build(&st, st.peer_ctx(phone)?)?
        };
        self.deliver_envelope_or_queue_inbox(phone, &envelope, started)
    }

    /// Send UTF-8 clipboard text to a paired phone (`M3.1`).
    /// Inline text (`<= 7,680 B`) rides inside the `512 B` / `8,448 B` HPKE envelope
    /// (live or queued in the RAM-only blind device inbox when offline); larger text
    /// (`<= 10 MiB`) streams via the chunked file-transfer pipeline with
    /// `CLIPBOARD_STREAM_MIME`.
    pub fn send_clipboard_to_phone(
        &self,
        phone: &DeviceId,
        text: &str,
    ) -> Result<PcSendReport, NetError> {
        self.send_clipboard_to_phone_with_decision(phone, text, None)
    }

    /// [`PcNode::send_clipboard_to_phone`] with the sender's relay decision for
    /// streamed clipboard text (`> 7,680 B`) that needs relay consent (`M3.1.2`).
    pub fn send_clipboard_to_phone_with_decision(
        &self,
        phone: &DeviceId,
        text: &str,
        prompt_decision: Option<crate::file_transfer::RelayPromptDecision>,
    ) -> Result<PcSendReport, NetError> {
        if text.is_empty() || text.len() > crate::limits::MAX_STREAMED_CLIPBOARD_BYTES {
            return Err(NetError::Rejected(RejectReason::UrlTooLong));
        }
        let started = crate::time::Stopwatch::start();
        if text.len() > crate::limits::MAX_INLINE_CLIPBOARD_BYTES {
            let tid = crate::file_transfer::TransferId::random();
            let rep = self.send_file_bytes_to_phone(
                phone,
                tid,
                "clipboard.txt",
                crate::clipboard::CLIPBOARD_STREAM_MIME,
                text.as_bytes(),
                prompt_decision,
            )?;
            return Ok(PcSendReport {
                outcome: if rep.awaiting_accept {
                    SendOutcome::Prompted
                } else {
                    SendOutcome::Opened
                },
                delivery_path: rep.delivery_path,
                latency_us: started.elapsed_us(),
            });
        }
        let sensitive = crate::clipboard::looks_sensitive_clipboard(text);
        self.send_sealed(phone, started, |st, PeerCtx { group, head, rk }| {
            let body = crate::wire::encode_signed_clipboard(
                &st.identity,
                &crate::wire::OutgoingClipboard {
                    group,
                    recipient: *phone,
                    log_head: head,
                    msg_id: crate::ids::MsgId::random(),
                    timestamp: now().wall,
                    text,
                    sensitive,
                },
            )?;
            Ok(crate::envelope::seal(phone, &rk, &body)?)
        })
    }

    /// Auto-detect whether `raw_text` is a single `http`/`https` link or arbitrary
    /// clipboard text and send it to `phone` (`M3.1`).
    pub fn send_text_or_url_to_phone(
        &self,
        phone: &DeviceId,
        raw_text: &str,
    ) -> Result<PcSendReport, NetError> {
        self.send_text_or_url_to_phone_with_decision(phone, raw_text, None)
    }

    /// [`PcNode::send_text_or_url_to_phone`] carrying the sender's relay decision
    /// (used when retrying after a `relay_prompt_required` confirmation, `M3.1.2`).
    pub fn send_text_or_url_to_phone_with_decision(
        &self,
        phone: &DeviceId,
        raw_text: &str,
        prompt_decision: Option<crate::file_transfer::RelayPromptDecision>,
    ) -> Result<PcSendReport, NetError> {
        match crate::clipboard::classify_shared_text(raw_text)? {
            crate::clipboard::SharedContentKind::Url { url } => self.send_url_to_phone(phone, &url),
            crate::clipboard::SharedContentKind::InlineClipboard { text, .. }
            | crate::clipboard::SharedContentKind::StreamedClipboard { text, .. } => {
                self.send_clipboard_to_phone_with_decision(phone, &text, prompt_decision)
            }
        }
    }

    /// Send a file from disk (`path`) to a paired phone (`M3.1`).
    pub fn send_file_to_phone(
        &self,
        phone: &DeviceId,
        path: &std::path::Path,
        mime: &str,
        prompt_decision: Option<crate::file_transfer::RelayPromptDecision>,
    ) -> Result<PcFileSendReport, NetError> {
        let tid = crate::file_transfer::TransferId::random();
        let raw_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file.bin");
        self.send_file_source_to_phone(
            phone,
            tid,
            raw_name,
            mime,
            OutboundFileData::Path(path.to_path_buf()),
            prompt_decision,
        )
    }

    /// Send an in-memory file payload to a paired phone (`M3.1`).
    pub fn send_file_bytes_to_phone(
        &self,
        phone: &DeviceId,
        transfer_id: crate::file_transfer::TransferId,
        filename: &str,
        mime: &str,
        data: &[u8],
        prompt_decision: Option<crate::file_transfer::RelayPromptDecision>,
    ) -> Result<PcFileSendReport, NetError> {
        self.send_file_source_to_phone(
            phone,
            transfer_id,
            filename,
            mime,
            OutboundFileData::Bytes(data.to_vec()),
            prompt_decision,
        )
    }

    fn deliver_envelope_or_queue_inbox(
        &self,
        phone: &DeviceId,
        envelope: &[u8],
        started: crate::time::Stopwatch,
    ) -> Result<PcSendReport, NetError> {
        let phone_id = *phone;
        let env_vec = envelope.to_vec();
        let live_res = self.block_on_rt(async {
            let mut fresh = false;
            loop {
                let conn = self.get_phone_conn(&phone_id, fresh).await?;
                let res = async {
                    let (mut s, mut r) = conn
                        .open_bi()
                        .await
                        .map_err(|e| super::conn_error(&conn, e))?;
                    write_frame(&mut s, frame::SEND, &env_vec).await?;
                    let _ = s.finish();
                    let (rt, p) = read_frame(&mut r, IO_TIMEOUT).await?;
                    if rt == frame::ERROR {
                        return Err(super::parse_error(&p));
                    }
                    if rt != frame::RESULT || p.len() != 3 {
                        return Err(NetError::Protocol("bad result frame from phone".into()));
                    }
                    let code = u16::from_be_bytes([p[0], p[1]]);
                    if code != 0 {
                        return Err(NetError::Rejected(RejectReason::from_code(code)));
                    }
                    let outcome = SendOutcome::from_u8(p[2])
                        .ok_or_else(|| NetError::Protocol("bad outcome byte".into()))?;
                    let is_relayed = conn_is_relayed(&self.shared, &conn);
                    Ok::<(SendOutcome, bool), NetError>((outcome, is_relayed))
                }
                .await;
                match res {
                    Ok(v) => return Ok(v),
                    Err(NetError::Protocol(_) | NetError::Timeout | NetError::Unreachable(_))
                        if !fresh =>
                    {
                        fresh = true;
                    }
                    Err(e) => return Err(e),
                }
            }
        });
        match live_res {
            Ok((outcome, is_relayed)) => {
                let path_kind = if is_relayed {
                    crate::file_transfer::TransportPathKind::Relayed
                } else {
                    crate::file_transfer::TransportPathKind::Direct
                };
                {
                    let mut st = self.shared.lock();
                    st.conn_stats.record_transfer(
                        &phone_id,
                        path_kind,
                        envelope.len() as u64,
                        now().wall,
                    );
                    let _ = st.commit(&*self.shared.store);
                }
                Ok(PcSendReport {
                    outcome,
                    delivery_path: if is_relayed {
                        super::DeliveryPath::Relayed
                    } else {
                        super::DeliveryPath::Direct
                    },
                    latency_us: started.elapsed_us(),
                })
            }
            Err(NetError::Rejected(r)) => Err(NetError::Rejected(r)),
            Err(live_err) => {
                self.push_to_link_inbox(&phone_id, envelope)
                    .map_err(|_| live_err)?;
                Ok(PcSendReport {
                    outcome: SendOutcome::Prompted,
                    delivery_path: super::DeliveryPath::QueuedInDeviceInbox,
                    latency_us: started.elapsed_us(),
                })
            }
        }
    }

    /// Put a sealed envelope into a v2 peer's inbox on the pairing relay
    /// (M4.2).
    fn push_to_link_inbox(&self, peer: &DeviceId, envelope: &[u8]) -> Result<(), NetError> {
        let target = {
            let st = self.shared.lock();
            let l = st.links.get(peer).ok_or(NetError::UnknownDevice)?;
            l.link
                .peer_inbox(st.relay_url.as_deref(), home_mailbox(&st))
                .ok_or_else(|| NetError::Unreachable("no relay for this pairing".into()))?
        };
        let item_id = crate::ids::MsgId::random().0;
        let env_vec = envelope.to_vec();
        let (eph_id, maybe_cap) = self
            .block_on_rt(async move { super::links::put_one(&target, item_id, env_vec).await })?;
        let mut st = self.shared.lock();
        if let Some(cap) = maybe_cap {
            st.relay_policy.set_server_cap_bytes(cap);
        }
        st.last_throwaway_id = Some(eph_id);
        Ok(())
    }

    fn send_file_source_to_phone(
        &self,
        phone: &DeviceId,
        transfer_id: crate::file_transfer::TransferId,
        filename: &str,
        mime: &str,
        data: OutboundFileData,
        prompt_decision: Option<crate::file_transfer::RelayPromptDecision>,
    ) -> Result<PcFileSendReport, NetError> {
        if matches!(
            prompt_decision,
            Some(crate::file_transfer::RelayPromptDecision::Cancel)
        ) {
            return Err(NetError::Cancelled);
        }
        let (size, root, chunk_hashes) = match &data {
            OutboundFileData::Bytes(bytes) => {
                let sz = bytes.len() as u64;
                if sz > crate::file_transfer::MAX_FILE_SIZE {
                    return Err(NetError::Protocol(format!(
                        "file exceeds 2 GiB cap ({sz} B)"
                    )));
                }
                let (r, ch) = crate::file_transfer::compute_file_hashes(bytes);
                (sz, r, ch)
            }
            OutboundFileData::Path(path) => {
                crate::file_transfer::compute_file_hashes_streaming(path)
                    .map_err(|e| NetError::Storage(e.to_string()))?
            }
        };
        let started = crate::time::Stopwatch::start();
        let (offer, envelope, k_file, rk, grp, head, to_name) = {
            let st = self.shared.lock();
            let PeerCtx {
                group: grp,
                head,
                rk,
            } = st.peer_ctx(phone)?;
            let ts = now().wall;
            let expires = UnixMillis(ts.0 + 3_600_000);
            let offer = crate::file_transfer::FileOffer::new(
                grp,
                st.identity.device_id(),
                *phone,
                transfer_id,
                filename,
                mime,
                size,
                root,
                chunk_hashes,
                ts,
                expires,
            )
            .map_err(NetError::Rejected)?
            .with_log_head(head.0);
            let (env, k_file) = crate::file_transfer::seal_file_offer(&offer, &st.identity, &rk)
                .map_err(NetError::Rejected)?;
            (offer, env, k_file, rk, grp, head, st.name_of(phone))
        };

        let phone_id = *phone;
        let conn_res = self.block_on_rt(async { self.get_phone_conn(&phone_id, false).await });
        match conn_res {
            Ok(conn) => {
                let is_relayed = conn_is_relayed(&self.shared, &conn);
                let path_kind = if is_relayed {
                    crate::file_transfer::TransportPathKind::Relayed
                } else {
                    crate::file_transfer::TransportPathKind::Direct
                };
                self.evaluate_phone_file_relay_policy(&phone_id, size, path_kind, prompt_decision)?;

                let delivery_path = if is_relayed {
                    super::DeliveryPath::Relayed
                } else {
                    super::DeliveryPath::Direct
                };
                {
                    let mut st = self.shared.lock();
                    st.cancelled_outbound_files.retain(|t| *t != transfer_id);
                    st.outbound_files.insert(
                        transfer_id,
                        OutboundPendingFile {
                            offer: offer.clone(),
                            envelope: envelope.clone(),
                            k_file: k_file.clone(),
                            data: data.clone(),
                            to: to_name.clone(),
                            chunks_sent: 0,
                            delivery_path,
                            created_at: now().wall,
                            pulled: false,
                            last_activity: now().wall,
                        },
                    );
                    // A PC recipient arms the pre-accept deadline.
                    self.shared.stall_cv.notify_all();
                }

                let live_offer_res = self.block_on_rt(async {
                    let (mut s, mut r) = conn
                        .open_bi()
                        .await
                        .map_err(|e| super::conn_error(&conn, e))?;
                    write_frame(&mut s, frame::FILE_OFFER, &envelope).await?;
                    let _ = s.finish();
                    let (rt, ack_bytes) = read_frame(&mut r, IO_TIMEOUT).await?;
                    if rt == frame::ERROR {
                        return Err(super::parse_error(&ack_bytes));
                    }
                    if rt != frame::FILE_OFFER_ACK {
                        return Err(NetError::Protocol("unexpected file offer reply".into()));
                    }
                    super::phone::PhoneClient::decode_file_ack(&ack_bytes)
                });

                match live_offer_res {
                    Ok((0 | 2, _tid, next_chunk, _msg)) => {
                        let sh = self.shared.clone();
                        let chunks_sent = self.block_on_rt(async move {
                            stream_outbound_chunks_on_conn(
                                &sh,
                                &conn,
                                &phone_id,
                                transfer_id,
                                next_chunk,
                                is_relayed,
                            )
                            .await
                        })?;
                        Ok(PcFileSendReport {
                            transfer_id,
                            filename: offer.filename,
                            size: offer.size,
                            blake3_root: offer.blake3_root,
                            chunks_sent,
                            resumed_from_chunk: next_chunk,
                            delivery_path,
                            awaiting_accept: false,
                            latency_us: started.elapsed_us(),
                        })
                    }
                    Ok((1, _tid, next_chunk, _msg)) => Ok(PcFileSendReport {
                        transfer_id,
                        filename: offer.filename,
                        size: offer.size,
                        blake3_root: offer.blake3_root,
                        chunks_sent: 0,
                        resumed_from_chunk: next_chunk,
                        delivery_path,
                        awaiting_accept: true,
                        latency_us: started.elapsed_us(),
                    }),
                    Ok((_, _tid, nc, msg)) => {
                        self.shared.lock().outbound_files.remove(&transfer_id);
                        let detail = if msg.contains("exceeds_relay_cap") && !msg.contains("cap=") {
                            format!("{msg}: cap={nc}")
                        } else {
                            msg
                        };
                        Err(NetError::Protocol(format!("file_offer_rejected: {detail}")))
                    }
                    Err(NetError::Rejected(r)) => {
                        self.shared.lock().outbound_files.remove(&transfer_id);
                        Err(NetError::Rejected(r))
                    }
                    Err(live_err) => {
                        // Connection dropped mid-offer: evict dead connection, evaluate relay policy,
                        // and fall back to queueing FileWake in RAM inbox.
                        {
                            let mut st = self.shared.lock();
                            st.conns.remove(&phone_id);
                            st.outbound_files.remove(&transfer_id);
                        }
                        self.evaluate_phone_file_relay_policy(
                            &phone_id,
                            size,
                            crate::file_transfer::TransportPathKind::Relayed,
                            prompt_decision,
                        )?;
                        self.queue_file_wake_in_inbox(
                            &phone_id, &rk, &grp, head, &offer, &envelope, &k_file, data, to_name,
                            started,
                        )
                        .map_err(|_| live_err)
                    }
                }
            }
            Err(live_err) => {
                // No live connection to phone: evaluate relay policy before queueing FileWake.
                self.evaluate_phone_file_relay_policy(
                    &phone_id,
                    size,
                    crate::file_transfer::TransportPathKind::Relayed,
                    prompt_decision,
                )?;
                self.queue_file_wake_in_inbox(
                    &phone_id, &rk, &grp, head, &offer, &envelope, &k_file, data, to_name, started,
                )
                .map_err(|_| live_err)
            }
        }
    }

    fn evaluate_phone_file_relay_policy(
        &self,
        phone_id: &DeviceId,
        size: u64,
        path_kind: crate::file_transfer::TransportPathKind,
        prompt_decision: Option<crate::file_transfer::RelayPromptDecision>,
    ) -> Result<(), NetError> {
        let outcome = {
            let mut st = self.shared.lock();
            let out = st.relay_policy.evaluate(size, path_kind, prompt_decision);
            if matches!(
                out,
                crate::file_transfer::RelayPolicyOutcome::PromptSender { .. }
            ) {
                st.conn_stats.record_prompt_shown(phone_id, now().wall);
                let _ = st.commit(&*self.shared.store);
            } else if matches!(
                out,
                crate::file_transfer::RelayPolicyOutcome::ProceedViaRelay
            ) && matches!(
                prompt_decision,
                Some(crate::file_transfer::RelayPromptDecision::SendViaRelay)
            ) {
                st.conn_stats.record_prompt_accepted(phone_id, now().wall);
                let _ = st.commit(&*self.shared.store);
            }
            out
        };
        match outcome {
            crate::file_transfer::RelayPolicyOutcome::ProceedDirect
            | crate::file_transfer::RelayPolicyOutcome::ProceedViaRelay => Ok(()),
            crate::file_transfer::RelayPolicyOutcome::PromptSender {
                size: file_size,
                effective_cap,
            } => Err(NetError::Protocol(format!(
                "relay_prompt_required: size={file_size} cap={effective_cap}"
            ))),
            crate::file_transfer::RelayPolicyOutcome::WaitForDirect => {
                Err(NetError::Protocol("waiting_for_direct_path".into()))
            }
            crate::file_transfer::RelayPolicyOutcome::Cancelled => Err(NetError::Cancelled),
            crate::file_transfer::RelayPolicyOutcome::NeverSendOverRelay => {
                Err(NetError::Protocol(format!(
                    "exceeds_relay_cap: never_send_files_over_relay: size={size} cap=0"
                )))
            }
            crate::file_transfer::RelayPolicyOutcome::ExceedsRelayCap {
                size: file_size,
                effective_cap,
            } => Err(NetError::Protocol(format!(
                "exceeds_relay_cap: size={file_size} cap={effective_cap}"
            ))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn queue_file_wake_in_inbox(
        &self,
        phone: &DeviceId,
        rk: &crate::keys::ReceivePublicKey,
        grp: &GroupId,
        head: LogHead,
        offer: &crate::file_transfer::FileOffer,
        envelope: &[u8],
        k_file: &crate::file_transfer::FileTransferKey,
        data: OutboundFileData,
        to_name: String,
        started: crate::time::Stopwatch,
    ) -> Result<PcFileSendReport, NetError> {
        let wake_env = {
            let st = self.shared.lock();
            // FileWake asks a phone to pull the file later; another PC
            // has no pull path, so an offline PC just fails the send.
            if let Some(l) = st.links.get(phone) {
                if !matches!(
                    l.link.peer_cert.platform(),
                    crate::keys::Platform::Android | crate::keys::Platform::Ios
                ) {
                    return Err(NetError::Unreachable("the device is offline".into()));
                }
            }
            let body = crate::wire::encode_signed_file_wake(
                &st.identity,
                &crate::wire::OutgoingFileWake {
                    group: *grp,
                    recipient: *phone,
                    log_head: head,
                    msg_id: crate::ids::MsgId::random(),
                    timestamp: now().wall,
                    wake: &crate::wire::FileWakePayload {
                        transfer_id: *offer.transfer_id.as_bytes(),
                        size_bytes: offer.size,
                        expires_at: offer.expires_at,
                        filename: offer.filename.clone(),
                        is_executable: crate::file_transfer::is_executable_filename(
                            &offer.filename,
                        ),
                    },
                },
            )?;
            crate::envelope::seal(phone, rk, &body)?
        };
        self.push_to_link_inbox(phone, &wake_env)?;
        {
            let mut st = self.shared.lock();
            st.cancelled_outbound_files
                .retain(|t| *t != offer.transfer_id);
            st.outbound_files.insert(
                offer.transfer_id,
                OutboundPendingFile {
                    offer: offer.clone(),
                    envelope: envelope.to_vec(),
                    k_file: k_file.clone(),
                    data,
                    to: to_name,
                    chunks_sent: 0,
                    delivery_path: super::DeliveryPath::QueuedInDeviceInbox,
                    created_at: now().wall,
                    pulled: false,
                    last_activity: now().wall,
                },
            );
        }
        Ok(PcFileSendReport {
            transfer_id: offer.transfer_id,
            filename: offer.filename.clone(),
            size: offer.size,
            blake3_root: offer.blake3_root,
            chunks_sent: 0,
            resumed_from_chunk: 0,
            delivery_path: super::DeliveryPath::QueuedInDeviceInbox,
            awaiting_accept: true,
            latency_us: started.elapsed_us(),
        })
    }

    async fn get_phone_conn(&self, phone: &DeviceId, fresh: bool) -> Result<Connection, NetError> {
        let ep = self
            .endpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        peer_conn(&self.shared, ep, self.mdns, phone, fresh).await
    }

    pub fn shutdown(self) {
        if let Some(a) = self.shared.lock().away.take() {
            a.close_all();
        }
        self.relay_watch
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        self.accept_task
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .abort();
        let ep = self
            .endpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        self.block_on_rt(async move { ep.close().await });
    }
}

/// The home relay's mailbox service, if mailbox traffic is allowed here.
fn home_mailbox(st: &PcState) -> Option<(DeviceId, bool)> {
    st.mailbox_peer.map(|p| (p, st.mailbox_peer_explicit))
}

fn device_info(st: &PcState, id: &DeviceId) -> DeviceInfo {
    let l = st.links.get(id);
    DeviceInfo {
        id: *id,
        name: st.name_of(id),
        platform: l.map(|l| l.link.peer_cert.platform()),
        paired_at: None,
    }
}

async fn send_error(send: &mut iroh::endpoint::SendStream, r: RejectReason) {
    let _ = write_frame(send, frame::ERROR, &error_payload(r)).await;
    finish(send).await;
}

/// Finish the stream and wait (briefly) until the peer has read it, so a
/// final frame isn't lost when the handler returns and the connection drops.
async fn finish(send: &mut iroh::endpoint::SendStream) {
    let _ = send.finish();
    let _ = tokio::time::timeout(Duration::from_secs(3), send.stopped()).await;
}

/// Pairing connections: v2 (M4.3) only.
async fn handle_pair(sh: Arc<Shared>, conn: Connection) {
    let Ok(Ok((mut send, mut recv))) = tokio::time::timeout(IO_TIMEOUT, conn.accept_bi()).await
    else {
        return;
    };
    // The only pairing hello is the v2 one (M4.3).
    match read_frame(&mut recv, IO_TIMEOUT).await {
        Ok((frame::HELLO, p)) if super::pair2::is_v2_hello(&p).is_some() => {
            let sid = super::pair2::is_v2_hello(&p).expect("checked");
            super::pair2::serve(&*sh, conn, send, recv, sid).await
        }
        _ => send_error(&mut send, RejectReason::MalformedFrame).await,
    }
}

/// Paired-device traffic. Strangers are closed before any stream is read.
async fn handle_app(sh: Arc<Shared>, conn: Connection) {
    let peer = match device_id_of(&conn.remote_id()) {
        Ok(p) => p,
        Err(r) => return conn.close(close_code(r), b""),
    };
    {
        let mut st = sh.lock();
        if !st.is_link(&peer) {
            drop(st);
            sh.emit(PcEvent::Rejected {
                reason: RejectReason::NotInRoster,
                from: None,
            });
            return conn.close(close_code(RejectReason::NotInRoster), b"not paired");
        }
        let list = st.conns.entry(peer).or_default();
        if !list.iter().any(|c| c.stable_id() == conn.stable_id()) {
            list.push(conn.clone());
        }
    }
    learn_phone_addrs(&sh, &peer, &conn);
    // Renames waiting for this peer go out on the connection it opened.
    tokio::spawn(super::pair_ops::flush(sh.clone(), conn.clone(), peer));
    loop {
        let Ok((mut send, mut recv)) = conn.accept_bi().await else {
            break;
        };
        let req = read_frame(&mut recv, IO_TIMEOUT).await;
        let (t, payload) = match req {
            Ok(x) => x,
            Err(NetError::Rejected(r)) => {
                // Over-cap or unknown frame type: refused unread (before the
                // inbox sees any bytes, so not in the inbox counters).
                sh.emit(PcEvent::Rejected {
                    reason: r,
                    from: Some(sh.lock().name_of(&peer)),
                });
                send_error(&mut send, r).await;
                continue;
            }
            Err(_) => continue,
        };
        match t {
            frame::SEND => {
                let is_relayed = conn_is_relayed(&sh, &conn);
                let res = on_send(&sh, &peer, &payload, is_relayed);
                let mut out = [0u8; 3];
                match res {
                    Ok(o) => out[2] = o as u8,
                    Err(r) => out[..2].copy_from_slice(&r.code().to_be_bytes()),
                }
                let _ = write_frame(&mut send, frame::RESULT, &out).await;
                let _ = send.finish();
            }
            frame::FILE_OFFER => {
                let is_relayed = conn_is_relayed(&sh, &conn);
                let reply = on_file_offer(&sh, &peer, &payload, is_relayed);
                if write_frame(&mut send, frame::FILE_OFFER_ACK, &reply)
                    .await
                    .is_ok()
                {
                    finish(&mut send).await;
                }
            }
            frame::FILE_CHUNK => {
                let is_relayed = conn_is_relayed(&sh, &conn);
                let reply = on_file_chunk(&sh, &peer, &payload, is_relayed);
                if write_frame(&mut send, frame::FILE_CHUNK_ACK, &reply)
                    .await
                    .is_ok()
                {
                    finish(&mut send).await;
                }
            }
            frame::FILE_CANCEL => {
                let reply = on_file_cancel(&sh, &peer, &payload);
                if write_frame(&mut send, frame::FILE_CANCEL, &reply)
                    .await
                    .is_ok()
                {
                    finish(&mut send).await;
                }
            }
            frame::FILE_PULL => {
                let sh_pull = sh.clone();
                let conn_pull = conn.clone();
                tokio::spawn(async move {
                    let ack = on_file_pull(&sh_pull, &conn_pull, &peer, &payload).await;
                    if write_frame(&mut send, frame::FILE_OFFER_ACK, &ack)
                        .await
                        .is_ok()
                    {
                        finish(&mut send).await;
                    }
                });
                continue;
            }
            frame::RELAY_PROPOSE | frame::RELAY_ACCEPT | frame::RELAY_DECLINE
                if sh.lock().is_link(&peer) =>
            {
                let status = super::relay_change::serve_frame(&*sh, &peer, t, &payload)
                    .unwrap_or(super::relay_change::ack::REFUSED);
                if write_frame(&mut send, frame::RELAY_ACK, &[status])
                    .await
                    .is_ok()
                {
                    finish(&mut send).await;
                }
            }
            frame::PAIR_OPS if sh.lock().is_link(&peer) => {
                let (status, resend) =
                    super::pair_ops::serve_frame(&*sh, &peer, now().wall, &payload);
                if write_frame(&mut send, frame::PAIR_OPS_ACK, &[status])
                    .await
                    .is_ok()
                {
                    finish(&mut send).await;
                }
                if resend {
                    tokio::spawn(super::pair_ops::flush(sh.clone(), conn.clone(), peer));
                }
            }
            _ => send_error(&mut send, RejectReason::MalformedFrame).await,
        }
    }
    let mut st = sh.lock();
    if let Some(v) = st.conns.get_mut(&peer) {
        v.retain(|c| c.stable_id() != conn.stable_id());
    }
}

fn conn_is_relayed(sh: &Shared, conn: &Connection) -> bool {
    if !sh.advertise_loopback && !sh.mdns {
        return true;
    }
    let paths = conn.paths();
    let has_selected_ip = paths
        .iter()
        .any(|p| p.is_selected() && matches!(p.remote_addr(), iroh::TransportAddr::Ip(_)));
    !has_selected_ip
}

fn on_send(
    sh: &Shared,
    peer: &DeviceId,
    envelope: &[u8],
    is_relayed: bool,
) -> Result<SendOutcome, RejectReason> {
    let mut st = sh.lock();
    let n = now();
    let from = st.name_of(peer);
    let received = st.inbox_for_mut(peer).receive_message(peer, envelope, n);
    st.save_high_water(&*sh.store);
    let path_kind = if is_relayed {
        crate::file_transfer::TransportPathKind::Relayed
    } else {
        crate::file_transfer::TransportPathKind::Direct
    };
    let verified_msg = match received {
        Ok(v) => v,
        Err(r) => {
            drop(st);
            sh.emit(PcEvent::Rejected {
                reason: r,
                from: Some(from),
            });
            return Err(r);
        }
    };
    on_verified(
        sh,
        st,
        peer,
        from,
        verified_msg,
        envelope.len() as u64,
        path_kind,
        n,
    )
}

/// Act on a verified message (live or pulled from an inbox).
#[allow(clippy::too_many_arguments)]
fn on_verified(
    sh: &Shared,
    mut st: MutexGuard<'_, PcState>,
    peer: &DeviceId,
    from: String,
    verified_msg: crate::verify::VerifiedMessage,
    env_len: u64,
    path_kind: crate::file_transfer::TransportPathKind,
    n: Now,
) -> Result<SendOutcome, RejectReason> {
    let verified = match verified_msg {
        crate::verify::VerifiedMessage::Url(u) => u,
        crate::verify::VerifiedMessage::Clipboard(clip) => {
            drop(st);
            return on_clipboard_verified(sh, peer, clip, env_len, path_kind, n);
        }
        crate::verify::VerifiedMessage::FileWake(_) => {
            return Err(RejectReason::MalformedFrame);
        }
        crate::verify::VerifiedMessage::PairNotice(pn) => {
            drop(st);
            return on_pair_notice(sh, peer, pn, false).map(|()| SendOutcome::Opened);
        }
    };
    let mode = if st.no_prompt {
        OpenMode::OpenImmediately
    } else {
        OpenMode::ConfirmBeforeOpen
    };
    st.conn_stats
        .record_transfer(peer, path_kind, env_len, n.wall);
    let host = verified.host_for_display().to_owned();
    let tag = verified.inbox_tag();
    match deliver(st.inbox_by_tag(peer, tag), verified, mode, &*sh.opener) {
        Ok(Delivery::Opened) => {
            drop(st);
            sh.emit(PcEvent::Opened {
                host,
                from,
                device: *peer,
                // Only `deliver` in OpenImmediately mode returns `Opened`.
                without_prompt: mode == OpenMode::OpenImmediately,
            });
            Ok(SendOutcome::Opened)
        }
        Ok(Delivery::NeedsConfirmation(p)) => {
            st.expire_prompts(n);
            let expires_mono = n.mono.saturating_add(st.prompt_ttl_ms);
            let id = st.next_pending;
            st.next_pending += 1;
            while st.pending.len() >= MAX_PENDING {
                let oldest = *st.pending.keys().next().expect("non-empty");
                st.pending.remove(&oldest);
            }
            st.pending.insert(
                id,
                Pending {
                    open: p,
                    from: from.clone(),
                    received_at: n.wall,
                    expires_mono,
                },
            );
            drop(st);
            sh.emit(PcEvent::PendingOpen { id, host, from });
            Ok(SendOutcome::Prompted)
        }
        Err(crate::opener::OpenError::Policy(r)) => Err(r),
        Err(_) => Err(RejectReason::Internal),
    }
}

/// M4.2: a pair notice from a v2 peer. Only its signed unpair of our
/// pairing is acted on: the pairing is erased here too. A notice that came
/// live keeps the connection open for the reply (`close_conns` false).
fn on_pair_notice(
    sh: &Shared,
    peer: &DeviceId,
    n: crate::verify::VerifiedPairNotice,
    close_conns: bool,
) -> Result<(), RejectReason> {
    let op =
        crate::pairwise::PairOp::decode(n.op_bytes()).map_err(|_| RejectReason::MalformedFrame)?;
    let pairing_id = sh
        .lock()
        .links
        .get(peer)
        .map(|l| l.link.pairing_id)
        .ok_or(RejectReason::NotInRoster)?;
    if n.sender() != *peer || !op.is_unpair_by(peer, &pairing_id) {
        return Err(RejectReason::BadLogOp);
    }
    erase_link(sh, peer, close_conns).map_err(|_| RejectReason::Internal)?;
    Ok(())
}

/// Erase a v2 pairing and everything received over it (M4.2). Saved
/// first; on failure nothing changes.
/// Dial a peer at `addrs` or through the relay and start serving the
/// connection (shared by sends and the background unpair notice).
async fn dial_peer(
    sh: Arc<Shared>,
    ep: Endpoint,
    mdns: bool,
    phone: DeviceId,
    addrs: Vec<SocketAddr>,
    relay_url: Option<String>,
) -> Result<Connection, NetError> {
    let c = dial_peer_raw(&sh, ep, mdns, phone, addrs, relay_url).await?;
    let c_reader = c.clone();
    tokio::spawn(async move {
        handle_app(sh, c_reader).await;
    });
    Ok(c)
}

/// [`dial_peer`] without serving the peer's streams: for a last message
/// to a peer we've already erased (our own reader would close the
/// connection as "not paired" before the reply arrives).
async fn dial_peer_raw(
    sh: &Shared,
    ep: Endpoint,
    mdns: bool,
    phone: DeviceId,
    addrs: Vec<SocketAddr>,
    relay_url: Option<String>,
) -> Result<Connection, NetError> {
    let (home, away) = {
        let st = sh.lock();
        (st.relay_url.clone(), st.away.clone())
    };
    if let (Some(url), Some(away)) = (away_route(home.as_deref(), relay_url.as_deref()), away) {
        let c = super::away::dial_via(&away, &ep, mdns, &phone, &addrs, &url, true).await?;
        learn_phone_addrs(sh, &phone, &c);
        return Ok(c);
    }
    let ep_id = super::endpoint_id_of(&phone)?;
    let parsed_relay = relay_url.as_deref().and_then(|r| {
        let t = r.trim();
        (!t.is_empty() && t != "off")
            .then(|| t.parse::<iroh::RelayUrl>().ok())
            .flatten()
    });
    let relay_is_local_test = parsed_relay.as_ref().is_some_and(|u| {
        let s = u.as_str();
        s.contains("127.0.0.1") || s.contains("localhost")
    });
    let has_loopback = addrs.iter().any(|a| a.ip().is_loopback());
    let use_relay =
        parsed_relay.is_some() && (relay_is_local_test || addrs.is_empty() || !has_loopback);
    if addrs.is_empty() && !use_relay && !mdns {
        return Err(NetError::Unreachable("no known address for phone".into()));
    }
    if use_relay {
        let _ = tokio::time::timeout(Duration::from_millis(1500), ep.online()).await;
    }
    let mut dial_addrs = addrs.clone();
    if dial_addrs.is_empty() && mdns {
        dial_addrs =
            super::phone::discover_addrs(&ep, &phone, Duration::from_millis(1200), true).await;
    }
    let mut addr = iroh::EndpointAddr::new(ep_id);
    for a in &dial_addrs {
        addr = addr.with_ip_addr(*a);
    }
    if let Some(ref u) = parsed_relay {
        if use_relay {
            addr = addr.with_relay_url(u.clone());
        }
    }
    let timeout = if use_relay {
        Duration::from_secs(4)
    } else {
        Duration::from_millis(1500)
    };
    let c = match tokio::time::timeout(timeout, ep.connect(addr, ALPN_APP)).await {
        Ok(Ok(c)) => c,
        _ if !dial_addrs.is_empty() && use_relay => {
            if let Some(u) = parsed_relay {
                let relay_only = iroh::EndpointAddr::new(ep_id).with_relay_url(u);
                match tokio::time::timeout(Duration::from_secs(4), ep.connect(relay_only, ALPN_APP))
                    .await
                {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => return Err(NetError::Unreachable(e.to_string())),
                    Err(_) => return Err(NetError::Unreachable("no answer from the phone".into())),
                }
            } else {
                return Err(NetError::Unreachable("no answer from the phone".into()));
            }
        }
        Ok(Err(e)) => return Err(NetError::Unreachable(e.to_string())),
        Err(_) => return Err(NetError::Unreachable("no answer from the phone".into())),
    };
    learn_phone_addrs(sh, &phone, &c);
    Ok(c)
}

/// `Some(pairing relay)` when a dial must go through an away endpoint: the
/// pairing has its own relay and it isn't our home relay.
pub(crate) fn away_route(home: Option<&str>, pairing: Option<&str>) -> Option<String> {
    let p = pairing
        .map(str::trim)
        .filter(|p| !p.is_empty() && *p != "off")?;
    match home {
        Some(h) if super::away::same_relay(h, p) => None,
        _ => Some(p.to_owned()),
    }
}

pub(crate) fn away_wanted_of<'a>(
    home: Option<&str>,
    relays: impl Iterator<Item = &'a crate::pairwise::RelayRef>,
) -> Vec<String> {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for r in relays {
        if away_route(home, Some(&r.url)).is_none() {
            continue;
        }
        match counts
            .iter_mut()
            .find(|(u, _)| super::away::same_relay(u, &r.url))
        {
            Some((_, n)) => *n += 1,
            None => counts.push((r.url.clone(), 1)),
        }
    }
    counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    counts.into_iter().map(|(u, _)| u).collect()
}

/// One SEND of an already sealed envelope on an open connection; Ok when
/// the peer accepted it.
async fn send_notice_on(conn: &Connection, env: &[u8]) -> Result<(), NetError> {
    let (mut s, mut r) = conn
        .open_bi()
        .await
        .map_err(|e| super::conn_error(conn, e))?;
    write_frame(&mut s, frame::SEND, env).await?;
    let _ = s.finish();
    let (rt, p) = read_frame(&mut r, IO_TIMEOUT).await?;
    if rt != frame::RESULT || p.len() != 3 || p[0] != 0 || p[1] != 0 {
        return Err(NetError::Protocol("unpair notice not accepted".into()));
    }
    Ok(())
}

/// The replay (seen-id) file of one v2 pairing's inbox.
fn seen_file(dir: &std::path::Path, pairing_id: &GroupId) -> std::path::PathBuf {
    dir.join(format!("seen-{}.bin", pairing_id.to_hex()))
}

fn erase_link(sh: &Shared, peer: &DeviceId, close_conns: bool) -> Result<bool, NetError> {
    let mut st = sh.lock();
    let Some(pairing_id) = st.links.get(peer).map(|l| l.link.pairing_id) else {
        return Ok(false);
    };
    let Some(removed) = st.pairings.remove(&pairing_id) else {
        return Ok(false);
    };
    if let Err(e) = st.commit(&*sh.store) {
        let _ = st.pairings.add(removed);
        st.rebuild_links();
        return Err(e);
    }
    st.forget_seen_file(&pairing_id);
    drop(removed);
    st.conn_stats.forget_peer(peer);
    let tids: Vec<crate::file_transfer::TransferId> = st
        .incoming_files
        .iter()
        .filter(|(_, f)| f.offer.sender == *peer)
        .map(|(t, _)| *t)
        .collect();
    for tid in tids {
        if let Some(mut f) = st.incoming_files.remove(&tid) {
            if let Some(rx) = f.receiver.take() {
                rx.cancel_and_delete();
            }
        }
    }
    st.pending.retain(|_, p| p.open.sender() != *peer);
    st.pending_clipboards.retain(|_, p| p.sender != *peer);
    st.outbound_files.retain(|_, o| o.offer.recipient != *peer);
    st.phone_addrs.remove(peer);
    if close_conns {
        for c in st.conns.remove(peer).unwrap_or_default() {
            c.close(close_code(RejectReason::Removed), b"removed");
        }
    }
    drop(st);
    sh.emit(PcEvent::DevicesChanged);
    Ok(true)
}

/// Pull every v2 pairing inbox of this PC, one throwaway session per relay
/// (M4.2). Event-driven only (start, foreground, a caller's request).
/// Send the unpair notices that are due (all of them when `force`). Runs
/// only from events that reach a relay anyway; failures back off on the
/// supervisor schedule (`net::outbox`).
async fn flush_outbox(sh: &Shared, force: bool) {
    let due = sh.lock().outbox.due(now().wall, force);
    if due.is_empty() {
        return;
    }
    let res = super::outbox::send(due).await;
    let mut st = sh.lock();
    let t = now().wall;
    for (item, ok) in res {
        if ok {
            st.outbox.delivered(&item);
        } else {
            st.outbox.failed(&item, t);
        }
    }
    let _ = st.commit(&*sh.store);
}

async fn pull_link_inboxes(sh: &Shared) -> Result<usize, NetError> {
    sh.inbox_pulls
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    flush_outbox(sh, false).await;
    let targets: Vec<super::links::InboxTarget> = {
        let mut st = sh.lock();
        let me = st.identity.device_id();
        let drains = super::relay_change::live_drains(&mut st.drains);
        let mut v: Vec<super::links::InboxTarget> = st
            .links
            .values()
            .filter_map(|l| {
                l.link
                    .my_inbox(&me, st.relay_url.as_deref(), home_mailbox(&st))
            })
            .collect();
        for d in drains {
            if let Some(l) = st.links.get(&d.peer) {
                v.push(l.link.my_inbox_at(&me, d.relay_url, d.mailbox));
            }
        }
        v
    };
    if targets.is_empty() {
        return Ok(0);
    }
    let mut delivered = 0usize;
    let out = super::links::pull_batched(targets, |peer, item, caps| {
        let n = now();
        let mut st = sh.lock();
        let ttl = caps
            .map(|c| c.inbox_ttl_secs)
            .unwrap_or_else(|| st.relay_policy.inbox_ttl_secs());
        if !st.is_link(peer) {
            return;
        }
        let from = st.name_of(peer);
        let res =
            st.inbox_for_mut(peer)
                .receive_from_device_inbox(&item.envelope, u64::from(ttl), n);
        let Ok(msg) = res else {
            return;
        };
        let msg = match msg {
            // A PC has no file pull path (FileWake is for phones).
            crate::verify::VerifiedMessage::FileWake(_) => return,
            crate::verify::VerifiedMessage::PairNotice(pn) => {
                drop(st);
                let _ = on_pair_notice(sh, peer, pn, true);
                return;
            }
            other => other,
        };
        if on_verified(
            sh,
            st,
            peer,
            from,
            msg,
            item.envelope.len() as u64,
            crate::file_transfer::TransportPathKind::Relayed,
            n,
        )
        .is_ok()
        {
            delivered += 1;
        }
    })
    .await;
    {
        let mut st = sh.lock();
        if let Some(eph) = out.last_session {
            st.last_throwaway_id = Some(eph);
        }
        if let Some(c) = out.caps {
            st.relay_policy.set_server_cap_bytes(c.max_relay_file_bytes);
            st.relay_policy
                .set_inbox_limits(c.inbox_max_items, c.inbox_ttl_secs);
        }
    }
    match out.last_err {
        Some(e) if delivered == 0 => Err(e),
        _ => Ok(delivered),
    }
}

fn encode_file_ack(
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

fn on_file_offer(sh: &Shared, peer: &DeviceId, envelope: &[u8], is_relayed: bool) -> Vec<u8> {
    let zero_tid = crate::file_transfer::TransferId::from_bytes([0u8; 16]);
    let mut st = sh.lock();
    let n = now();
    let from = st.name_of(peer);
    let dir = st.download_dir.clone();
    let auto_accept = st.auto_accept_files;

    crate::file_transfer::purge_expired_parts(&dir, n.wall);

    let active_in_mem: Vec<(
        crate::file_transfer::TransferId,
        DeviceId,
        u64,
        u64,
        [u8; 32],
    )> = st
        .incoming_files
        .values()
        .map(|inc| {
            (
                inc.offer.transfer_id,
                inc.offer.sender,
                inc.offer.size,
                inc.offer.chunk_count,
                inc.offer.blake3_root,
            )
        })
        .collect();
    let declined_in_mem: Vec<(crate::file_transfer::TransferId, DeviceId)> =
        st.declined_files.iter().copied().collect();
    let dir_for_resume = dir.clone();
    let verified = st.inbox_for_mut(peer).verify_file_offer(
        peer,
        envelope,
        |offer| {
            if active_in_mem.iter().any(|(tid, s, sz, cc, root)| {
                *tid == offer.transfer_id
                    && *s == offer.sender
                    && *sz == offer.size
                    && *cc == offer.chunk_count
                    && *root == offer.blake3_root
            }) {
                return true;
            }
            if declined_in_mem
                .iter()
                .any(|(tid, s)| *tid == offer.transfer_id && *s == offer.sender)
            {
                return true;
            }
            let (part_path, meta_path) =
                crate::file_transfer::part_paths(&dir_for_resume, &offer.transfer_id);
            if part_path.exists() && meta_path.exists() {
                if let Some(meta) = std::fs::read(&meta_path)
                    .ok()
                    .and_then(|b| crate::file_transfer::PartResumeMeta::from_bytes(&b))
                {
                    return meta.transfer_id == offer.transfer_id
                        && meta.total_size == offer.size
                        && meta.chunk_count == offer.chunk_count
                        && meta.blake3_root == offer.blake3_root
                        && n.wall.0 < meta.expires_at.0;
                }
            }
            false
        },
        n,
    );
    st.save_high_water(&*sh.store);
    let (offer, k_file) = match verified {
        Ok(x) => x,
        Err(r) => {
            drop(st);
            sh.emit(PcEvent::Rejected {
                reason: r,
                from: Some(from),
            });
            return encode_file_ack(3, &zero_tid, r.code() as u64, r.label());
        }
    };
    let tid = offer.transfer_id;

    if is_relayed {
        let eff_cap = st.relay_policy.effective_cap_bytes();
        if eff_cap == 0 || offer.size > eff_cap {
            return encode_file_ack(3, &tid, eff_cap, "exceeds_relay_cap");
        }
    }

    if st
        .declined_files
        .iter()
        .any(|(dtid, s)| *dtid == tid && *s == *peer)
    {
        return encode_file_ack(3, &tid, 0, "canceled_by_recipient (declined by recipient)");
    }

    // If we already have an in-memory session for this transfer_id, update its k_file from the fresh HPKE offer and return its next_chunk!
    if let Some(existing) = st.incoming_files.get_mut(&tid) {
        if existing.offer.sender != *peer
            || existing.offer.blake3_root != offer.blake3_root
            || existing.offer.size != offer.size
            || existing.offer.chunk_count != offer.chunk_count
        {
            return encode_file_ack(3, &tid, 0, "resume_metadata_mismatch");
        }
        existing.k_file = k_file.clone();
        existing.last_activity = n.wall;
        if let Some(ref mut rcv) = existing.receiver {
            rcv.update_file_key(k_file);
        }
        let next_chunk = existing
            .receiver
            .as_ref()
            .map(|r| r.next_chunk())
            .unwrap_or(0);
        let status = if existing.accepted { 0 } else { 1 };
        return encode_file_ack(status, &tid, next_chunk, "");
    }

    if st.incoming_files.len() >= MAX_CONCURRENT_INCOMING_FILES {
        return encode_file_ack(3, &tid, 0, "too_many_concurrent_transfers");
    }

    let is_clipboard_stream = offer.mime == crate::clipboard::CLIPBOARD_STREAM_MIME
        && offer.size <= crate::limits::MAX_STREAMED_CLIPBOARD_BYTES as u64;
    if offer.mime == crate::clipboard::CLIPBOARD_STREAM_MIME
        && offer.size > crate::limits::MAX_STREAMED_CLIPBOARD_BYTES as u64
    {
        return encode_file_ack(3, &tid, 0, "clipboard_too_large");
    }
    let auto_accept_clipboard_stream =
        is_clipboard_stream && offer.size <= crate::file_transfer::DEFAULT_SMALL_ITEM_CAP_BYTES;

    // Check if an accepted .part.meta already exists on disk from a previous session
    let (part_path, meta_path) = crate::file_transfer::part_paths(&dir, &tid);
    let has_disk_part = part_path.exists() && meta_path.exists();

    let (receiver, accepted, next_chunk) =
        if auto_accept || auto_accept_clipboard_stream || has_disk_part {
            // Create or resume PartFileReceiver on disk (enforces 2 GiB cap and size + 64 MiB free space).
            let rcv = match crate::file_transfer::PartFileReceiver::open_or_resume(
                offer.clone(),
                k_file.clone(),
                &dir,
                n.wall,
            ) {
                Ok(r) => r,
                Err(crate::file_transfer::FileAcceptError::ExceedsMaxFileSize { size, .. }) => {
                    return encode_file_ack(3, &tid, size, "offer_too_large");
                }
                Err(crate::file_transfer::FileAcceptError::InsufficientDiskSpace {
                    required,
                    available,
                }) => {
                    return encode_file_ack(
                        3,
                        &tid,
                        available.min(required),
                        "insufficient_disk_space",
                    );
                }
                Err(e) => {
                    return encode_file_ack(3, &tid, 0, &e.to_string());
                }
            };
            let nc = rcv.next_chunk();
            (Some(rcv), true, nc)
        } else {
            // M26-H1: Do NOT write .part or .part.meta to disk before user consent!
            match crate::file_transfer::check_offer_acceptable(&offer, &dir, n.wall) {
                Ok(()) => {}
                Err(crate::file_transfer::FileAcceptError::ExceedsMaxFileSize { size, .. }) => {
                    return encode_file_ack(3, &tid, size, "offer_too_large");
                }
                Err(crate::file_transfer::FileAcceptError::InsufficientDiskSpace {
                    required,
                    available,
                }) => {
                    return encode_file_ack(
                        3,
                        &tid,
                        available.min(required),
                        "insufficient_disk_space",
                    );
                }
                Err(e) => {
                    return encode_file_ack(3, &tid, 0, &e.to_string());
                }
            }
            (None, false, 0)
        };

    let filename = offer.filename.clone();
    let size = offer.size;
    let allow_open = offer.allow_open;
    st.incoming_files.insert(
        tid,
        IncomingFileSession {
            offer,
            from: from.clone(),
            k_file,
            receiver,
            accepted,
            last_activity: n.wall,
        },
    );
    drop(st);
    sh.stall_cv.notify_all();
    if !auto_accept_clipboard_stream {
        sh.emit(PcEvent::FileOfferPending {
            transfer_id: tid,
            filename,
            size,
            from,
            allow_open,
        });
    }
    let status = if accepted { 0 } else { 1 };
    encode_file_ack(status, &tid, next_chunk, "")
}

fn on_file_chunk(sh: &Shared, peer: &DeviceId, payload: &[u8], is_relayed: bool) -> Vec<u8> {
    let zero_tid = crate::file_transfer::TransferId::from_bytes([0u8; 16]);
    if payload.len() < 16 + 8 + 1 {
        return encode_file_ack(3, &zero_tid, 0, "short_chunk_frame");
    }
    let mut tid_b = [0u8; 16];
    tid_b.copy_from_slice(&payload[..16]);
    let tid = crate::file_transfer::TransferId::from_bytes(tid_b);
    let chunk_index = u64::from_be_bytes(payload[16..24].try_into().expect("8"));
    let is_final = payload[24] == 1;
    let ciphertext = &payload[25..];

    let mut st = sh.lock();
    if !st.is_link(peer) {
        if let Some(sess) = st.incoming_files.remove(&tid) {
            if let Some(rcv) = sess.receiver {
                rcv.cancel_and_delete();
            }
        }
        return encode_file_ack(3, &tid, RejectReason::Removed.code() as u64, "not_active");
    }
    let eff_cap = st.relay_policy.effective_cap_bytes();
    let was_declined = st
        .declined_files
        .iter()
        .any(|(dtid, s)| *dtid == tid && *s == *peer);
    let Some(sess) = st.incoming_files.get_mut(&tid) else {
        let reason = if was_declined {
            "canceled_by_recipient"
        } else {
            "unknown_transfer"
        };
        return encode_file_ack(3, &tid, 0, reason);
    };
    if sess.offer.sender != *peer {
        return encode_file_ack(3, &tid, 0, "sender_mismatch");
    }
    if is_relayed && (eff_cap == 0 || sess.offer.size > eff_cap) {
        if let Some(failed_sess) = st.incoming_files.remove(&tid) {
            if let Some(rcv) = failed_sess.receiver {
                rcv.cancel_and_delete();
            }
        }
        return encode_file_ack(3, &tid, eff_cap, "exceeds_relay_cap");
    }
    if !sess.accepted || sess.receiver.is_none() {
        let nc = sess.receiver.as_ref().map(|r| r.next_chunk()).unwrap_or(0);
        return encode_file_ack(1, &tid, nc, "awaiting_accept");
    }
    if is_final != (chunk_index + 1 == sess.offer.chunk_count) {
        if let Some(failed_sess) = st.incoming_files.remove(&tid) {
            if let Some(rcv) = failed_sess.receiver {
                rcv.cancel_and_delete();
            }
        }
        return encode_file_ack(3, &tid, chunk_index, "is_final_mismatch");
    }
    sess.last_activity = now().wall;
    sh.file_progress.notify_waiters();
    let rcv = sess.receiver.as_mut().expect("checked is_some");
    if let Err(e) = rcv.write_encrypted_chunk(chunk_index, ciphertext) {
        let msg = e.to_string();
        if let Some(failed_sess) = st.incoming_files.remove(&tid) {
            if let Some(r) = failed_sess.receiver {
                r.cancel_and_delete();
            }
        }
        drop(st);
        sh.emit(PcEvent::FileCancelled {
            transfer_id: tid,
            reason: msg.clone(),
        });
        return encode_file_ack(3, &tid, chunk_index, &msg);
    }
    let next_chunk = rcv.next_chunk();
    if rcv.is_complete() {
        let completed_sess = st.incoming_files.remove(&tid).expect("just checked");
        let offer = completed_sess.offer;
        let from = completed_sess.from;
        let rcv = completed_sess.receiver.expect("checked is_some");
        match rcv.finalize() {
            Ok(completed) => {
                let final_path = completed.path;
                let path_kind = if is_relayed {
                    crate::file_transfer::TransportPathKind::Relayed
                } else {
                    crate::file_transfer::TransportPathKind::Direct
                };
                st.conn_stats
                    .record_transfer(peer, path_kind, offer.size, now().wall);
                let _ = st.commit(&*sh.store);
                if offer.mime == crate::clipboard::CLIPBOARD_STREAM_MIME {
                    let bytes = std::fs::read(&final_path).unwrap_or_default();
                    let _ = std::fs::remove_file(&final_path);
                    drop(st);
                    match String::from_utf8(bytes) {
                        Ok(text)
                            if !text.is_empty()
                                && text.len() <= crate::limits::MAX_STREAMED_CLIPBOARD_BYTES =>
                        {
                            let sensitive = crate::clipboard::looks_sensitive_clipboard(&text);
                            deliver_clipboard_text(sh, peer, text, sensitive, now());
                            encode_file_ack(2, &tid, next_chunk, "completed")
                        }
                        _ => encode_file_ack(3, &tid, next_chunk, "bad_clipboard_utf8"),
                    }
                } else {
                    let info = CompletedFileInfo {
                        transfer_id: tid,
                        sender: *peer,
                        from: from.clone(),
                        filename: offer.filename.clone(),
                        path: final_path.clone(),
                        size: offer.size,
                        blake3_root: offer.blake3_root,
                        allow_open: offer.allow_open,
                    };
                    if st.keep_file_history {
                        if st.completed_files.len() >= MAX_COMPLETED_FILES_HISTORY {
                            st.completed_files.remove(0);
                        }
                        st.completed_files.push(info);
                    }
                    drop(st);
                    sh.emit(PcEvent::FileCompleted {
                        transfer_id: tid,
                        filename: offer.filename,
                        path: final_path,
                        size: offer.size,
                        from,
                        allow_open: offer.allow_open,
                    });
                    encode_file_ack(2, &tid, next_chunk, "completed")
                }
            }
            Err(e) => {
                let msg = e.to_string();
                drop(st);
                sh.emit(PcEvent::FileCancelled {
                    transfer_id: tid,
                    reason: msg.clone(),
                });
                encode_file_ack(3, &tid, next_chunk, &msg)
            }
        }
    } else {
        encode_file_ack(0, &tid, next_chunk, "")
    }
}

fn on_file_cancel(sh: &Shared, peer: &DeviceId, payload: &[u8]) -> Vec<u8> {
    let zero_tid = crate::file_transfer::TransferId::from_bytes([0u8; 16]);
    if payload.len() < 16 {
        return encode_file_ack(3, &zero_tid, 0, "short_cancel");
    }
    let mut tid_b = [0u8; 16];
    tid_b.copy_from_slice(&payload[..16]);
    let tid = crate::file_transfer::TransferId::from_bytes(tid_b);
    let (removed_incoming, removed_outbound) = {
        let mut st = sh.lock();
        let inc = if st
            .incoming_files
            .get(&tid)
            .is_some_and(|s| s.offer.sender == *peer)
        {
            st.incoming_files.remove(&tid)
        } else {
            None
        };
        let out = if st
            .outbound_files
            .get(&tid)
            .is_some_and(|o| o.offer.recipient == *peer)
        {
            if !st.cancelled_outbound_files.contains(&tid) {
                if st.cancelled_outbound_files.len() >= 64 {
                    st.cancelled_outbound_files.pop_front();
                }
                st.cancelled_outbound_files.push_back(tid);
            }
            st.outbound_files.remove(&tid)
        } else {
            None
        };
        (inc, out)
    };
    if let Some(sess) = removed_incoming {
        if let Some(rcv) = sess.receiver {
            rcv.cancel_and_delete();
        }
        sh.emit(PcEvent::FileCancelled {
            transfer_id: tid,
            reason: "cancelled_by_sender".into(),
        });
    } else if let Some(o) = removed_outbound {
        end_outbound(&mut sh.lock(), &o, OutboundEnd::Declined);
        sh.stall_cv.notify_all();
        sh.emit(PcEvent::FileCancelled {
            transfer_id: tid,
            reason: "canceled_by_recipient".into(),
        });
    }
    encode_file_ack(4, &tid, 0, "cancelled")
}

fn learn_phone_addrs(sh: &Shared, phone: &DeviceId, conn: &Connection) {
    let paths = conn.paths();
    let mut addrs = Vec::new();
    for p in paths.iter() {
        if let iroh::TransportAddr::Ip(sock) = p.remote_addr() {
            if !addrs.contains(sock) {
                addrs.push(*sock);
            }
        }
    }
    if !addrs.is_empty() {
        sh.lock().phone_addrs.insert(*phone, addrs);
    }
}

fn on_clipboard_verified(
    sh: &Shared,
    peer: &DeviceId,
    clip: crate::verify::VerifiedClipboard,
    bytes: u64,
    path_kind: crate::file_transfer::TransportPathKind,
    n: Now,
) -> Result<SendOutcome, RejectReason> {
    {
        let mut st = sh.lock();
        st.conn_stats
            .record_transfer(peer, path_kind, bytes, n.wall);
        let _ = st.commit(&*sh.store);
    }
    let text = clip.as_str().to_owned();
    let sensitive = clip.is_sensitive() || crate::clipboard::looks_sensitive_clipboard(&text);
    Ok(deliver_clipboard_text(sh, peer, text, sensitive, n))
}

fn deliver_clipboard_text(
    sh: &Shared,
    peer: &DeviceId,
    text: String,
    sensitive: bool,
    n: Now,
) -> SendOutcome {
    let byte_len = text.len();
    let mut st = sh.lock();
    st.expire_prompts(n);
    let from = st.name_of(peer);
    if st.auto_copy_clipboard {
        drop(st);
        sh.emit(PcEvent::ClipboardAutoCopied {
            from,
            device: *peer,
            text,
            byte_len,
            sensitive,
        });
        return SendOutcome::Opened;
    }
    if st.pending.len() + st.pending_clipboards.len() >= MAX_PENDING {
        if let Some((&oldest_id, _)) = st.pending_clipboards.iter().next() {
            st.pending_clipboards.remove(&oldest_id);
        }
    }
    let id = st.next_pending;
    st.next_pending += 1;
    let expires_mono = n.mono.saturating_add(st.prompt_ttl_ms);
    st.pending_clipboards.insert(
        id,
        PendingClipboard {
            from: from.clone(),
            sender: *peer,
            text: zeroize::Zeroizing::new(text),
            sensitive,
            received_at: n.wall,
            expires_mono,
        },
    );
    drop(st);
    sh.emit(PcEvent::ClipboardPending {
        id,
        from,
        byte_len,
        sensitive,
    });
    SendOutcome::Prompted
}

async fn on_file_pull(
    sh: &Arc<Shared>,
    conn: &Connection,
    peer: &DeviceId,
    payload: &[u8],
) -> Vec<u8> {
    let Some(arr) = payload
        .get(0..16)
        .and_then(|s| <[u8; 16]>::try_from(s).ok())
    else {
        return encode_file_ack(
            3,
            &crate::file_transfer::TransferId::from_bytes([0u8; 16]),
            0,
            "bad_pull_payload",
        );
    };
    let tid = crate::file_transfer::TransferId::from_bytes(arr);
    let is_relayed = conn_is_relayed(sh, conn);
    let envelope = {
        let mut st = sh.lock();
        if st.cancelled_outbound_files.contains(&tid) {
            return encode_file_ack(3, &tid, 0, "cancelled_by_sender");
        }
        let Some(out) = st.outbound_files.get(&tid) else {
            return encode_file_ack(3, &tid, 0, "unknown_or_expired_transfer");
        };
        if out.offer.recipient != *peer || now().wall.0 >= out.offer.expires_at.0 {
            st.outbound_files.remove(&tid);
            return encode_file_ack(3, &tid, 0, "unknown_or_expired_transfer");
        }
        if is_relayed {
            let eff_cap = st.relay_policy.effective_cap_bytes();
            if eff_cap == 0 || out.offer.size > eff_cap {
                return encode_file_ack(3, &tid, eff_cap, "exceeds_relay_cap");
            }
        }
        let env = out.envelope.clone();
        if let Some(o) = st.outbound_files.get_mut(&tid) {
            o.pulled = true;
            o.last_activity = now().wall;
        }
        // The pre-accept deadline is gone.
        sh.stall_cv.notify_all();
        env
    };

    let offer_ack = async {
        let (mut s, mut r) = conn
            .open_bi()
            .await
            .map_err(|e| super::conn_error(conn, e))?;
        write_frame(&mut s, frame::FILE_OFFER, &envelope).await?;
        let _ = s.finish();
        let (rt, ack_bytes) = read_frame(&mut r, IO_TIMEOUT).await?;
        if rt == frame::ERROR {
            return Err(super::parse_error(&ack_bytes));
        }
        if rt != frame::FILE_OFFER_ACK {
            return Err(NetError::Protocol("unexpected file offer reply".into()));
        }
        super::phone::PhoneClient::decode_file_ack(&ack_bytes)
    }
    .await;

    match offer_ack {
        Ok((0 | 2, _t, next_chunk, _m)) => {
            match stream_outbound_chunks_on_conn(sh, conn, peer, tid, next_chunk, is_relayed).await
            {
                Ok(chunks_sent) => encode_file_ack(2, &tid, chunks_sent, "completed"),
                Err(e) => encode_file_ack(3, &tid, 0, &e.to_string()),
            }
        }
        Ok((_, _t, nc, msg)) => encode_file_ack(3, &tid, nc, &msg),
        Err(e) => encode_file_ack(3, &tid, 0, &e.to_string()),
    }
}

async fn stream_outbound_chunks_on_conn(
    sh: &Arc<Shared>,
    conn: &Connection,
    peer: &DeviceId,
    tid: crate::file_transfer::TransferId,
    start_chunk: u64,
    is_relayed: bool,
) -> Result<u64, NetError> {
    let (offer, k_file, data) = {
        let st = sh.lock();
        let out = st
            .outbound_files
            .get(&tid)
            .ok_or_else(|| NetError::Protocol("outbound_file_not_found".into()))?;
        (out.offer.clone(), out.k_file.clone(), out.data.clone())
    };
    let mut file_handle = match &data {
        OutboundFileData::Bytes(_) => None,
        OutboundFileData::Path(p) => {
            Some(std::fs::File::open(p).map_err(|e| NetError::Storage(e.to_string()))?)
        }
    };
    let mut chunks_sent = 0u64;
    let mut chunk_buf = Vec::new();
    for idx in start_chunk..offer.chunk_count {
        while sh
            .hold_outbound_chunks
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        {
            let st = sh.lock();
            if st.cancelled_outbound_files.contains(&tid) || !st.outbound_files.contains_key(&tid) {
                return Err(NetError::Cancelled);
            }
        }
        let c_start = (idx as usize) * crate::file_transfer::FILE_CHUNK_SIZE;
        let c_len = ((offer.size - idx * crate::file_transfer::FILE_CHUNK_SIZE as u64) as usize)
            .min(crate::file_transfer::FILE_CHUNK_SIZE);
        let plain_slice: &[u8] = match (&data, &mut file_handle) {
            (OutboundFileData::Bytes(bytes), _) => &bytes[c_start..c_start + c_len],
            (OutboundFileData::Path(_), Some(f)) => {
                use std::io::{Read, Seek, SeekFrom};
                f.seek(SeekFrom::Start(
                    idx * crate::file_transfer::FILE_CHUNK_SIZE as u64,
                ))
                .map_err(|e| NetError::Storage(e.to_string()))?;
                chunk_buf.resize(c_len, 0);
                f.read_exact(&mut chunk_buf)
                    .map_err(|e| NetError::Storage(e.to_string()))?;
                &chunk_buf[..]
            }
            _ => unreachable!(),
        };
        let is_final = idx + 1 == offer.chunk_count;
        let ct = crate::file_transfer::encrypt_chunk(&k_file, &tid, idx, is_final, plain_slice)
            .map_err(NetError::Rejected)?;
        let mut frame_bytes = Vec::with_capacity(16 + 8 + 1 + ct.len());
        frame_bytes.extend_from_slice(tid.as_bytes());
        frame_bytes.extend_from_slice(&idx.to_be_bytes());
        frame_bytes.push(u8::from(is_final));
        frame_bytes.extend_from_slice(&ct);
        let (mut s, mut r) = conn
            .open_bi()
            .await
            .map_err(|e| super::conn_error(conn, e))?;
        write_frame(&mut s, frame::FILE_CHUNK, &frame_bytes).await?;
        let _ = s.finish();
        let (rt, ack_bytes) = read_frame(&mut r, IO_TIMEOUT).await?;
        if rt == frame::ERROR {
            return Err(super::parse_error(&ack_bytes));
        }
        if rt != frame::FILE_CHUNK_ACK {
            return Err(NetError::Protocol("unexpected file chunk reply".into()));
        }
        let (c_status, _ctid, c_next, c_msg) =
            super::phone::PhoneClient::decode_file_ack(&ack_bytes)?;
        if c_status >= 3 {
            sh.lock().outbound_files.remove(&tid);
            if c_msg.contains("canceled_by_recipient") {
                return Err(NetError::Protocol(
                    "file_offer_rejected: canceled_by_recipient".into(),
                ));
            }
            let detail = if c_msg.contains("exceeds_relay_cap") && !c_msg.contains("cap=") {
                format!("{c_msg}: cap={c_next}")
            } else {
                c_msg
            };
            return Err(NetError::Protocol(format!("file_chunk_rejected: {detail}")));
        }
        chunks_sent += 1;
        {
            let mut st = sh.lock();
            if let Some(out) = st.outbound_files.get_mut(&tid) {
                out.chunks_sent = idx + 1;
                out.last_activity = now().wall;
            }
        }
        sh.emit(PcEvent::OutgoingFileUpdated {
            transfer_id: tid,
            recipient: *peer,
            chunks_sent: idx + 1,
            chunk_count: offer.chunk_count,
            completed: c_status == 2 || idx + 1 == offer.chunk_count,
        });
        if c_status == 2 {
            break;
        }
    }
    let path_kind = if is_relayed {
        crate::file_transfer::TransportPathKind::Relayed
    } else {
        crate::file_transfer::TransportPathKind::Direct
    };
    {
        let mut st = sh.lock();
        st.outbound_files.remove(&tid);
        st.conn_stats
            .record_transfer(peer, path_kind, offer.size, now().wall);
        let _ = st.commit(&*sh.store);
    }
    Ok(chunks_sent)
}

/// A live connection to `peer` (reused, or dialed with our stream reader).
async fn peer_conn(
    sh: &Arc<Shared>,
    ep: Endpoint,
    mdns: bool,
    phone: &DeviceId,
    fresh: bool,
) -> Result<Connection, NetError> {
    {
        let mut st = sh.lock();
        let _ = st.peer_ctx(phone)?;
        if fresh {
            if let Some(old_list) = st.conns.remove(phone) {
                for c in old_list {
                    c.close(0u32.into(), b"reconnect");
                }
            }
        } else if let Some(list) = st.conns.get_mut(phone) {
            list.retain(|c| c.close_reason().is_none());
            if let Some(c) = list.last().cloned() {
                return Ok(c);
            }
        }
    }
    let (addrs, relay_url) = {
        let st = sh.lock();
        (
            st.phone_addrs.get(phone).cloned().unwrap_or_default(),
            st.live_relay_for(phone),
        )
    };
    dial_peer(sh.clone(), ep, mdns, *phone, addrs, relay_url).await
}

/// Ask a desktop sender for an accepted file (FILE_PULL) and wait for its
/// final ack while the chunks land on our stream reader. The wait ends
/// with the sender's answer, or when no chunk has landed for IO_TIMEOUT.
async fn pull_file_from_peer(
    sh: &Arc<Shared>,
    conn: &Connection,
    tid: &crate::file_transfer::TransferId,
) -> Result<(), NetError> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| super::conn_error(conn, e))?;
    write_frame(&mut send, frame::FILE_PULL, tid.as_bytes()).await?;
    let _ = send.finish();
    let read_fut = async {
        let mut hdr = [0u8; 5];
        recv.read_exact(&mut hdr)
            .await
            .map_err(|e| super::conn_error(conn, e))?;
        let t = hdr[0];
        let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        if len > super::frame_cap(t) {
            return Err(NetError::Rejected(RejectReason::MalformedFrame));
        }
        let mut payload = vec![0u8; len];
        recv.read_exact(&mut payload)
            .await
            .map_err(|e| super::conn_error(conn, e))?;
        Ok((t, payload))
    };
    tokio::pin!(read_fut);
    let (rt, ack) = loop {
        let progressed = sh.file_progress.notified();
        tokio::select! {
            res = &mut read_fut => break res?,
            r = tokio::time::timeout(IO_TIMEOUT, progressed) => {
                if r.is_err() {
                    return Err(NetError::Timeout);
                }
            }
        }
    };
    if rt == frame::ERROR {
        return Err(super::parse_error(&ack));
    }
    if rt != frame::FILE_OFFER_ACK {
        return Err(NetError::Protocol("unexpected file pull reply".into()));
    }
    let (status, _t, _nc, msg) = super::phone::PhoneClient::decode_file_ack(&ack)?;
    if status >= 3 {
        return Err(NetError::Protocol(format!("file_offer_rejected: {msg}")));
    }
    if sh.lock().incoming_files.contains_key(tid) {
        return Err(NetError::Protocol(
            "the sender stopped before the end".into(),
        ));
    }
    Ok(())
}

/// Short, content-free reason for a failed incoming transfer.
fn file_failure_reason(e: &NetError) -> String {
    match e {
        NetError::Timeout => "timed_out".into(),
        NetError::Cancelled => "cancelled".into(),
        NetError::Unreachable(_) => "sender_unreachable".into(),
        other => other.to_string(),
    }
}

/// An incoming transfer failed: forget it, delete its `.part` and
/// `.part.meta`, and tell the UI. No-op when it already finished.
fn fail_incoming_file(sh: &Shared, tid: &crate::file_transfer::TransferId, reason: &str) {
    let sess = sh.lock().incoming_files.remove(tid);
    if let Some(sess) = sess {
        if let Some(rcv) = sess.receiver {
            rcv.cancel_and_delete();
        }
        sh.emit(PcEvent::FileCancelled {
            transfer_id: *tid,
            reason: reason.to_owned(),
        });
    }
}

impl super::pair_ops::Host for Shared {
    fn po_me(&self) -> DeviceKeypair {
        DeviceKeypair::from_secret_bytes(&self.lock().identity.secret_bytes())
    }
    fn po_with(
        &self,
        f: &mut dyn FnMut(&mut crate::pairwise::PairingSet, &mut super::pair_ops::Unsent) -> bool,
    ) {
        {
            let mut st = self.lock();
            let st2 = &mut *st;
            if !f(&mut st2.pairings, &mut st2.unsent_ops) {
                return;
            }
            // Not saved: RAM is ahead and the next save catches up.
            let _ = st.commit(&*self.store);
        }
        self.emit(PcEvent::DevicesChanged);
    }
}

impl super::relay_change::Host for Shared {
    fn rc_me(&self) -> DeviceKeypair {
        DeviceKeypair::from_secret_bytes(&self.lock().identity.secret_bytes())
    }
    fn rc_log(&self, peer: &DeviceId) -> Option<(crate::pairwise::PairLog, String)> {
        let st = self.lock();
        if !st.is_link(peer) {
            return None;
        }
        super::relay_change::log_of(&st.pairings, peer)
    }
    fn rc_room(&self, peer: &DeviceId, relay: &crate::pairwise::RelayRef) -> bool {
        let st = self.lock();
        super::relay_change::room(&st.pairings, &st.relay_settings, peer, relay)
    }
    fn rc_is_saved(&self, url: &str) -> bool {
        super::relay_change::is_saved(&self.lock().relay_settings, url)
    }
    fn rc_commit(&self, peer: &DeviceId, log: crate::pairwise::PairLog) -> Result<(), NetError> {
        {
            let mut st = self.lock();
            let old = st
                .links
                .get(peer)
                .and_then(|l| l.link.place(st.relay_url.as_deref(), home_mailbox(&st)));
            let st = &mut *st;
            super::relay_change::apply_commit(
                &mut st.pairings,
                &mut st.relay_settings,
                &mut st.drains,
                peer,
                log,
                old,
            )?;
            // New sends dial on the new relay; a connection still serving
            // this exchange finishes on its own.
            st.conns.remove(peer);
            st.commit(&*self.store)?;
        }
        self.emit(PcEvent::DevicesChanged);
        Ok(())
    }
    fn rc_slots(&self) -> MutexGuard<'_, super::relay_change::Slots> {
        self.relay_change.lock().unwrap_or_else(|p| p.into_inner())
    }
    fn rc_changed(&self) {
        self.emit(PcEvent::RelayChangeChanged);
    }
}
