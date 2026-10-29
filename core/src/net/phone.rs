//! The phone side: QR pairing (joiner) and sending links to paired PCs.
//! Blocking API (an internal tokio runtime); the Android app calls it from a
//! background thread through UniFFI (`crate::ffi`).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, SecretKey};

use super::links::{PairLink, PeerLog};
use super::state::{read_ops, read_secret, write_ops, Reader, StateStore, Writer};
use super::{
    close_code, conn_error, decode_ops, endpoint_id_of, frame, pairing_exporter, pairing_handshake,
    parse_error, read_frame, write_frame, NetError, SendOutcome, ALPN_APP, ALPN_PAIR, IO_TIMEOUT,
    MDNS_SERVICE,
};
use crate::envelope;
use crate::grouplog::{GroupReplica, Membership};
use crate::ids::{DeviceId, GroupId, MsgId};
use crate::keys::{valid_device_name, DeviceCert, DeviceKeypair, Platform, ReceiveKeypair};
use crate::pairing::{PairingRequest, ScannedInvite};
use crate::reject::RejectReason;
use crate::time::{Clock, SystemClock};
use crate::wire::{encode_signed, Outgoing};

/// State format v2 (M4.1); v1 files (v0.4.x and older) load unchanged and
/// are rewritten as v2 on the next save.
const STATE_MAGIC: &[u8] = b"VWPH2\n";
const STATE_MAGIC_V1: &[u8] = b"VWPH1\n";
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
    /// The PC removed us ("Forget this device"), learned at the last sync.
    pub removed: bool,
    pub addrs: Vec<SocketAddr>,
}

/// What a scanned pairing QR would do, worked out **before** any network
/// traffic (OQ-9 / PAIR-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteCheck {
    pub pc: DeviceId,
    pub group: GroupId,
    /// The inviting PC's name from the QR (`n=`); verified against its
    /// signed certificate during pairing.
    pub pc_name: Option<String>,
    /// This phone already belongs to at least one other device group, so
    /// pairing joins a **different** one: the UI must warn and the user
    /// must confirm (`GroupChange::Confirmed`).
    ///
    /// "Same group" is decided from authenticated identity, never from the
    /// QR's `g=` alone (QA M1 re-check, PAIR-11 bypass): the inviter's device
    /// id must be the owner, or a member, of a group whose signed log this
    /// phone already holds. The id is the PC's TLS key, which the handshake
    /// proves, and it is re-checked against the signed certificate and log
    /// before anything is committed.
    pub joins_different_group: bool,
    /// The PC's name equals the name of a *different* PC this phone is
    /// already paired with ("two Home PCs"): warn too, same confirmation.
    pub duplicate_name: bool,
    /// Names of the PCs whose groups this phone is in now (for the warning).
    pub current_groups: Vec<String>,
}

/// The user's answer to the "different device group" warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupChange {
    /// Default: refuse to join a different group (`GroupChangeNotConfirmed`).
    NotConfirmed,
    /// The user saw the warning and chose to join.
    Confirmed,
}

/// How a pairing target relates to what this phone already has (PAIR-11).
struct GroupRelation {
    current_groups: Vec<String>,
    /// The inviter is the owner or a member of a group we're in, and the
    /// group id matches.
    same_group: bool,
    duplicate_name: bool,
}

impl GroupRelation {
    fn needs_confirmation(&self) -> bool {
        (!self.current_groups.is_empty() && !self.same_group) || self.duplicate_name
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendReport {
    pub outcome: SendOutcome,
    /// From the call to the PC's answer (opened or prompt shown), including
    /// connect and sync. Microseconds.
    pub latency_us: u64,
}

const STATE_SECTION_RELAY: u8 = 1;
const STATE_SECTION_MAILBOX: u8 = 2;
const STATE_SECTION_MAILBOX_PEERS: u8 = 3;
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
    epoch: u64,
    gs_e: Option<crate::mailbox::EpochSecret>,
    mailbox_peer: Option<DeviceId>,
}

struct PhoneState {
    identity: DeviceKeypair,
    receive_secret: zeroize::Zeroizing<[u8; 32]>,
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
}

impl PhoneState {
    /// One link per PC group this phone is still a member of.
    fn legacy_links(&self) -> Vec<crate::pairwise::LegacyLink> {
        let me = self.identity.device_id();
        self.pcs
            .iter()
            .filter(|p| !p.replica.is_pair() && p.replica.membership(&me) != Membership::Removed)
            .map(|p| {
                let cert = p.replica.owner_cert().cloned();
                crate::pairwise::LegacyLink {
                    group: p.replica.group(),
                    peer: crate::pairwise::PeerInfo {
                        id: p.replica.owner(),
                        name: cert
                            .as_ref()
                            .map(|c| c.name().to_owned())
                            .unwrap_or_else(|| p.replica.owner().short()),
                        platform: cert
                            .as_ref()
                            .map(|c| c.platform())
                            .unwrap_or(crate::keys::Platform::Unknown),
                    },
                    peer_cert: cert,
                    relay: super::pairings_state::relay_ref(
                        p.relay_url.as_deref().or(self.relay_url.as_deref()),
                        p.mailbox_peer,
                    ),
                    epoch: p.epoch,
                }
            })
            .collect()
    }

    /// Pairings and relay settings in step with the legacy state.
    fn pairwise(&self) -> (crate::pairwise::PairingSet, crate::pairwise::RelaySettings) {
        let (mut p, mut r) = (self.pairings.clone(), self.relay_settings.clone());
        let configured = super::pairings_state::relay_ref(
            self.relay_url.as_deref(),
            self.custom_mailbox_peer.flatten(),
        );
        super::pairings_state::sync(
            &mut p,
            &mut r,
            &self.identity.device_id(),
            &self.legacy_links(),
            configured,
        );
        (p, r)
    }

    /// A new pairing with `peer` fits under the 16-pairing limit (re-pairing
    /// a PC we already have always fits).
    fn has_pairing_room_for(&self, peer: &DeviceId) -> bool {
        self.pcs.iter().any(|p| p.replica.owner() == *peer) || self.pairwise().0.has_room()
    }

    /// The state blob holds both secret keys: wiped when dropped.
    fn encode(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut w = Writer::new(STATE_MAGIC);
        w.raw(&self.identity.secret_bytes()[..]);
        w.raw(&self.receive_secret[..]);
        w.bytes8(self.name.as_bytes());
        // v2 links are not legacy groups: they live in the pairwise section
        // and are rebuilt from it on load (M4.2).
        let legacy: Vec<&PcEntry> = self.pcs.iter().filter(|p| !p.replica.is_pair()).collect();
        w.u8(legacy.len() as u8);
        for pc in &legacy {
            w.raw(pc.replica.owner().as_bytes());
            w.u8(pc.addrs.len() as u8);
            for a in &pc.addrs {
                w.bytes8(a.to_string().as_bytes());
            }
            write_ops(&mut w, pc.replica.ops());
        }
        w.u8(STATE_SECTION_RELAY);
        w.bytes16(self.relay_url.as_deref().unwrap_or("").as_bytes());
        w.u8(legacy.len() as u8);
        for pc in &legacy {
            w.bytes16(pc.relay_url.as_deref().unwrap_or("").as_bytes());
        }
        if legacy.iter().any(|p| p.gs_e.is_some() || p.epoch > 0) {
            w.u8(STATE_SECTION_MAILBOX);
            w.u8(legacy.len() as u8);
            let id_sk = self.identity.secret_bytes();
            for pc in &legacy {
                w.raw(&pc.epoch.to_be_bytes());
                match &pc.gs_e {
                    Some(gs) => {
                        w.u8(1);
                        w.raw(&crate::mailbox::seal_secret_for_state(
                            &id_sk,
                            gs.as_bytes(),
                        ));
                    }
                    None => {
                        w.u8(0);
                    }
                }
            }
        }
        if legacy.iter().any(|p| p.mailbox_peer.is_some()) {
            w.u8(STATE_SECTION_MAILBOX_PEERS);
            w.u8(legacy.len() as u8);
            for pc in &legacy {
                match &pc.mailbox_peer {
                    Some(mp) => {
                        w.u8(1);
                        w.raw(mp.as_bytes());
                    }
                    None => {
                        w.u8(0);
                    }
                }
            }
        }
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
            &self.identity.secret_bytes(),
        );
        w.bytes32(&body);
        zeroize::Zeroizing::new(w.0)
    }

    fn decode(b: &[u8]) -> Option<PhoneState> {
        let mut r = Reader::new(b);
        let magic = r.take(STATE_MAGIC.len())?;
        if magic != STATE_MAGIC && magic != STATE_MAGIC_V1 {
            return None;
        }
        let id_sk = read_secret(&mut r)?;
        let receive_secret = read_secret(&mut r)?;
        ReceiveKeypair::from_secret_bytes(&receive_secret)?;
        let name = std::str::from_utf8(r.bytes8()?).ok()?.to_owned();
        let n = r.u8()? as usize;
        let mut pcs = Vec::with_capacity(n);
        for _ in 0..n {
            let owner = DeviceId::from_bytes(r.arr32()?).ok()?;
            let na = r.u8()? as usize;
            let mut addrs = Vec::with_capacity(na);
            for _ in 0..na {
                addrs.push(std::str::from_utf8(r.bytes8()?).ok()?.parse().ok()?);
            }
            let ops = read_ops(&mut r)?;
            let replica = GroupReplica::new(owner, ops).ok()?;
            let epoch = replica.epoch();
            pcs.push(PcEntry {
                replica: PeerLog::Legacy(replica),
                addrs,
                relay_url: None,
                epoch,
                gs_e: None,
                mailbox_peer: None,
            });
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
                    let nr = r.u8()? as usize;
                    if nr != pcs.len() {
                        return None;
                    }
                    for pc in &mut pcs {
                        let pr = std::str::from_utf8(r.bytes16()?).ok()?;
                        if !pr.is_empty() {
                            pc.relay_url = Some(pr.to_owned());
                        }
                    }
                }
                STATE_SECTION_MAILBOX => {
                    let nm = r.u8()? as usize;
                    if nm != pcs.len() {
                        return None;
                    }
                    for pc in &mut pcs {
                        let ep_b = r.take(8)?;
                        pc.epoch = u64::from_be_bytes(ep_b.try_into().expect("8"));
                        let has_gs = r.u8()?;
                        if has_gs == 1 {
                            let s_bytes = r.take(crate::mailbox::SEALED_STATE_SECRET_LEN)?;
                            let s_arr: &[u8; crate::mailbox::SEALED_STATE_SECRET_LEN] =
                                s_bytes.try_into().expect("72");
                            let raw = crate::mailbox::open_secret_from_state(&id_sk, s_arr)?;
                            pc.gs_e = Some(crate::mailbox::EpochSecret::from_bytes(*raw));
                        } else if has_gs == 0 {
                            pc.gs_e = None;
                        } else {
                            return None;
                        }
                    }
                }
                STATE_SECTION_MAILBOX_PEERS => {
                    let nm = r.u8()? as usize;
                    if nm != pcs.len() {
                        return None;
                    }
                    for pc in &mut pcs {
                        match r.u8()? {
                            1 => {
                                pc.mailbox_peer = Some(DeviceId::from_bytes(r.arr32()?).ok()?);
                            }
                            0 => {
                                pc.mailbox_peer = None;
                            }
                            _ => return None,
                        }
                    }
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
        // v1 file (v0.4.x): split into one pairing per PC, no re-pair.
        let (pairings, relay_settings, outbox) = pairwise.unwrap_or_else(|| {
            (
                crate::pairwise::PairingSet::new(),
                crate::pairwise::RelaySettings::new(super::pairings_state::builtin_relay()),
                super::outbox::Outbox::default(),
            )
        });
        let mut st = PhoneState {
            identity: DeviceKeypair::from_secret_bytes(&id_sk),
            receive_secret,
            name,
            pcs,
            relay_url,
            custom_mailbox_peer,
            relay_policy,
            conn_stats,
            seen_ids,
            pairings,
            relay_settings,
            outbox,
        };
        st.rebuild_links();
        Some(st)
    }

    /// M4.2: one entry per v2 pairing (any peer, PC or phone). A v2 pairing
    /// replaces a legacy group entry for the same peer.
    fn rebuild_links(&mut self) {
        let me = self.identity.device_id();
        let links = super::links::links_of(&me, &self.pairings);
        self.pcs
            .retain(|p| !p.replica.is_pair() && !links.contains_key(&p.replica.owner()));
        for (_, link) in links {
            self.pcs.push(pc_entry_for_link(link));
        }
    }

    fn pc(&self, id: &DeviceId) -> Option<&PcEntry> {
        self.pcs.iter().find(|p| p.replica.owner() == *id)
    }

    fn pc_mut(&mut self, id: &DeviceId) -> Option<&mut PcEntry> {
        self.pcs.iter_mut().find(|p| p.replica.owner() == *id)
    }

    fn cert(&self, platform: Platform) -> Result<DeviceCert, RejectReason> {
        let rx = ReceiveKeypair::from_secret_bytes(&self.receive_secret)
            .ok_or(RejectReason::Internal)?;
        DeviceCert::issue(
            &self.identity,
            rx.public(),
            &self.name,
            platform,
            SystemClock.now().wall,
        )
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
    let removed_pairing = entry
        .replica
        .link()
        .and_then(|l| st.pairings.remove(&l.pairing_id));
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
        let Some(link) = st.pc(peer).and_then(|e| e.replica.link()) else {
            return;
        };
        link.pairing_id
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
    let epoch = link.epoch;
    let mailbox_peer = link.relay.as_ref().and_then(|r| r.mailbox_id);
    PcEntry {
        replica: PeerLog::Pair(Box::new(link)),
        addrs: Vec::new(),
        // Live dials go through the peer's home relay, which is ours for
        // now (away relays arrive with M4.4).
        relay_url: None,
        epoch,
        gs_e: None,
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
    last_mailbox_ok: Mutex<Option<crate::time::UnixMillis>>,
    mailbox_failed_at: Mutex<Option<crate::time::UnixMillis>>,
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
    /// Legacy PCs a split was tried with this run (M4.2: one try each, so
    /// an older PC costs one round trip, not one per app open).
    split_tried: Mutex<std::collections::HashSet<DeviceId>>,
    /// Test harness: act as if `SPLIT_DONE` was lost.
    split_skip_done: std::sync::atomic::AtomicBool,
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
    auto_accept_files: std::sync::atomic::AtomicBool,
    background_listening: std::sync::atomic::AtomicBool,
    accept_incoming_enabled: std::sync::atomic::AtomicBool,
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
pub(crate) async fn discover_addrs(
    endpoint: &Endpoint,
    pc: &DeviceId,
    wait: Duration,
) -> Vec<SocketAddr> {
    use n0_future::StreamExt;
    let Ok(id) = endpoint_id_of(pc) else {
        return Vec::new();
    };
    let Ok(services) = endpoint.address_lookup() else {
        return Vec::new();
    };
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
        let mut b = Endpoint::builder(presets::Minimal)
            .secret_key(sk)
            .alpns(vec![ALPN_APP.to_vec()])
            .relay_mode(relay_mode)
            .clear_address_lookup()
            .net_report_config(super::default_net_report_config());
        if mdns {
            b = b.address_lookup(
                iroh_mdns_address_lookup::MdnsAddressLookup::builder()
                    .service_name(MDNS_SERVICE)
                    .advertise(false),
            );
        }
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
            Some(b) => PhoneState::decode(&b).ok_or_else(|| {
                NetError::Storage("state is damaged or from another version".into())
            })?,
            None => {
                let name = if valid_device_name(&cfg.default_name) {
                    cfg.default_name.clone()
                } else {
                    "Phone".to_owned()
                };
                let st = PhoneState {
                    identity: DeviceKeypair::generate(),
                    receive_secret: ReceiveKeypair::generate().secret_bytes(),
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
            last_mailbox_ok: Mutex::new(None),
            mailbox_failed_at: Mutex::new(None),
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
            split_tried: Mutex::new(std::collections::HashSet::new()),
            split_skip_done: std::sync::atomic::AtomicBool::new(false),
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
            auto_accept_files: std::sync::atomic::AtomicBool::new(false),
            background_listening: std::sync::atomic::AtomicBool::new(false),
            accept_incoming_enabled: std::sync::atomic::AtomicBool::new(true),
        });
        let task =
            spawn_phone_accept_loop(&inner.rt, Arc::downgrade(&inner), ep_for_accept.clone());
        *inner.accept_task.lock().unwrap_or_else(|p| p.into_inner()) = Some(task);
        let client = PhoneClient { inner };
        client.restart_relay_watch(&ep_for_accept);
        // Event: start. Unpair notices a previous run couldn't deliver.
        if !client.inner.lock().outbox.is_empty() {
            let inner = client.inner.clone();
            client.inner.rt.spawn(async move {
                flush_outbox_phone(&inner, false).await;
            });
        }
        Ok(client)
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
        if foreground {
            // M4.2: the app was opened, so move legacy (v0.4.x hub) PCs to
            // their own pairings. Once per PC per run; never in background.
            let inner = self.inner.clone();
            self.inner.rt.spawn(async move {
                let _ = Self::split_legacy_all(&inner).await;
            });
        }
    }

    /// Move every legacy PC this phone has not tried yet this run to a v2
    /// pairing (M4.2 split; no re-pair). Returns how many moved. The app
    /// does this when it comes to the front; tests call it directly.
    pub fn split_legacy_pairings_now(&self) -> Result<usize, NetError> {
        let inner = self.inner.clone();
        self.inner
            .rt
            .block_on(async move { Self::split_legacy_all(&inner).await })
    }

    /// Test harness: drop `SPLIT_DONE` (as if the reply was lost).
    #[cfg(feature = "test-util")]
    pub fn skip_split_done_for_tests(&self, skip: bool) {
        self.inner
            .split_skip_done
            .store(skip, std::sync::atomic::Ordering::SeqCst);
    }

    async fn split_legacy_all(inner: &Arc<Inner>) -> Result<usize, NetError> {
        let todo: Vec<DeviceId> = {
            let st = inner.lock();
            let me = st.identity.device_id();
            let tried = inner.split_tried.lock().unwrap_or_else(|p| p.into_inner());
            st.pcs
                .iter()
                .filter(|p| !p.replica.is_pair())
                .filter(|p| p.replica.membership(&me) == Membership::Member)
                .map(|p| p.replica.owner())
                .filter(|pc| !tried.contains(pc))
                .collect()
        };
        let mut moved = 0;
        for pc in todo {
            inner
                .split_tried
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(pc);
            if let Ok(conn) = Self::get_conn(inner, &pc, false).await {
                if Self::split_legacy_on(inner, &conn, &pc).await.is_ok() {
                    moved += 1;
                }
            }
        }
        Ok(moved)
    }

    /// The phone side of the split (see `split`).
    async fn split_legacy_on(
        inner: &Arc<Inner>,
        conn: &Connection,
        pc: &DeviceId,
    ) -> Result<(), NetError> {
        // An older PC answers ERROR here: the pairing just stays legacy.
        request(conn, frame::SPLIT_REQ, &[], frame::SPLIT_READY).await?;
        let rx = ReceiveKeypair::generate();
        let (cert, me) = {
            let st = inner.lock();
            (st.cert(inner.platform)?, st.identity.device_id())
        };
        let join_req = super::split::encode_join(&cert, &rx.public());
        let offer = request(conn, frame::SPLIT_JOIN, &join_req, frame::SPLIT_OFFER).await?;
        let (genesis, wrapped) = super::split::decode_offer(&offer)?;
        let bad = NetError::Rejected(RejectReason::BadLogOp);
        match genesis.body() {
            crate::pairwise::PairBody::Genesis {
                kind: crate::pairwise::PairingKind::Own,
                inviter,
                joiner,
                ..
            } if genesis.author() == *pc && inviter.device() == *pc && joiner.device() == me => {}
            _ => return Err(bad),
        }
        let (log, cosigned, caps, gs) = {
            let st = inner.lock();
            crate::pairwise::v2::join(&st.identity, &rx, genesis, &wrapped, SystemClock.now().wall)
                .map_err(|_| NetError::Rejected(RejectReason::BadLogOp))?
        };
        let accept = super::split::encode_accept(&cosigned, &caps);
        let caps_reply = request(conn, frame::SPLIT_ACCEPT, &accept, frame::SPLIT_CAPS).await?;
        let caps_cosigned = super::split::decode_caps(&caps_reply)?;
        let mut log = log;
        {
            let st = inner.lock();
            crate::pairwise::v2::finish_join(&st.identity, &mut log, caps_cosigned)
                .map_err(|_| NetError::Rejected(RejectReason::BadLogOp))?;
        }
        let pairing = crate::pairwise::v2::record(&me, log, rx, gs)
            .map_err(|_| NetError::Rejected(RejectReason::BadLogOp))?;
        let pairing_id = pairing.pairing_id;
        {
            let mut st = inner.lock();
            let Some(idx) = st
                .pcs
                .iter()
                .position(|p| !p.replica.is_pair() && p.replica.owner() == *pc)
            else {
                return Err(NetError::UnknownDevice);
            };
            let legacy = st.pcs.remove(idx);
            let before = st.pairings.clone();
            let stale: Vec<GroupId> = st.pairings.by_peer(pc).map(|p| p.pairing_id).collect();
            for id in stale {
                st.pairings.remove(&id);
            }
            let res = st
                .pairings
                .add(pairing)
                .map_err(|_| NetError::Rejected(RejectReason::BadLogOp))
                .and_then(|()| {
                    st.rebuild_links();
                    if let Some(e) = st.pc_mut(pc) {
                        e.addrs = legacy.addrs.clone();
                    }
                    inner.save(&st)
                });
            if let Err(e) = res {
                st.pairings = before;
                st.rebuild_links();
                st.pcs.retain(|p| p.replica.owner() != *pc);
                st.pcs.push(legacy);
                return Err(e);
            }
        }
        inner
            .inboxes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(pc);
        // Tell the PC; if this is lost it notices on our first message.
        if inner
            .split_skip_done
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }
        let _ = request(conn, frame::SPLIT_DONE, &pairing_id.0, frame::RESULT).await;
        Ok(())
    }

    /// The OS reported a network change: retry parked relays now.
    pub fn network_changed(&self) {
        self.with_relay_watch(|w| w.network_change());
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
        let relay = self.inner.lock().relay_url.clone().unwrap_or_default();
        let skew = self
            .inner
            .event_skew_ms
            .load(std::sync::atomic::Ordering::SeqCst);
        let t = SystemClock.now().mono.saturating_add(skew);
        {
            let mut last = self
                .inner
                .last_event_pull
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if !force {
                if let Some(prev) = last.get(&relay) {
                    if t.saturating_sub(*prev) < EVENT_PULL_MIN_GAP_MS {
                        return Ok(0);
                    }
                }
            }
            last.insert(relay, t);
        }
        self.pull_device_inbox_now()
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
        st.name = name.to_owned();
        self.inner.save(&st)
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

    /// This phone's pairings (state v2, M4.1): one per paired PC.
    pub fn pairings(&self) -> Vec<super::pairings_state::PairingSummary> {
        super::pairings_state::summaries(&self.inner.lock().pairwise().0)
    }

    pub fn paired_pcs(&self) -> Vec<PairedPc> {
        let st = self.inner.lock();
        let me = st.identity.device_id();
        st.pcs
            .iter()
            .map(|p| PairedPc {
                id: p.replica.owner(),
                name: p
                    .replica
                    .owner_cert()
                    .map(|c| c.name().to_owned())
                    .unwrap_or_else(|| p.replica.owner().short()),
                removed: p.replica.membership(&me) == Membership::Removed,
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
        let link = entry.replica.link()?;
        let (pairing_id, head, rk) = (link.pairing_id, link.head(), link.peer_rx);
        let home_url = entry.relay_url.clone().or_else(|| st.relay_url.clone());
        let target = link.peer_inbox(home_url.as_deref(), home_mb);
        let addrs = entry.addrs.clone();
        let ts = SystemClock.now().wall;
        let op = st
            .pairings
            .get(&pairing_id)?
            .log
            .clone()?
            .unpair(&st.identity, ts)
            .ok()?;
        let body = crate::wire::encode_signed_pair_notice(
            &st.identity,
            &crate::wire::OutgoingPairNotice {
                group: pairing_id,
                recipient: *peer,
                log_head: head,
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

    /// PAIR-11: relation of `inviter` (an id the caller has authenticated, or
    /// will authenticate before committing) to the groups we're in.
    fn relation(
        st: &PhoneState,
        inviter: &DeviceId,
        group: &GroupId,
        name: Option<&str>,
    ) -> GroupRelation {
        let me = st.identity.device_id();
        let mut current_groups: Vec<String> = Vec::new();
        let mut same_group = false;
        let mut duplicate_name = false;
        for pc in &st.pcs {
            if pc.replica.is_pair() || pc.replica.membership(&me) != Membership::Member {
                continue;
            }
            let pc_name = pc
                .replica
                .owner_cert()
                .map(|c| c.name().to_owned())
                .unwrap_or_else(|| pc.replica.owner().short());
            // Same group only if the *authenticated* inviter belongs to it
            // according to the signed log we already hold. A matching `g=`
            // from someone else is a different group (QA PAIR-11 bypass).
            if pc.replica.group() == *group
                && (pc.replica.owner() == *inviter
                    || pc.replica.membership(inviter) == Membership::Member)
            {
                same_group = true;
            }
            if pc.replica.owner() != *inviter && name.is_some_and(|n| n == pc_name) {
                duplicate_name = true;
            }
            current_groups.push(pc_name);
        }
        GroupRelation {
            current_groups,
            same_group,
            duplicate_name,
        }
    }

    /// OQ-9 / PAIR-11: what pairing with this QR would do. No network.
    ///
    /// The inviter id comes from the QR here; it is the PC's endpoint key,
    /// which the QUIC/TLS handshake proves before anything else happens, and
    /// `begin_pairing_with` / `wait_welcome` re-decide from the signed
    /// certificate and group log before committing.
    pub fn inspect_invite(&self, qr: &str) -> Result<InviteCheck, NetError> {
        let invite = ScannedInvite::parse(qr, SystemClock.now())?;
        let st = self.inner.lock();
        let rel = Self::relation(
            &st,
            &invite.inviter,
            &invite.group,
            invite.inviter_name.as_deref(),
        );
        Ok(InviteCheck {
            pc: invite.inviter,
            group: invite.group,
            pc_name: invite.inviter_name.clone(),
            joins_different_group: !rel.current_groups.is_empty() && !rel.same_group,
            duplicate_name: rel.duplicate_name,
            current_groups: rel.current_groups,
        })
    }

    /// [`begin_pairing_with`](Self::begin_pairing_with) without confirming a
    /// group change: refused if the QR is for a different device group.
    pub fn begin_pairing(&self, qr: &str) -> Result<PairingSession, NetError> {
        self.begin_pairing_with(qr, GroupChange::NotConfirmed)
    }

    /// Scan result → connect, prove possession of the QR secret, get the
    /// code to show. The user then types that code on the PC.
    ///
    /// If this phone already belongs to another device group (OQ-9), this
    /// refuses with `GroupChangeNotConfirmed` **before any network traffic**
    /// (the QR secret stays unspent) unless `change` is `Confirmed`.
    pub fn begin_pairing_with(
        &self,
        qr: &str,
        change: GroupChange,
    ) -> Result<PairingSession, NetError> {
        let now = SystemClock.now();
        let check = self.inspect_invite(qr)?;
        if (check.joins_different_group || check.duplicate_name) && change != GroupChange::Confirmed
        {
            return Err(NetError::Rejected(RejectReason::GroupChangeNotConfirmed));
        }
        let invite = ScannedInvite::parse(qr, now)?;
        if !self.inner.lock().has_pairing_room_for(&invite.inviter) {
            return Err(NetError::Rejected(RejectReason::PairingLimitReached));
        }
        let (cert, has_room) = {
            let st = self.inner.lock();
            (
                st.cert(self.inner.platform)?,
                st.pcs.len() < MAX_PCS || st.pc(&invite.inviter).is_some(),
            )
        };
        if !has_room {
            return Err(NetError::Protocol("too many paired PCs".into()));
        }
        let inner = self.inner.clone();
        let invite2 = ScannedInvite::parse(qr, now)?;
        let fallback_relay = self.inner.lock().relay_url.clone();
        let (conn, send, recv, sas, inviter_cert) = self.inner.rt.block_on(async move {
            let qr_relay = (!invite2.relay_url.is_empty())
                .then_some(invite2.relay_url.as_str())
                .or(fallback_relay.as_deref());
            let ep = inner
                .endpoint
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            let conn = connect(&ep, &invite2.inviter, &invite2.addrs, qr_relay, ALPN_PAIR).await?;
            let (mut send, mut recv) = conn.open_bi().await.map_err(|e| conn_error(&conn, e))?;
            let secret_id = invite2.secret_id();
            write_frame(&mut send, frame::HELLO, &secret_id).await?;
            let inviter_cert = match read_frame(&mut recv, IO_TIMEOUT).await? {
                (frame::INVITER_CERT, p) => DeviceCert::parse_verified(&p)?,
                (frame::ERROR, p) => return Err(parse_error(&p)),
                _ => return Err(NetError::Protocol("unexpected frame".into())),
            };
            // The TLS handshake already proved the PC holds the QR's id key;
            // its certificate must be for that same id.
            // The name we warned with (QR `n=`) must be the certified one.
            if inviter_cert.device() != invite2.inviter
                || invite2
                    .inviter_name
                    .as_deref()
                    .is_some_and(|n| n != inviter_cert.name())
            {
                conn.close(close_code(RejectReason::SenderMismatch), b"");
                return Err(NetError::Rejected(RejectReason::SenderMismatch));
            }
            // PAIR-11, decided again from the signed certificate (its device
            // id is the key the TLS handshake proved; its name is signed)
            // before proving the secret or committing anything.
            let rel = {
                let st = inner.lock();
                Self::relation(
                    &st,
                    &inviter_cert.device(),
                    &invite2.group,
                    Some(inviter_cert.name()),
                )
            };
            if rel.needs_confirmation() && change != GroupChange::Confirmed {
                conn.close(close_code(RejectReason::GroupChangeNotConfirmed), b"");
                return Err(NetError::Rejected(RejectReason::GroupChangeNotConfirmed));
            }
            let exporter = pairing_exporter(&conn, &secret_id)?;
            let handshake = pairing_handshake(&exporter, inviter_cert.as_bytes(), cert.as_bytes());
            let req = PairingRequest::create_with_cert(&invite2, &cert, &handshake);
            let mut p = req.proof.to_vec();
            p.extend_from_slice(cert.as_bytes());
            write_frame(&mut send, frame::PROOF, &p).await?;
            match read_frame(&mut recv, IO_TIMEOUT).await? {
                (frame::PROOF_OK, _) => {}
                (frame::ERROR, p) => return Err(parse_error(&p)),
                _ => return Err(NetError::Protocol("unexpected frame".into())),
            }
            let sas = invite2.sas_code(&cert.device(), cert.name(), &handshake);
            Ok::<_, NetError>((conn, send, recv, sas, inviter_cert))
        })?;
        Ok(PairingSession {
            client: self.clone(),
            invite,
            conn,
            streams: Mutex::new(Some((send, recv))),
            sas,
            pc_name: inviter_cert.name().to_owned(),
            inviter_cert,
            change,
        })
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
        let (addrs, relay_url) = {
            let st = inner.lock();
            let p = st.pc(pc).ok_or(NetError::UnknownDevice)?;
            (
                p.addrs.clone(),
                p.relay_url.clone().or_else(|| st.relay_url.clone()),
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
                let found = discover_addrs(&ep, pc, MDNS_FALLBACK_WAIT).await;
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

    /// Fail-open warning (`"Couldn't check for removals since <time>"`) when the
    /// last mailbox pull failed, or `None` when healthy.
    pub fn removal_check_warning(&self) -> Option<String> {
        let failed_at = (*self
            .inner
            .mailbox_failed_at
            .lock()
            .unwrap_or_else(|p| p.into_inner()))?;
        let since = *self
            .inner
            .last_mailbox_ok
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        Some(super::mailbox_client::format_removal_warning(
            since, failed_at,
        ))
    }

    /// Pull the blind mailbox chain for `pc` over a fresh throwaway `Endpoint`
    /// (`docs/PROTOCOL.md` §7.1(e), `docs/M2-PLAN.md` §2.1 rev. 3).
    /// Follows `MailboxSeal` tombstones across epoch boundaries (`e -> e+1 -> ...`).
    pub fn pull_mailbox(&self, pc: &DeviceId) -> Result<(Membership, DeviceId), NetError> {
        let (peer, _) = self
            .effective_mailbox_peer(pc)
            .ok_or_else(|| NetError::Unreachable("no mailbox peer configured".into()))?;
        let (my_id, rx_kp, grp, relay_url, start_epoch, start_gs, current_membership) = {
            let st = self.inner.lock();
            let my_id = st.identity.device_id();
            let rx_kp = ReceiveKeypair::from_secret_bytes(&st.receive_secret)
                .ok_or(NetError::Rejected(RejectReason::Internal))?;
            let entry = st.pc(pc).ok_or(NetError::UnknownDevice)?;
            let m = entry.replica.membership(&my_id);
            let Some(gs) = entry.gs_e.clone() else {
                return Ok((m, my_id));
            };
            let relay_url = entry
                .relay_url
                .clone()
                .or_else(|| st.relay_url.clone())
                .ok_or_else(|| NetError::Unreachable("no relay URL configured".into()))?;
            (
                my_id,
                rx_kp,
                entry.replica.group(),
                relay_url,
                entry.epoch,
                gs,
                m,
            )
        };
        if current_membership == Membership::Removed {
            let eph = self.last_throwaway_id().unwrap_or(my_id);
            return Ok((Membership::Removed, eph));
        }
        let ts = SystemClock.now().wall;
        let pulled = self
            .inner
            .rt
            .block_on(super::mailbox_client::pull_mailbox_chain_with_config(
                &peer,
                &relay_url,
                &my_id,
                &rx_kp,
                &grp,
                start_epoch,
                &start_gs,
            ));
        match pulled {
            Ok((eph_id, new_epoch, new_gs, ops, maybe_cfg, maybe_adv_cap)) => {
                if maybe_cfg.is_some() || maybe_adv_cap.is_some() {
                    let mut st = self.inner.lock();
                    let mut changed = false;
                    if let Some(cap) = maybe_adv_cap {
                        st.relay_policy.set_server_cap_bytes(cap);
                        changed = true;
                    }
                    if let Some(ref cfg) = maybe_cfg {
                        if st
                            .relay_policy
                            .apply_signed_config(cfg, peer.as_bytes())
                            .is_ok()
                        {
                            changed = true;
                        }
                    }
                    if changed {
                        let _ = self.inner.save(&st);
                    }
                }
                *self
                    .inner
                    .last_throwaway_id
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = Some(eph_id);
                // M2.4 (§8 / §10): if the mailbox returned empty (0 records) when our
                // local replica already holds a paired log, treat it as suspicious
                // (unseeded/wiped store or withholding relay) — flag the fail-open
                // warning instead of claiming a successful check.
                if ops.is_empty() {
                    *self
                        .inner
                        .mailbox_failed_at
                        .lock()
                        .unwrap_or_else(|p| p.into_inner()) = Some(ts);
                    return Err(NetError::Protocol(
                        "mailbox empty while local log is ahead".into(),
                    ));
                }
                *self
                    .inner
                    .last_mailbox_ok
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = Some(ts);
                *self
                    .inner
                    .mailbox_failed_at
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = None;

                let mut st = self.inner.lock();
                let entry = st.pc_mut(pc).ok_or(NetError::UnknownDevice)?;
                let _ = entry.replica.update(ops)?;
                let m = entry.replica.membership(&my_id);
                if m == Membership::Removed {
                    entry.gs_e = None;
                    entry.epoch = entry.replica.epoch();
                } else {
                    entry.epoch = new_epoch.max(entry.replica.epoch());
                    entry.gs_e = Some(new_gs);
                }
                self.inner.save(&st)?;
                Ok((m, eph_id))
            }
            Err(e) => {
                *self
                    .inner
                    .mailbox_failed_at
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = Some(ts);
                Err(e)
            }
        }
    }

    /// Pull the PC's log (learns removals). Pulls the blind mailbox first when
    /// configured (`docs/PROTOCOL.md` §7.1(e)), falling back to direct/relay sync.
    pub fn sync(&self, pc: &DeviceId) -> Result<Membership, NetError> {
        let should_pull = self
            .effective_mailbox_peer(pc)
            .map(|(p, explicit)| {
                super::mailbox_client::should_dial_mailbox_in_current_env(&p, explicit)
            })
            .unwrap_or(false);
        let mb_res = if should_pull {
            Some(self.pull_mailbox(pc))
        } else {
            None
        };
        if let Some(Ok((Membership::Removed, _))) = mb_res {
            return Ok(Membership::Removed);
        }
        let inner = self.inner.clone();
        let pc_id = *pc;
        match self.inner.rt.block_on(async move {
            let conn = Self::get_conn(&inner, &pc_id, false).await?;
            match Self::sync_on(&inner, &conn, &pc_id).await {
                Ok(m) => Ok(m),
                Err(NetError::Protocol(_) | NetError::Timeout | NetError::Unreachable(_)) => {
                    let conn2 = Self::get_conn(&inner, &pc_id, true).await?;
                    Self::sync_on(&inner, &conn2, &pc_id).await
                }
                Err(e) => Err(e),
            }
        }) {
            Ok(m) => Ok(m),
            Err(e) => {
                if let Some(Ok((m, _))) = mb_res {
                    Ok(m)
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn sync_on(
        inner: &Inner,
        conn: &Connection,
        pc: &DeviceId,
    ) -> Result<Membership, NetError> {
        let head = {
            let st = inner.lock();
            let e = st.pc(pc).ok_or(NetError::UnknownDevice)?;
            // A v2 link has no group log to sync (its pairing log travels
            // in the pairing's own messages).
            if e.replica.is_pair() {
                return Ok(Membership::Member);
            }
            e.replica.head()
        };
        let p = request(conn, frame::SYNC, &head.0, frame::OPS).await?;
        let ops = decode_ops(&p)?;
        let mut st = inner.lock();
        let me = st.identity.device_id();
        let rx_kp = ReceiveKeypair::from_secret_bytes(&st.receive_secret)
            .ok_or(NetError::Rejected(RejectReason::Internal))?;
        let entry = st.pc_mut(pc).ok_or(NetError::UnknownDevice)?;
        if !ops.is_empty() {
            let mut latest_rekey: Option<crate::mailbox::RekeyPayload> = None;
            for op in &ops {
                if op.kind == crate::roster::OpKind::Rekey {
                    if let Some(ref rp) = op.rekey {
                        latest_rekey = Some(rp.clone());
                    }
                }
            }
            if entry.replica.update(ops)? {
                entry.epoch = entry.replica.epoch();
                let grp = entry.replica.group();
                if let Some(rp) = latest_rekey {
                    if rp.removed == me || entry.replica.membership(&me) == Membership::Removed {
                        entry.gs_e = None;
                    } else if let Ok(Some(new_gs)) = rp.unwrap_for(&rx_kp, &me, &grp) {
                        entry.gs_e = Some(new_gs);
                    }
                }
                let m = entry.replica.membership(&me);
                inner.save(&st)?;
                return Ok(m);
            }
        }
        Ok(entry.replica.membership(&me))
    }

    /// Send one link. Checks it locally first (same policy as the PC), and
    /// performs pull-before-trust (`docs/PROTOCOL.md` §7.1(e)) when a mailbox is configured.
    pub fn send_url(&self, pc: &DeviceId, url: &str) -> Result<SendReport, NetError> {
        let canonical = crate::url_policy::check_url(url)?;
        let started = crate::time::Stopwatch::start();
        let should_pull = self
            .effective_mailbox_peer(pc)
            .map(|(p, explicit)| {
                super::mailbox_client::should_dial_mailbox_in_current_env(&p, explicit)
            })
            .unwrap_or(false);
        if should_pull {
            if let Ok((Membership::Removed, _)) = self.pull_mailbox(pc) {
                return Err(NetError::Rejected(RejectReason::Removed));
            }
        }
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
                        match Self::sync_on(&inner, &conn, &pc).await? {
                            Membership::Member => {}
                            Membership::Removed => {
                                return Err(NetError::Rejected(RejectReason::Removed))
                            }
                            Membership::NotYetAdded => {
                                return Err(NetError::Rejected(RejectReason::NotInRoster))
                            }
                        }
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
                        Err(NetError::Rejected(RejectReason::Removed)) => {
                            if let Ok(c) = Self::get_conn(&inner, &pc, true).await {
                                let _ = Self::sync_on(&inner, &c, &pc).await;
                            }
                            return Err(NetError::Rejected(RejectReason::Removed));
                        }
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
        self.inner
            .lock()
            .pc(peer)
            .is_some_and(|e| e.replica.is_pair())
    }

    /// Put a sealed envelope into a v2 peer's inbox on the pairing relay
    /// (the peer is offline, M4.2).
    fn queue_in_pair_inbox(&self, peer: &DeviceId, env: Vec<u8>) -> Result<(), NetError> {
        let home_mb = self.effective_mailbox_peer(peer);
        let target = {
            let st = self.inner.lock();
            let entry = st.pc(peer).ok_or(NetError::UnknownDevice)?;
            let link = entry.replica.link().ok_or(NetError::UnknownDevice)?;
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
        let rk = entry
            .replica
            .seal_key()
            .ok_or(NetError::Rejected(RejectReason::BadLogOp))?;
        let body = encode_signed(
            &st.identity,
            &Outgoing {
                group: entry.replica.group(),
                recipient: *pc,
                log_head: entry.replica.head(),
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
            log_head: e.replica.head(),
            seal_to: e.replica.seal_key()?,
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
        st.pc(peer)?
            .replica
            .link()
            .map(|l| l.inbox_keys_for_tests(&me))
    }

    /// Test harness (M4.3): the inbox derivation inputs of the v2 pairing
    /// with `peer`.
    #[cfg(feature = "test-util")]
    pub fn pairing_inbox_inputs_for_tests(
        &self,
        peer: &DeviceId,
    ) -> Option<super::PairingInboxInputs> {
        let st = self.inner.lock();
        st.pc(peer)?
            .replica
            .link()
            .map(|l| l.inbox_inputs_for_tests())
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
        let peer = p
            .log
            .as_ref()
            .and_then(|l| l.peer_of(&me))
            .ok_or(NetError::UnknownDevice)?;
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

    /// Test harness: register a PC this phone never paired with (to show
    /// that an unpaired sender is refused at the socket).
    #[cfg(feature = "test-util")]
    pub fn adopt_pc_for_tests(
        &self,
        ops: Vec<crate::grouplog::SignedOp>,
        owner: DeviceId,
        addrs: Vec<SocketAddr>,
    ) -> Result<(), NetError> {
        let replica = GroupReplica::new(owner, ops)?;
        let mut st = self.inner.lock();
        st.pcs.retain(|p| p.replica.owner() != owner);
        let relay_url = st.relay_url.clone();
        let epoch = replica.epoch();
        st.pcs.push(PcEntry {
            replica: PeerLog::Legacy(replica),
            addrs,
            relay_url,
            epoch,
            gs_e: None,
            mailbox_peer: None,
        });
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
        self.inner
            .rt
            .block_on(async move { discover_addrs(&ep, &pc, wait).await })
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

    /// Test harness: the stored replica ops for `pc`.
    #[cfg(feature = "test-util")]
    pub fn replica_ops_for_tests(&self, pc: &DeviceId) -> Vec<crate::grouplog::SignedOp> {
        self.inner
            .lock()
            .pc(pc)
            .map(|p| p.replica.ops().to_vec())
            .unwrap_or_default()
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
        let should_pull = self
            .effective_mailbox_peer(pc)
            .map(|(p, explicit)| {
                super::mailbox_client::should_dial_mailbox_in_current_env(&p, explicit)
            })
            .unwrap_or(false);
        if should_pull {
            if let Ok((Membership::Removed, _)) = self.pull_mailbox(pc) {
                return Err(NetError::Rejected(RejectReason::Removed));
            }
        }
        let inner = self.inner.clone();
        let pc_id = *pc;
        let filename_str = filename.to_owned();
        let mime_str = mime.to_owned();
        self.inner.rt.block_on(async move {
            let mut conn = Self::get_conn(&inner, &pc_id, false).await?;
            let membership = match Self::sync_on(&inner, &conn, &pc_id).await {
                Ok(m) => m,
                Err(NetError::Protocol(_) | NetError::Timeout | NetError::Unreachable(_)) => {
                    conn = Self::get_conn(&inner, &pc_id, true).await?;
                    Self::sync_on(&inner, &conn, &pc_id).await?
                }
                Err(e) => return Err(e),
            };
            match membership {
                Membership::Member => {}
                Membership::Removed => return Err(NetError::Rejected(RejectReason::Removed)),
                Membership::NotYetAdded => {
                    return Err(NetError::Rejected(RejectReason::NotInRoster))
                }
            }
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
            .seal_key()
            .ok_or(NetError::Rejected(RejectReason::BadLogOp))?;
                let grp = entry.replica.group();
                let head = entry.replica.head().0;
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
                .map_err(NetError::Rejected)?
                .with_log_head(head);
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
        let should_pull = self
            .effective_mailbox_peer(pc)
            .map(|(p, explicit)| {
                super::mailbox_client::should_dial_mailbox_in_current_env(&p, explicit)
            })
            .unwrap_or(false);
        if should_pull {
            if let Ok((Membership::Removed, _)) = self.pull_mailbox(pc) {
                return Err(NetError::Rejected(RejectReason::Removed));
            }
        }
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
                    match Self::sync_on(&inner, &conn, &pc).await? {
                        Membership::Member => {}
                        Membership::Removed => {
                            return Err(NetError::Rejected(RejectReason::Removed))
                        }
                        Membership::NotYetAdded => {
                            return Err(NetError::Rejected(RejectReason::NotInRoster))
                        }
                    }
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
                    Err(NetError::Rejected(RejectReason::Removed)) => {
                        if let Ok(c) = Self::get_conn(&inner, &pc, true).await {
                            let _ = Self::sync_on(&inner, &c, &pc).await;
                        }
                        return Err(NetError::Rejected(RejectReason::Removed));
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
        let rk = entry
            .replica
            .seal_key()
            .ok_or(NetError::Rejected(RejectReason::BadLogOp))?;
        let body = crate::wire::encode_signed_clipboard(
            &st.identity,
            &crate::wire::OutgoingClipboard {
                group: entry.replica.group(),
                recipient: *pc,
                log_head: entry.replica.head(),
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
        }
    }

    /// Pull and acknowledge all pending envelopes from this phone's RAM-only blind
    /// device inboxes: the legacy group inbox of each v0.4.x PC and the
    /// per-pairing inbox of each v2 peer (`M3.1`, M4.2). One throwaway
    /// session per relay. Call it on events (start, network change,
    /// foreground, a wake push); it never schedules itself.
    /// Returns the number of newly verified items/offers added to the phone's incoming queues.
    pub fn pull_device_inbox_now(&self) -> Result<usize, NetError> {
        self.inner
            .inbox_pulls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let inner = self.inner.clone();
        self.inner
            .rt
            .block_on(async move { flush_outbox_phone(&inner, false).await });
        let peers: Vec<(DeviceId, bool)> = self
            .inner
            .lock()
            .pcs
            .iter()
            .map(|p| (p.replica.owner(), p.replica.is_pair()))
            .collect();
        let mut targets: Vec<super::links::InboxTarget> = Vec::new();
        for (peer, is_pair) in peers {
            let home_mb = self.effective_mailbox_peer(&peer);
            if !is_pair {
                let Some((mb_peer, explicit)) = home_mb else {
                    continue;
                };
                if !super::mailbox_client::should_dial_mailbox_in_current_env(&mb_peer, explicit) {
                    continue;
                }
                // Pull the group log mailbox first so our epoch, gs_e, and SignedConfig are fresh.
                if let Ok((Membership::Removed, _)) = self.pull_mailbox(&peer) {
                    continue;
                }
            }
            let st = self.inner.lock();
            let my_id = st.identity.device_id();
            let Some(entry) = st.pc(&peer) else {
                continue;
            };
            if entry.replica.membership(&my_id) != Membership::Member {
                continue;
            }
            let home_url = entry.relay_url.clone().or_else(|| st.relay_url.clone());
            if let Some(link) = entry.replica.link() {
                if let Some(t) = link.my_inbox(&my_id, home_url.as_deref(), home_mb) {
                    targets.push(t);
                }
                continue;
            }
            let Some(rx_kp) = ReceiveKeypair::from_secret_bytes(&st.receive_secret) else {
                continue;
            };
            let (Some(gs), Some(relay_url), Some((mb_peer, _))) =
                (entry.gs_e.as_ref(), home_url, home_mb)
            else {
                continue;
            };
            if relay_url.is_empty() || relay_url == "off" {
                continue;
            }
            let grp = entry.replica.group();
            let keys = gs.derive_device_inbox_keys(&grp, entry.epoch, &my_id, &rx_kp.public());
            targets.push(super::links::InboxTarget {
                tag: peer,
                relay_url,
                mailbox: mb_peer,
                keys,
            });
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
        if pull_res.is_err() {
            if let Some(sess) = self
                .inner
                .incoming_files
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get_mut(transfer_id)
            {
                sess.accepted = false;
            }
        }
        pull_res
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

    /// Current epoch `e` known for `pc`.
    pub fn pc_epoch(&self, pc: &DeviceId) -> Option<u64> {
        self.inner.lock().pc(pc).map(|p| p.epoch)
    }

    /// Current mailbox id `HKDF-Expand(gs_e, "voidwire-v1/mailbox-id", 32)` known for `pc`.
    pub fn pc_mailbox_id(&self, pc: &DeviceId) -> Option<crate::mailbox::MailboxId> {
        self.inner
            .lock()
            .pc(pc)
            .and_then(|p| p.gs_e.as_ref().map(|gs| gs.derive_keys().mailbox_id))
    }
}

/// An in-progress pairing on the phone (after the PC accepted our proof).
pub struct PairingSession {
    client: PhoneClient,
    invite: ScannedInvite,
    conn: Connection,
    streams: Mutex<Option<(SendStream, RecvStream)>>,
    sas: String,
    pc_name: String,
    inviter_cert: DeviceCert,
    /// The user's answer to the PAIR-11 warning, re-applied to the signed log.
    change: GroupChange,
}

impl std::fmt::Debug for PairingSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingSession").finish_non_exhaustive()
    }
}

impl PairingSession {
    /// The 6-digit code to show; the user types it on the PC.
    pub fn sas(&self) -> String {
        self.sas.clone()
    }

    pub fn pc_name(&self) -> String {
        self.pc_name.clone()
    }

    pub fn pc_id(&self) -> DeviceId {
        self.invite.inviter
    }

    /// Block until the PC confirms (the user typed the code) or refuses.
    pub fn wait_welcome(&self, timeout: Duration) -> Result<PairedPc, NetError> {
        let (mut send, mut recv) = self
            .streams
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .ok_or(NetError::Cancelled)?;
        let inner = &self.client.inner;
        let res = inner.rt.block_on(async {
            match read_frame(&mut recv, timeout).await {
                Ok((frame::WELCOME, p)) => Ok(p),
                Ok((frame::ERROR, p)) => Err(parse_error(&p)),
                Ok(_) => Err(NetError::Protocol("unexpected frame".into())),
                Err(NetError::Protocol(m)) => Err(match self.conn.close_reason() {
                    Some(_) => conn_error(&self.conn, m),
                    None => NetError::Protocol(m),
                }),
                Err(e) => Err(e),
            }
        });
        let decoded = match res {
            Ok(p) => super::decode_welcome(&p),
            Err(e) => {
                self.conn
                    .close(close_code(RejectReason::PairingCancelled), b"");
                return Err(e);
            }
        };
        let mut done = |r: RejectReason| {
            let _ = send.finish();
            self.conn.close(close_code(r), b"");
        };
        let (ops, m2_welcome, welcome_mb_peer) = match decoded {
            Ok(o) => o,
            Err(r) => {
                done(r);
                return Err(r.into());
            }
        };
        let replica = match GroupReplica::new(self.invite.inviter, ops) {
            Ok(r) => r,
            Err(r) => {
                done(r);
                return Err(r.into());
            }
        };
        let me = self.client.device_id();
        if replica.membership(&me) != Membership::Member
            || replica.owner_cert() != Some(&self.inviter_cert)
            || replica.group() != self.invite.group
        {
            done(RejectReason::BadLogOp);
            return Err(NetError::Rejected(RejectReason::BadLogOp));
        }
        let mut st = inner.lock();
        // PAIR-11, final check against the signed group log (owner + group id
        // from the verified genesis) before anything is stored.
        let rel = PhoneClient::relation(
            &st,
            &replica.owner(),
            &replica.group(),
            replica.owner_cert().map(|c| c.name()),
        );
        if rel.needs_confirmation() && self.change != GroupChange::Confirmed {
            drop(st);
            done(RejectReason::GroupChangeNotConfirmed);
            return Err(NetError::Rejected(RejectReason::GroupChangeNotConfirmed));
        }
        let (epoch, gs_e) = match m2_welcome {
            Some((ep, sealed_gs)) => {
                let rx_kp = ReceiveKeypair::from_secret_bytes(&st.receive_secret)
                    .ok_or(NetError::Rejected(RejectReason::Internal))?;
                match crate::mailbox::unwrap_epoch_secret(
                    &rx_kp,
                    &me,
                    &replica.group(),
                    ep,
                    &sealed_gs,
                ) {
                    Ok(gs) => (ep, Some(gs)),
                    Err(r) => {
                        drop(st);
                        done(r);
                        return Err(NetError::Rejected(r));
                    }
                }
            }
            None => (replica.epoch(), None),
        };
        let relay_url = (!self.invite.relay_url.is_empty())
            .then(|| self.invite.relay_url.clone())
            .or_else(|| st.relay_url.clone());
        let mailbox_peer = welcome_mb_peer.or(self.invite.mailbox_peer);
        if !st.has_pairing_room_for(&self.invite.inviter) {
            drop(st);
            done(RejectReason::PairingLimitReached);
            return Err(NetError::Rejected(RejectReason::PairingLimitReached));
        }
        st.pcs.retain(|p| p.replica.owner() != self.invite.inviter);
        st.pcs.push(PcEntry {
            replica: PeerLog::Legacy(replica),
            addrs: self.invite.addrs.clone(),
            relay_url,
            epoch,
            gs_e,
            mailbox_peer,
        });
        let saved = inner.save(&st);
        drop(st);
        let _ = send.finish();
        self.conn.close(0u32.into(), b"ok");
        saved?;
        Ok(self
            .client
            .paired_pcs()
            .into_iter()
            .find(|p| p.id == self.invite.inviter)
            .expect("just added"))
    }

    /// Give up (the user backed out).
    pub fn cancel(&self) {
        self.streams
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        self.conn
            .close(close_code(RejectReason::PairingCancelled), b"cancelled");
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
                if alpn.as_slice() != ALPN_APP {
                    return;
                }
                let Ok(conn) = accepting.await else {
                    return;
                };
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
                    let st = inner.lock();
                    let me = st.identity.device_id();
                    let Some(entry) = st.pc(&peer) else {
                        conn.close(close_code(RejectReason::NotInRoster), b"not paired");
                        return;
                    };
                    if entry.replica.membership(&me) != Membership::Member {
                        conn.close(close_code(RejectReason::Removed), b"removed");
                        return;
                    }
                }
                PhoneClient::learn_addrs(&inner, &peer, &conn);
                inner
                    .conns
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(peer, conn.clone());
                handle_pc_conn_streams(weak_conn, peer, conn).await;
            });
        }
    })
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
    loop {
        let Ok((mut send, mut recv)) = conn.accept_bi().await else {
            break;
        };
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
            frame::OPS => {
                let res = apply_pushed_ops_on_phone(&inner, &pc, &payload);
                match res {
                    Ok(()) => {
                        let _ = write_frame(&mut send, frame::RESULT, &[0, 0, 1]).await;
                    }
                    Err(r) => {
                        let _ =
                            write_frame(&mut send, frame::ERROR, &super::error_payload(r)).await;
                    }
                }
                let _ = send.finish();
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
                let _ = write_frame(&mut send, frame::FILE_CHUNK_ACK, &reply).await;
                let _ = send.finish();
            }
            frame::FILE_CANCEL => {
                let reply = on_phone_file_cancel(&inner, &pc, &payload);
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

fn apply_pushed_ops_on_phone(
    inner: &Inner,
    pc: &DeviceId,
    payload: &[u8],
) -> Result<(), RejectReason> {
    let ops = decode_ops(payload).map_err(|_| RejectReason::MalformedFrame)?;
    if ops.is_empty() {
        return Ok(());
    }
    let mut st = inner.lock();
    let me = st.identity.device_id();
    let rx_kp =
        ReceiveKeypair::from_secret_bytes(&st.receive_secret).ok_or(RejectReason::Internal)?;
    let entry = st.pc_mut(pc).ok_or(RejectReason::NotInRoster)?;
    let mut latest_rekey: Option<crate::mailbox::RekeyPayload> = None;
    for op in &ops {
        if op.kind == crate::roster::OpKind::Rekey {
            if let Some(ref rp) = op.rekey {
                latest_rekey = Some(rp.clone());
            }
        }
    }
    if entry.replica.update(ops)? {
        entry.epoch = entry.replica.epoch();
        let grp = entry.replica.group();
        if let Some(rp) = latest_rekey {
            if rp.removed == me || entry.replica.membership(&me) == Membership::Removed {
                entry.gs_e = None;
            } else if let Ok(Some(new_gs)) = rp.unwrap_for(&rx_kp, &me, &grp) {
                entry.gs_e = Some(new_gs);
            }
        }
        let _ = inner.save(&st);
    }
    Ok(())
}

struct PhoneSeenIdStore {
    pc: DeviceId,
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
    let (my_id, rx_kp, roster, sender_name, state_seen) = {
        let st = inner.lock();
        let my_id = st.identity.device_id();
        let entry = st.pc(pc)?;
        if entry.replica.membership(&my_id) != Membership::Member {
            return None;
        }
        let rx_kp = match entry.replica.my_rx() {
            Some(rx) => rx,
            None => ReceiveKeypair::from_secret_bytes(&st.receive_secret)?,
        };
        let sender_name = entry
            .replica
            .owner_cert()
            .map(|c| c.name().to_owned())
            .unwrap_or_else(|| pc.short());
        let state_seen = st.seen_ids.get(pc).cloned().unwrap_or_default();
        (
            my_id,
            rx_kp,
            entry.replica.roster().clone(),
            sender_name,
            state_seen,
        )
    };
    let mut roster = roster;
    roster.set_self_id(my_id);
    let data_dir = inner
        .data_dir
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let out = {
        let mut inboxes = inner.inboxes.lock().unwrap_or_else(|p| p.into_inner());
        let inbox = inboxes.entry(*pc).or_insert_with(|| {
            let now = SystemClock.now();
            let file_store = data_dir.and_then(|dir| {
                let _ = std::fs::create_dir_all(&dir);
                let path = dir.join(format!("seen-{}.bin", pc.to_hex()));
                crate::replay::FileSeenIdStore::open(path, now, false).ok()
            });
            let store = PhoneSeenIdStore {
                pc: *pc,
                file_store,
                state_entries: state_seen,
                pending_sync: inner.pending_seen_sync.clone(),
            };
            crate::verify::Inbox::new_for_phone_group(
                roster.clone(),
                rx_kp,
                crate::verify::InboxConfig::default(),
                Box::new(store),
            )
            .expect("default InboxConfig valid")
        });
        inbox.sync_roster(roster);
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
    .ok_or(RejectReason::NotInRoster)?;
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
            RejectReason::NotInRoster.code() as u64,
            "not_in_roster",
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
