//! The pairing log (M4): a linear, hash-chained log shared by exactly two
//! devices. After the co-signed genesis, every op except `Rename` (of the
//! author itself) and `Unpair` must carry both devices' signatures.
//!
//! Op wire format (all integers big-endian):
//!
//! ```text
//! "VW" 02 'P' | kind u8 | pairing[32] | prev[32] | author[32] | ts u64
//!   | body_len u16 | body | flags u8 (bit 0: co-signed) | sig_author[64] | [sig_cosigner[64]]
//! ```
//!
//! Both signatures cover `TAG_PAIR_SIG || core`, where `core` is everything up
//! to and including the body. The op hash (the next op's `prev`) is
//! `SHA-256(TAG_PAIR_HEAD || core)`, so signatures don't change the chain.
//!
//! Concurrent proposals: when two ops compete for the same `prev`, the op with
//! the lower hash wins on both devices and the loser's author re-proposes on
//! top (`Received::*::requeue`).

use super::codec::{Dec, Enc};
use crate::ids::{DeviceId, GroupId, LogHead};
use crate::keys::{valid_device_name, DeviceCert, DeviceKeypair, ReceivePublicKey};
use crate::mailbox::WRAPPED_EPOCH_SECRET_LEN;
use crate::time::UnixMillis;
use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};

pub const OP_MAGIC: [u8; 4] = *b"VW\x02P";
const TAG_PAIR_SIG: &[u8] = b"voidwire/v2/pair-sig\0";
const TAG_PAIR_HEAD: &[u8] = b"voidwire/v2/pair-head\0";
/// Hard cap on ops kept for one pairing.
pub const MAX_PAIR_LOG_OPS: usize = 512;
/// Compact once this many ops are kept (genesis + latest of each kind).
pub const COMPACT_AT_OPS: usize = 256;
pub const MAX_RELAY_URL_BYTES: usize = 512;
/// Local self-signed ops (renames) not yet seen by the peer.
const MAX_UNACKED: usize = 32;
const LOG_STATE_VERSION: u8 = 1;

/// Feature bit: the device speaks the pairwise (v2) protocol.
pub const FEAT_PAIRWISE: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairError {
    Malformed,
    BadSignature,
    /// A co-signed op kind arrived without the second signature.
    MissingCosign,
    /// A self-signed op kind (rename, unpair) carried a second signature.
    UnexpectedCosign,
    NotMember,
    WrongPairing,
    WrongPrev,
    BadEpoch,
    Unpaired,
    TooManyOps,
    BadRelay,
    BadName,
    BadGenesis,
    /// The other side's competing op has the lower hash.
    LostRace,
    /// A proposal is already waiting for the peer's signature.
    TooManyPending,
    LimitReached,
    Duplicate,
    NotFound,
    InUse,
}

impl std::fmt::Display for PairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PairError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingKind {
    /// Two of the owner's own devices.
    Own = 1,
    /// A device of someone else (M4.5).
    Friend = 2,
}

impl PairingKind {
    pub(crate) fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(PairingKind::Own),
            2 => Some(PairingKind::Friend),
            _ => None,
        }
    }
}

/// Where a pairing's offline inbox lives: a relay and its mailbox id.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayRef {
    pub url: String,
    /// The relay's mailbox service id; `None` = the relay's default.
    pub mailbox_id: Option<DeviceId>,
}

impl std::fmt::Debug for RelayRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayRef").finish_non_exhaustive()
    }
}

impl RelayRef {
    pub fn new(url: impl Into<String>, mailbox_id: Option<DeviceId>) -> Self {
        RelayRef {
            url: url.into(),
            mailbox_id,
        }
    }
    pub fn validate(&self) -> Result<(), PairError> {
        let u = self.url.as_str();
        if u.is_empty()
            || u.len() > MAX_RELAY_URL_BYTES
            || !(u.starts_with("https://") || u.starts_with("http://"))
            || u.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(PairError::BadRelay);
        }
        Ok(())
    }
}

pub(crate) fn enc_relay(e: &mut Enc, r: &Option<RelayRef>) {
    match r {
        None => e.u8(0),
        Some(r) => {
            e.u8(1);
            e.bytes16(r.url.as_bytes());
            match &r.mailbox_id {
                None => e.u8(0),
                Some(m) => {
                    e.u8(1);
                    e.raw(m.as_bytes());
                }
            }
        }
    }
}

pub(crate) fn dec_relay(d: &mut Dec<'_>) -> Option<Option<RelayRef>> {
    match d.u8()? {
        0 => Some(None),
        1 => {
            let url = d.str16()?;
            let mailbox_id = match d.u8()? {
                0 => None,
                1 => Some(DeviceId::from_bytes(d.arr::<32>()?).ok()?),
                _ => return None,
            };
            let r = RelayRef { url, mailbox_id };
            r.validate().ok()?;
            Some(Some(r))
        }
        _ => None,
    }
}

/// Protocol version and feature bits both devices agreed on (version gating).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub proto: u16,
    pub features: u64,
}

impl Caps {
    /// What a v0.4.x (M3) device speaks.
    pub const V1: Caps = Caps {
        proto: 1,
        features: 0,
    };
    /// What this build speaks.
    pub const V2: Caps = Caps {
        proto: 2,
        features: FEAT_PAIRWISE,
    };
    pub fn supports_pairwise(&self) -> bool {
        self.proto >= 2 && self.features & FEAT_PAIRWISE != 0
    }
}

#[derive(Clone, PartialEq, Eq)]
// Few, short-lived values; boxing would only add indirection.
#[allow(clippy::large_enum_variant)]
pub enum PairBody {
    /// Starts the log. Authored by the inviter, co-signed by the joiner.
    Genesis {
        kind: PairingKind,
        inviter: DeviceCert,
        joiner: DeviceCert,
        /// Per-pairing receive keys.
        inviter_rx: ReceivePublicKey,
        joiner_rx: ReceivePublicKey,
        relay: Option<RelayRef>,
    },
    SetRelay {
        relay: Option<RelayRef>,
    },
    /// New epoch: `gs_{epoch}` sealed to the co-signer's current per-pairing
    /// receive key, and a fresh receive key for each side.
    Rekey {
        epoch: u64,
        wrapped: [u8; WRAPPED_EPOCH_SECRET_LEN],
        author_rx: ReceivePublicKey,
        cosigner_rx: ReceivePublicKey,
    },
    Caps(Caps),
    /// The author renames itself (self-signed).
    Rename {
        name: String,
    },
    /// The author leaves (self-signed, one-sided, final).
    Unpair,
}

impl std::fmt::Debug for PairBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Names, URLs and secrets are never printed.
        let k = match self {
            PairBody::Genesis { .. } => "Genesis",
            PairBody::SetRelay { .. } => "SetRelay",
            PairBody::Rekey { .. } => "Rekey",
            PairBody::Caps(_) => "Caps",
            PairBody::Rename { .. } => "Rename",
            PairBody::Unpair => "Unpair",
        };
        f.write_str(k)
    }
}

impl PairBody {
    pub fn kind_byte(&self) -> u8 {
        match self {
            PairBody::Genesis { .. } => 1,
            PairBody::SetRelay { .. } => 2,
            PairBody::Rekey { .. } => 3,
            PairBody::Caps(_) => 4,
            PairBody::Rename { .. } => 5,
            PairBody::Unpair => 6,
        }
    }

    /// Everything except a self-rename and unpairing needs both signatures.
    pub fn requires_cosign(&self) -> bool {
        !matches!(self, PairBody::Rename { .. } | PairBody::Unpair)
    }

    fn validate_standalone(&self) -> Result<(), PairError> {
        match self {
            PairBody::Genesis {
                inviter,
                joiner,
                relay,
                ..
            } => {
                if inviter.device() == joiner.device() {
                    return Err(PairError::BadGenesis);
                }
                if let Some(r) = relay {
                    r.validate()?;
                }
            }
            PairBody::SetRelay { relay: Some(r) } => r.validate()?,
            PairBody::SetRelay { relay: None } => {}
            PairBody::Rekey { epoch, .. } => {
                if *epoch == 0 {
                    return Err(PairError::BadEpoch);
                }
            }
            PairBody::Caps(c) => {
                if c.proto == 0 {
                    return Err(PairError::Malformed);
                }
            }
            PairBody::Rename { name } => {
                if !valid_device_name(name) {
                    return Err(PairError::BadName);
                }
            }
            PairBody::Unpair => {}
        }
        Ok(())
    }

    fn encode(&self, e: &mut Enc) {
        match self {
            PairBody::Genesis {
                kind,
                inviter,
                joiner,
                inviter_rx,
                joiner_rx,
                relay,
            } => {
                e.u8(*kind as u8);
                e.bytes16(inviter.as_bytes());
                e.bytes16(joiner.as_bytes());
                e.raw(&inviter_rx.0);
                e.raw(&joiner_rx.0);
                enc_relay(e, relay);
            }
            PairBody::SetRelay { relay } => enc_relay(e, relay),
            PairBody::Rekey {
                epoch,
                wrapped,
                author_rx,
                cosigner_rx,
            } => {
                e.u64(*epoch);
                e.raw(wrapped);
                e.raw(&author_rx.0);
                e.raw(&cosigner_rx.0);
            }
            PairBody::Caps(c) => {
                e.u16(c.proto);
                e.u64(c.features);
            }
            PairBody::Rename { name } => e.bytes8(name.as_bytes()),
            PairBody::Unpair => {}
        }
    }

    fn decode(kind: u8, b: &[u8]) -> Result<PairBody, PairError> {
        let mut d = Dec::new(b);
        let m = PairError::Malformed;
        let body = match kind {
            1 => {
                let k = PairingKind::from_u8(d.u8().ok_or(m)?).ok_or(m)?;
                let inviter = DeviceCert::parse_verified(d.bytes16().ok_or(m)?)
                    .map_err(|_| PairError::BadSignature)?;
                let joiner = DeviceCert::parse_verified(d.bytes16().ok_or(m)?)
                    .map_err(|_| PairError::BadSignature)?;
                let inviter_rx = ReceivePublicKey(d.arr::<32>().ok_or(m)?);
                let joiner_rx = ReceivePublicKey(d.arr::<32>().ok_or(m)?);
                let relay = dec_relay(&mut d).ok_or(m)?;
                PairBody::Genesis {
                    kind: k,
                    inviter,
                    joiner,
                    inviter_rx,
                    joiner_rx,
                    relay,
                }
            }
            2 => PairBody::SetRelay {
                relay: dec_relay(&mut d).ok_or(m)?,
            },
            3 => PairBody::Rekey {
                epoch: d.u64().ok_or(m)?,
                wrapped: d.arr::<WRAPPED_EPOCH_SECRET_LEN>().ok_or(m)?,
                author_rx: ReceivePublicKey(d.arr::<32>().ok_or(m)?),
                cosigner_rx: ReceivePublicKey(d.arr::<32>().ok_or(m)?),
            },
            4 => PairBody::Caps(Caps {
                proto: d.u16().ok_or(m)?,
                features: d.u64().ok_or(m)?,
            }),
            5 => PairBody::Rename {
                name: d.str8().ok_or(m)?,
            },
            6 => PairBody::Unpair,
            _ => return Err(m),
        };
        if !d.is_empty() {
            return Err(m);
        }
        body.validate_standalone()?;
        Ok(body)
    }
}

/// One signed pairing-log op.
#[derive(Clone, PartialEq, Eq)]
pub struct PairOp {
    pairing: GroupId,
    prev: LogHead,
    author: DeviceId,
    ts: UnixMillis,
    body: PairBody,
    core: Vec<u8>,
    sig_author: [u8; 64],
    sig_cosigner: Option<[u8; 64]>,
}

impl std::fmt::Debug for PairOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairOp")
            .field("body", &self.body)
            .field("author", &self.author)
            .field("cosigned", &self.sig_cosigner.is_some())
            .finish_non_exhaustive()
    }
}

fn sig_input(core: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(TAG_PAIR_SIG.len() + core.len());
    v.extend_from_slice(TAG_PAIR_SIG);
    v.extend_from_slice(core);
    v
}

fn verify_sig(id: &DeviceId, core: &[u8], sig: &[u8; 64]) -> bool {
    id.verifying_key().is_some_and(|k| {
        k.verify_strict(&sig_input(core), &Signature::from_bytes(sig))
            .is_ok()
    })
}

/// `prev` of a pairing's genesis op.
pub fn genesis_prev(pairing: &GroupId) -> LogHead {
    let mut h = Sha256::new();
    h.update(TAG_PAIR_HEAD);
    h.update(b"genesis");
    h.update(pairing.0);
    LogHead(h.finalize().into())
}

impl PairOp {
    fn build_core(
        pairing: &GroupId,
        prev: &LogHead,
        author: &DeviceId,
        ts: UnixMillis,
        body: &PairBody,
    ) -> Vec<u8> {
        let mut be = Enc::new();
        body.encode(&mut be);
        let mut e = Enc::new();
        e.raw(&OP_MAGIC);
        e.u8(body.kind_byte());
        e.raw(&pairing.0);
        e.raw(&prev.0);
        e.raw(author.as_bytes());
        e.u64(ts.0);
        e.bytes16(&be.0);
        std::mem::take(&mut e.0)
    }

    /// Sign a new op as its author (co-signature still missing for kinds
    /// that need one).
    pub fn propose(
        author: &DeviceKeypair,
        pairing: GroupId,
        prev: LogHead,
        ts: UnixMillis,
        body: PairBody,
    ) -> Result<PairOp, PairError> {
        body.validate_standalone()?;
        let id = author.device_id();
        let core = Self::build_core(&pairing, &prev, &id, ts, &body);
        if core.len() > u16::MAX as usize {
            return Err(PairError::Malformed);
        }
        let sig_author = author.sign(&sig_input(&core)).to_bytes();
        Ok(PairOp {
            pairing,
            prev,
            author: id,
            ts,
            body,
            core,
            sig_author,
            sig_cosigner: None,
        })
    }

    fn add_cosignature(&mut self, cosigner: &DeviceKeypair) {
        self.sig_cosigner = Some(cosigner.sign(&sig_input(&self.core)).to_bytes());
    }

    /// The op hash: the next op's `prev`.
    pub fn hash(&self) -> LogHead {
        let mut h = Sha256::new();
        h.update(TAG_PAIR_HEAD);
        h.update(&self.core);
        LogHead(h.finalize().into())
    }

    pub fn pairing(&self) -> GroupId {
        self.pairing
    }
    pub fn prev(&self) -> LogHead {
        self.prev
    }
    pub fn author(&self) -> DeviceId {
        self.author
    }
    pub fn ts(&self) -> UnixMillis {
        self.ts
    }
    pub fn body(&self) -> &PairBody {
        &self.body
    }
    pub fn is_cosigned(&self) -> bool {
        self.sig_cosigner.is_some()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.core.clone();
        v.push(self.sig_cosigner.is_some() as u8);
        v.extend_from_slice(&self.sig_author);
        if let Some(s) = &self.sig_cosigner {
            v.extend_from_slice(s);
        }
        v
    }

    /// Strict decode; checks the author's signature. The co-signature is
    /// checked against the log (only the log knows who the other member is).
    pub fn decode(b: &[u8]) -> Result<PairOp, PairError> {
        let m = PairError::Malformed;
        let mut d = Dec::new(b);
        if d.take(4).ok_or(m)? != OP_MAGIC {
            return Err(m);
        }
        let kind = d.u8().ok_or(m)?;
        let pairing = GroupId(d.arr::<32>().ok_or(m)?);
        let prev = LogHead(d.arr::<32>().ok_or(m)?);
        let author = DeviceId::from_bytes(d.arr::<32>().ok_or(m)?).map_err(|_| m)?;
        let ts = UnixMillis(d.u64().ok_or(m)?);
        let body_bytes = d.bytes16().ok_or(m)?;
        let core_len = b.len() - remaining_after(&d);
        let core = b[..core_len].to_vec();
        let flags = d.u8().ok_or(m)?;
        let sig_author = d.arr::<64>().ok_or(m)?;
        let sig_cosigner = match flags {
            0 => None,
            1 => Some(d.arr::<64>().ok_or(m)?),
            _ => return Err(m),
        };
        if !d.is_empty() {
            return Err(m);
        }
        let body = PairBody::decode(kind, body_bytes)?;
        if !verify_sig(&author, &core, &sig_author) {
            return Err(PairError::BadSignature);
        }
        Ok(PairOp {
            pairing,
            prev,
            author,
            ts,
            body,
            core,
            sig_author,
            sig_cosigner,
        })
    }
}

fn remaining_after(d: &Dec<'_>) -> usize {
    d.remaining()
}

/// What the log says right now (everything except the ops themselves).
#[derive(Clone, PartialEq, Eq)]
struct PairState {
    head: LogHead,
    len: u64,
    epoch: u64,
    rx: [ReceivePublicKey; 2],
    names: [String; 2],
    relay: Option<RelayRef>,
    caps: Option<Caps>,
    unpaired_by: Option<usize>,
}

/// Result of [`PairLog::propose`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proposed {
    /// Send to the peer; applied once it comes back co-signed.
    NeedsCosign(PairOp),
    /// Self-signed op, applied locally. Send to the peer.
    Applied(PairOp),
}

/// Result of [`PairLog::receive`].
#[derive(Debug, Clone, PartialEq, Eq)]
// Few, short-lived values; boxing would only add indirection.
#[allow(clippy::large_enum_variant)]
pub enum Received {
    /// Applied. `requeue`: our own ops that lost a race; propose them again.
    Applied { requeue: Vec<PairBody> },
    /// We co-signed and applied the peer's proposal: send `op` back.
    Cosigned { op: PairOp, requeue: Vec<PairBody> },
    /// Not applied: it lost a race against our op, or we already have it.
    Ignored,
}

/// A two-device pairing log replica.
#[derive(Clone)]
pub struct PairLog {
    pairing: GroupId,
    kind: PairingKind,
    members: [DeviceId; 2],
    certs: [DeviceCert; 2],
    genesis: PairOp,
    /// After compaction: the latest op of each kind, signatures checked.
    snapshot: Vec<PairOp>,
    /// After compaction: head and length where `tail` starts.
    snapshot_head: Option<(LogHead, u64)>,
    tail: Vec<PairOp>,
    st: PairState,
    /// Our own self-signed ops the peer hasn't built on yet: state before the
    /// op and its index in `tail`.
    unacked: Vec<(PairState, usize)>,
    /// Our proposal waiting for the peer's signature.
    pending: Option<PairOp>,
}

impl std::fmt::Debug for PairLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairLog")
            .field("pairing", &self.pairing)
            .field("len", &self.st.len)
            .field("epoch", &self.st.epoch)
            .finish_non_exhaustive()
    }
}

impl PairLog {
    // ---- genesis ----

    /// Inviter: sign a genesis op (send it to the joiner to co-sign).
    pub fn propose_genesis(
        inviter: &DeviceKeypair,
        pairing: GroupId,
        ts: UnixMillis,
        body: PairBody,
    ) -> Result<PairOp, PairError> {
        let PairBody::Genesis { inviter: ic, .. } = &body else {
            return Err(PairError::BadGenesis);
        };
        if ic.device() != inviter.device_id() {
            return Err(PairError::BadGenesis);
        }
        PairOp::propose(inviter, pairing, genesis_prev(&pairing), ts, body)
    }

    /// Joiner: check the inviter's genesis names us, co-sign it and start our
    /// replica. Send the returned op back to the inviter.
    pub fn accept_genesis(
        joiner: &DeviceKeypair,
        mut op: PairOp,
    ) -> Result<(PairLog, PairOp), PairError> {
        Self::check_genesis_shape(&op)?;
        let PairBody::Genesis { joiner: jc, .. } = &op.body else {
            return Err(PairError::BadGenesis);
        };
        if jc.device() != joiner.device_id() || op.sig_cosigner.is_some() {
            return Err(PairError::BadGenesis);
        }
        op.add_cosignature(joiner);
        let log = Self::from_genesis(op.clone())?;
        Ok((log, op))
    }

    fn check_genesis_shape(op: &PairOp) -> Result<(), PairError> {
        let PairBody::Genesis { inviter, .. } = &op.body else {
            return Err(PairError::BadGenesis);
        };
        if op.prev != genesis_prev(&op.pairing) || op.author != inviter.device() {
            return Err(PairError::BadGenesis);
        }
        if !verify_sig(&op.author, &op.core, &op.sig_author) {
            return Err(PairError::BadSignature);
        }
        Ok(())
    }

    /// Start a replica from a fully co-signed genesis.
    pub fn from_genesis(op: PairOp) -> Result<PairLog, PairError> {
        Self::check_genesis_shape(&op)?;
        let PairBody::Genesis {
            kind,
            inviter,
            joiner,
            inviter_rx,
            joiner_rx,
            relay,
        } = op.body.clone()
        else {
            return Err(PairError::BadGenesis);
        };
        let cs = op.sig_cosigner.ok_or(PairError::MissingCosign)?;
        if !verify_sig(&joiner.device(), &op.core, &cs) {
            return Err(PairError::BadSignature);
        }
        let st = PairState {
            head: op.hash(),
            len: 1,
            epoch: 0,
            rx: [inviter_rx, joiner_rx],
            names: [inviter.name().to_owned(), joiner.name().to_owned()],
            relay,
            caps: None,
            unpaired_by: None,
        };
        Ok(PairLog {
            pairing: op.pairing,
            kind,
            members: [inviter.device(), joiner.device()],
            certs: [inviter, joiner],
            genesis: op,
            snapshot: Vec::new(),
            snapshot_head: None,
            tail: Vec::new(),
            st,
            unacked: Vec::new(),
            pending: None,
        })
    }

    // ---- accessors ----

    pub fn pairing(&self) -> GroupId {
        self.pairing
    }
    pub fn kind(&self) -> PairingKind {
        self.kind
    }
    pub fn members(&self) -> [DeviceId; 2] {
        self.members
    }
    pub fn head(&self) -> LogHead {
        self.st.head
    }
    /// Ops ever applied (including compacted ones).
    pub fn len(&self) -> u64 {
        self.st.len
    }
    pub fn is_empty(&self) -> bool {
        false
    }
    /// Ops kept on disk (genesis + snapshot + tail).
    pub fn retained_len(&self) -> usize {
        1 + self.snapshot.len() + self.tail.len()
    }
    pub fn epoch(&self) -> u64 {
        self.st.epoch
    }
    pub fn relay(&self) -> Option<&RelayRef> {
        self.st.relay.as_ref()
    }
    pub fn caps(&self) -> Option<Caps> {
        self.st.caps
    }
    pub fn is_unpaired(&self) -> bool {
        self.st.unpaired_by.is_some()
    }
    pub fn pending(&self) -> Option<&PairOp> {
        self.pending.as_ref()
    }
    pub fn cert_of(&self, id: &DeviceId) -> Option<&DeviceCert> {
        self.index_of(id).map(|i| &self.certs[i])
    }
    pub fn name_of(&self, id: &DeviceId) -> Option<&str> {
        self.index_of(id).map(|i| self.st.names[i].as_str())
    }
    /// Current per-pairing receive key of a member.
    pub fn rx_of(&self, id: &DeviceId) -> Option<ReceivePublicKey> {
        self.index_of(id).map(|i| self.st.rx[i])
    }
    pub fn peer_of(&self, me: &DeviceId) -> Option<DeviceId> {
        self.index_of(me).map(|i| self.members[1 - i])
    }
    fn index_of(&self, id: &DeviceId) -> Option<usize> {
        self.members.iter().position(|m| m == id)
    }

    // ---- validation and apply ----

    /// Checks everything except the presence of a co-signature (a proposal
    /// passes; a co-signature that is present must verify).
    fn validate(&self, op: &PairOp, st: &PairState) -> Result<usize, PairError> {
        if st.unpaired_by.is_some() {
            return Err(PairError::Unpaired);
        }
        if op.pairing != self.pairing {
            return Err(PairError::WrongPairing);
        }
        let ai = self.index_of(&op.author).ok_or(PairError::NotMember)?;
        if !verify_sig(&op.author, &op.core, &op.sig_author) {
            return Err(PairError::BadSignature);
        }
        match (&op.body, op.sig_cosigner) {
            (PairBody::Genesis { .. }, _) => return Err(PairError::BadGenesis),
            (b, Some(_)) if !b.requires_cosign() => return Err(PairError::UnexpectedCosign),
            (_, Some(cs)) => {
                if !verify_sig(&self.members[1 - ai], &op.core, &cs) {
                    return Err(PairError::BadSignature);
                }
            }
            _ => {}
        }
        if let PairBody::Rekey { epoch, .. } = &op.body {
            if *epoch != st.epoch + 1 {
                return Err(PairError::BadEpoch);
            }
        }
        op.body.validate_standalone()?;
        Ok(ai)
    }

    fn apply_state(st: &mut PairState, ai: usize, op: &PairOp) {
        match &op.body {
            PairBody::Genesis { .. } => {}
            PairBody::SetRelay { relay } => st.relay = relay.clone(),
            PairBody::Rekey {
                epoch,
                author_rx,
                cosigner_rx,
                ..
            } => {
                st.epoch = *epoch;
                st.rx[ai] = *author_rx;
                st.rx[1 - ai] = *cosigner_rx;
            }
            PairBody::Caps(c) => st.caps = Some(*c),
            PairBody::Rename { name } => st.names[ai] = name.clone(),
            PairBody::Unpair => st.unpaired_by = Some(ai),
        }
    }

    fn apply(&mut self, op: PairOp, ai: usize) -> Result<(), PairError> {
        if op.body.requires_cosign() && op.sig_cosigner.is_none() {
            return Err(PairError::MissingCosign);
        }
        if self.retained_len() >= MAX_PAIR_LOG_OPS {
            return Err(PairError::TooManyOps);
        }
        Self::apply_state(&mut self.st, ai, &op);
        self.st.head = op.hash();
        self.st.len += 1;
        self.tail.push(op);
        if self.retained_len() >= COMPACT_AT_OPS {
            self.compact();
        }
        Ok(())
    }

    /// Keep genesis + the latest op of each kind; the chain restarts at the
    /// head of the last absorbed op. Unacked local ops are never absorbed.
    fn compact(&mut self) {
        let keep_from = self.unacked.first().map_or(self.tail.len(), |u| u.1);
        if keep_from == 0 {
            return;
        }
        let absorbed: Vec<PairOp> = self.tail.drain(..keep_from).collect();
        let head_at = absorbed.last().expect("non-empty").hash();
        let len_at = self.st.len - self.tail.len() as u64;
        let mut all: Vec<PairOp> = std::mem::take(&mut self.snapshot);
        all.extend(absorbed);
        let mut latest: Vec<PairOp> = Vec::new();
        for op in all.into_iter().rev() {
            let key = |o: &PairOp| match &o.body {
                PairBody::Rename { .. } => (o.body.kind_byte(), Some(o.author)),
                _ => (o.body.kind_byte(), None),
            };
            if !latest.iter().any(|k| key(k) == key(&op)) {
                latest.push(op);
            }
        }
        latest.reverse();
        self.snapshot = latest;
        self.snapshot_head = Some((head_at, len_at));
        for u in &mut self.unacked {
            u.1 -= keep_from;
        }
    }

    // ---- proposing ----

    /// Propose a new op as `me`. Co-signed kinds wait for the peer
    /// ([`Proposed::NeedsCosign`]); a rename or unpair applies at once.
    pub fn propose(
        &mut self,
        me: &DeviceKeypair,
        ts: UnixMillis,
        body: PairBody,
    ) -> Result<Proposed, PairError> {
        let ai = self.index_of(&me.device_id()).ok_or(PairError::NotMember)?;
        if self.st.unpaired_by.is_some() {
            return Err(PairError::Unpaired);
        }
        let unpair = matches!(body, PairBody::Unpair);
        if !unpair && self.pending.is_some() {
            return Err(PairError::TooManyPending);
        }
        if matches!(body, PairBody::Rename { .. }) && self.unacked.len() >= MAX_UNACKED {
            return Err(PairError::TooManyPending);
        }
        let op = PairOp::propose(me, self.pairing, self.st.head, ts, body)?;
        self.validate(&op, &self.st)?;
        if op.body.requires_cosign() {
            self.pending = Some(op.clone());
            return Ok(Proposed::NeedsCosign(op));
        }
        if unpair {
            // Final and local: nothing to undo, nothing pending.
            self.pending = None;
            self.unacked.clear();
        } else {
            self.unacked.push((self.st.clone(), self.tail.len()));
        }
        self.apply(op.clone(), ai)?;
        Ok(Proposed::Applied(op))
    }

    /// Local, immediate unpair (the notice to the peer is best effort).
    pub fn unpair(&mut self, me: &DeviceKeypair, ts: UnixMillis) -> Result<PairOp, PairError> {
        match self.propose(me, ts, PairBody::Unpair)? {
            Proposed::Applied(op) | Proposed::NeedsCosign(op) => Ok(op),
        }
    }

    // ---- receiving ----

    /// Handle an op from the peer (a proposal to co-sign, our own proposal
    /// coming back co-signed, or a self-signed op).
    pub fn receive(&mut self, me: &DeviceKeypair, op: PairOp) -> Result<Received, PairError> {
        let my_id = me.device_id();
        let mi = self.index_of(&my_id).ok_or(PairError::NotMember)?;
        if self.st.unpaired_by.is_some() {
            return Err(PairError::Unpaired);
        }
        let h = op.hash();
        if op.prev == self.st.head {
            return self.receive_at_head(me, mi, op);
        }
        // Competing with one of our unacked self-signed ops?
        if let Some(k) = self.unacked.iter().position(|(s, _)| s.head == op.prev) {
            if op.author == my_id {
                return Err(PairError::WrongPrev);
            }
            let mine = self.tail[self.unacked[k].1].hash();
            let theirs_wins = matches!(op.body, PairBody::Unpair) || h.0 < mine.0;
            if !theirs_wins {
                return Ok(Received::Ignored);
            }
            self.validate(&op, &self.unacked[k].0)?;
            let mut requeue = self.undo_to(k);
            match self.receive_at_head(me, mi, op)? {
                Received::Applied { requeue: r } => {
                    requeue.extend(r);
                    Ok(Received::Applied { requeue })
                }
                Received::Cosigned { op, requeue: r } => {
                    requeue.extend(r);
                    Ok(Received::Cosigned { op, requeue })
                }
                Received::Ignored => Ok(Received::Applied { requeue }),
            }
        } else if self.contains(&h) {
            Ok(Received::Ignored)
        } else {
            Err(PairError::WrongPrev)
        }
    }

    fn contains(&self, h: &LogHead) -> bool {
        self.genesis.hash() == *h
            || self.tail.iter().any(|o| o.hash() == *h)
            || self.snapshot.iter().any(|o| o.hash() == *h)
    }

    /// Roll back our unacked ops from index `k` on; returns their bodies
    /// (and a now-stale pending proposal) for re-proposal.
    fn undo_to(&mut self, k: usize) -> Vec<PairBody> {
        let (st, idx) = self.unacked[k].clone();
        let mut requeue: Vec<PairBody> = self.tail.drain(idx..).map(|o| o.body).collect();
        self.unacked.truncate(k);
        self.st = st;
        if let Some(p) = self.pending.take() {
            requeue.push(p.body);
        }
        requeue
    }

    fn receive_at_head(
        &mut self,
        me: &DeviceKeypair,
        mi: usize,
        mut op: PairOp,
    ) -> Result<Received, PairError> {
        let ai = self.validate(&op, &self.st)?;
        if ai == mi {
            // Our own proposal, back with the peer's signature.
            if op.sig_cosigner.is_none() {
                return Err(PairError::MissingCosign);
            }
            if self.pending.as_ref().map(PairOp::hash) == Some(op.hash()) {
                self.pending = None;
            }
            self.unacked.clear();
            self.apply(op, ai)?;
            return Ok(Received::Applied {
                requeue: Vec::new(),
            });
        }
        let h = op.hash();
        let pending_wins = self
            .pending
            .as_ref()
            .is_some_and(|p| p.prev == self.st.head && p.hash().0 < h.0);
        let is_unpair = matches!(op.body, PairBody::Unpair);
        if pending_wins && !is_unpair && op.sig_cosigner.is_none() {
            return Ok(Received::Ignored);
        }
        let mut requeue = Vec::new();
        if let Some(p) = self.pending.take() {
            requeue.push(p.body);
        }
        self.unacked.clear();
        if op.body.requires_cosign() && op.sig_cosigner.is_none() {
            op.add_cosignature(me);
            self.apply(op.clone(), ai)?;
            return Ok(Received::Cosigned { op, requeue });
        }
        self.apply(op, ai)?;
        Ok(Received::Applied { requeue })
    }

    // ---- storage ----

    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u8(LOG_STATE_VERSION);
        e.bytes16(&self.genesis.encode());
        e.u16(self.snapshot.len() as u16);
        for o in &self.snapshot {
            e.bytes16(&o.encode());
        }
        match &self.snapshot_head {
            None => e.u8(0),
            Some((h, n)) => {
                e.u8(1);
                e.raw(&h.0);
                e.u64(*n);
            }
        }
        e.u16(self.tail.len() as u16);
        for o in &self.tail {
            e.bytes16(&o.encode());
        }
        e.u8(self.unacked.len() as u8);
        match &self.pending {
            None => e.u8(0),
            Some(p) => {
                e.u8(1);
                e.bytes16(&p.encode());
            }
        }
        std::mem::take(&mut e.0)
    }

    /// Rebuild and fully re-verify a stored replica.
    pub fn decode(b: &[u8]) -> Result<PairLog, PairError> {
        let m = PairError::Malformed;
        let mut d = Dec::new(b);
        if d.u8().ok_or(m)? != LOG_STATE_VERSION {
            return Err(m);
        }
        let genesis = PairOp::decode(d.bytes16().ok_or(m)?)?;
        let mut log = PairLog::from_genesis(genesis)?;
        let ns = d.u16().ok_or(m)? as usize;
        if ns > MAX_PAIR_LOG_OPS {
            return Err(PairError::TooManyOps);
        }
        let mut snapshot = Vec::with_capacity(ns);
        for _ in 0..ns {
            snapshot.push(PairOp::decode(d.bytes16().ok_or(m)?)?);
        }
        let snap_head = match d.u8().ok_or(m)? {
            0 => None,
            1 => Some((LogHead(d.arr::<32>().ok_or(m)?), d.u64().ok_or(m)?)),
            _ => return Err(m),
        };
        if snap_head.is_none() && !snapshot.is_empty() {
            return Err(m);
        }
        for op in snapshot {
            // Signatures and kinds only: the chain under a snapshot is gone.
            let mut st = log.st.clone();
            if let PairBody::Rekey { epoch, .. } = op.body {
                st.epoch = epoch.saturating_sub(1);
            }
            let ai = log.validate(&op, &st)?;
            if op.body.requires_cosign() && op.sig_cosigner.is_none() {
                return Err(PairError::MissingCosign);
            }
            Self::apply_state(&mut log.st, ai, &op);
            log.snapshot.push(op);
        }
        if let Some((h, n)) = snap_head {
            if n < 1 + log.snapshot.len() as u64 {
                return Err(m);
            }
            log.st.head = h;
            log.st.len = n;
            log.snapshot_head = Some((h, n));
        }
        let nt = d.u16().ok_or(m)? as usize;
        if 1 + log.snapshot.len() + nt > MAX_PAIR_LOG_OPS {
            return Err(PairError::TooManyOps);
        }
        let mut tail = Vec::with_capacity(nt);
        for _ in 0..nt {
            tail.push(PairOp::decode(d.bytes16().ok_or(m)?)?);
        }
        let n_unacked = d.u8().ok_or(m)? as usize;
        if n_unacked > nt {
            return Err(m);
        }
        let first_unacked = nt - n_unacked;
        for (i, op) in tail.into_iter().enumerate() {
            if op.prev != log.st.head {
                return Err(PairError::WrongPrev);
            }
            let ai = log.validate(&op, &log.st)?;
            if i >= first_unacked {
                if op.body.requires_cosign() {
                    return Err(m);
                }
                log.unacked.push((log.st.clone(), log.tail.len()));
            }
            if op.body.requires_cosign() && op.sig_cosigner.is_none() {
                return Err(PairError::MissingCosign);
            }
            Self::apply_state(&mut log.st, ai, &op);
            log.st.head = op.hash();
            log.st.len += 1;
            log.tail.push(op);
        }
        log.pending = match d.u8().ok_or(m)? {
            0 => None,
            1 => {
                let p = PairOp::decode(d.bytes16().ok_or(m)?)?;
                // A stale proposal is dropped (its author re-proposes).
                (p.prev == log.st.head && log.validate(&p, &log.st).is_ok()).then_some(p)
            }
            _ => return Err(m),
        };
        if !d.is_empty() {
            return Err(m);
        }
        Ok(log)
    }
}

#[cfg(test)]
impl PairOp {
    pub(crate) fn sig_cosigner_for_tests(&mut self, kp: &DeviceKeypair) {
        self.add_cosignature(kp);
    }
}
