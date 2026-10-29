//! Pairing records (M4 §1.2), the pairing set and relay settings, and the
//! v0.4.x migration helpers (one pairing per legacy peer, no re-pair).

use super::codec::{Dec, Enc};
use super::log::{dec_relay, enc_relay, Caps, PairError, PairLog, PairingKind, RelayRef};
use crate::ids::{DeviceId, GroupId};
use crate::keys::{valid_device_name, DeviceCert, Platform, ReceiveKeypair, ReceivePublicKey};
use crate::mailbox::{open_secret_from_state, seal_secret_for_state, EpochSecret};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// At most this many pairings per device.
pub const MAX_PAIRINGS: usize = 16;
/// At most this many saved relays.
pub const MAX_SAVED_RELAYS: usize = 8;
/// At most this many relays in use at once (home + pairing relays).
pub const MAX_RELAYS_IN_USE: usize = 4;

const TAG_LEGACY_PAIRING_ID: &[u8] = b"voidwire/v2/legacy-pairing-id\0";
const RECORD_VERSION: u8 = 1;
const SET_VERSION: u8 = 1;
const RELAYS_VERSION: u8 = 1;
const SEALED: usize = crate::mailbox::SEALED_STATE_SECRET_LEN;

/// How a pairing came to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingOrigin {
    /// Paired with the pairwise protocol (has its own log).
    V2,
    /// Split out of a v0.4.x PC-hosted group; traffic still runs on the
    /// legacy group until both sides speak v2 (version gating).
    LegacyHub { group: GroupId },
}

/// The peer as shown to the user.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub id: DeviceId,
    pub name: String,
    pub platform: Platform,
}

impl std::fmt::Debug for PeerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerInfo")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Our receive key for one pairing.
pub enum MyRx {
    /// Migrated pairings keep using the device receive key until their
    /// first rekey.
    DeviceKey,
    Own(ReceiveKeypair),
}

impl std::fmt::Debug for MyRx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MyRx::DeviceKey => f.write_str("DeviceKey"),
            MyRx::Own(k) => write!(f, "Own({:?})", k.public()),
        }
    }
}

impl Clone for MyRx {
    fn clone(&self) -> Self {
        match self {
            MyRx::DeviceKey => MyRx::DeviceKey,
            MyRx::Own(k) => MyRx::Own(
                ReceiveKeypair::from_secret_bytes(&k.secret_bytes()).expect("valid stored key"),
            ),
        }
    }
}

/// One pairing: a two-device group with its own keys, relay and inbox.
#[derive(Debug, Clone)]
pub struct Pairing {
    pub pairing_id: GroupId,
    pub kind: PairingKind,
    pub origin: PairingOrigin,
    pub peer: PeerInfo,
    pub peer_cert: Option<DeviceCert>,
    pub my_rx: MyRx,
    pub peer_rx: Option<ReceivePublicKey>,
    pub relay: Option<RelayRef>,
    pub epoch: u64,
    /// Epoch secrets of v2 pairings. Legacy pairings keep theirs in the
    /// legacy group state (never copied).
    pub gs_e: Option<EpochSecret>,
    pub prev_gs_e: Option<EpochSecret>,
    pub log: Option<PairLog>,
    pub peer_caps: Caps,
    /// Local-only nickname.
    pub label: Option<String>,
}

/// Both sides of a legacy group derive the same pairing id for their pair.
pub fn legacy_pairing_id(group: &GroupId, a: &DeviceId, b: &DeviceId) -> GroupId {
    let (lo, hi) = if a.as_bytes() <= b.as_bytes() {
        (a, b)
    } else {
        (b, a)
    };
    let mut h = Sha256::new();
    h.update(TAG_LEGACY_PAIRING_ID);
    h.update(group.0);
    h.update(lo.as_bytes());
    h.update(hi.as_bytes());
    GroupId(h.finalize().into())
}

/// A peer of a v0.4.x group, as the legacy state knows it.
#[derive(Debug, Clone)]
pub struct LegacyLink {
    pub group: GroupId,
    pub peer: PeerInfo,
    pub peer_cert: Option<DeviceCert>,
    pub relay: Option<RelayRef>,
    pub epoch: u64,
}

impl Pairing {
    /// The pairing split out of a legacy group for one peer.
    pub fn from_legacy(me: &DeviceId, link: &LegacyLink) -> Pairing {
        Pairing {
            pairing_id: legacy_pairing_id(&link.group, me, &link.peer.id),
            kind: PairingKind::Own,
            origin: PairingOrigin::LegacyHub { group: link.group },
            peer: link.peer.clone(),
            peer_cert: link.peer_cert.clone(),
            my_rx: MyRx::DeviceKey,
            peer_rx: link.peer_cert.as_ref().map(DeviceCert::receive_key),
            relay: link.relay.clone(),
            epoch: link.epoch,
            gs_e: None,
            prev_gs_e: None,
            log: None,
            peer_caps: Caps::V1,
            label: None,
        }
    }

    /// The v2 protocol is used for this pairing only once both devices
    /// co-signed a `Caps` op saying they speak it (version gating).
    pub fn v2_active(&self) -> bool {
        self.origin == PairingOrigin::V2
            && self
                .log
                .as_ref()
                .and_then(PairLog::caps)
                .is_some_and(|c| c.supports_pairwise())
    }

    pub fn display_name(&self) -> &str {
        self.label.as_deref().unwrap_or(&self.peer.name)
    }

    fn encode(&self, seal_key: &[u8; 32], e: &mut Enc) {
        e.u8(RECORD_VERSION);
        e.raw(&self.pairing_id.0);
        e.u8(self.kind as u8);
        match self.origin {
            PairingOrigin::V2 => e.u8(0),
            PairingOrigin::LegacyHub { group } => {
                e.u8(1);
                e.raw(&group.0);
            }
        }
        e.raw(self.peer.id.as_bytes());
        e.bytes8(self.peer.name.as_bytes());
        e.u8(self.peer.platform as u8);
        match &self.peer_cert {
            None => e.u8(0),
            Some(c) => {
                e.u8(1);
                e.bytes16(c.as_bytes());
            }
        }
        match &self.my_rx {
            MyRx::DeviceKey => e.u8(0),
            MyRx::Own(k) => {
                e.u8(1);
                e.raw(&seal_secret_for_state(seal_key, &k.secret_bytes()));
            }
        }
        match &self.peer_rx {
            None => e.u8(0),
            Some(k) => {
                e.u8(1);
                e.raw(&k.0);
            }
        }
        enc_relay(e, &self.relay);
        e.u64(self.epoch);
        for s in [&self.gs_e, &self.prev_gs_e] {
            match s {
                None => e.u8(0),
                Some(s) => {
                    e.u8(1);
                    e.raw(&seal_secret_for_state(seal_key, s.as_bytes()));
                }
            }
        }
        match &self.log {
            None => e.u8(0),
            Some(l) => {
                e.u8(1);
                e.bytes32(&l.encode());
            }
        }
        e.u16(self.peer_caps.proto);
        e.u64(self.peer_caps.features);
        match &self.label {
            None => e.u8(0),
            Some(l) => {
                e.u8(1);
                e.bytes8(l.as_bytes());
            }
        }
    }

    fn decode(seal_key: &[u8; 32], d: &mut Dec<'_>) -> Option<Pairing> {
        if d.u8()? != RECORD_VERSION {
            return None;
        }
        let pairing_id = GroupId(d.arr::<32>()?);
        let kind = PairingKind::from_u8(d.u8()?)?;
        let origin = match d.u8()? {
            0 => PairingOrigin::V2,
            1 => PairingOrigin::LegacyHub {
                group: GroupId(d.arr::<32>()?),
            },
            _ => return None,
        };
        let id = DeviceId::from_bytes(d.arr::<32>()?).ok()?;
        let name = d.str8()?;
        let platform = Platform::from_u8(d.u8()?);
        let peer_cert = match d.u8()? {
            0 => None,
            1 => Some(DeviceCert::parse_verified(d.bytes16()?).ok()?),
            _ => return None,
        };
        if peer_cert.as_ref().is_some_and(|c| c.device() != id) {
            return None;
        }
        let my_rx = match d.u8()? {
            0 => MyRx::DeviceKey,
            1 => {
                let raw = open_secret_from_state(seal_key, &d.arr::<SEALED>()?)?;
                MyRx::Own(ReceiveKeypair::from_secret_bytes(&raw)?)
            }
            _ => return None,
        };
        let peer_rx = match d.u8()? {
            0 => None,
            1 => Some(ReceivePublicKey(d.arr::<32>()?)),
            _ => return None,
        };
        let relay = dec_relay(d)?;
        let epoch = d.u64()?;
        let mut secrets = [None, None];
        for s in &mut secrets {
            *s = match d.u8()? {
                0 => None,
                1 => {
                    let raw = open_secret_from_state(seal_key, &d.arr::<SEALED>()?)?;
                    Some(EpochSecret::from_bytes(*raw))
                }
                _ => return None,
            };
        }
        let [gs_e, prev_gs_e] = secrets;
        let log = match d.u8()? {
            0 => None,
            1 => Some(PairLog::decode(d.bytes32()?).ok()?),
            _ => return None,
        };
        if let Some(l) = &log {
            if l.pairing() != pairing_id || !l.members().contains(&id) {
                return None;
            }
        }
        let peer_caps = Caps {
            proto: d.u16()?,
            features: d.u64()?,
        };
        let label = match d.u8()? {
            0 => None,
            1 => Some(d.str8()?),
            _ => return None,
        };
        Some(Pairing {
            pairing_id,
            kind,
            origin,
            peer: PeerInfo { id, name, platform },
            peer_cert,
            my_rx,
            peer_rx,
            relay,
            epoch,
            gs_e,
            prev_gs_e,
            log,
            peer_caps,
            label,
        })
    }
}

/// All pairings of this device.
#[derive(Debug, Clone, Default)]
pub struct PairingSet {
    items: Vec<Pairing>,
}

impl PairingSet {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &Pairing> {
        self.items.iter()
    }
    pub fn get(&self, pairing_id: &GroupId) -> Option<&Pairing> {
        self.items.iter().find(|p| p.pairing_id == *pairing_id)
    }
    pub fn get_mut(&mut self, pairing_id: &GroupId) -> Option<&mut Pairing> {
        self.items.iter_mut().find(|p| p.pairing_id == *pairing_id)
    }
    pub fn by_peer(&self, peer: &DeviceId) -> impl Iterator<Item = &Pairing> {
        let peer = *peer;
        self.items.iter().filter(move |p| p.peer.id == peer)
    }
    /// A new pairing can be added (the 16-pairing limit).
    pub fn has_room(&self) -> bool {
        self.items.len() < MAX_PAIRINGS
    }

    /// Add a new pairing (limit and duplicate checked).
    pub fn add(&mut self, p: Pairing) -> Result<(), PairError> {
        if self.get(&p.pairing_id).is_some() {
            return Err(PairError::Duplicate);
        }
        if !self.has_room() {
            return Err(PairError::LimitReached);
        }
        self.items.push(p);
        Ok(())
    }

    /// Unpair: one-sided, immediate and local. Secrets are wiped on drop.
    pub fn remove(&mut self, pairing_id: &GroupId) -> Option<Pairing> {
        let i = self
            .items
            .iter()
            .position(|p| p.pairing_id == *pairing_id)?;
        Some(self.items.remove(i))
    }

    /// Keep the legacy (v0.4.x group) pairings in step with the legacy state:
    /// one pairing per active peer, created with no re-pair, dropped when the
    /// peer is gone. Existing v0.4.x pairings are never refused by the limit.
    /// Returns whether anything changed.
    pub fn sync_legacy(&mut self, me: &DeviceId, links: &[LegacyLink]) -> bool {
        let wanted: Vec<(GroupId, &LegacyLink)> = links
            .iter()
            .filter(|l| l.peer.id != *me)
            .map(|l| (legacy_pairing_id(&l.group, me, &l.peer.id), l))
            .collect();
        let before = self.items.len();
        self.items.retain(|p| match p.origin {
            PairingOrigin::LegacyHub { .. } => wanted.iter().any(|(id, _)| *id == p.pairing_id),
            PairingOrigin::V2 => true,
        });
        let mut changed = before != self.items.len();
        for (id, l) in wanted {
            match self.get_mut(&id) {
                Some(p) => {
                    let cert_rx = l.peer_cert.as_ref().map(DeviceCert::receive_key);
                    if p.peer != l.peer
                        || p.relay != l.relay
                        || p.epoch != l.epoch
                        || p.peer_cert != l.peer_cert
                        || p.peer_rx != cert_rx
                    {
                        p.peer = l.peer.clone();
                        p.peer_cert = l.peer_cert.clone();
                        p.peer_rx = cert_rx;
                        p.relay = l.relay.clone();
                        p.epoch = l.epoch;
                        changed = true;
                    }
                }
                None => {
                    self.items.push(Pairing::from_legacy(me, l));
                    changed = true;
                }
            }
        }
        changed
    }

    /// Sealed with `seal_key` (the identity secret): wiped when dropped.
    pub fn encode(&self, seal_key: &[u8; 32]) -> Zeroizing<Vec<u8>> {
        let mut e = Enc::new();
        e.u8(SET_VERSION);
        e.u16(self.items.len() as u16);
        for p in &self.items {
            let mut pe = Enc::new();
            p.encode(seal_key, &mut pe);
            e.bytes32(&pe.0);
        }
        Zeroizing::new(std::mem::take(&mut e.0))
    }

    pub fn decode(seal_key: &[u8; 32], b: &[u8]) -> Option<PairingSet> {
        let mut d = Dec::new(b);
        if d.u8()? != SET_VERSION {
            return None;
        }
        let n = d.u16()? as usize;
        let mut items = Vec::with_capacity(n.min(256));
        for _ in 0..n {
            let mut pd = Dec::new(d.bytes32()?);
            let p = Pairing::decode(seal_key, &mut pd)?;
            if !pd.is_empty() || items.iter().any(|x: &Pairing| x.pairing_id == p.pairing_id) {
                return None;
            }
            items.push(p);
        }
        d.is_empty().then_some(PairingSet { items })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaySource {
    Builtin = 1,
    FromInvite = 2,
    Manual = 3,
}

impl RelaySource {
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(RelaySource::Builtin),
            2 => Some(RelaySource::FromInvite),
            3 => Some(RelaySource::Manual),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEntry {
    pub nickname: String,
    pub relay: RelayRef,
    pub source: RelaySource,
}

/// Saved relays and the home relay (`None` = relay off).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySettings {
    pub home_relay: Option<String>,
    pub relays: Vec<RelayEntry>,
}

pub const BUILTIN_RELAY_NICKNAME: &str = "Voidwire public relay";
pub const CUSTOM_RELAY_NICKNAME: &str = "My relay";

impl RelaySettings {
    pub fn new(builtin: RelayRef) -> Self {
        RelaySettings {
            home_relay: Some(builtin.url.clone()),
            relays: vec![RelayEntry {
                nickname: BUILTIN_RELAY_NICKNAME.to_owned(),
                relay: builtin,
                source: RelaySource::Builtin,
            }],
        }
    }

    /// From a v0.4.x single relay setting (`configured = None`: relay off).
    pub fn from_legacy(builtin: RelayRef, configured: Option<RelayRef>) -> Self {
        let mut s = RelaySettings::new(builtin);
        s.sync_home(configured);
        s
    }

    /// Follow the legacy relay setting (Settings → Relay keeps working).
    /// Returns whether anything changed.
    pub fn sync_home(&mut self, configured: Option<RelayRef>) -> bool {
        let before = self.clone();
        match configured {
            None => self.home_relay = None,
            Some(r) => {
                match self.relays.iter_mut().find(|e| e.relay.url == r.url) {
                    Some(e) => {
                        if e.source != RelaySource::Builtin {
                            e.relay.mailbox_id = r.mailbox_id;
                        }
                    }
                    None => {
                        if self.relays.len() >= MAX_SAVED_RELAYS {
                            // Make room: drop the oldest manual relay that
                            // isn't home (simplest safe choice; documented).
                            if let Some(i) = self.relays.iter().position(|e| {
                                e.source == RelaySource::Manual
                                    && Some(&e.relay.url) != self.home_relay.as_ref()
                            }) {
                                self.relays.remove(i);
                            }
                        }
                        if self.relays.len() < MAX_SAVED_RELAYS {
                            self.relays.push(RelayEntry {
                                nickname: CUSTOM_RELAY_NICKNAME.to_owned(),
                                relay: r.clone(),
                                source: RelaySource::Manual,
                            });
                        }
                    }
                }
                self.home_relay = Some(r.url);
            }
        }
        *self != before
    }

    pub fn add(&mut self, e: RelayEntry) -> Result<(), PairError> {
        e.relay.validate()?;
        if !valid_device_name(&e.nickname) {
            return Err(PairError::BadName);
        }
        if self.relays.iter().any(|x| x.relay.url == e.relay.url) {
            return Err(PairError::Duplicate);
        }
        if self.relays.len() >= MAX_SAVED_RELAYS {
            return Err(PairError::LimitReached);
        }
        self.relays.push(e);
        Ok(())
    }

    /// Remove a saved relay that nothing uses. The built-in relay stays.
    pub fn remove(&mut self, url: &str, pairings: &PairingSet) -> Result<(), PairError> {
        let i = self
            .relays
            .iter()
            .position(|e| e.relay.url == url)
            .ok_or(PairError::NotFound)?;
        if self.relays[i].source == RelaySource::Builtin
            || self.in_use(pairings).iter().any(|u| u == url)
        {
            return Err(PairError::InUse);
        }
        self.relays.remove(i);
        Ok(())
    }

    /// Relays in use: home plus every pairing's relay, distinct.
    pub fn in_use(&self, pairings: &PairingSet) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for u in self.home_relay.iter().chain(
            pairings
                .iter()
                .filter_map(|p| p.relay.as_ref().map(|r| &r.url)),
        ) {
            if !v.contains(u) {
                v.push(u.clone());
            }
        }
        v
    }

    /// A pairing may use `url` (the 4-relays-in-use limit).
    pub fn can_use(&self, pairings: &PairingSet, url: &str) -> bool {
        let used = self.in_use(pairings);
        used.iter().any(|u| u == url) || used.len() < MAX_RELAYS_IN_USE
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u8(RELAYS_VERSION);
        match &self.home_relay {
            None => e.u8(0),
            Some(u) => {
                e.u8(1);
                e.bytes16(u.as_bytes());
            }
        }
        e.u8(self.relays.len() as u8);
        for r in &self.relays {
            e.bytes8(r.nickname.as_bytes());
            enc_relay(&mut e, &Some(r.relay.clone()));
            e.u8(r.source as u8);
        }
        std::mem::take(&mut e.0)
    }

    pub fn decode(b: &[u8]) -> Option<RelaySettings> {
        let mut d = Dec::new(b);
        if d.u8()? != RELAYS_VERSION {
            return None;
        }
        let home_relay = match d.u8()? {
            0 => None,
            1 => Some(d.str16()?),
            _ => return None,
        };
        let n = d.u8()? as usize;
        if n > MAX_SAVED_RELAYS {
            return None;
        }
        let mut relays = Vec::with_capacity(n);
        for _ in 0..n {
            let nickname = d.str8()?;
            let relay = dec_relay(&mut d)??;
            let source = RelaySource::from_u8(d.u8()?)?;
            relays.push(RelayEntry {
                nickname,
                relay,
                source,
            });
        }
        d.is_empty().then_some(RelaySettings { home_relay, relays })
    }
}
