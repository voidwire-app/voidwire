//! Pairing records (M4 §1.2), the pairing set and relay settings.

use super::codec::{Dec, Enc};
use super::log::{dec_relay, enc_relay, Caps, PairError, PairLog, PairingKind, RelayRef};
use crate::ids::{DeviceId, GroupId};
use crate::keys::{valid_device_name, DeviceCert, Platform, ReceiveKeypair, ReceivePublicKey};
use crate::mailbox::{open_secret_from_state, seal_secret_for_state, EpochSecret};
use zeroize::Zeroizing;

/// At most this many pairings per device.
pub const MAX_PAIRINGS: usize = 16;
/// At most this many saved relays.
pub const MAX_SAVED_RELAYS: usize = 8;
/// At most this many relays in use at once (home + pairing relays).
pub const MAX_RELAYS_IN_USE: usize = 4;

/// v2: every field a finished pairing needs is required (no back-compat).
const RECORD_VERSION: u8 = 2;
/// Records from an older Voidwire: dropped on load, flagged for the user.
const OLD_RECORD_VERSION: u8 = 1;
const SET_VERSION: u8 = 1;
const RELAYS_VERSION: u8 = 1;
const SEALED: usize = crate::mailbox::SEALED_STATE_SECRET_LEN;

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

/// One pairing: a two-device group with its own keys, relay and inbox. The
/// peer's cert and receive key live in the co-signed `log`.
pub struct Pairing {
    pub pairing_id: GroupId,
    pub kind: PairingKind,
    pub peer: PeerInfo,
    /// Our receive key for this pairing.
    pub my_rx: ReceiveKeypair,
    pub relay: Option<RelayRef>,
    pub epoch: u64,
    /// Epoch secrets.
    pub gs_e: EpochSecret,
    pub prev_gs_e: Option<EpochSecret>,
    pub log: PairLog,
    pub peer_caps: Caps,
    /// Local-only nickname.
    pub label: Option<String>,
}

impl std::fmt::Debug for Pairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pairing")
            .field("pairing_id", &self.pairing_id)
            .field("peer", &self.peer)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl Clone for Pairing {
    fn clone(&self) -> Self {
        Pairing {
            pairing_id: self.pairing_id,
            kind: self.kind,
            peer: self.peer.clone(),
            my_rx: ReceiveKeypair::from_secret_bytes(&self.my_rx.secret_bytes())
                .expect("valid stored key"),
            relay: self.relay.clone(),
            epoch: self.epoch,
            gs_e: self.gs_e.clone(),
            prev_gs_e: self.prev_gs_e.clone(),
            log: self.log.clone(),
            peer_caps: self.peer_caps,
            label: self.label.clone(),
        }
    }
}

/// How one stored record decoded.
enum Decoded {
    Pairing(Box<Pairing>),
    /// A record from an older Voidwire (record v1): dropped, the user pairs
    /// again.
    Old,
}

impl Pairing {
    /// The v2 protocol is used for this pairing only once both devices
    /// co-signed a `Caps` op saying they speak it (version gating).
    pub fn v2_active(&self) -> bool {
        self.log.caps().is_some_and(|c| c.supports_pairwise())
    }

    pub fn display_name(&self) -> &str {
        self.label.as_deref().unwrap_or(&self.peer.name)
    }

    /// The peer's device cert (from the co-signed log).
    pub fn peer_cert(&self) -> Option<&DeviceCert> {
        self.log.cert_of(&self.peer.id)
    }

    /// The peer's receive key for this pairing (from the co-signed log).
    pub fn peer_rx(&self) -> Option<ReceivePublicKey> {
        self.log.rx_of(&self.peer.id)
    }

    fn encode(&self, seal_key: &[u8; 32], e: &mut Enc) {
        e.u8(RECORD_VERSION);
        e.raw(&self.pairing_id.0);
        e.u8(self.kind as u8);
        e.raw(self.peer.id.as_bytes());
        e.bytes8(self.peer.name.as_bytes());
        e.u8(self.peer.platform as u8);
        e.raw(&seal_secret_for_state(seal_key, &self.my_rx.secret_bytes()));
        enc_relay(e, &self.relay);
        e.u64(self.epoch);
        e.raw(&seal_secret_for_state(seal_key, self.gs_e.as_bytes()));
        match &self.prev_gs_e {
            None => e.u8(0),
            Some(s) => {
                e.u8(1);
                e.raw(&seal_secret_for_state(seal_key, s.as_bytes()));
            }
        }
        e.bytes32(&self.log.encode());
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

    /// `None`: damaged (the whole set fails closed).
    fn decode(seal_key: &[u8; 32], d: &mut Dec<'_>) -> Option<Decoded> {
        match d.u8()? {
            RECORD_VERSION => {}
            OLD_RECORD_VERSION => {
                d.take(d.remaining())?;
                return Some(Decoded::Old);
            }
            _ => return None,
        }
        let pairing_id = GroupId(d.arr::<32>()?);
        let kind = PairingKind::from_u8(d.u8()?)?;
        let id = DeviceId::from_bytes(d.arr::<32>()?).ok()?;
        let name = d.str8()?;
        let platform = Platform::from_u8(d.u8()?);
        let raw = open_secret_from_state(seal_key, &d.arr::<SEALED>()?)?;
        let my_rx = ReceiveKeypair::from_secret_bytes(&raw)?;
        let relay = dec_relay(d)?;
        let epoch = d.u64()?;
        let raw = open_secret_from_state(seal_key, &d.arr::<SEALED>()?)?;
        let gs_e = EpochSecret::from_bytes(*raw);
        let prev_gs_e = match d.u8()? {
            0 => None,
            1 => {
                let raw = open_secret_from_state(seal_key, &d.arr::<SEALED>()?)?;
                Some(EpochSecret::from_bytes(*raw))
            }
            _ => return None,
        };
        let log = PairLog::decode(d.bytes32()?).ok()?;
        if log.pairing() != pairing_id || !log.members().contains(&id) || log.cert_of(&id).is_none()
        {
            return None;
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
        Some(Decoded::Pairing(Box::new(Pairing {
            pairing_id,
            kind,
            peer: PeerInfo { id, name, platform },
            my_rx,
            relay,
            epoch,
            gs_e,
            prev_gs_e,
            log,
            peer_caps,
            label,
        })))
    }
}

/// All pairings of this device.
#[derive(Debug, Clone, Default)]
pub struct PairingSet {
    items: Vec<Pairing>,
    /// Records from an older Voidwire were dropped when this set loaded.
    old_dropped: bool,
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
    /// Pairings from an older Voidwire were dropped when this set loaded
    /// ("This pairing is from an older Voidwire. Pair again.").
    pub fn old_dropped(&self) -> bool {
        self.old_dropped
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
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Pairing> {
        self.items.iter_mut()
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
        let mut old_dropped = false;
        for _ in 0..n {
            let mut pd = Dec::new(d.bytes32()?);
            let rec = Pairing::decode(seal_key, &mut pd)?;
            if !pd.is_empty() {
                return None;
            }
            match rec {
                Decoded::Old => old_dropped = true,
                Decoded::Pairing(p) => {
                    if items.iter().any(|x: &Pairing| x.pairing_id == p.pairing_id) {
                        return None;
                    }
                    items.push(*p);
                }
            }
        }
        d.is_empty().then_some(PairingSet { items, old_dropped })
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
    /// The relay's link said "no UDP 7842" (`q=0`): skip QUIC address
    /// discovery there (a relay behind an HTTPS tunnel).
    pub no_udp: bool,
    /// The relay's access token (`t=` in its link), sent to the relay as
    /// its auth token. Only relays that restrict access have one.
    pub token: Option<RelayToken>,
}

/// Set on the stored source byte when [`RelayEntry::no_udp`].
const NO_UDP_BIT: u8 = 0x80;
/// Set on the stored source byte when a [`RelayToken`] follows.
const TOKEN_BIT: u8 = 0x40;

/// A relay access token: 16-128 URL-safe characters (`A-Z a-z 0-9 - . _ ~`).
/// A secret: its `Debug` is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayToken(String);

impl RelayToken {
    pub const MIN_LEN: usize = 16;
    pub const MAX_LEN: usize = 128;

    pub fn new(s: &str) -> Option<RelayToken> {
        let ok = (Self::MIN_LEN..=Self::MAX_LEN).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b));
        ok.then(|| RelayToken(s.to_owned()))
    }

    /// A fresh random token (256 bits, 64 hex characters).
    pub fn generate() -> RelayToken {
        use rand_core::RngCore;
        let mut b = zeroize::Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(&mut *b);
        RelayToken(crate::hex::encode(&*b))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for RelayToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RelayToken(..)")
    }
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
                no_udp: false,
                token: None,
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
                                no_udp: false,
                                token: None,
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
            let mut b = r.source as u8;
            if r.no_udp {
                b |= NO_UDP_BIT;
            }
            if r.token.is_some() {
                b |= TOKEN_BIT;
            }
            e.u8(b);
            if let Some(t) = &r.token {
                e.bytes8(t.as_str().as_bytes());
            }
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
            let b = d.u8()?;
            let source = RelaySource::from_u8(b & !(NO_UDP_BIT | TOKEN_BIT))?;
            let token = if b & TOKEN_BIT != 0 {
                Some(RelayToken::new(&d.str8()?)?)
            } else {
                None
            };
            relays.push(RelayEntry {
                nickname,
                relay,
                source,
                no_udp: b & NO_UDP_BIT != 0,
                token,
            });
        }
        d.is_empty().then_some(RelaySettings { home_relay, relays })
    }
}

#[cfg(test)]
mod old_record_tests {
    use super::*;

    /// A v1 record (an older Voidwire) is dropped and flagged; the rest of
    /// the set loads. An unknown record version still fails closed.
    #[test]
    fn v1_pairing_record_dropped_and_flagged() {
        let seal = [3u8; 32];
        let (a, b) = (
            crate::keys::DeviceKeypair::generate(),
            crate::keys::DeviceKeypair::generate(),
        );
        let cert = |k: &crate::keys::DeviceKeypair, n: &str, p: Platform| {
            let rx = ReceiveKeypair::generate().public();
            DeviceCert::issue(k, rx, n, p, crate::time::UnixMillis(1)).unwrap()
        };
        let (ca, cb) = (
            cert(&a, "A", Platform::Windows),
            cert(&b, "B", Platform::Android),
        );
        let (keep, _) = super::super::v2::pair_for_tests(&a, ca, &b, cb, None);
        let mut rec = Enc::new();
        keep.encode(&seal, &mut rec);
        let mut old = rec.0.clone();
        old[0] = OLD_RECORD_VERSION;
        let set_of = |recs: &[&[u8]]| {
            let mut e = Enc::new();
            e.u8(SET_VERSION);
            e.u16(recs.len() as u16);
            for r in recs {
                e.bytes32(r);
            }
            std::mem::take(&mut e.0)
        };
        let set = PairingSet::decode(&seal, &set_of(&[&old, &rec.0])).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.get(&keep.pairing_id).is_some());
        assert!(set.old_dropped());
        let clean = PairingSet::decode(&seal, &set_of(&[&rec.0])).unwrap();
        assert!(!clean.old_dropped());
        let mut bad = rec.0.clone();
        bad[0] = 3;
        assert!(PairingSet::decode(&seal, &set_of(&[&bad])).is_none());
    }
}
