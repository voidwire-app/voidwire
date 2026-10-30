//! M4.1: the pairwise view of v0.4.x state (state format v2).
//!
//! v0.4.x groups are hub-shaped: one PC owns a group with its phones. In
//! state v2 every device also keeps a [`PairingSet`]: one pairing per peer,
//! split out of the legacy group with no re-pair (both sides derive the
//! same pairing id). The legacy group keeps working for the wire protocol
//! and its secrets are never copied. The split is re-derived from the
//! legacy state on every save, so the two never disagree.

use crate::ids::DeviceId;
use crate::keys::Platform;
use crate::pairwise::{LegacyLink, PairingSet, PeerInfo, RelayRef, RelaySettings};
use crate::roster::Roster;

/// The built-in public relay.
pub(crate) fn builtin_relay() -> RelayRef {
    RelayRef {
        url: super::DEFAULT_RELAY_URL.to_owned(),
        mailbox_id: None,
    }
}

/// A configured relay as a [`RelayRef`] (`None` when relays are off or the
/// URL doesn't validate).
pub(crate) fn relay_ref(url: Option<&str>, mailbox: Option<DeviceId>) -> Option<RelayRef> {
    let url = url?;
    let r = RelayRef {
        url: url.trim_end_matches('/').to_owned(),
        mailbox_id: mailbox.filter(|m| *m != super::mailbox_client::default_mailbox_device_id()),
    };
    r.validate().ok().map(|_| r)
}

/// PC: one link per active peer of the PC-hosted group.
pub(crate) fn pc_links(
    roster: &Roster,
    me: &DeviceId,
    relay: Option<RelayRef>,
    epoch: u64,
) -> Vec<LegacyLink> {
    roster
        .active_devices()
        .filter(|d| d.id != *me)
        .map(|d| LegacyLink {
            group: roster.group(),
            peer: PeerInfo {
                id: d.id,
                name: d.name.clone(),
                platform: d
                    .cert
                    .as_ref()
                    .map(|c| c.platform())
                    .unwrap_or(Platform::Unknown),
            },
            peer_cert: d.cert.clone(),
            relay: relay.clone(),
            epoch,
        })
        .collect()
}

/// Keep pairings and relay settings in step with the legacy state.
pub(crate) fn sync(
    pairings: &mut PairingSet,
    relays: &mut RelaySettings,
    me: &DeviceId,
    links: &[LegacyLink],
    configured: Option<RelayRef>,
) {
    pairings.sync_legacy(me, links);
    relays.sync_home(configured);
}

pub(crate) const SECTION_VERSION: u8 = 1;

/// Body of the PAIRINGS state section.
pub(crate) fn encode_section(
    pairings: &PairingSet,
    relays: &RelaySettings,
    outbox: &super::outbox::Outbox,
    seal_key: &[u8; 32],
) -> zeroize::Zeroizing<Vec<u8>> {
    let p = pairings.encode(seal_key);
    let r = relays.encode();
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(p.len() + r.len() + 9));
    out.push(SECTION_VERSION);
    out.extend_from_slice(&(p.len() as u32).to_be_bytes());
    out.extend_from_slice(&p);
    out.extend_from_slice(&(r.len() as u32).to_be_bytes());
    out.extend_from_slice(&r);
    // M4.3: unsent unpair notices, only when there are any (so a state
    // without them stays readable by 0.6.x).
    if !outbox.is_empty() {
        let mut w = super::state::Writer(Vec::new());
        outbox.encode(&mut w);
        out.extend_from_slice(&(w.0.len() as u32).to_be_bytes());
        out.extend_from_slice(&w.0);
    }
    let tag = section_mac(seal_key, &out);
    out.extend_from_slice(&tag);
    out
}

/// Keyed BLAKE3 over the section, so damage to the public fields (peer ids,
/// names, relays) fails closed too, not only damage to the sealed secrets.
fn section_mac(seal_key: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let key = zeroize::Zeroizing::new(blake3::derive_key(
        "voidwire 2026 state v2 pairings section mac",
        seal_key,
    ));
    *blake3::keyed_hash(&key, body).as_bytes()
}

pub(crate) type Section = (PairingSet, RelaySettings, super::outbox::Outbox);

pub(crate) fn decode_section(b: &[u8], seal_key: &[u8; 32]) -> Option<Section> {
    let (b, tag) = b.split_at(b.len().checked_sub(32)?);
    let want = section_mac(seal_key, b);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(&want[..], tag)) {
        return None;
    }
    let mut r = super::state::Reader::new(b);
    if r.u8()? != SECTION_VERSION {
        return None;
    }
    let p = PairingSet::decode(seal_key, r.bytes32()?)?;
    let s = RelaySettings::decode(r.bytes32()?)?;
    super::relays::remember_no_udp(&s);
    let mut o = super::outbox::Outbox::default();
    if !r.is_empty() {
        let mut or = super::state::Reader::new(r.bytes32()?);
        o = super::outbox::Outbox::decode(&mut or)?;
        if !or.is_empty() {
            return None;
        }
    }
    r.is_empty().then_some((p, s, o))
}

/// A pairing as the apps and tests see it (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingSummary {
    pub pairing_id: crate::ids::GroupId,
    pub peer: DeviceId,
    pub peer_name: String,
    /// Split out of a v0.4.x group (still uses the legacy wire path).
    pub legacy: bool,
    pub relay_url: Option<String>,
}

pub(crate) fn summaries(p: &PairingSet) -> Vec<PairingSummary> {
    p.iter()
        .map(|x| PairingSummary {
            pairing_id: x.pairing_id,
            peer: x.peer.id,
            peer_name: x.display_name().to_owned(),
            legacy: matches!(x.origin, crate::pairwise::PairingOrigin::LegacyHub { .. }),
            relay_url: x.relay.as_ref().map(|r| r.url.clone()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_round_trips_and_any_flipped_byte_fails_closed() {
        let key = [7u8; 32];
        let p = PairingSet::new();
        let r = RelaySettings::new(builtin_relay());
        let mut o = super::super::outbox::Outbox::default();
        assert!(decode_section(&encode_section(&p, &r, &o, &key), &key).is_some());
        o.push(super::super::outbox::OutboxItem {
            relay_url: "https://relay.example".into(),
            mailbox: crate::keys::DeviceKeypair::generate().device_id(),
            put: vec![3; 90],
            attempts: 2,
            next_try: crate::time::UnixMillis(9),
        });
        let body = encode_section(&p, &r, &o, &key);
        assert_eq!(decode_section(&body, &key).unwrap().2, o);
        assert!(decode_section(&body, &[8u8; 32]).is_none());
        for i in 0..body.len() {
            let mut b = body.to_vec();
            b[i] ^= 1;
            assert!(decode_section(&b, &key).is_none(), "byte {i}");
        }
        assert!(decode_section(&body[..body.len() - 1], &key).is_none());
        assert!(decode_section(&[], &key).is_none());
    }
}
