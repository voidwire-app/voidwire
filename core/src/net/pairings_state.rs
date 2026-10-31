//! The PAIRINGS state section: each device's [`PairingSet`], relay
//! settings, unsent unpair notices and replay marks.

use crate::ids::DeviceId;
use crate::pairwise::{PairingSet, RelayRef, RelaySettings};
use crate::replay::HighWater;

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

pub(crate) const SECTION_VERSION: u8 = 1;

/// Body of the PAIRINGS state section.
pub(crate) fn encode_section(
    pairings: &PairingSet,
    relays: &RelaySettings,
    outbox: &super::outbox::Outbox,
    marks: &ReplayMarks,
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
    if !outbox.is_empty() || !marks.is_empty() {
        let mut w = super::state::Writer(Vec::new());
        outbox.encode(&mut w);
        out.extend_from_slice(&(w.0.len() as u32).to_be_bytes());
        out.extend_from_slice(&w.0);
    }
    // Each pairing's replay-file high-water mark (L2), when any.
    if !marks.is_empty() {
        let mut w = super::state::Writer(Vec::new());
        w.u16(marks.len() as u16);
        for (id, hw) in marks {
            w.raw(&id.0);
            w.raw(&hw.encode());
        }
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

/// Per pairing: the high-water mark of its replay file (`seen-<id>.bin`).
pub(crate) type ReplayMarks = std::collections::BTreeMap<crate::ids::GroupId, HighWater>;

pub(crate) type Section = (
    PairingSet,
    RelaySettings,
    super::outbox::Outbox,
    ReplayMarks,
);

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
    super::relays::remember_relay_opts(&s);
    let mut o = super::outbox::Outbox::default();
    if !r.is_empty() {
        let mut or = super::state::Reader::new(r.bytes32()?);
        o = super::outbox::Outbox::decode(&mut or)?;
        if !or.is_empty() {
            return None;
        }
    }
    let mut marks = ReplayMarks::new();
    if !r.is_empty() {
        let mut mr = super::state::Reader::new(r.bytes32()?);
        for _ in 0..mr.u16()? {
            let id = crate::ids::GroupId(mr.take(32)?.try_into().ok()?);
            let hw = HighWater::decode(mr.take(HighWater::ENCODED_LEN)?)?;
            marks.insert(id, hw);
        }
        if !mr.is_empty() {
            return None;
        }
    }
    r.is_empty().then_some((p, s, o, marks))
}

/// A pairing as the apps and tests see it (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingSummary {
    pub pairing_id: crate::ids::GroupId,
    pub peer: DeviceId,
    pub peer_name: String,
    pub relay_url: Option<String>,
}

pub(crate) fn summaries(p: &PairingSet) -> Vec<PairingSummary> {
    p.iter()
        .map(|x| PairingSummary {
            pairing_id: x.pairing_id,
            peer: x.peer.id,
            peer_name: x.display_name().to_owned(),
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
        let none = ReplayMarks::new();
        assert!(decode_section(&encode_section(&p, &r, &o, &none, &key), &key).is_some());
        o.push(super::super::outbox::OutboxItem {
            relay_url: "https://relay.example".into(),
            mailbox: crate::keys::DeviceKeypair::generate().device_id(),
            put: vec![3; 90],
            attempts: 2,
            next_try: crate::time::UnixMillis(9),
        });
        let mut marks = ReplayMarks::new();
        marks.insert(
            crate::ids::GroupId([5; 32]),
            HighWater::decode(&[9u8; HighWater::ENCODED_LEN]).unwrap(),
        );
        let only_marks = encode_section(&p, &r, &Default::default(), &marks, &key);
        let back = decode_section(&only_marks, &key).unwrap();
        assert!(back.2.is_empty());
        assert_eq!(back.3, marks);
        let body = encode_section(&p, &r, &o, &marks, &key);
        let back = decode_section(&body, &key).unwrap();
        assert_eq!((back.2, back.3), (o, marks));
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
