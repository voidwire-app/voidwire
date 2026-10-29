//! M4.2: the runtime view of a v2 pairing ("link").
//!
//! A link is everything a device needs to talk to one v2 peer: the peer's
//! certificate and per-pairing receive key, our own per-pairing receive
//! key, the pairing relay and inbox secret, and a two-member roster the
//! wire layer verifies against. The roster is synthetic: both sides build
//! it the same way from the co-signed genesis (inviter first, then the
//! joiner), so its head is identical on both ends and a v2 message's
//! `log_head` checks out the same way a legacy one does.

use crate::ids::{DeviceId, GroupId, LogHead};
use crate::keys::{DeviceCert, ReceiveKeypair, ReceivePublicKey};
use crate::mailbox::EpochSecret;
use crate::pairwise::{MyRx, Pairing, RelayRef};
use crate::roster::{OpKind, Roster};

pub(crate) struct PairLink {
    pub pairing_id: GroupId,
    pub peer: DeviceId,
    pub peer_cert: DeviceCert,
    pub peer_rx: ReceivePublicKey,
    my_rx: zeroize::Zeroizing<[u8; 32]>,
    pub roster: Roster,
    pub relay: Option<RelayRef>,
    pub epoch: u64,
    pub gs_e: EpochSecret,
}

impl std::fmt::Debug for PairLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairLink")
            .field("pairing_id", &self.pairing_id)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl PairLink {
    /// The link for a co-signed v2 pairing `me` is in (`None` for legacy,
    /// half-built or unpaired ones).
    pub fn from_pairing(me: &DeviceId, p: &Pairing) -> Option<PairLink> {
        if !p.v2_active() {
            return None;
        }
        let log = p.log.as_ref()?;
        if log.is_unpaired() {
            return None;
        }
        let MyRx::Own(rx) = &p.my_rx else {
            return None;
        };
        let [inviter, joiner] = log.members();
        if inviter != *me && joiner != *me {
            return None;
        }
        let inviter_cert = log.cert_of(&inviter)?.clone();
        let joiner_cert = log.cert_of(&joiner)?.clone();
        let mut roster = Roster::genesis_with_cert(p.pairing_id, inviter_cert);
        let jname = joiner_cert.name().to_owned();
        if !roster.apply(OpKind::AddDevice, joiner, jname, Some(joiner_cert)) {
            return None;
        }
        roster.set_self_id(*me);
        let peer = log.peer_of(me)?;
        Some(PairLink {
            pairing_id: p.pairing_id,
            peer,
            peer_cert: log.cert_of(&peer)?.clone(),
            peer_rx: log.rx_of(&peer)?,
            my_rx: rx.secret_bytes(),
            roster,
            relay: p.relay.clone(),
            epoch: p.epoch,
            gs_e: p.gs_e.clone()?,
        })
    }

    pub fn rx(&self) -> ReceiveKeypair {
        ReceiveKeypair::from_secret_bytes(&self.my_rx).expect("checked when the pairing was made")
    }

    pub fn head(&self) -> LogHead {
        self.roster.head()
    }

    pub fn name(&self) -> String {
        self.peer_cert.name().to_owned()
    }

    /// The relay URL this pairing's inbox lives on.
    pub fn relay_url(&self) -> Option<&str> {
        self.relay.as_ref().map(|r| r.url.as_str())
    }
}

/// Live v2 links of a pairing set, keyed by peer.
pub(crate) fn links_of(
    me: &DeviceId,
    set: &crate::pairwise::PairingSet,
) -> std::collections::HashMap<DeviceId, PairLink> {
    set.iter()
        .filter_map(|p| PairLink::from_pairing(me, p))
        .map(|l| (l.peer, l))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{DeviceKeypair, Platform};
    use crate::time::UnixMillis;

    fn ident(name: &str) -> (DeviceKeypair, DeviceCert) {
        let k = DeviceKeypair::generate();
        let rx = ReceiveKeypair::generate();
        let c = DeviceCert::issue(&k, rx.public(), name, Platform::Windows, UnixMillis(1)).unwrap();
        (k, c)
    }

    #[test]
    fn both_ends_build_the_same_roster_head() {
        let (a, ac) = ident("A");
        let (b, bc) = ident("B");
        let (pa, pb) = crate::pairwise::v2::pair_for_tests(&a, ac, &b, bc, None);
        let la = PairLink::from_pairing(&a.device_id(), &pa).unwrap();
        let lb = PairLink::from_pairing(&b.device_id(), &pb).unwrap();
        assert_eq!(la.head(), lb.head());
        assert_eq!(la.peer, b.device_id());
        assert_eq!(lb.peer, a.device_id());
        assert_eq!(la.roster.self_id(), a.device_id());
        assert_eq!(lb.rx().public(), la.peer_rx);
        assert_eq!(la.rx().public(), lb.peer_rx);
    }

    #[test]
    fn legacy_and_unpaired_pairings_are_not_links() {
        let (a, ac) = ident("A");
        let (b, bc) = ident("B");
        let (mut pa, _) = crate::pairwise::v2::pair_for_tests(&a, ac, &b, bc, None);
        pa.log.as_mut().unwrap().unpair(&a, UnixMillis(5)).unwrap();
        assert!(PairLink::from_pairing(&a.device_id(), &pa).is_none());
    }
}
