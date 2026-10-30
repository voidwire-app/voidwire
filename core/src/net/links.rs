//! M4.2: the runtime view of a v2 pairing ("link").
//!
//! A link is everything a device needs to talk to one v2 peer: the peer's
//! certificate and per-pairing receive key, our own per-pairing receive
//! key, the pairing relay and inbox secret, and a two-member roster the
//! wire layer verifies against. The roster is synthetic: both sides build
//! it the same way from the co-signed genesis (inviter first, then the
//! joiner), so its head is identical on both ends and a v2 message's
//! `log_head` checks out the same way a legacy one does.

use crate::grouplog::{GroupReplica, Membership, SignedOp};
use crate::ids::{DeviceId, GroupId, LogHead};
use crate::mailbox::{AdvertisedInboxCaps, DeviceInboxKeys, InboxPullItem};
use crate::reject::RejectReason;

use super::mailbox_client::ThrowawaySession;
use super::NetError;
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
}

/// A phone's view of one peer: the legacy group replica of a v0.4.x PC, or
/// a v2 link (any device). Same accessors as [`GroupReplica`], so the phone
/// code paths stay shared.
#[allow(clippy::large_enum_variant)] // one per paired device; never moved in hot paths
pub(crate) enum PeerLog {
    Legacy(GroupReplica),
    Pair(Box<PairLink>),
}

impl PeerLog {
    pub fn owner(&self) -> DeviceId {
        match self {
            PeerLog::Legacy(r) => r.owner(),
            PeerLog::Pair(l) => l.peer,
        }
    }
    pub fn group(&self) -> GroupId {
        match self {
            PeerLog::Legacy(r) => r.group(),
            PeerLog::Pair(l) => l.pairing_id,
        }
    }
    pub fn head(&self) -> LogHead {
        match self {
            PeerLog::Legacy(r) => r.head(),
            PeerLog::Pair(l) => l.head(),
        }
    }
    pub fn epoch(&self) -> u64 {
        match self {
            PeerLog::Legacy(r) => r.epoch(),
            PeerLog::Pair(l) => l.epoch,
        }
    }
    pub fn roster(&self) -> &Roster {
        match self {
            PeerLog::Legacy(r) => r.roster(),
            PeerLog::Pair(l) => &l.roster,
        }
    }
    pub fn owner_cert(&self) -> Option<&DeviceCert> {
        match self {
            PeerLog::Legacy(r) => r.owner_cert(),
            PeerLog::Pair(l) => Some(&l.peer_cert),
        }
    }
    pub fn membership(&self, me: &DeviceId) -> Membership {
        match self {
            PeerLog::Legacy(r) => r.membership(me),
            PeerLog::Pair(l) if l.roster.self_id() == *me => Membership::Member,
            PeerLog::Pair(_) => Membership::NotYetAdded,
        }
    }
    /// Signed group ops (none for a v2 link: its log travels separately).
    pub fn ops(&self) -> &[SignedOp] {
        match self {
            PeerLog::Legacy(r) => r.ops(),
            PeerLog::Pair(_) => &[],
        }
    }
    /// Pushed or synced group ops. A v2 peer has no group log: ignored.
    pub fn update(&mut self, ops: Vec<SignedOp>) -> Result<bool, RejectReason> {
        match self {
            PeerLog::Legacy(r) => r.update(ops),
            PeerLog::Pair(_) => Ok(false),
        }
    }
    /// The key messages to this peer are sealed to.
    pub fn seal_key(&self) -> Option<ReceivePublicKey> {
        match self {
            PeerLog::Legacy(r) => r.owner_cert().map(|c| c.receive_key()),
            PeerLog::Pair(l) => Some(l.peer_rx),
        }
    }
    /// Our receive key for this peer (`None`: the device key).
    pub fn my_rx(&self) -> Option<ReceiveKeypair> {
        match self {
            PeerLog::Legacy(_) => None,
            PeerLog::Pair(l) => Some(l.rx()),
        }
    }
    pub fn link(&self) -> Option<&PairLink> {
        match self {
            PeerLog::Legacy(_) => None,
            PeerLog::Pair(l) => Some(l),
        }
    }
    pub fn is_pair(&self) -> bool {
        matches!(self, PeerLog::Pair(_))
    }
    /// The peer is a phone (v2 pairing with a phone certificate). A legacy
    /// group entry is always a PC.
    pub fn peer_is_mobile(&self) -> bool {
        match self {
            PeerLog::Legacy(_) => false,
            PeerLog::Pair(l) => l.peer_cert.platform().is_mobile(),
        }
    }
}

/// Where an inbox lives and the capability keys for it.
pub(crate) struct InboxTarget {
    /// The peer the inbox belongs to (`me` for a pull, the peer for a put).
    pub tag: DeviceId,
    pub relay_url: String,
    pub mailbox: DeviceId,
    pub keys: DeviceInboxKeys,
}

impl PairLink {
    /// The pairing relay: its own URL and mailbox, or the home relay when
    /// the pairing names none. `None` when there is no usable relay.
    pub fn place(
        &self,
        home_url: Option<&str>,
        home_mailbox: Option<(DeviceId, bool)>,
    ) -> Option<(String, DeviceId)> {
        let (url, mailbox, explicit) = match &self.relay {
            Some(r) => (
                r.url.clone(),
                r.mailbox_id
                    .unwrap_or_else(super::mailbox_client::default_mailbox_device_id),
                r.mailbox_id.is_some(),
            ),
            None => {
                let (mb, explicit) = home_mailbox?;
                (home_url?.to_owned(), mb, explicit)
            }
        };
        if url.is_empty() || url == "off" {
            return None;
        }
        if !super::mailbox_client::should_dial_mailbox_in_current_env(&mailbox, explicit) {
            return None;
        }
        Some((url, mailbox))
    }

    /// Our own inbox on this pairing (`me` = our device id).
    pub fn my_inbox(
        &self,
        me: &DeviceId,
        home_url: Option<&str>,
        home_mailbox: Option<(DeviceId, bool)>,
    ) -> Option<InboxTarget> {
        let (relay_url, mailbox) = self.place(home_url, home_mailbox)?;
        let keys = self.gs_e.derive_device_inbox_keys(
            &self.pairing_id,
            self.epoch,
            me,
            &self.rx().public(),
        );
        Some(InboxTarget {
            tag: self.peer,
            relay_url,
            mailbox,
            keys,
        })
    }

    /// Test harness: (our inbox keys, the peer's inbox keys), no relay.
    #[cfg(feature = "test-util")]
    pub fn inbox_keys_for_tests(&self, me: &DeviceId) -> (DeviceInboxKeys, DeviceInboxKeys) {
        let mine = self.gs_e.derive_device_inbox_keys(
            &self.pairing_id,
            self.epoch,
            me,
            &self.rx().public(),
        );
        let theirs = self.gs_e.derive_device_inbox_keys(
            &self.pairing_id,
            self.epoch,
            &self.peer,
            &self.peer_rx,
        );
        (mine, theirs)
    }

    /// Test harness: what an inbox key derivation takes on this pairing
    /// (pairing id, epoch, our receive key, the peer's, `gs_e`).
    #[cfg(feature = "test-util")]
    pub fn inbox_inputs_for_tests(&self) -> super::PairingInboxInputs {
        super::PairingInboxInputs {
            pairing_id: self.pairing_id,
            epoch: self.epoch,
            my_rx: self.rx().public(),
            peer_rx: self.peer_rx,
            gs_e: self.gs_e.clone(),
        }
    }

    /// The peer's inbox on this pairing.
    pub fn peer_inbox(
        &self,
        home_url: Option<&str>,
        home_mailbox: Option<(DeviceId, bool)>,
    ) -> Option<InboxTarget> {
        let (relay_url, mailbox) = self.place(home_url, home_mailbox)?;
        let keys = self.gs_e.derive_device_inbox_keys(
            &self.pairing_id,
            self.epoch,
            &self.peer,
            &self.peer_rx,
        );
        Some(InboxTarget {
            tag: self.peer,
            relay_url,
            mailbox,
            keys,
        })
    }
}

/// Outcome of one batched pull.
#[derive(Default)]
pub(crate) struct PullOutcome {
    pub last_session: Option<DeviceId>,
    pub caps: Option<AdvertisedInboxCaps>,
    pub last_err: Option<NetError>,
}

/// Pull every inbox in `targets` with one throwaway session per relay
/// (M4.2 batched pull), hand each item to `on_item(tag, item, advertised caps)` and ack all
/// pulled items on the same session. Event-driven callers only: nothing
/// here schedules a retry.
pub(crate) async fn pull_batched<F>(targets: Vec<InboxTarget>, mut on_item: F) -> PullOutcome
where
    F: FnMut(&DeviceId, &InboxPullItem, Option<AdvertisedInboxCaps>),
{
    let mut by_relay: Vec<((String, DeviceId), Vec<InboxTarget>)> = Vec::new();
    for t in targets {
        let key = (t.relay_url.clone(), t.mailbox);
        match by_relay.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(t),
            None => by_relay.push((key, vec![t])),
        }
    }
    let mut out = PullOutcome::default();
    for ((url, mailbox), group) in by_relay {
        let sess = match ThrowawaySession::connect(&mailbox, &url).await {
            Ok(s) => s,
            Err(e) => {
                out.last_err = Some(e);
                continue;
            }
        };
        out.last_session = Some(sess.ephemeral_id);
        for t in &group {
            let (items, caps) = match sess.pull_device_inbox_with_caps(&t.keys).await {
                Ok(x) => x,
                Err(e) => {
                    out.last_err = Some(e);
                    continue;
                }
            };
            if caps.is_some() {
                out.caps = caps;
            }
            if items.is_empty() {
                continue;
            }
            let ids: Vec<[u8; 16]> = items.iter().map(|i| i.item_id).collect();
            for item in &items {
                on_item(&t.tag, item, caps);
            }
            if let Err(e) = sess.ack_device_inbox(&t.keys, &ids).await {
                out.last_err = Some(e);
            }
        }
        sess.close().await;
    }
    out
}

/// Put one sealed envelope into `target` over a fresh throwaway session.
pub(crate) async fn put_one(
    target: &InboxTarget,
    item_id: [u8; 16],
    envelope: Vec<u8>,
) -> Result<(DeviceId, Option<u64>), NetError> {
    super::mailbox_client::put_device_inbox_item(
        &target.mailbox,
        &target.relay_url,
        &target.keys,
        item_id,
        envelope,
    )
    .await
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
