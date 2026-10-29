//! M4.2: creating a v2 pairing (genesis + co-signed `Caps`) and the record
//! each side keeps.
//!
//! Two round trips, inviter first:
//!
//! 1. inviter: [`invite`] → genesis (inviter-signed) and `gs_0` wrapped to
//!    the joiner's new per-pairing receive key;
//! 2. joiner: [`join`] → co-signed genesis and a `Caps(V2)` proposal;
//! 3. inviter: [`finish_invite`] → its log and the co-signed `Caps`;
//! 4. joiner: [`finish_join`] → its log.
//!
//! Both sides then hold a [`Pairing`] with `origin = V2` and a co-signed
//! `Caps(V2)`, so [`Pairing::v2_active`] holds (version gating).

use super::log::{Caps, PairBody, PairError, PairLog, PairOp, PairingKind, Proposed, RelayRef};
use super::record::{MyRx, Pairing, PairingOrigin, PeerInfo};
use crate::ids::{DeviceId, GroupId};
use crate::keys::{DeviceCert, DeviceKeypair, ReceiveKeypair, ReceivePublicKey};
use crate::mailbox::{EpochSecret, WRAPPED_EPOCH_SECRET_LEN};
use crate::time::UnixMillis;

/// The inviter's half-open pairing (kept in RAM until [`finish_invite`]).
pub struct Invite {
    pub pairing_id: GroupId,
    pub genesis: PairOp,
    pub my_rx: ReceiveKeypair,
    pub gs: EpochSecret,
    pub wrapped_gs: [u8; WRAPPED_EPOCH_SECRET_LEN],
}

impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field("pairing_id", &self.pairing_id)
            .finish_non_exhaustive()
    }
}

fn random_pairing_id() -> GroupId {
    let mut b = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    GroupId(b)
}

/// Inviter: sign a genesis for `joiner` and wrap a fresh `gs_0` to the
/// joiner's per-pairing receive key.
pub fn invite(
    me: &DeviceKeypair,
    my_cert: DeviceCert,
    joiner_cert: DeviceCert,
    joiner_rx: ReceivePublicKey,
    relay: Option<RelayRef>,
    ts: UnixMillis,
) -> Result<Invite, PairError> {
    if my_cert.device() != me.device_id() || joiner_cert.device() == me.device_id() {
        return Err(PairError::BadGenesis);
    }
    let pairing_id = random_pairing_id();
    let my_rx = ReceiveKeypair::generate();
    let joiner = joiner_cert.device();
    let genesis = PairLog::propose_genesis(
        me,
        pairing_id,
        ts,
        PairBody::Genesis {
            kind: PairingKind::Own,
            inviter: my_cert,
            joiner: joiner_cert,
            inviter_rx: my_rx.public(),
            joiner_rx,
            relay,
        },
    )?;
    let gs = EpochSecret::generate();
    let wrapped = crate::mailbox::wrap_epoch_secret(&joiner, &joiner_rx, &pairing_id, 0, &gs)
        .map_err(|_| PairError::Malformed)?;
    Ok(Invite {
        pairing_id,
        genesis,
        my_rx,
        gs,
        wrapped_gs: wrapped.sealed,
    })
}

/// Joiner: check and co-sign the genesis, open `gs_0`, propose `Caps(V2)`.
/// Returns the log (with the proposal pending), the co-signed genesis, the
/// proposal and `gs_0`.
pub fn join(
    me: &DeviceKeypair,
    my_rx: &ReceiveKeypair,
    genesis: PairOp,
    wrapped_gs: &[u8],
    ts: UnixMillis,
) -> Result<(PairLog, PairOp, PairOp, EpochSecret), PairError> {
    let me_id = me.device_id();
    let pairing = genesis.pairing();
    let PairBody::Genesis { joiner_rx, .. } = genesis.body() else {
        return Err(PairError::BadGenesis);
    };
    if *joiner_rx != my_rx.public() {
        return Err(PairError::BadGenesis);
    }
    let gs = crate::mailbox::unwrap_epoch_secret(my_rx, &me_id, &pairing, 0, wrapped_gs)
        .map_err(|_| PairError::BadSignature)?;
    let (mut log, cosigned) = PairLog::accept_genesis(me, genesis)?;
    let caps = match log.propose(me, ts, PairBody::Caps(Caps::V2))? {
        Proposed::NeedsCosign(op) => op,
        Proposed::Applied(_) => return Err(PairError::Malformed),
    };
    Ok((log, cosigned, caps, gs))
}

/// Inviter: start the log from the co-signed genesis (it must be ours) and
/// co-sign the joiner's `Caps(V2)`.
pub fn finish_invite(
    me: &DeviceKeypair,
    inv: &Invite,
    cosigned_genesis: PairOp,
    caps: PairOp,
) -> Result<(PairLog, PairOp), PairError> {
    if cosigned_genesis.hash() != inv.genesis.hash() {
        return Err(PairError::BadGenesis);
    }
    let mut log = PairLog::from_genesis(cosigned_genesis)?;
    if !matches!(caps.body(), PairBody::Caps(c) if c.supports_pairwise()) {
        return Err(PairError::Malformed);
    }
    match log.receive(me, caps)? {
        super::log::Received::Cosigned { op, .. } => Ok((log, op)),
        _ => Err(PairError::Malformed),
    }
}

/// Joiner: apply our `Caps` proposal, back with the inviter's signature.
pub fn finish_join(
    me: &DeviceKeypair,
    log: &mut PairLog,
    caps_cosigned: PairOp,
) -> Result<(), PairError> {
    if caps_cosigned.author() != me.device_id() {
        return Err(PairError::Malformed);
    }
    match log.receive(me, caps_cosigned)? {
        super::log::Received::Applied { .. } => {}
        _ => return Err(PairError::Malformed),
    }
    if log.caps().is_some_and(|c| c.supports_pairwise()) {
        Ok(())
    } else {
        Err(PairError::Malformed)
    }
}

/// The record `me` keeps for a finished v2 pairing.
pub fn record(
    me: &DeviceId,
    log: PairLog,
    my_rx: ReceiveKeypair,
    gs: EpochSecret,
) -> Result<Pairing, PairError> {
    let peer = log.peer_of(me).ok_or(PairError::NotMember)?;
    let peer_cert = log.cert_of(&peer).cloned().ok_or(PairError::NotMember)?;
    if log.rx_of(me) != Some(my_rx.public()) {
        return Err(PairError::BadGenesis);
    }
    Ok(Pairing {
        pairing_id: log.pairing(),
        kind: log.kind(),
        origin: PairingOrigin::V2,
        peer: PeerInfo {
            id: peer,
            name: log.name_of(&peer).unwrap_or("").to_owned(),
            platform: peer_cert.platform(),
        },
        peer_rx: log.rx_of(&peer),
        relay: log.relay().cloned(),
        epoch: log.epoch(),
        gs_e: Some(gs),
        prev_gs_e: None,
        peer_cert: Some(peer_cert),
        my_rx: MyRx::Own(my_rx),
        peer_caps: log.caps().unwrap_or(Caps::V1),
        log: Some(log),
        label: None,
    })
}

/// Test harness: run the whole exchange between two local identities.
/// Returns `(a's record, b's record)`; `a` invites.
#[cfg(any(test, feature = "test-util"))]
pub fn pair_for_tests(
    a: &DeviceKeypair,
    a_cert: DeviceCert,
    b: &DeviceKeypair,
    b_cert: DeviceCert,
    relay: Option<RelayRef>,
) -> (Pairing, Pairing) {
    let ts = UnixMillis(1);
    let b_rx = ReceiveKeypair::generate();
    let inv = invite(a, a_cert, b_cert, b_rx.public(), relay, ts).expect("invite");
    let (mut b_log, cosigned, caps, b_gs) =
        join(b, &b_rx, inv.genesis.clone(), &inv.wrapped_gs, ts).expect("join");
    let (a_log, caps_done) = finish_invite(a, &inv, cosigned, caps).expect("finish invite");
    finish_join(b, &mut b_log, caps_done).expect("finish join");
    let a_rx = ReceiveKeypair::from_secret_bytes(&inv.my_rx.secret_bytes()).expect("rx");
    let a_rec = record(&a.device_id(), a_log, a_rx, inv.gs.clone()).expect("a record");
    let b_rec = record(&b.device_id(), b_log, b_rx, b_gs).expect("b record");
    (a_rec, b_rec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Platform;

    fn ident(name: &str) -> (DeviceKeypair, DeviceCert) {
        let k = DeviceKeypair::generate();
        let rx = ReceiveKeypair::generate();
        let c = DeviceCert::issue(&k, rx.public(), name, Platform::Android, UnixMillis(1))
            .expect("cert");
        (k, c)
    }

    #[test]
    fn both_sides_end_v2_active_with_the_same_log_and_secret() {
        let (a, ac) = ident("A");
        let (b, bc) = ident("B");
        let relay = Some(RelayRef::new("https://relay.example", None));
        let (pa, pb) = pair_for_tests(&a, ac, &b, bc, relay.clone());
        assert!(pa.v2_active() && pb.v2_active());
        assert_eq!(pa.pairing_id, pb.pairing_id);
        assert_eq!(pa.peer.id, b.device_id());
        assert_eq!(pb.peer.id, a.device_id());
        assert_eq!(pa.relay, relay);
        let (la, lb) = (pa.log.as_ref().unwrap(), pb.log.as_ref().unwrap());
        assert_eq!(la.head(), lb.head());
        assert_eq!(
            pa.gs_e.as_ref().unwrap().as_bytes(),
            pb.gs_e.as_ref().unwrap().as_bytes()
        );
        // Each side seals to the other's per-pairing key.
        let MyRx::Own(a_rx) = &pa.my_rx else { panic!() };
        assert_eq!(pb.peer_rx, Some(a_rx.public()));
    }

    #[test]
    fn a_genesis_for_someone_else_is_refused() {
        let (a, ac) = ident("A");
        let (b, bc) = ident("B");
        let (c, _) = ident("C");
        let b_rx = ReceiveKeypair::generate();
        let inv = invite(&a, ac, bc, b_rx.public(), None, UnixMillis(1)).unwrap();
        // C can't open gs_0 nor co-sign a genesis that names B.
        let c_rx = ReceiveKeypair::generate();
        assert!(join(
            &c,
            &c_rx,
            inv.genesis.clone(),
            &inv.wrapped_gs,
            UnixMillis(1)
        )
        .is_err());
        // B with the wrong receive key fails too.
        assert!(join(&b, &c_rx, inv.genesis, &inv.wrapped_gs, UnixMillis(1)).is_err());
    }

    #[test]
    fn unpair_notice_is_checked_without_a_replica() {
        let (a, ac) = ident("A");
        let (b, bc) = ident("B");
        let (mut pa, pb) = pair_for_tests(&a, ac, &b, bc, None);
        let op = pa.log.as_mut().unwrap().unpair(&a, UnixMillis(2)).unwrap();
        let op = PairOp::decode(&op.encode()).unwrap();
        assert!(op.is_unpair_by(&a.device_id(), &pb.pairing_id));
        assert!(!op.is_unpair_by(&b.device_id(), &pb.pairing_id));
        assert!(!op.is_unpair_by(&a.device_id(), &GroupId([9; 32])));
    }
}
