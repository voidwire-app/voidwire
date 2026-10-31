//! Change a pairing's relay (M4 §5.5).
//!
//! A proposes a `SetRelay` op signed by A. B shows "<A> wants to move your
//! pairing to <host>. Allow?"; only when B's user allows does B co-sign and
//! send it back. A checks it against its own proposal and applies it; B
//! applies once A confirms. Both then switch: live traffic and inboxes go to
//! the new relay, and each side keeps pulling its inbox on the old relay
//! for an hour ([`DRAIN_MS`]) to catch anything sent before the switch.
//!
//! Proposals live in RAM only and expire after [`PROPOSAL_TTL_MS`]. Both
//! devices must be online: a proposal is sent live, never queued.
//!
//! Frames (request/response on an ALPN_APP stream):
//! * `RELAY_PROPOSE` A→B: A's signed op. Reply `RELAY_ACK [status]`.
//! * `RELAY_ACCEPT` B→A: the co-signed op. Reply `RELAY_ACK [status]`.
//! * `RELAY_DECLINE` B→A: the op hash. Reply `RELAY_ACK [0]`.

use std::collections::HashMap;
use std::sync::MutexGuard;
use std::time::Duration;

use iroh::endpoint::Connection;

use super::relays::RelayError;
use super::{frame, read_frame, write_frame, NetError, IO_TIMEOUT};
use crate::ids::{DeviceId, LogHead};
use crate::keys::DeviceKeypair;
use crate::pairwise::{PairBody, PairLog, PairOp, Proposed, Received, RelayRef};
use crate::time::UnixMillis;

pub const PROPOSAL_TTL_MS: u64 = 10 * 60_000;
pub const DRAIN_MS: u64 = 60 * 60_000;
/// Largest op we accept in a relay-change frame.
pub(crate) const MAX_RELAY_OP: usize = 4096;

pub(crate) mod ack {
    pub const OK: u8 = 0;
    pub const NO_ROOM: u8 = 1;
    pub const REFUSED: u8 = 2;
}

/// The proposer's view of its proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayChangeState {
    /// Waiting for the other device's user to allow it.
    Waiting,
    Declined,
    Done,
    /// The other device has no room for another relay.
    NoRoom,
}

/// "<peer> wants to move your pairing to <host>. Allow?"
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayChangeRequest {
    pub peer: DeviceId,
    pub peer_name: String,
    pub host: String,
    pub url: String,
    /// The relay isn't saved yet: allowing adds it.
    pub new_relay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayChangeStatus {
    pub peer: DeviceId,
    pub host: String,
    pub state: RelayChangeState,
}

struct InProp {
    op: PairOp,
    relay: RelayRef,
    at: UnixMillis,
}

struct OutProp {
    hash: LogHead,
    relay: RelayRef,
    at: UnixMillis,
    state: RelayChangeState,
}

/// RAM-only proposal slots, one per peer each way.
#[derive(Default)]
pub(crate) struct Slots {
    incoming: HashMap<DeviceId, InProp>,
    outgoing: HashMap<DeviceId, OutProp>,
}

impl Slots {
    fn prune(&mut self, now: UnixMillis) {
        let live = |at: UnixMillis| now.0.saturating_sub(at.0) < PROPOSAL_TTL_MS;
        self.incoming.retain(|_, p| live(p.at));
        self.outgoing.retain(|_, p| live(p.at));
    }
}

/// An old relay inbox still pulled for a while after a move.
#[derive(Debug, Clone)]
pub(crate) struct Drain {
    pub peer: DeviceId,
    pub relay_url: String,
    pub mailbox: DeviceId,
    pub until: UnixMillis,
}

/// What a node provides to the relay-change flow.
pub(crate) trait Host: Send + Sync {
    fn rc_me(&self) -> DeviceKeypair;
    /// A copy of the v2 pairing log with `peer`, and the peer's name.
    fn rc_log(&self, peer: &DeviceId) -> Option<(PairLog, String)>;
    /// Can this device move its pairing with `peer` to `relay` (8 saved,
    /// 4 in use)?
    fn rc_room(&self, peer: &DeviceId, relay: &RelayRef) -> bool;
    fn rc_is_saved(&self, url: &str) -> bool;
    /// Store `log` (now on a new relay): pairing relay, saved relay, old
    /// relay drain, links, save.
    fn rc_commit(&self, peer: &DeviceId, log: PairLog) -> Result<(), NetError>;
    fn rc_slots(&self) -> MutexGuard<'_, Slots>;
    fn rc_changed(&self);
}

fn now() -> UnixMillis {
    use crate::time::Clock;
    crate::time::SystemClock.now().wall
}

fn set_relay_of(op: &PairOp) -> Option<&RelayRef> {
    match op.body() {
        PairBody::SetRelay { relay: Some(r) } => Some(r),
        _ => None,
    }
}

/// A: sign a proposal to move the pairing with `peer` to `relay`. Returns
/// the op to send.
pub(crate) fn propose<H: Host + ?Sized>(
    h: &H,
    peer: &DeviceId,
    relay: RelayRef,
) -> Result<PairOp, RelayError> {
    let (mut log, _) = h.rc_log(peer).ok_or_else(|| {
        RelayError::Other("Only pairings made with this version can move.".into())
    })?;
    if log
        .relay()
        .is_some_and(|r| super::away::same_relay(&r.url, &relay.url))
    {
        return Err(RelayError::Other(
            "The pairing already uses that relay.".into(),
        ));
    }
    if !h.rc_room(peer, &relay) {
        return Err(RelayError::InUseFull);
    }
    let me = h.rc_me();
    let op = match log.propose(
        &me,
        now(),
        PairBody::SetRelay {
            relay: Some(relay.clone()),
        },
    ) {
        Ok(Proposed::NeedsCosign(op)) => op,
        Ok(Proposed::Applied(_)) => return Err(RelayError::Other("unexpected op".into())),
        Err(e) => return Err(RelayError::Other(format!("{e:?}"))),
    };
    let mut s = h.rc_slots();
    s.prune(now());
    s.outgoing.insert(
        *peer,
        OutProp {
            hash: op.hash(),
            relay,
            at: now(),
            state: RelayChangeState::Waiting,
        },
    );
    Ok(op)
}

/// A: the proposal never reached `peer`.
pub(crate) fn forget_outgoing<H: Host + ?Sized>(h: &H, peer: &DeviceId) {
    h.rc_slots().outgoing.remove(peer);
}

/// A: the peer said it has no room.
pub(crate) fn mark_no_room<H: Host + ?Sized>(h: &H, peer: &DeviceId) {
    if let Some(p) = h.rc_slots().outgoing.get_mut(peer) {
        p.state = RelayChangeState::NoRoom;
    }
}

/// B: a proposal from `peer`. Checked, then kept for the user's answer.
pub(crate) fn on_propose<H: Host + ?Sized>(h: &H, peer: &DeviceId, payload: &[u8]) -> u8 {
    let Ok(op) = PairOp::decode(payload) else {
        return ack::REFUSED;
    };
    let Some(relay) = set_relay_of(&op).cloned() else {
        return ack::REFUSED;
    };
    if op.author() != *peer || op.is_cosigned() {
        return ack::REFUSED;
    }
    let Some((mut log, _)) = h.rc_log(peer) else {
        return ack::REFUSED;
    };
    if op.pairing() != log.pairing() {
        return ack::REFUSED;
    }
    // Validate (signature, prev = our head) on a copy; the real log is
    // untouched until the user allows it.
    let me = h.rc_me();
    if !matches!(log.receive(&me, op.clone()), Ok(Received::Cosigned { .. })) {
        return ack::REFUSED;
    }
    if !h.rc_room(peer, &relay) {
        return ack::NO_ROOM;
    }
    {
        let mut s = h.rc_slots();
        s.prune(now());
        s.incoming.insert(
            *peer,
            InProp {
                op,
                relay,
                at: now(),
            },
        );
    }
    h.rc_changed();
    ack::OK
}

/// B: proposals waiting for an answer.
pub(crate) fn requests<H: Host + ?Sized>(h: &H) -> Vec<RelayChangeRequest> {
    let pending: Vec<(DeviceId, RelayRef)> = {
        let mut s = h.rc_slots();
        s.prune(now());
        s.incoming
            .iter()
            .map(|(p, i)| (*p, i.relay.clone()))
            .collect()
    };
    let mut v: Vec<RelayChangeRequest> = pending
        .into_iter()
        .filter_map(|(peer, relay)| {
            let (_, name) = h.rc_log(&peer)?;
            Some(RelayChangeRequest {
                peer,
                peer_name: name,
                host: super::pair2::relay_host(&relay.url),
                new_relay: !h.rc_is_saved(&relay.url),
                url: relay.url,
            })
        })
        .collect();
    v.sort_by(|a, b| a.peer_name.cmp(&b.peer_name));
    v
}

/// B allowed: co-sign on a copy of the log. Returns the copy (commit it
/// once A confirms) and the op to send back. The proposal stays until
/// [`finish_incoming`], so a failed send can be retried.
pub(crate) fn cosign<H: Host + ?Sized>(
    h: &H,
    peer: &DeviceId,
) -> Result<(PairLog, PairOp), RelayError> {
    let (op, relay) = {
        let mut s = h.rc_slots();
        s.prune(now());
        let p = s
            .incoming
            .get(peer)
            .ok_or_else(|| RelayError::Other("That request expired.".into()))?;
        (p.op.clone(), p.relay.clone())
    };
    if !h.rc_room(peer, &relay) {
        return Err(RelayError::InUseFull);
    }
    let (mut log, _) = h
        .rc_log(peer)
        .ok_or_else(|| RelayError::Other("That pairing is gone.".into()))?;
    match log.receive(&h.rc_me(), op) {
        Ok(Received::Cosigned { op, .. }) => Ok((log, op)),
        _ => {
            h.rc_slots().incoming.remove(peer);
            Err(RelayError::Other("That request is out of date.".into()))
        }
    }
}

/// B: drop the proposal from `peer` (answered or declined). Returns the
/// op hash for a decline notice.
pub(crate) fn finish_incoming<H: Host + ?Sized>(h: &H, peer: &DeviceId) -> Option<LogHead> {
    let r = h.rc_slots().incoming.remove(peer).map(|p| p.op.hash());
    h.rc_changed();
    r
}

/// A: B co-signed our proposal.
pub(crate) fn on_accept<H: Host + ?Sized>(h: &H, peer: &DeviceId, payload: &[u8]) -> u8 {
    let Ok(op) = PairOp::decode(payload) else {
        return ack::REFUSED;
    };
    let Some(relay) = set_relay_of(&op).cloned() else {
        return ack::REFUSED;
    };
    let me = h.rc_me();
    if op.author() != me.device_id() || !op.is_cosigned() {
        return ack::REFUSED;
    }
    let Some((mut log, _)) = h.rc_log(peer) else {
        return ack::REFUSED;
    };
    let ours = h
        .rc_slots()
        .outgoing
        .get(peer)
        .is_some_and(|p| p.hash == op.hash());
    let res = log.receive(&me, op);
    let same = |l: &PairLog| {
        l.relay()
            .is_some_and(|r| super::away::same_relay(&r.url, &relay.url))
    };
    match res {
        Ok(Received::Applied { .. }) if ours => {
            if h.rc_commit(peer, log).is_err() {
                return ack::REFUSED;
            }
            if let Some(p) = h.rc_slots().outgoing.get_mut(peer) {
                p.state = RelayChangeState::Done;
            }
            h.rc_changed();
            ack::OK
        }
        // Already applied (our earlier OK was lost): confirm again.
        Ok(Received::Ignored) if same(&log) => ack::OK,
        _ => ack::REFUSED,
    }
}

/// A: B declined.
pub(crate) fn on_decline<H: Host + ?Sized>(h: &H, peer: &DeviceId, payload: &[u8]) -> u8 {
    let mut s = h.rc_slots();
    if let Some(p) = s.outgoing.get_mut(peer) {
        if payload == p.hash.0 {
            p.state = RelayChangeState::Declined;
        }
    }
    drop(s);
    h.rc_changed();
    ack::OK
}

/// A: where our proposals stand.
pub(crate) fn statuses<H: Host + ?Sized>(h: &H) -> Vec<RelayChangeStatus> {
    let mut s = h.rc_slots();
    s.prune(now());
    s.outgoing
        .iter()
        .map(|(peer, p)| RelayChangeStatus {
            peer: *peer,
            host: super::pair2::relay_host(&p.relay.url),
            state: p.state.clone(),
        })
        .collect()
}

/// Handle one relay-change frame; the reply payload for `RELAY_ACK`.
pub(crate) fn serve_frame<H: Host + ?Sized>(
    h: &H,
    peer: &DeviceId,
    t: u8,
    payload: &[u8],
) -> Option<u8> {
    match t {
        frame::RELAY_PROPOSE => Some(on_propose(h, peer, payload)),
        frame::RELAY_ACCEPT => Some(on_accept(h, peer, payload)),
        frame::RELAY_DECLINE => Some(on_decline(h, peer, payload)),
        _ => None,
    }
}

/// One request on `conn`; the peer's status byte.
pub(crate) async fn request(conn: &Connection, t: u8, payload: &[u8]) -> Result<u8, NetError> {
    let (mut s, mut r) = conn
        .open_bi()
        .await
        .map_err(|e| super::conn_error(conn, e))?;
    write_frame(&mut s, t, payload).await?;
    let _ = s.finish();
    let (rt, p) = read_frame(&mut r, IO_TIMEOUT.min(Duration::from_secs(10))).await?;
    if rt != frame::RELAY_ACK || p.len() != 1 {
        return Err(NetError::Protocol("unexpected relay-change reply".into()));
    }
    Ok(p[0])
}

/// User-facing text for a failed live exchange.
pub(crate) fn offline_error(name: &str) -> RelayError {
    RelayError::Other(format!(
        "Couldn't reach {name}. Both devices need to be online with Voidwire open."
    ))
}

// ---- state helpers shared by the PC and the phone ----

use crate::pairwise::{PairingSet, RelaySettings, RelaySource, MAX_RELAYS_IN_USE};

/// Each pairing's own relay URL (`None`: the home relay), with the pairing
/// to `moving.0` already on `moving.1`.
pub(crate) fn pairing_relays(
    ps: &PairingSet,
    moving: Option<(&DeviceId, &str)>,
) -> Vec<Option<String>> {
    ps.iter()
        .map(|p| match moving {
            Some((peer, url)) if p.peer.id == *peer => Some(url.to_owned()),
            _ => p.relay.as_ref().map(|r| r.url.clone()),
        })
        .collect()
}

/// Room to move the pairing with `peer` to `relay`.
pub(crate) fn room(ps: &PairingSet, rs: &RelaySettings, peer: &DeviceId, relay: &RelayRef) -> bool {
    let saved = rs
        .relays
        .iter()
        .any(|e| super::away::same_relay(&e.relay.url, &relay.url))
        || rs.relays.len() < crate::pairwise::MAX_SAVED_RELAYS;
    let used = super::relays::in_use(
        rs.home_relay.as_deref(),
        &pairing_relays(ps, Some((peer, &relay.url))),
    );
    saved && used.len() <= MAX_RELAYS_IN_USE
}

pub(crate) fn is_saved(rs: &RelaySettings, url: &str) -> bool {
    rs.relays
        .iter()
        .any(|e| super::away::same_relay(&e.relay.url, url))
}

/// The v2 log with `peer` and the name to show.
pub(crate) fn log_of(ps: &PairingSet, peer: &DeviceId) -> Option<(PairLog, String)> {
    ps.by_peer(peer).next().map(|p| {
        let name = p.label.clone().unwrap_or_else(|| p.peer.name.clone());
        (p.log.clone(), name)
    })
}

/// Store a log that moved to a new relay. `old`: our inbox on the old
/// relay, drained for [`DRAIN_MS`].
pub(crate) fn apply_commit(
    ps: &mut PairingSet,
    rs: &mut RelaySettings,
    drains: &mut Vec<Drain>,
    peer: &DeviceId,
    log: PairLog,
    old: Option<(String, DeviceId)>,
) -> Result<(), NetError> {
    let relay = log.relay().cloned();
    let pid = log.pairing();
    let p = ps.get_mut(&pid).ok_or(NetError::UnknownDevice)?;
    p.log = log;
    p.relay = relay.clone();
    if let Some(r) = relay {
        if !is_saved(rs, &r.url) {
            // Room was checked before co-signing; a full list only loses
            // the nickname row, never the pairing.
            let _ = super::relays::add(rs, r, "", RelaySource::FromInvite, false, None);
        }
    }
    let t = now();
    drains.retain(|d| d.until.0 > t.0 && d.peer != *peer);
    if let Some((relay_url, mailbox)) = old {
        drains.push(Drain {
            peer: *peer,
            relay_url,
            mailbox,
            until: UnixMillis(t.0 + DRAIN_MS),
        });
    }
    Ok(())
}

/// Drains still running.
pub(crate) fn live_drains(drains: &mut Vec<Drain>) -> Vec<Drain> {
    let t = now();
    drains.retain(|d| d.until.0 > t.0);
    drains.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{DeviceCert, Platform, ReceiveKeypair};
    use std::sync::Mutex;

    struct Fake {
        me: DeviceKeypair,
        peer: DeviceId,
        log: Mutex<PairLog>,
        slots: Mutex<Slots>,
        room: bool,
    }

    impl Host for Fake {
        fn rc_me(&self) -> DeviceKeypair {
            DeviceKeypair::from_secret_bytes(&self.me.secret_bytes())
        }
        fn rc_log(&self, peer: &DeviceId) -> Option<(PairLog, String)> {
            (*peer == self.peer).then(|| (self.log.lock().unwrap().clone(), "Peer".into()))
        }
        fn rc_room(&self, _: &DeviceId, _: &RelayRef) -> bool {
            self.room
        }
        fn rc_is_saved(&self, _: &str) -> bool {
            false
        }
        fn rc_commit(&self, _: &DeviceId, log: PairLog) -> Result<(), NetError> {
            *self.log.lock().unwrap() = log;
            Ok(())
        }
        fn rc_slots(&self) -> MutexGuard<'_, Slots> {
            self.slots.lock().unwrap()
        }
        fn rc_changed(&self) {}
    }

    fn cert(k: &DeviceKeypair, name: &str) -> DeviceCert {
        DeviceCert::issue(
            k,
            ReceiveKeypair::generate().public(),
            name,
            Platform::Android,
            UnixMillis(1),
        )
        .unwrap()
    }

    fn two(room_b: bool) -> (Fake, Fake) {
        let (ak, bk) = (DeviceKeypair::generate(), DeviceKeypair::generate());
        let (pa, pb) = crate::pairwise::v2::pair_for_tests(
            &ak,
            cert(&ak, "A"),
            &bk,
            cert(&bk, "B"),
            Some(RelayRef::new("https://r1.example", None)),
        );
        let mk = |k: DeviceKeypair, peer: DeviceId, log: PairLog, room| Fake {
            me: k,
            peer,
            log: Mutex::new(log),
            slots: Mutex::new(Slots::default()),
            room,
        };
        let (a_id, b_id) = (ak.device_id(), bk.device_id());
        (mk(ak, b_id, pa.log, true), mk(bk, a_id, pb.log, room_b))
    }

    fn r2() -> RelayRef {
        RelayRef::new("https://r2.example", None)
    }

    fn url(f: &Fake) -> String {
        f.log.lock().unwrap().relay().unwrap().url.clone()
    }

    #[test]
    fn both_sign_then_both_move() {
        let (a, b) = two(true);
        let op = propose(&a, &a.peer, r2()).unwrap();
        assert_eq!(on_propose(&b, &b.peer, &op.encode()), ack::OK);
        assert_eq!(
            url(&a),
            "https://r1.example",
            "nothing moves before B allows"
        );
        let (log_b, cosigned) = cosign(&b, &b.peer).unwrap();
        assert_eq!(on_accept(&a, &a.peer, &cosigned.encode()), ack::OK);
        b.rc_commit(&b.peer, log_b).unwrap();
        assert_eq!(url(&a), "https://r2.example");
        assert_eq!(url(&b), "https://r2.example");
        assert_eq!(statuses(&a)[0].state, RelayChangeState::Done);
        // A lost OK: B retries, A confirms again without applying twice.
        assert_eq!(on_accept(&a, &a.peer, &cosigned.encode()), ack::OK);
    }

    #[test]
    fn unsigned_forged_or_unproposed_ops_are_refused() {
        let (a, b) = two(true);
        let op = propose(&a, &a.peer, r2()).unwrap();
        // A's own op, not co-signed, sent back as an accept.
        assert_eq!(on_accept(&a, &a.peer, &op.encode()), ack::REFUSED);
        // B proposing in A's name (author must be the sender).
        assert_eq!(
            on_propose(&b, &DeviceKeypair::generate().device_id(), &op.encode()),
            ack::REFUSED
        );
        // A co-signed op A never proposed (A forgot its proposal).
        assert_eq!(on_propose(&b, &b.peer, &op.encode()), ack::OK);
        let (_, cosigned) = cosign(&b, &b.peer).unwrap();
        forget_outgoing(&a, &a.peer);
        assert_eq!(on_accept(&a, &a.peer, &cosigned.encode()), ack::REFUSED);
        assert_eq!(url(&a), "https://r1.example");
        // Garbage.
        assert_eq!(on_propose(&b, &b.peer, b"nope"), ack::REFUSED);
    }

    #[test]
    fn no_room_and_decline() {
        let (a, b) = two(false);
        let op = propose(&a, &a.peer, r2()).unwrap();
        assert_eq!(on_propose(&b, &b.peer, &op.encode()), ack::NO_ROOM);
        assert!(requests(&b).is_empty());
        let (a, b) = two(true);
        let op = propose(&a, &a.peer, r2()).unwrap();
        assert_eq!(on_propose(&b, &b.peer, &op.encode()), ack::OK);
        assert_eq!(requests(&b).len(), 1);
        let h = finish_incoming(&b, &b.peer).unwrap();
        assert_eq!(on_decline(&a, &a.peer, &h.0), ack::OK);
        assert_eq!(statuses(&a)[0].state, RelayChangeState::Declined);
        assert!(cosign(&b, &b.peer).is_err());
        assert_eq!(url(&b), "https://r1.example");
    }
}
