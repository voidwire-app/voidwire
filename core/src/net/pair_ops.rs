//! Self-signed pairing ops sent to the peer (M4.5: renames).
//!
//! A rename is a `Rename` op the device signs itself, one per v2 pairing.
//! It goes to the peer on a v2 connection that exists or next comes up for
//! another reason: no timers, retries or wake-ups. Until the peer confirms
//! it, the op stays in the pairing log (stored), and is sent again on each
//! new connection. A rename made before the previous one was ever sent
//! replaces it, so only the latest name waits.
//!
//! The peer checks each op against the pairing log (signature by the
//! pairing key, chain position) and shows the new name, unless its user set
//! a local nickname. Two devices renaming at once: the op with the lower
//! hash wins on both ends, and the loser re-signs its rename on top.
//!
//! Frame (request/response on an ALPN_APP stream):
//! * `PAIR_OPS` count u8 + (len u16 + op) per op, oldest first.
//!   Reply `PAIR_OPS_ACK [status]`.

use std::collections::HashSet;
use std::sync::Arc;

use iroh::endpoint::Connection;

use super::{frame, read_frame, write_frame, NetError, IO_TIMEOUT};
use crate::ids::{DeviceId, GroupId, LogHead};
use crate::keys::DeviceKeypair;
use crate::pairwise::{PairBody, PairOp, PairingSet, Proposed, Received};
use crate::time::UnixMillis;

/// Most ops in one frame (a pairing log keeps at most this many of ours
/// unconfirmed).
pub(crate) const MAX_OPS: usize = crate::pairwise::log::MAX_UNACKED;
/// Largest `PAIR_OPS` payload.
pub(crate) const MAX_FRAME: usize = 1 + MAX_OPS * (2 + super::pair_codec::MAX_PAIR_OP);

pub(crate) mod status {
    /// Applied, or already had them.
    pub const OK: u8 = 0;
    /// One lost a race against the peer's own op (which is on its way).
    pub const LOST: u8 = 1;
    /// Not valid for this pairing: don't send them again.
    pub const REFUSED: u8 = 2;
}

/// Hashes of ops signed in this run and never sent: a newer rename may
/// take them back. After a restart nothing is in here, so a newer rename
/// goes on top (safe either way).
pub(crate) type Unsent = HashSet<LogHead>;

/// A device's state, as this module needs it.
pub(crate) trait Host: Send + Sync + 'static {
    fn po_me(&self) -> DeviceKeypair;
    /// Run `f` on the pairings under the state lock; persist (and refresh
    /// the views of the pairings) when it returns true.
    fn po_with(&self, f: &mut dyn FnMut(&mut PairingSet, &mut Unsent) -> bool);
}

pub(crate) fn encode(ops: &[PairOp]) -> Vec<u8> {
    let mut v = vec![ops.len() as u8];
    for o in ops {
        let b = o.encode();
        v.extend_from_slice(&(b.len() as u16).to_be_bytes());
        v.extend_from_slice(&b);
    }
    v
}

fn decode(b: &[u8]) -> Option<Vec<PairOp>> {
    let (&n, mut rest) = b.split_first()?;
    let n = n as usize;
    if n == 0 || n > MAX_OPS {
        return None;
    }
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        if rest.len() < 2 {
            return None;
        }
        let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        if len > super::pair_codec::MAX_PAIR_OP || rest.len() < 2 + len {
            return None;
        }
        v.push(PairOp::decode(&rest[2..2 + len]).ok()?);
        rest = &rest[2 + len..];
    }
    rest.is_empty().then_some(v)
}

/// Rename ourselves in every live v2 pairing. Returns the peers that now
/// have something to be sent.
pub(crate) fn rename_all(
    ps: &mut PairingSet,
    unsent: &mut Unsent,
    me: &DeviceKeypair,
    ts: UnixMillis,
    name: &str,
) -> Vec<DeviceId> {
    let mut peers = Vec::new();
    for p in ps.iter_mut() {
        if !p.v2_active() {
            continue;
        }
        let log = &mut p.log;
        if log.is_unpaired() {
            continue;
        }
        // Our renames the peer never saw: replace them with this one.
        let waiting = log.unconfirmed();
        let never_sent = waiting
            .iter()
            .rev()
            .take_while(|o| unsent.contains(&o.hash()))
            .count();
        if never_sent > 0 && log.withdraw(never_sent) {
            for o in &waiting[waiting.len() - never_sent..] {
                unsent.remove(&o.hash());
            }
        }
        let body = PairBody::Rename {
            name: name.to_owned(),
        };
        if let Ok(Proposed::Applied(op)) = log.propose(me, ts, body) {
            unsent.insert(op.hash());
            peers.push(p.peer.id);
        }
    }
    peers
}

/// What to send `peer` now, if anything (then no longer "never sent").
fn outgoing(
    ps: &PairingSet,
    unsent: &mut Unsent,
    peer: &DeviceId,
) -> Option<(GroupId, Vec<PairOp>)> {
    let p = ps
        .by_peer(peer)
        .find(|p| p.v2_active() && !p.log.is_unpaired())?;
    let ops = p.log.unconfirmed();
    if ops.is_empty() || ops.len() > MAX_OPS {
        return None;
    }
    for o in &ops {
        unsent.remove(&o.hash());
    }
    Some((p.pairing_id, ops))
}

/// The peer answered for ops up to `last`. True: persist.
fn on_reply(ps: &mut PairingSet, pairing: &GroupId, last: &LogHead, st: u8) -> bool {
    if st == status::LOST {
        // The winner is on its way; ours are re-signed when it lands.
        return false;
    }
    let Some(log) = ps.get_mut(pairing).map(|p| &mut p.log) else {
        return false;
    };
    log.confirm(last);
    true
}

/// The result of serving a `PAIR_OPS` frame.
pub(crate) struct Served {
    pub status: u8,
    /// Something changed (persist).
    pub changed: bool,
    /// Our own rename lost a race and was re-signed: send it.
    pub resend: bool,
}

/// Apply the peer's ops to our replica of the pairing.
pub(crate) fn serve(
    ps: &mut PairingSet,
    unsent: &mut Unsent,
    me: &DeviceKeypair,
    ts: UnixMillis,
    peer: &DeviceId,
    payload: &[u8],
) -> Served {
    let refused = Served {
        status: status::REFUSED,
        changed: false,
        resend: false,
    };
    let Some(ops) = decode(payload) else {
        return refused;
    };
    let Some(p) = ps.iter_mut().find(|p| p.peer.id == *peer && p.v2_active()) else {
        return refused;
    };
    let mut log = p.log.clone();
    let mut out = Served {
        status: status::OK,
        changed: false,
        resend: false,
    };
    let mut mine_lost: Option<String> = None;
    for op in ops {
        if op.author() != *peer || !matches!(op.body(), PairBody::Rename { .. }) {
            out.status = status::REFUSED;
            break;
        }
        if log.has(&op.hash()) {
            continue;
        }
        match log.receive(me, op) {
            Ok(Received::Applied { requeue }) => {
                out.changed = true;
                for b in requeue {
                    if let PairBody::Rename { name } = b {
                        mine_lost = Some(name);
                    }
                }
            }
            Ok(Received::Ignored) => {
                // Lost to one of ours; the rest builds on it.
                out.status = status::LOST;
                break;
            }
            Ok(Received::Cosigned { .. }) | Err(_) => {
                out.status = status::REFUSED;
                break;
            }
        }
    }
    if !out.changed {
        return out;
    }
    if let Some(name) = mine_lost {
        if let Ok(Proposed::Applied(op)) = log.propose(me, ts, PairBody::Rename { name }) {
            unsent.insert(op.hash());
            out.resend = true;
        }
    }
    if let Some(n) = log.name_of(peer) {
        p.peer.name = n.to_owned();
    }
    p.log = log;
    out
}

async fn request(conn: &Connection, payload: &[u8]) -> Result<u8, NetError> {
    let (mut s, mut r) = conn
        .open_bi()
        .await
        .map_err(|e| super::conn_error(conn, e))?;
    write_frame(&mut s, frame::PAIR_OPS, payload).await?;
    let _ = s.finish();
    let (rt, p) = read_frame(&mut r, IO_TIMEOUT).await?;
    if rt != frame::PAIR_OPS_ACK || p.len() != 1 {
        return Err(NetError::Protocol("unexpected pair-ops reply".into()));
    }
    Ok(p[0])
}

/// Send `peer` our unconfirmed ops on `conn` (nothing to send: no traffic).
/// One attempt; on failure they wait for the next connection.
pub(crate) async fn flush<H: Host + ?Sized>(h: Arc<H>, conn: Connection, peer: DeviceId) {
    let mut out = None;
    h.po_with(&mut |ps, unsent| {
        out = outgoing(ps, unsent, &peer);
        false
    });
    let Some((pairing, ops)) = out else { return };
    let Some(last) = ops.last().map(PairOp::hash) else {
        return;
    };
    let Ok(st) = request(&conn, &encode(&ops)).await else {
        return;
    };
    h.po_with(&mut |ps, _| on_reply(ps, &pairing, &last, st));
}

/// Serve a `PAIR_OPS` frame from `peer`: returns the reply status and
/// whether we now have a re-signed rename of ours to send.
pub(crate) fn serve_frame<H: Host + ?Sized>(
    h: &H,
    peer: &DeviceId,
    ts: UnixMillis,
    payload: &[u8],
) -> (u8, bool) {
    let me = h.po_me();
    let mut res = (status::REFUSED, false);
    h.po_with(&mut |ps, unsent| {
        let s = serve(ps, unsent, &me, ts, peer, payload);
        res = (s.status, s.resend);
        s.changed
    });
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{DeviceCert, Platform};
    use crate::net::links::PairLink;
    use crate::pairwise::v2::pair_for_tests;

    struct Side {
        k: DeviceKeypair,
        ps: PairingSet,
        unsent: Unsent,
    }

    fn ident(name: &str) -> (DeviceKeypair, DeviceCert) {
        let k = DeviceKeypair::generate();
        let c = DeviceCert::issue(&k, name, Platform::Android, UnixMillis(1)).expect("cert");
        (k, c)
    }

    fn paired() -> (Side, Side) {
        let (a, ac) = ident("Old A");
        let (b, bc) = ident("Old B");
        let (pa, pb) = pair_for_tests(&a, ac, &b, bc, None);
        let side = |k, p| {
            let mut ps = PairingSet::new();
            ps.add(p).expect("add");
            Side {
                k,
                ps,
                unsent: Unsent::new(),
            }
        };
        (side(a, pa), side(b, pb))
    }

    impl Side {
        fn id(&self) -> DeviceId {
            self.k.device_id()
        }
        fn rename(&mut self, name: &str) {
            let peers = rename_all(&mut self.ps, &mut self.unsent, &self.k, UnixMillis(2), name);
            assert_eq!(peers.len(), 1);
        }
        fn waiting(&self) -> usize {
            let p = self.ps.iter().next().expect("pairing");
            p.log.unconfirmed().len()
        }
        fn shown(&self) -> String {
            let p = self.ps.iter().next().expect("pairing");
            PairLink::from_pairing(&self.id(), p).expect("link").name()
        }
        /// Send what's waiting to `to`; returns (status, to's resend).
        fn send_to(&mut self, to: &mut Side) -> (u8, bool) {
            let peer = to.id();
            let (pairing, ops) = outgoing(&self.ps, &mut self.unsent, &peer).expect("ops");
            let s = serve(
                &mut to.ps,
                &mut to.unsent,
                &to.k,
                UnixMillis(3),
                &self.id(),
                &encode(&ops),
            );
            let last = ops.last().expect("op").hash();
            on_reply(&mut self.ps, &pairing, &last, s.status);
            (s.status, s.resend)
        }
    }

    #[test]
    fn a_rename_reaches_the_peer_and_is_confirmed() {
        let (mut a, mut b) = paired();
        assert_eq!(b.shown(), "Old A");
        a.rename("New A");
        assert_eq!(a.waiting(), 1);
        assert_eq!(a.send_to(&mut b), (status::OK, false));
        assert_eq!(b.shown(), "New A");
        assert_eq!(a.waiting(), 0, "confirmed: not sent again");
        // The same frame again (a lost reply): still fine, nothing changes.
        a.rename("Newer A");
        let (_, ops) = outgoing(&a.ps, &mut a.unsent, &b.id()).unwrap();
        let again = encode(&ops);
        for _ in 0..2 {
            let s = serve(
                &mut b.ps,
                &mut b.unsent,
                &b.k,
                UnixMillis(3),
                &a.id(),
                &again,
            );
            assert_eq!(s.status, status::OK);
        }
        assert_eq!(b.shown(), "Newer A");
    }

    #[test]
    fn only_the_latest_unsent_rename_waits() {
        let (mut a, mut b) = paired();
        a.rename("One");
        a.rename("Two");
        a.rename("Three");
        assert_eq!(a.waiting(), 1);
        // Once sent, a newer rename goes on top (the peer may have it).
        let _ = outgoing(&a.ps, &mut a.unsent, &b.id());
        a.rename("Four");
        assert_eq!(a.waiting(), 2);
        assert_eq!(a.send_to(&mut b).0, status::OK);
        assert_eq!(b.shown(), "Four");
    }

    #[test]
    fn a_local_nickname_wins_over_the_peer_name() {
        let (mut a, mut b) = paired();
        let pid = b.ps.iter().next().unwrap().pairing_id;
        b.ps.get_mut(&pid).unwrap().label = Some("Kitchen".into());
        a.rename("New A");
        assert_eq!(a.send_to(&mut b).0, status::OK);
        assert_eq!(b.shown(), "Kitchen");
        b.ps.get_mut(&pid).unwrap().label = None;
        assert_eq!(b.shown(), "New A");
    }

    #[test]
    fn forged_or_foreign_ops_change_nothing() {
        let (mut a, mut b) = paired();
        // Signed by a third device.
        let (mut c, _) = paired();
        c.rename("Evil");
        let (_, ops) =
            outgoing(&c.ps, &mut c.unsent, &c.ps.iter().next().unwrap().peer.id).unwrap();
        let s = serve(
            &mut b.ps,
            &mut b.unsent,
            &b.k,
            UnixMillis(3),
            &a.id(),
            &encode(&ops),
        );
        assert_eq!((s.status, s.changed), (status::REFUSED, false));
        // A's op with its name changed after signing.
        a.rename("Fine");
        let (_, ops) = outgoing(&a.ps, &mut a.unsent, &b.id()).unwrap();
        let mut raw = encode(&ops);
        let at = raw
            .windows(4)
            .position(|w| w == b"Fine")
            .expect("name bytes");
        raw[at..at + 4].copy_from_slice(b"Evil");
        let s = serve(&mut b.ps, &mut b.unsent, &b.k, UnixMillis(3), &a.id(), &raw);
        assert_eq!((s.status, s.changed), (status::REFUSED, false));
        assert_eq!(b.shown(), "Old A");
        // Truncated, empty, trailing bytes.
        let good = encode(&ops);
        for bad in [&good[..good.len() - 1], &[][..], &[0u8][..]] {
            let s = serve(&mut b.ps, &mut b.unsent, &b.k, UnixMillis(3), &a.id(), bad);
            assert_eq!(s.status, status::REFUSED);
        }
        let mut long = good.clone();
        long.push(0);
        let s = serve(
            &mut b.ps,
            &mut b.unsent,
            &b.k,
            UnixMillis(3),
            &a.id(),
            &long,
        );
        assert_eq!(s.status, status::REFUSED);
        // The real one still lands.
        let s = serve(
            &mut b.ps,
            &mut b.unsent,
            &b.k,
            UnixMillis(3),
            &a.id(),
            &good,
        );
        assert_eq!(s.status, status::OK);
        assert_eq!(b.shown(), "Fine");
    }

    #[test]
    fn crossing_renames_end_with_both_new_names() {
        let (mut a, mut b) = paired();
        a.rename("New A");
        b.rename("New B");
        // Both frames cross on the wire.
        let (pa, ops_a) = outgoing(&a.ps, &mut a.unsent, &b.id()).unwrap();
        let (pb, ops_b) = outgoing(&b.ps, &mut b.unsent, &a.id()).unwrap();
        let at_b = serve(
            &mut b.ps,
            &mut b.unsent,
            &b.k,
            UnixMillis(3),
            &a.id(),
            &encode(&ops_a),
        );
        let at_a = serve(
            &mut a.ps,
            &mut a.unsent,
            &a.k,
            UnixMillis(3),
            &b.id(),
            &encode(&ops_b),
        );
        on_reply(&mut a.ps, &pa, &ops_a[0].hash(), at_b.status);
        on_reply(&mut b.ps, &pb, &ops_b[0].hash(), at_a.status);
        // Exactly one lost and re-signed.
        assert!(at_a.resend ^ at_b.resend);
        let (loser, winner) = if at_a.resend {
            (&mut a, &mut b)
        } else {
            (&mut b, &mut a)
        };
        assert_eq!(loser.send_to(winner).0, status::OK);
        assert_eq!(a.shown(), "New B");
        assert_eq!(b.shown(), "New A");
        let (la, lb) = (
            a.ps.iter().next().unwrap().log.head(),
            b.ps.iter().next().unwrap().log.head(),
        );
        assert_eq!(la, lb, "same log on both ends");
    }
}
