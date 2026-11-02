//! Direct upgrade for away pairings (S40, extends S39).
//!
//! An away endpoint is relay-only ([`super::away`]), so a connection through
//! it carries no IP addresses and iroh can't move it to a direct path. When
//! mDNS doesn't work on a LAN (multicast filtered, a host firewall), such a
//! pairing stayed on the relay for good, even with both devices side by side.
//!
//! Once an away connection is up, either side asks the other for the private
//! LAN addresses of its **main** endpoint, over that connection (end-to-end
//! encrypted; the relay sees nothing), and sends its own. Then both sides
//! dial each other's main endpoint at the same time, briefly. Two dials at
//! once also open each host firewall for the other's packets. A connection
//! that comes up is used for the next sends, and the addresses are saved
//! like any learned LAN address (settings `PEER_LAN`).
//!
//! Wire: on a new stream the asker writes [`frame::LAN_HELLO`] (empty), then
//! [`frame::LAN_ADDRS`] with its addresses; the other side answers with its
//! own [`frame::LAN_ADDRS`]. An older peer reads the empty hello as an
//! unknown frame and answers `ERROR` without reading on (an empty unknown
//! frame passes its size check, so it raises no "refused" event there).
//!
//! Rules: private addresses only (the [`super::lan_addrs`] filter: RFC 1918,
//! link-local, ULA), at most [`super::lan_addrs::MAX_PER_PEER`]; never
//! logged. Event-driven: when a connection is established and when the
//! phone reports a network change. A phone does it only while the app is
//! open. No timers.

use std::net::{SocketAddr, SocketAddrV6};
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::Endpoint;

use super::{frame, read_frame, write_frame};

/// How long each side's direct dial may take. QUIC resends its first
/// packet within this, so a dial whose first packet a firewall dropped
/// (before the other side's own dial opened it) still gets through.
pub(crate) const DIAL_WAIT: Duration = Duration::from_secs(3);
/// How long the asker waits for the answer.
const ANSWER_WAIT: Duration = Duration::from_secs(5);

/// Largest `LAN_ADDRS` payload: a count, then per address a family byte,
/// 16 address bytes and a port.
pub(crate) const MAX_FRAME: usize = 1 + super::lan_addrs::MAX_PER_PEER * (1 + 16 + 2);

/// `LAN_ADDRS` payload for `addrs` (filtered: private only, at most 4).
pub(crate) fn encode(addrs: &[SocketAddr], allow_loopback: bool) -> Vec<u8> {
    let lan = super::lan_addrs::lan_only(addrs, allow_loopback);
    let mut out = Vec::with_capacity(MAX_FRAME);
    out.push(lan.len() as u8);
    for a in &lan {
        match a {
            SocketAddr::V4(v4) => {
                out.push(4);
                out.extend_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                out.push(6);
                out.extend_from_slice(&v6.ip().octets());
            }
        }
        out.extend_from_slice(&a.port().to_be_bytes());
    }
    debug_assert!(out.len() <= MAX_FRAME);
    out
}

/// The private addresses in a `LAN_ADDRS` payload. Malformed: `None`.
/// Anything not private is dropped (a peer can't point our dial elsewhere).
pub(crate) fn decode(b: &[u8], allow_loopback: bool) -> Option<Vec<SocketAddr>> {
    let (&n, mut rest) = b.split_first()?;
    if n as usize > super::lan_addrs::MAX_PER_PEER {
        return None;
    }
    let mut v = Vec::new();
    for _ in 0..n {
        let (&fam, r) = rest.split_first()?;
        let len = match fam {
            4 => 4,
            6 => 16,
            _ => return None,
        };
        if r.len() < len + 2 {
            return None;
        }
        let port = u16::from_be_bytes([r[len], r[len + 1]]);
        let a = if fam == 4 {
            let o: [u8; 4] = r[..4].try_into().ok()?;
            SocketAddr::from((o, port))
        } else {
            let o: [u8; 16] = r[..16].try_into().ok()?;
            SocketAddr::V6(SocketAddrV6::new(o.into(), port, 0, 0))
        };
        v.push(a);
        rest = &r[len + 2..];
    }
    if !rest.is_empty() {
        return None;
    }
    Some(super::lan_addrs::lan_only(&v, allow_loopback))
}

/// The main endpoint's private addresses (loopback first when allowed:
/// tests on one host).
pub(crate) fn own_addrs(ep: &Endpoint, allow_loopback: bool) -> Vec<SocketAddr> {
    let mut v: Vec<SocketAddr> = Vec::new();
    if allow_loopback {
        for s in ep.bound_sockets() {
            if s.is_ipv4() && s.port() != 0 {
                v.push(SocketAddr::from(([127, 0, 0, 1], s.port())));
            }
        }
    }
    let mut ips: Vec<SocketAddr> = ep.addr().ip_addrs().copied().collect();
    ips.sort_by_key(|a| (a.is_ipv6(), *a));
    v.extend(ips);
    super::lan_addrs::lan_only(&v, allow_loopback)
}

/// Ask the peer on `conn` for its addresses, sending ours. `None`: an older
/// peer, or no answer.
pub(crate) async fn ask(
    conn: &Connection,
    ours: &[SocketAddr],
    allow_loopback: bool,
) -> Option<Vec<SocketAddr>> {
    let fut = async {
        let (mut send, mut recv) = conn.open_bi().await.ok()?;
        write_frame(&mut send, frame::LAN_HELLO, &[]).await.ok()?;
        write_frame(&mut send, frame::LAN_ADDRS, &encode(ours, allow_loopback))
            .await
            .ok()?;
        let _ = send.finish();
        match read_frame(&mut recv, ANSWER_WAIT).await.ok()? {
            (frame::LAN_ADDRS, p) => decode(&p, allow_loopback),
            _ => None,
        }
    };
    tokio::time::timeout(ANSWER_WAIT, fut).await.ok().flatten()
}

/// Answer a `LAN_HELLO` (already read from `recv`): read the asker's
/// addresses, send `ours`. Returns the asker's addresses.
pub(crate) async fn answer(
    send: &mut SendStream,
    recv: &mut RecvStream,
    ours: &[SocketAddr],
    allow_loopback: bool,
) -> Option<Vec<SocketAddr>> {
    let theirs = match read_frame(recv, ANSWER_WAIT).await.ok()? {
        (frame::LAN_ADDRS, p) => decode(&p, allow_loopback),
        _ => None,
    };
    let _ = write_frame(send, frame::LAN_ADDRS, &encode(ours, allow_loopback)).await;
    let _ = send.finish();
    let _ = tokio::time::timeout(Duration::from_secs(3), send.stopped()).await;
    theirs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn round_trip_keeps_private_only_and_caps() {
        let v = [
            a("8.8.8.8:1"),
            a("192.168.1.2:48484"),
            a("10.0.0.7:9"),
            a("[fd00::5]:7"),
            a("127.0.0.1:5"),
            a("172.16.0.1:3"),
            a("169.254.1.1:2"),
        ];
        let enc = encode(&v, false);
        assert!(enc.len() <= MAX_FRAME);
        let back = decode(&enc, false).unwrap();
        assert_eq!(
            back,
            vec![
                a("192.168.1.2:48484"),
                a("10.0.0.7:9"),
                a("[fd00::5]:7"),
                a("172.16.0.1:3")
            ]
        );
        assert_eq!(decode(&encode(&[], false), false).unwrap(), vec![]);
        // Loopback only when allowed (tests on one host).
        let lo = encode(&[a("127.0.0.1:5")], true);
        assert_eq!(decode(&lo, true).unwrap(), vec![a("127.0.0.1:5")]);
        assert_eq!(decode(&lo, false).unwrap(), vec![]);
    }

    #[test]
    fn hostile_payloads_are_refused_or_filtered() {
        assert!(decode(&[], false).is_none());
        assert!(decode(&[5], false).is_none());
        assert!(decode(&[1, 9, 0, 0], false).is_none());
        assert!(decode(&[1, 4, 10, 0, 0], false).is_none());
        let mut ok = encode(&[a("10.0.0.1:2")], false);
        ok.push(0);
        assert!(decode(&ok, false).is_none());
        // A public address is dropped, not dialled.
        let mut p = vec![1, 4];
        p.extend_from_slice(&[1, 1, 1, 1]);
        p.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(decode(&p, false).unwrap(), vec![]);
        for cut in 0..MAX_FRAME {
            let _ = decode(&vec![4u8; cut], false);
        }
    }

    #[test]
    fn frame_caps_fit() {
        assert_eq!(super::super::frame_cap(frame::LAN_HELLO), 0);
        assert_eq!(super::super::frame_cap(frame::LAN_ADDRS), MAX_FRAME);
    }
}
