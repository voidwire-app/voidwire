//! Saved LAN addresses of paired peers (S39).
//!
//! After a restart a device knew no address for its peers until one of them
//! dialled in, so the first sends went through the relay (and could stay
//! there). Each device now keeps the last few **private** addresses it saw
//! for each paired peer, in the user's settings file (owner-only, sealed like
//! the state file) under [`super::settings::PEER_LAN`].
//!
//! Rules:
//! * Private or link-local only: IPv4 RFC 1918 and 169.254/16, IPv6 ULA
//!   (fc00::/7) and link-local (fe80::/10). Public addresses are never saved.
//! * At most [`MAX_PER_PEER`] per peer; a new set replaces the old one.
//! * Only peers that are still paired are written, so Forget and a state
//!   reset (which drops every pairing) remove them on the next save.
//! * Never logged.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};

use super::state::{Reader, Writer};
use crate::ids::DeviceId;

/// Addresses kept per peer.
pub const MAX_PER_PEER: usize = 4;
/// Peers kept (well above the pairing cap; a guard against a damaged file).
const MAX_PEERS: usize = 64;
const FORMAT: u8 = 1;

/// A private (LAN) address: RFC 1918, IPv4 link-local, IPv6 ULA or
/// link-local. `allow_loopback` is for tests on one host only.
pub fn is_lan_ip(ip: IpAddr, allow_loopback: bool) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    if ip.is_loopback() {
        return allow_loopback;
    }
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            (s0 & 0xfe00) == 0xfc00 || (s0 & 0xffc0) == 0xfe80
        }
    }
}

/// The addresses of `addrs` worth saving: LAN only, no port 0, no
/// duplicates, at most [`MAX_PER_PEER`], in the order given.
pub fn lan_only(addrs: &[SocketAddr], allow_loopback: bool) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in addrs {
        if a.port() != 0 && is_lan_ip(a.ip(), allow_loopback) && !out.contains(a) {
            out.push(*a);
            if out.len() == MAX_PER_PEER {
                break;
            }
        }
    }
    out
}

/// Encode `peers` (already filtered by the caller to paired peers). `None`
/// when nothing is worth saving, so the settings entry is removed.
pub(crate) fn encode<'a>(
    peers: impl Iterator<Item = (&'a DeviceId, &'a [SocketAddr])>,
    allow_loopback: bool,
) -> Option<Vec<u8>> {
    let mut sorted: BTreeMap<DeviceId, Vec<SocketAddr>> = BTreeMap::new();
    for (id, addrs) in peers {
        let lan = lan_only(addrs, allow_loopback);
        if !lan.is_empty() {
            sorted.insert(*id, lan);
        }
    }
    if sorted.is_empty() {
        return None;
    }
    let mut w = Writer(Vec::new());
    w.u8(FORMAT);
    let n = sorted.len().min(MAX_PEERS);
    w.u8(n as u8);
    for (id, addrs) in sorted.iter().take(n) {
        w.raw(id.as_bytes());
        w.u8(addrs.len() as u8);
        for a in addrs {
            match a {
                SocketAddr::V4(v4) => {
                    w.u8(4);
                    w.raw(&v4.ip().octets());
                }
                SocketAddr::V6(v6) => {
                    w.u8(6);
                    w.raw(&v6.ip().octets());
                    w.raw(&v6.scope_id().to_be_bytes());
                }
            }
            w.u16(a.port());
        }
    }
    Some(w.0)
}

/// Decode a saved entry. Anything malformed is dropped whole (it is only a
/// hint); addresses that aren't LAN addresses are skipped.
pub(crate) fn decode(b: &[u8], allow_loopback: bool) -> BTreeMap<DeviceId, Vec<SocketAddr>> {
    fn inner(b: &[u8], allow_loopback: bool) -> Option<BTreeMap<DeviceId, Vec<SocketAddr>>> {
        let mut r = Reader::new(b);
        if r.u8()? != FORMAT {
            return None;
        }
        let mut out = BTreeMap::new();
        for _ in 0..r.u8()?.min(MAX_PEERS as u8) {
            let id = DeviceId::from_bytes(r.arr32()?).ok()?;
            let mut addrs = Vec::new();
            for _ in 0..r.u8()? {
                let ip: SocketAddr = match r.u8()? {
                    4 => {
                        let o: [u8; 4] = r.take(4)?.try_into().ok()?;
                        SocketAddr::from((o, r.u16()?))
                    }
                    6 => {
                        let o: [u8; 16] = r.take(16)?.try_into().ok()?;
                        let scope = u32::from_be_bytes(r.take(4)?.try_into().ok()?);
                        let port = r.u16()?;
                        SocketAddr::V6(SocketAddrV6::new(o.into(), port, 0, scope))
                    }
                    _ => return None,
                };
                addrs.push(ip);
            }
            let lan = lan_only(&addrs, allow_loopback);
            if !lan.is_empty() {
                out.insert(id, lan);
            }
        }
        r.is_empty().then_some(out)
    }
    inner(b, allow_loopback).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_private_and_link_local_addresses_are_kept() {
        for ok in [
            "10.1.2.3:1",
            "172.16.0.9:1",
            "172.31.255.1:1",
            "192.168.1.20:1",
            "169.254.3.4:1",
            "[fd12:3456::1]:1",
            "[fc00::1]:1",
            "[fe80::1]:1",
            "[::ffff:192.168.0.2]:1",
        ] {
            assert!(is_lan_ip(a(ok).ip(), false), "{ok}");
        }
        for bad in [
            "8.8.8.8:1",
            "172.32.0.1:1",
            "100.64.0.1:1",
            "1.1.1.1:1",
            "[2606:4700::1111]:1",
            "[2001:db8::1]:1",
            "[::ffff:8.8.8.8]:1",
            "0.0.0.0:1",
            "255.255.255.255:1",
            "224.0.0.251:1",
            "[ff02::fb]:1",
            "127.0.0.1:1",
            "[::1]:1",
        ] {
            assert!(!is_lan_ip(a(bad).ip(), false), "{bad}");
        }
        assert!(is_lan_ip(a("127.0.0.1:1").ip(), true));
        assert!(!is_lan_ip(a("8.8.8.8:1").ip(), true));
    }

    #[test]
    fn lan_only_filters_dedups_and_caps() {
        let got = lan_only(
            &[
                a("8.8.8.8:5"),
                a("192.168.1.2:5"),
                a("192.168.1.2:5"),
                a("192.168.1.2:0"),
                a("10.0.0.1:5"),
                a("10.0.0.2:5"),
                a("[fe80::1]:5"),
                a("10.0.0.3:5"),
            ],
            false,
        );
        assert_eq!(
            got,
            vec![
                a("192.168.1.2:5"),
                a("10.0.0.1:5"),
                a("10.0.0.2:5"),
                a("[fe80::1]:5")
            ]
        );
    }

    #[test]
    fn round_trip_drops_public_addresses_and_empty_peers() {
        let p1 = crate::keys::DeviceKeypair::generate().device_id();
        let p2 = crate::keys::DeviceKeypair::generate().device_id();
        let v1 = [
            a("192.168.1.2:7"),
            a("1.2.3.4:7"),
            SocketAddr::V6(SocketAddrV6::new("fe80::9".parse().unwrap(), 7, 0, 3)),
        ];
        let v2 = [a("8.8.8.8:7")];
        let enc = encode([(&p1, &v1[..]), (&p2, &v2[..])].into_iter(), false).unwrap();
        let back = decode(&enc, false);
        assert_eq!(back.len(), 1);
        assert_eq!(back[&p1], vec![v1[0], v1[2]]);
        assert!(encode([(&p2, &v2[..])].into_iter(), false).is_none());
        // Damaged: dropped whole, never a panic.
        for cut in 0..enc.len() {
            let _ = decode(&enc[..cut], false);
        }
        assert!(decode(&enc[..enc.len() - 1], false).is_empty());
        assert!(decode(&[9, 0], false).is_empty());
        // Loopback saved only when allowed (tests on one host).
        let lo = [a("127.0.0.1:9")];
        assert!(encode([(&p1, &lo[..])].into_iter(), false).is_none());
        let enc = encode([(&p1, &lo[..])].into_iter(), true).unwrap();
        assert!(decode(&enc, false).is_empty());
        assert_eq!(decode(&enc, true)[&p1], lo.to_vec());
    }
}
