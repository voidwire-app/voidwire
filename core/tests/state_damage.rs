//! A PC state file whose pairings section was damaged must not load: the
//! section is keyed-MAC'd, so a flipped byte in a pairing (public fields or
//! sealed secrets) or in the tag itself fails closed instead of loading a
//! pairing an attacker edited.

use std::sync::Arc;

use voidwire_core::keys::Platform;
use voidwire_core::net::pc::{PcConfig, PcNode};
use voidwire_core::net::phone::{PhoneClient, PhoneConfig};
use voidwire_core::net::state::{MemoryStateStore, StateStore};
use voidwire_core::net::{pair_v2_for_tests, NetError, V2Node};
use voidwire_core::test_util::SharedSpyOpener;

fn loopback(v: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    v.into_iter()
        .filter(|a| a.is_ipv4())
        .map(|a| std::net::SocketAddr::from(([127, 0, 0, 1], a.port())))
        .collect()
}

fn pc(store: Arc<MemoryStateStore>) -> Result<PcNode, NetError> {
    let mut cfg = PcConfig::new("PC", store, Arc::new(SharedSpyOpener::default()));
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some("off".into());
    PcNode::start(cfg)
}

/// A saved PC state holding one v2 pairing.
fn paired_state() -> Vec<u8> {
    let store = Arc::new(MemoryStateStore::default());
    let node = pc(store.clone()).unwrap();
    let phone = PhoneClient::new(PhoneConfig {
        state: Arc::new(MemoryStateStore::default()),
        default_name: "Phone".into(),
        platform: Platform::Android,
        mdns: false,
    })
    .unwrap();
    phone.set_relay_url(Some("off".into())).unwrap();
    pair_v2_for_tests(
        V2Node::Pc(&node),
        loopback(node.bound_sockets()),
        V2Node::Phone(&phone),
        loopback(phone.bound_sockets_for_tests()),
        None,
    )
    .expect("v2 pair");
    assert_eq!(node.pairings().len(), 1);
    node.shutdown();
    store.load().unwrap().unwrap()
}

fn loads(blob: &[u8]) -> bool {
    let s = Arc::new(MemoryStateStore::default());
    s.save(blob).unwrap();
    match pc(s) {
        Ok(n) => {
            n.shutdown();
            true
        }
        Err(_) => false,
    }
}

#[test]
fn damaged_pairings_section_fails_closed() {
    let blob = paired_state();
    assert_eq!(&blob[..6], b"VWPC3\n");
    assert!(loads(&blob), "the untouched state must load");
    // The pairings section is last and ends with a 32-byte keyed MAC: flip
    // a byte of the MAC, then one just before it (inside the section body).
    for off in [1, 33, 60] {
        let mut bad = blob.clone();
        let i = bad.len() - off;
        bad[i] ^= 0x55;
        assert!(
            !loads(&bad),
            "a damaged pairings section must not load ({off})"
        );
    }
}

/// A damaged VWPC3 file never resets to a fresh identity: start fails.
#[test]
fn damaged_v3_file_does_not_reset() {
    let blob = paired_state();
    for bad in [
        blob[..blob.len() - 40].to_vec(),
        // flags: an unknown bit
        {
            let mut b = blob.clone();
            b[6 + 64] |= 0x80;
            b
        },
        // a byte inside the own cert
        {
            let mut b = blob.clone();
            b[6 + 64 + 1 + 2 + 10] ^= 1;
            b
        },
    ] {
        assert!(!loads(&bad), "a damaged state must not load");
    }
}

/// The own cert must be this identity's own: one signed by another key,
/// or a re-signed one for another device, fails closed.
#[test]
fn own_cert_swapped_or_resigned_fails_closed() {
    use voidwire_core::keys::{DeviceCert, DeviceKeypair, ReceiveKeypair};
    use voidwire_core::time::UnixMillis;
    let blob = paired_state();
    let len = u16::from_be_bytes([blob[71], blob[72]]) as usize;
    let at = 73;
    let swap = |cert: &DeviceCert| {
        let mut b = blob[..71].to_vec();
        b.extend_from_slice(&(cert.as_bytes().len() as u16).to_be_bytes());
        b.extend_from_slice(cert.as_bytes());
        b.extend_from_slice(&blob[at + len..]);
        b
    };
    let other = DeviceKeypair::generate();
    let stranger = DeviceCert::issue(
        &other,
        ReceiveKeypair::generate().public(),
        "PC",
        Platform::current(),
        UnixMillis(1),
    )
    .unwrap();
    assert!(!loads(&swap(&stranger)), "another device's cert");
    // Our identity, but a receive key that isn't ours.
    let me = DeviceKeypair::from_secret_bytes(&blob[6..38].try_into().unwrap());
    let resigned = DeviceCert::issue(
        &me,
        ReceiveKeypair::generate().public(),
        "PC",
        Platform::current(),
        UnixMillis(1),
    )
    .unwrap();
    assert!(!loads(&swap(&resigned)), "a re-signed cert");
    // Our own cert, re-inserted the same way, still loads.
    let own = DeviceCert::parse_verified(&blob[at..at + len]).unwrap();
    assert!(loads(&swap(&own)));
}
