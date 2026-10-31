//! H1: an unpaired peer costs the product no parse and no decrypt, on the PC
//! and on the phone. Real nodes over loopback; the process-wide probe
//! counters (`voidwire_core::probe`) count HPKE opens and accepted app
//! streams. This binary holds only these tests and runs them one at a time,
//! so the counters see nothing else.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use voidwire_core::keys::Platform;
use voidwire_core::net::pc::{PcConfig, PcNode};
use voidwire_core::net::phone::{PhoneClient, PhoneConfig};
use voidwire_core::net::state::MemoryStateStore;
use voidwire_core::net::{pair_v2_for_tests, NetError, V2Node};
use voidwire_core::probe::{app_streams_accepted, envelope_opens};
use voidwire_core::reject::RejectReason;
use voidwire_core::test_util::SharedSpyOpener;

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn pc(name: &str) -> PcNode {
    let mut cfg = PcConfig::new(
        name,
        Arc::new(MemoryStateStore::default()),
        Arc::new(SharedSpyOpener::default()),
    );
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some("off".into());
    PcNode::start(cfg).expect("pc")
}

fn phone(name: &str) -> PhoneClient {
    let p = PhoneClient::new(PhoneConfig {
        state: Arc::new(MemoryStateStore::default()),
        default_name: name.into(),
        platform: Platform::Android,
        mdns: false,
    })
    .expect("phone");
    p.set_relay_url(Some("off".into())).unwrap();
    p
}

fn loopback(v: Vec<SocketAddr>) -> Vec<SocketAddr> {
    v.into_iter()
        .filter(|a| a.is_ipv4())
        .map(|a| SocketAddr::from(([127, 0, 0, 1], a.port())))
        .collect()
}

fn pair(pc: &PcNode, p: &PhoneClient) {
    pair_v2_for_tests(
        V2Node::Pc(pc),
        loopback(pc.bound_sockets()),
        V2Node::Phone(p),
        loopback(p.bound_sockets_for_tests()),
        None,
    )
    .expect("v2 pair");
}

fn rejected(r: Result<impl std::fmt::Debug, NetError>) -> RejectReason {
    match r {
        Err(NetError::Rejected(r)) => r,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

/// Phone side: a PC holding a pairing the phone never accepted is closed at
/// the connection. The phone accepts no stream from it, opens nothing, and
/// lists nothing; a paired PC still delivers.
#[test]
fn phone_refuses_unpaired_pc_before_reading() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
    let real = pc("Real PC");
    let outsider = pc("Outsider PC");
    let p = phone("Phone");
    pair(&real, &p);
    let phone_id = p.device_id();
    let (ok, ocert) = outsider.v2_identity_for_tests();
    let (pk, pcert) = p.v2_identity_for_tests();
    let (ours, _) = voidwire_core::pairwise::v2::pair_for_tests(&ok, ocert, &pk, pcert, None);
    outsider
        .adopt_v2_pairing_for_tests(ours, loopback(p.bound_sockets_for_tests()))
        .unwrap();

    let (o0, s0) = (envelope_opens(), app_streams_accepted());
    for i in 0..3 {
        assert_eq!(
            rejected(outsider.send_url_to_phone(&phone_id, &format!("https://example.com/o{i}"))),
            RejectReason::NotPaired
        );
    }
    assert_eq!(envelope_opens(), o0, "phone opened an outsider envelope");
    assert_eq!(
        app_streams_accepted(),
        s0,
        "phone accepted a stream from an unpaired PC"
    );
    assert!(p.poll_incoming().items.is_empty());

    real.send_url_to_phone(&phone_id, "https://example.com/real")
        .expect("paired PC still delivers");
    assert!(envelope_opens() > o0, "probe counts the phone's opens");
    assert!(
        app_streams_accepted() > s0,
        "probe counts the phone's streams"
    );
    let items = p.poll_incoming().items;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].payload_text, "https://example.com/real");
}

/// PC side: a phone holding a pairing the PC never accepted is closed at the
/// connection, with no stream accepted and no envelope opened; a paired phone
/// still delivers.
#[test]
fn pc_refuses_unpaired_phone_before_reading() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
    let host = pc("PC");
    let real = phone("Real Phone");
    let outsider = phone("Outsider Phone");
    pair(&host, &real);
    let pc_id = host.device_id();
    let (pk, pcert) = host.v2_identity_for_tests();
    let (ok, ocert) = outsider.v2_identity_for_tests();
    let (_, theirs) = voidwire_core::pairwise::v2::pair_for_tests(&pk, pcert, &ok, ocert, None);
    outsider
        .adopt_v2_pairing_for_tests(theirs, loopback(host.bound_sockets()))
        .unwrap();

    let (o0, s0) = (envelope_opens(), app_streams_accepted());
    for i in 0..3 {
        assert_eq!(
            rejected(outsider.send_url(&pc_id, &format!("https://example.com/o{i}"))),
            RejectReason::NotPaired
        );
    }
    assert_eq!(envelope_opens(), o0, "PC opened an outsider envelope");
    assert_eq!(
        app_streams_accepted(),
        s0,
        "PC accepted a stream from an unpaired phone"
    );

    real.send_url(&pc_id, "https://example.com/real")
        .expect("paired phone still delivers");
    assert!(envelope_opens() > o0, "probe counts the PC's opens");
    assert!(app_streams_accepted() > s0, "probe counts the PC's streams");
}
