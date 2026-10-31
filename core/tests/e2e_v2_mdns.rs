//! mDNS discovery on v2 pairings (set VOIDWIRE_E2E_MDNS=1; needs
//! multicast), and the phone's no-standing-lookup rule.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use voidwire_core::keys::Platform;
use voidwire_core::net::pc::{PcConfig, PcNode};
use voidwire_core::net::phone::{PhoneClient, PhoneConfig};
use voidwire_core::net::state::MemoryStateStore;
use voidwire_core::net::{pair_v2_for_tests, SendOutcome, V2Node};
use voidwire_core::test_util::SharedSpyOpener;
use voidwire_core::time::Stopwatch;

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

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Discovery without address hints: the phone finds the PC by mDNS/DNS-SD
/// only. Needs multicast on a real interface, so it's opt-in:
/// `VOIDWIRE_E2E_MDNS=1 cargo test -p voidwire-core --features net --test e2e_net`.
#[test]
fn e2e_mdns_discovery_without_hints() {
    if std::env::var("VOIDWIRE_E2E_MDNS").as_deref() != Ok("1") {
        eprintln!("skipped (set VOIDWIRE_E2E_MDNS=1)");
        return;
    }
    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new(
        "mDNS PC",
        Arc::new(MemoryStateStore::default()),
        spy.clone(),
    );
    cfg.port = Some(0);
    cfg.relay_url = Some("off".into());
    cfg.unchecked_inbox_for_tests = true;
    let pc = PcNode::start(cfg).unwrap();
    let pc_id = pc.device_id();
    pc.set_no_prompt(true).unwrap();
    let phone_state: Arc<dyn voidwire_core::net::state::StateStore> =
        Arc::new(MemoryStateStore::default());
    let p = PhoneClient::new(PhoneConfig {
        state: phone_state.clone(),
        default_name: "mDNS Phone".into(),
        platform: Platform::Android,
        mdns: true,
    })
    .unwrap();
    p.set_relay_url(Some("off".into())).unwrap();
    // Pairing gives the phone the PC's address; the sends below find the
    // PC again by mDNS once that address goes stale.
    pair_v2_for_tests(
        V2Node::Pc(&pc),
        loopback(pc.bound_sockets()),
        V2Node::Phone(&p),
        loopback(p.bound_sockets_for_tests()),
        None,
    )
    .expect("v2 pair");
    let r = p.send_url(&pc_id, "https://example.com/mdns").unwrap();
    println!(
        "E2E mDNS: first send {:.2} ms",
        r.latency_us as f64 / 1000.0
    );
    assert_eq!(spy.count(), 1);

    // Poisoned cached address (another device answers there): the phone
    // falls back to a fresh mDNS lookup once, reaches the right PC, and
    // replaces the cached address.
    let rogue = PhoneClient::new(PhoneConfig {
        state: Arc::new(MemoryStateStore::default()),
        default_name: "Rogue".into(),
        platform: Platform::Android,
        mdns: false,
    })
    .unwrap();
    let rogue_port = rogue.bound_sockets_for_tests()[0].port();
    let poisoned: std::net::SocketAddr = ([127, 0, 0, 1], rogue_port).into();
    p.set_pc_addrs_for_tests(&pc_id, vec![poisoned]);
    let t = Stopwatch::start();
    let r = p
        .send_url(&pc_id, "https://example.com/after-poison")
        .expect("fell back to mDNS");
    println!(
        "E2E mDNS fallback after a poisoned address: {:.1} ms",
        t.elapsed_us() as f64 / 1000.0
    );
    assert_eq!(r.outcome, SendOutcome::Opened);
    assert_eq!(spy.count(), 2);
    let addrs = &p.paired_pcs()[0].addrs;
    assert!(
        !addrs.contains(&poisoned),
        "cached address replaced: {addrs:?}"
    );
    // A dead cached address (nothing listening) also falls back.
    p.set_pc_addrs_for_tests(&pc_id, vec![([127, 0, 0, 1], free_udp_port()).into()]);
    p.send_url(&pc_id, "https://example.com/after-dead")
        .expect("fell back to mDNS");
    assert_eq!(spy.count(), 3);

    // L3: a COLD process (the share sheet's usual case): a fresh phone
    // client whose cached address is answered fast by the wrong device.
    // mDNS has no answers yet; the fallback must wait (bounded) for one
    // instead of failing in ~20 ms.
    drop(p);
    let cold = PhoneClient::new(PhoneConfig {
        state: phone_state,
        default_name: "ignored".into(),
        platform: Platform::Android,
        mdns: true,
    })
    .unwrap();
    // QA's case: the cached address is another *PC* (TLS fails fast with
    // the wrong identity), not a dead port.
    let mut evil_cfg = PcConfig::new(
        "Evil PC",
        Arc::new(MemoryStateStore::default()),
        Arc::new(SharedSpyOpener::default()),
    );
    evil_cfg.mdns = false;
    evil_cfg.relay_url = Some("off".into());
    let evil_port = free_udp_port();
    evil_cfg.port = Some(evil_port);
    evil_cfg.advertise_loopback = true;
    evil_cfg.unchecked_inbox_for_tests = true;
    let evil = PcNode::start(evil_cfg).unwrap();
    let evil_addr: std::net::SocketAddr = ([127, 0, 0, 1], evil_port).into();
    cold.set_pc_addrs_for_tests(&pc_id, vec![evil_addr]);
    let t = Stopwatch::start();
    let r = cold
        .send_url(&pc_id, "https://example.com/cold-fallback")
        .expect("cold process fell back to mDNS");
    let cold_ms = t.elapsed_us() as f64 / 1000.0;
    println!("E2E mDNS fallback from a cold process: {cold_ms:.1} ms");
    assert_eq!(r.outcome, SendOutcome::Opened);
    assert_eq!(spy.count(), 4);
    assert!(cold_ms < 2_000.0 + 8_000.0, "bounded");

    // The wait is bounded: an unknown PC gives up after MDNS_FALLBACK_WAIT.
    let nobody = voidwire_core::keys::DeviceKeypair::generate().device_id();
    let t = Stopwatch::start();
    let found = cold.discover_for_tests(&nobody, voidwire_core::net::phone::MDNS_FALLBACK_WAIT);
    let waited_ms = t.elapsed_us() / 1000;
    assert!(found.is_empty());
    assert!((1_900..3_000).contains(&waited_ms), "waited {waited_ms} ms");
    evil.shutdown();
    pc.shutdown();
}

/// 0.8.1 field test: a phone with mDNS on kept a standing lookup that
/// multicast a query every 0.7 s for as long as the process lived, the
/// background included (~35 MB/day on Wi-Fi). mDNS is now asked only while
/// dialling, so an idle phone has no lookup running.
#[test]
fn phone_has_no_standing_mdns_lookup() {
    let p = PhoneClient::new(PhoneConfig {
        state: Arc::new(MemoryStateStore::default()),
        default_name: "Idle Phone".into(),
        platform: Platform::Android,
        mdns: true,
    })
    .unwrap();
    assert_eq!(p.standing_lookups_for_tests(), 0);
    // Asked per dial, bounded, and gone afterwards.
    let nobody = voidwire_core::keys::DeviceKeypair::generate().device_id();
    let t = Stopwatch::start();
    assert!(p
        .discover_for_tests(&nobody, Duration::from_millis(600))
        .is_empty());
    assert!(t.elapsed_us() < 3_000_000, "bounded");
    assert_eq!(p.standing_lookups_for_tests(), 0);
}

/// L3 without multicast: with no address lookup configured, the fallback
/// helper returns at once (nothing to wait for).
#[test]
fn e2e_mdns_wait_without_lookup_returns_immediately() {
    let p = phone("No mDNS");
    let nobody = voidwire_core::keys::DeviceKeypair::generate().device_id();
    let t = Stopwatch::start();
    assert!(p
        .discover_for_tests(&nobody, Duration::from_secs(2))
        .is_empty());
    assert!(t.elapsed_us() < 500_000, "no lookup: no wait");
}
