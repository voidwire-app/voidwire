//! S39: each device keeps the last private LAN addresses of its paired
//! peers in the settings file, so after a restart a send goes direct at
//! once instead of through the relay (or not at all). Only paired peers are
//! kept: Forget and a state reset drop them. And the phone tells every
//! endpoint about an OS network change.
#![cfg(all(feature = "net", feature = "test-util"))]

use std::net::SocketAddr;
use std::sync::Arc;

use voidwire_core::keys::Platform;
use voidwire_core::net::pc::{PcConfig, PcNode};
use voidwire_core::net::phone::{PhoneClient, PhoneConfig};
use voidwire_core::net::state::{FileStateStore, MemoryStateStore, StateStore};
use voidwire_core::net::{pair_v2_for_tests, saved_peer_lan_for_tests, DeliveryPath, V2Node};
use voidwire_core::test_util::SharedSpyOpener;

fn loopback(v: Vec<SocketAddr>) -> Vec<SocketAddr> {
    v.into_iter()
        .filter(|a| a.is_ipv4())
        .map(|a| SocketAddr::from(([127, 0, 0, 1], a.port())))
        .collect()
}

fn pc(name: &str, state: Arc<dyn StateStore>, dir: &std::path::Path) -> PcNode {
    let mut cfg = PcConfig::new(name, state, Arc::new(SharedSpyOpener::default()))
        .with_download_dir(dir.to_path_buf());
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some("off".into());
    PcNode::start(cfg).expect("pc")
}

fn temp(tag: &str) -> std::path::PathBuf {
    let uniq = voidwire_core::keys::DeviceKeypair::generate()
        .device_id()
        .to_hex();
    let d = std::env::temp_dir().join(format!("vw-s39-{tag}-{}", &uniq[..16]));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn pair(a: &PcNode, b: &PcNode) {
    pair_v2_for_tests(
        V2Node::Pc(a),
        loopback(a.bound_sockets()),
        V2Node::Pc(b),
        loopback(b.bound_sockets()),
        None,
    )
    .expect("pair");
}

/// Round-2 sheet step 16: after a restart PC B knew no address for PC A
/// until A dialled in, so its first send went through the relay. With no
/// relay at all (as here) it couldn't reach A live. Now B dials A's saved
/// LAN address at once.
#[test]
fn pc_restart_sends_direct_on_saved_lan_address() {
    let dir = temp("restart");
    let a = pc(
        "Desk A",
        Arc::new(MemoryStateStore::default()),
        &dir.join("a"),
    );
    let b_state: Arc<dyn StateStore> = Arc::new(MemoryStateStore::default());
    let b = pc("Desk B", b_state.clone(), &dir.join("b"));
    pair(&a, &b);
    let saved = saved_peer_lan_for_tests(&*b_state);
    assert_eq!(saved.get(&a.device_id()).map(|v| !v.is_empty()), Some(true));
    let a_id = a.device_id();
    b.shutdown();

    let b = pc("Desk B", b_state.clone(), &dir.join("b"));
    let r = b
        .send_url_to_phone(&a_id, "https://example.com/after-restart")
        .expect("send after restart");
    assert_eq!(r.delivery_path, DeliveryPath::Direct, "straight to PC A");
    b.shutdown();
    a.shutdown();
}

/// Forget removes the peer's saved addresses; a state reset (state file
/// gone, settings file kept) removes all of them.
#[test]
fn forget_and_reset_clear_saved_addresses() {
    let dir = temp("forget");
    let a = pc(
        "Desk A",
        Arc::new(MemoryStateStore::default()),
        &dir.join("a"),
    );
    let c = pc(
        "Desk C",
        Arc::new(MemoryStateStore::default()),
        &dir.join("c"),
    );
    let b_state: Arc<dyn StateStore> = Arc::new(FileStateStore::new(dir.join("state.bin")));
    let b = pc("Desk B", b_state.clone(), &dir.join("b"));
    pair(&a, &b);
    pair(&c, &b);
    let saved = saved_peer_lan_for_tests(&*b_state);
    assert!(saved.contains_key(&a.device_id()));
    assert!(saved.contains_key(&c.device_id()));

    assert!(b.forget_device(&a.device_id()).expect("forget"));
    let saved = saved_peer_lan_for_tests(&*b_state);
    assert!(!saved.contains_key(&a.device_id()), "Forget drops them");
    assert!(saved.contains_key(&c.device_id()), "others kept");
    b.shutdown();

    // Reset: the state file goes, the settings file stays.
    std::fs::remove_file(dir.join("state.bin")).expect("reset");
    assert!(!saved_peer_lan_for_tests(&*b_state).is_empty());
    let b = pc("Desk B", b_state.clone(), &dir.join("b"));
    assert!(
        saved_peer_lan_for_tests(&*b_state).is_empty(),
        "reset drops them"
    );
    b.shutdown();
    a.shutdown();
    c.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A phone's PC addresses survive a restart too.
#[test]
fn phone_restart_keeps_pc_lan_address() {
    let dir = temp("phone");
    let a = pc(
        "Desk A",
        Arc::new(MemoryStateStore::default()),
        &dir.join("a"),
    );
    let p_state: Arc<dyn StateStore> = Arc::new(MemoryStateStore::default());
    let start = || {
        let p = PhoneClient::new(PhoneConfig {
            state: p_state.clone(),
            default_name: "Phone".into(),
            platform: Platform::Android,
            mdns: false,
        })
        .expect("phone");
        p.set_relay_url(Some("off".into())).unwrap();
        p
    };
    let p = start();
    pair_v2_for_tests(
        V2Node::Pc(&a),
        loopback(a.bound_sockets()),
        V2Node::Phone(&p),
        loopback(p.bound_sockets_for_tests()),
        None,
    )
    .expect("pair");
    assert!(saved_peer_lan_for_tests(&*p_state).contains_key(&a.device_id()));
    drop(p);
    let p = start();
    let r = p
        .send_url(&a.device_id(), "https://example.com/phone-restart")
        .expect("send after restart");
    assert_eq!(r.delivery_path, DeliveryPath::Direct);
    assert!(p.forget_pc(&a.device_id()).is_ok());
    assert!(
        saved_peer_lan_for_tests(&*p_state).is_empty(),
        "Forget drops them"
    );
    drop(p);
    a.shutdown();
}

/// Item 2 of S39: an OS network change reaches the main endpoint and
/// every away endpoint (iroh rebinds and redoes relay links; Android
/// doesn't tell it otherwise).
#[test]
fn network_change_reaches_every_endpoint() {
    let p = PhoneClient::new(PhoneConfig {
        state: Arc::new(MemoryStateStore::default()),
        default_name: "Phone".into(),
        platform: Platform::Android,
        mdns: false,
    })
    .expect("phone");
    p.set_relay_url(Some("off".into())).unwrap();
    let before = p.network_changes_for_tests();
    p.network_changed();
    let away = p.away_endpoints_for_tests() as u64;
    assert_eq!(p.network_changes_for_tests() - before, 1 + away);
}
