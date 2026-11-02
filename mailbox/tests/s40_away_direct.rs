//! S40: a pairing on an away relay goes direct on the LAN without mDNS.
//!
//! An away endpoint is relay-only, so such a pairing could only go direct
//! when mDNS found the peer; on a LAN where mDNS doesn't get through it
//! stayed on the relay for good. Now both sides swap their main endpoint's
//! LAN addresses over the away connection and dial each other directly.
//! Here mDNS is off in config and the LAN is loopback.
mod common;
use common::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use voidwire_core::net::pc::PcEvent;
use voidwire_core::net::relays::RelayError;
use voidwire_core::net::saved_peer_lan_for_tests;
use voidwire_core::net::DeliveryPath;

fn setup() {
    voidwire_core::net::away::set_away_idle_ms_for_tests(400);
}

fn save_relay(d: &Dev, b: &RelayBox) {
    let m = b.server.device_id().to_hex();
    let r = match d {
        Dev::Pc { node, .. } => node.add_relay(&b.url(), &m, ""),
        Dev::Phone { node, .. } => node.add_relay(&b.url(), &m, ""),
    };
    assert!(matches!(r, Ok(()) | Err(RelayError::Duplicate)), "{r:?}");
}

/// A PC homed on `home`, no mDNS, loopback counts as LAN (one host).
fn lan_pc(name: &str, home: String, root: &Path, store: Arc<MemoryStateStore>) -> Dev {
    lan_pc_events(name, home, root, store, None)
}

fn lan_pc_events(
    name: &str,
    home: String,
    root: &Path,
    store: Arc<MemoryStateStore>,
    rejected: Option<Arc<AtomicUsize>>,
) -> Dev {
    let dl = root.join(format!("{name}-dl"));
    std::fs::create_dir_all(&dl).unwrap();
    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new(name, store, spy.clone())
        .with_download_dir(dl.clone())
        .with_auto_accept_files(true);
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.inbox = roomy();
    cfg.relay_url = Some(home);
    if let Some(n) = rejected {
        cfg.events = Some(Arc::new(move |e| {
            if matches!(e, PcEvent::Rejected { .. }) {
                n.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    let node = PcNode::start(cfg).expect("pc");
    Dev::Pc { node, spy, dl }
}

fn path_of(d: &Dev, to: &DeviceId, url: &str) -> DeliveryPath {
    match d {
        Dev::Pc { node, .. } => node.send_url_to_phone(to, url).expect("send").delivery_path,
        Dev::Phone { node, .. } => node.send_url(to, url).expect("send").delivery_path,
    }
}

/// Sends from `from` to `to` until one goes direct; how many it took.
/// The first one may still use the relay (the upgrade runs beside it).
fn sends_until_direct(from: &Dev, to: &DeviceId, tag: &str) -> usize {
    for i in 1..=12 {
        if path_of(from, to, &format!("https://example.com/{tag}/{i}")) == DeliveryPath::Direct {
            return i;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("{tag}: never went direct");
}

fn store_of(s: &Arc<MemoryStateStore>) -> &dyn voidwire_core::net::state::StateStore {
    &**s
}

/// Two PCs homed on H, pairing on away relay V, no mDNS: direct within a
/// couple of sends, both ways; the addresses are saved; and again after
/// both restart (new ports, so the saved ones are stale).
#[test]
fn away_pc_pc_goes_direct_without_mdns() {
    setup();
    let root = temp_dir("s40-pcpc");
    let h = RelayBox::start();
    let v = RelayBox::start();
    let sa = Arc::new(MemoryStateStore::default());
    let sb = Arc::new(MemoryStateStore::default());
    let a = lan_pc("PC A", h.url(), &root, sa.clone());
    let b = lan_pc("PC B", h.url(), &root, sb.clone());
    pair(&a, &b, false, Some(v.rref()));
    save_relay(&a, &v);
    save_relay(&b, &v);
    let (ai, bi) = (a.id(), b.id());
    wait("both on V", || {
        v.relay.has_peer(&ai) && v.relay.has_peer(&bi)
    });
    assert!(sends_until_direct(&a, &bi, "ab") <= 3);
    assert_eq!(
        path_of(&b, &ai, "https://example.com/ba"),
        DeliveryPath::Direct
    );
    assert!(saved_peer_lan_for_tests(store_of(&sa)).contains_key(&bi));
    assert!(saved_peer_lan_for_tests(store_of(&sb)).contains_key(&ai));

    let (Dev::Pc { node: na, .. }, Dev::Pc { node: nb, .. }) = (a, b) else {
        unreachable!()
    };
    na.shutdown();
    nb.shutdown();
    let a = lan_pc("PC A", h.url(), &root, sa.clone());
    let b = lan_pc("PC B", h.url(), &root, sb.clone());
    wait("both on V again", || {
        v.relay.has_peer(&ai) && v.relay.has_peer(&bi)
    });
    assert!(sends_until_direct(&a, &bi, "ab2") <= 3);
    assert_eq!(
        path_of(&b, &ai, "https://example.com/ba2"),
        DeliveryPath::Direct
    );
    let (Dev::Pc { node: na, .. }, Dev::Pc { node: nb, .. }) = (a, b) else {
        unreachable!()
    };
    na.shutdown();
    nb.shutdown();
}

/// A PC and a phone (app open), pairing on away relay V, no mDNS: direct
/// both ways, also after the phone app restarts (new port).
#[test]
fn away_pc_phone_goes_direct_without_mdns() {
    setup();
    let root = temp_dir("s40-pcph");
    let h = RelayBox::start();
    let v = RelayBox::start();
    let sa = Arc::new(MemoryStateStore::default());
    let sp = Arc::new(MemoryStateStore::default());
    let a = lan_pc("PC A", h.url(), &root, sa.clone());
    let p = phone_on("Phone A", Some(h.url()), &root, sp.clone());
    pair(&a, &p, false, Some(v.rref()));
    save_relay(&a, &v);
    save_relay(&p, &v);
    let (ai, pi) = (a.id(), p.id());
    wait("both on V", || {
        v.relay.has_peer(&ai) && v.relay.has_peer(&pi)
    });
    assert!(sends_until_direct(&a, &pi, "ap") <= 3);
    assert_eq!(
        path_of(&p, &ai, "https://example.com/pa"),
        DeliveryPath::Direct
    );
    assert!(saved_peer_lan_for_tests(store_of(&sa)).contains_key(&pi));
    assert!(saved_peer_lan_for_tests(store_of(&sp)).contains_key(&ai));

    let Dev::Phone { node, .. } = p else {
        unreachable!()
    };
    drop(node);
    let p = phone_on("Phone A", Some(h.url()), &root, sp.clone());
    wait("phone on V again", || v.relay.has_peer(&pi));
    assert!(sends_until_direct(&p, &ai, "pa2") <= 3);
    // One more to the phone only: its inbox allows a burst of 5 per PC.
    assert_eq!(
        path_of(&a, &pi, "https://example.com/ap2"),
        DeliveryPath::Direct
    );
    drop(p);
    let Dev::Pc { node, .. } = a else {
        unreachable!()
    };
    node.shutdown();
}

/// A peer from before S40 treats the hello as an unknown frame: sends keep
/// working (on the relay), and it reports nothing as refused.
#[test]
fn pre_s40_peer_ignores_the_upgrade() {
    setup();
    let root = temp_dir("s40-old");
    let h = RelayBox::start();
    let v = RelayBox::start();
    let rejected = Arc::new(AtomicUsize::new(0));
    let old = lan_pc_events(
        "Old PC",
        h.url(),
        &root,
        Arc::new(MemoryStateStore::default()),
        Some(rejected.clone()),
    );
    let Dev::Pc { node, .. } = &old else {
        unreachable!()
    };
    node.act_pre_s40_for_tests();
    let new = lan_pc(
        "New PC",
        h.url(),
        &root,
        Arc::new(MemoryStateStore::default()),
    );
    pair(&old, &new, false, Some(v.rref()));
    save_relay(&old, &v);
    save_relay(&new, &v);
    let (oi, ni) = (old.id(), new.id());
    wait("both on V", || {
        v.relay.has_peer(&oi) && v.relay.has_peer(&ni)
    });
    for i in 0..4 {
        assert_eq!(
            path_of(&new, &oi, &format!("https://example.com/no/{i}")),
            DeliveryPath::Relayed
        );
        wait("old got it", || {
            old.got_url(&format!("https://example.com/no/{i}"))
        });
        assert_eq!(
            path_of(&old, &ni, &format!("https://example.com/on/{i}")),
            DeliveryPath::Relayed
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    assert_eq!(
        rejected.load(Ordering::SeqCst),
        0,
        "nothing shown as refused"
    );
    for d in [old, new] {
        let Dev::Pc { node, .. } = d else {
            unreachable!()
        };
        node.shutdown();
    }
}
