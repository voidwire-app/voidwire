//! QA 10-13 (Medium): "Forget" whose state write fails must roll back.
//! The device stays paired in memory, is not told it was removed, can keep
//! sending, and a later Forget (once the disk is writable) works normally.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use voidwire_core::keys::Platform;
use voidwire_core::net::pc::{PcConfig, PcNode};
use voidwire_core::net::phone::{PhoneClient, PhoneConfig};
use voidwire_core::net::state::{MemoryStateStore, StateStore};
use voidwire_core::net::{pair_v2_for_tests, NetError, SendOutcome, V2Node};
use voidwire_core::test_util::SharedSpyOpener;

/// Memory store whose writes can be made to fail (a read-only data dir).
#[derive(Default)]
struct FlakyStore {
    inner: MemoryStateStore,
    fail: AtomicBool,
}

impl StateStore for FlakyStore {
    fn load(&self) -> Result<Option<Vec<u8>>, String> {
        self.inner.load()
    }
    fn save(&self, data: &[u8]) -> Result<(), String> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("write state: Permission denied (test)".into());
        }
        self.inner.save(data)
    }
}

fn loopback(v: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    v.into_iter()
        .filter(|a| a.is_ipv4())
        .map(|a| std::net::SocketAddr::from(([127, 0, 0, 1], a.port())))
        .collect()
}

/// A v2 pairing over loopback (no relay).
fn pair(pc: &PcNode, phone: &PhoneClient) {
    phone.set_relay_url(Some("off".into())).unwrap();
    pair_v2_for_tests(
        V2Node::Pc(pc),
        loopback(pc.bound_sockets()),
        V2Node::Phone(phone),
        loopback(phone.bound_sockets_for_tests()),
        None,
    )
    .expect("v2 pair");
}

/// The unpair notice reaches the phone asynchronously.
fn wait_unpaired(phone: &PhoneClient) {
    for tries in 0.. {
        if phone.paired_pcs().is_empty() {
            return;
        }
        assert!(tries < 500, "phone never got the unpair notice");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
fn forget_rolls_back_when_save_fails() {
    let store = Arc::new(FlakyStore::default());
    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new("Test PC", store.clone(), spy.clone());
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    let pc = PcNode::start(cfg).expect("pc");
    let pc_id = pc.device_id();

    let phone = PhoneClient::new(PhoneConfig {
        state: Arc::new(MemoryStateStore::default()),
        default_name: "Test Phone".into(),
        platform: Platform::Android,
        mdns: false,
    })
    .expect("phone");
    pair(&pc, &phone);
    let pairings = pc.pairings();
    let saved = store.load().unwrap();

    // ---- the save fails: nothing changes ----
    store.fail.store(true, Ordering::SeqCst);
    match pc.forget_device(&phone.device_id()) {
        Err(NetError::Storage(e)) => assert!(e.contains("Permission denied"), "{e}"),
        other => panic!("expected a storage error, got {other:?}"),
    }
    assert_eq!(pc.devices().len(), 1, "phone stays listed");
    assert_eq!(pc.pairings(), pairings, "pairing kept");
    assert_eq!(store.load().unwrap(), saved, "disk untouched");
    // The phone was not told and can still send.
    let r = phone
        .send_url(&pc_id, "https://example.com/still-paired")
        .unwrap();
    assert_eq!(r.outcome, SendOutcome::Opened);
    assert_eq!(phone.paired_pcs().len(), 1);

    // ---- disk writable again: Forget works and reaches the phone ----
    store.fail.store(false, Ordering::SeqCst);
    assert!(pc.forget_device(&phone.device_id()).unwrap());
    assert!(pc.devices().is_empty());
    wait_unpaired(&phone);
    assert!(matches!(
        phone.send_url(&pc_id, "https://example.com/after"),
        Err(NetError::UnknownDevice)
    ));
    assert_eq!(spy.count(), 1);
    pc.shutdown();
}

#[test]
fn phone_forget_rolls_back_when_save_fails() {
    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new("Test PC", Arc::new(MemoryStateStore::default()), spy);
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    let pc = PcNode::start(cfg).expect("pc");
    let pc_id = pc.device_id();

    let store = Arc::new(FlakyStore::default());
    let phone = PhoneClient::new(PhoneConfig {
        state: store.clone(),
        default_name: "Test Phone".into(),
        platform: Platform::Android,
        mdns: false,
    })
    .expect("phone");
    pair(&pc, &phone);
    let saved = store.load().unwrap();

    store.fail.store(true, Ordering::SeqCst);
    match phone.forget_pc(&pc_id) {
        Err(NetError::Storage(e)) => assert!(e.contains("Permission denied"), "{e}"),
        other => panic!("expected a storage error, got {other:?}"),
    }
    assert_eq!(phone.paired_pcs().len(), 1, "PC card stays");
    assert_eq!(store.load().unwrap(), saved, "disk untouched");
    let r = phone.send_url(&pc_id, "https://example.com/still").unwrap();
    assert_eq!(r.outcome, SendOutcome::Opened);

    store.fail.store(false, Ordering::SeqCst);
    assert!(phone.forget_pc(&pc_id).unwrap());
    assert!(phone.paired_pcs().is_empty());
    assert!(!phone.forget_pc(&pc_id).unwrap(), "already gone");
    pc.shutdown();
}
