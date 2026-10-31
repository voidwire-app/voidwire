//! S29: the "devices will need to be re-paired" flag is cleared by the next
//! pairing, saved with it. If that save fails, the pairing is not kept and
//! the flag is put back, so the notice still shows; once the disk is
//! writable a pairing clears it. PC and phone each.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use voidwire_core::keys::Platform;
use voidwire_core::net::pc::{PcConfig, PcNode};
use voidwire_core::net::phone::{PhoneClient, PhoneConfig};
use voidwire_core::net::state::{MemoryStateStore, StateStore};
use voidwire_core::net::{pair_v2_for_tests, NetError, V2Node};
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

fn pc_on(store: Arc<dyn StateStore>) -> PcNode {
    let mut cfg = PcConfig::new("Test PC", store, Arc::new(SharedSpyOpener::default()));
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some("off".into());
    PcNode::start(cfg).expect("pc")
}

fn phone_on(store: Arc<dyn StateStore>) -> PhoneClient {
    let p = PhoneClient::new(PhoneConfig {
        state: store,
        default_name: "Test Phone".into(),
        platform: Platform::Android,
        mdns: false,
    })
    .expect("phone");
    p.set_relay_url(Some("off".into())).unwrap();
    p
}

fn loopback(v: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    v.into_iter()
        .filter(|a| a.is_ipv4())
        .map(|a| std::net::SocketAddr::from(([127, 0, 0, 1], a.port())))
        .collect()
}

fn pair(pc: &PcNode, phone: &PhoneClient) -> Result<(), NetError> {
    pair_v2_for_tests(
        V2Node::Pc(pc),
        loopback(pc.bound_sockets()),
        V2Node::Phone(phone),
        loopback(phone.bound_sockets_for_tests()),
        None,
    )
    .map(|_| ())
}

fn old_pc() -> Arc<FlakyStore> {
    let old = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/custom_folder/pc-v0.7.0.state"
    ))
    .expect("fixture");
    let s = Arc::new(FlakyStore::default());
    s.save(&old).unwrap();
    s
}

fn old_phone() -> Arc<FlakyStore> {
    let mut old = b"VWPH2\n".to_vec();
    old.extend_from_slice(&[0x11; 32]);
    old.extend_from_slice(&[0x22; 32]);
    old.extend_from_slice(&[5, b'P', b'h', b'o', b'n', b'e', 0]);
    let s = Arc::new(FlakyStore::default());
    s.save(&old).unwrap();
    s
}

#[test]
fn pc_flag_stays_when_the_pairing_save_fails() {
    let store = old_pc();
    let pc = pc_on(store.clone());
    let phone = phone_on(Arc::new(MemoryStateStore::default()));
    assert!(pc.old_pairings_dropped(), "shown after the upgrade");

    store.fail.store(true, Ordering::SeqCst);
    assert!(
        pair(&pc, &phone).is_err(),
        "the PC could not save the pairing"
    );
    assert!(pc.old_pairings_dropped(), "flag put back with the pairing");
    assert!(pc.devices().is_empty(), "pairing not kept");

    store.fail.store(false, Ordering::SeqCst);
    pair(&pc, &phone).expect("pair");
    assert!(!pc.old_pairings_dropped(), "cleared by the saved pairing");
    drop(pc);
    assert!(!pc_on(store).old_pairings_dropped(), "and on disk");
}

#[test]
fn phone_flag_stays_when_the_pairing_save_fails() {
    let store = old_phone();
    let phone = phone_on(store.clone());
    let pc = pc_on(Arc::new(MemoryStateStore::default()));
    assert!(phone.old_pairings_dropped(), "shown after the upgrade");

    store.fail.store(true, Ordering::SeqCst);
    assert!(
        pair(&pc, &phone).is_err(),
        "the phone could not save the pairing"
    );
    assert!(
        phone.old_pairings_dropped(),
        "flag put back with the pairing"
    );
    assert!(phone.paired_pcs().is_empty(), "pairing not kept");

    store.fail.store(false, Ordering::SeqCst);
    pair(&pc, &phone).expect("pair");
    assert!(
        !phone.old_pairings_dropped(),
        "cleared by the saved pairing"
    );
    drop(phone);
    assert!(!phone_on(store).old_pairings_dropped(), "and on disk");
}
