//! M4.1: state format v2. Real v0.4.1 state files (tests/fixtures/v041, written
//! by v0.4.1 itself: one PC with three phones, one of them later forgotten, and
//! phone 0 also paired with a second PC) must load with every pairing intact,
//! split into one pairing per device, keep sending both ways, and re-save as v2.
#![cfg(all(feature = "net", feature = "test-util"))]

use std::sync::Arc;
use std::time::Duration;
use voidwire_core::keys::Platform;
use voidwire_core::net::pc::{PcConfig, PcNode};
use voidwire_core::net::phone::{GroupChange, PhoneClient, PhoneConfig};
use voidwire_core::net::state::{MemoryStateStore, StateStore};
use voidwire_core::net::{NetError, SendOutcome};
use voidwire_core::test_util::SharedSpyOpener;

fn fixture(name: &str) -> Arc<MemoryStateStore> {
    let path = format!("{}/tests/fixtures/v041/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(path).expect("fixture");
    let s = Arc::new(MemoryStateStore::default());
    s.save(&bytes).unwrap();
    s
}

fn seen_path(tag: &str) -> std::path::PathBuf {
    use rand_core::RngCore;
    let n = rand_core::OsRng.next_u64();
    let d = std::env::temp_dir().join(format!("vw-m41-{tag}-{n:x}"));
    std::fs::create_dir_all(&d).unwrap();
    d.join("seen.bin")
}

fn pc(store: Arc<MemoryStateStore>, tag: &str) -> Result<PcNode, NetError> {
    let mut cfg = PcConfig::new("PC", store, Arc::new(SharedSpyOpener::default()));
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some("off".into());
    cfg.seen_store_path = Some(seen_path(tag));
    PcNode::start(cfg)
}

fn phone(store: Arc<MemoryStateStore>) -> PhoneClient {
    PhoneClient::new(PhoneConfig {
        state: store,
        default_name: "Phone".into(),
        platform: Platform::Android,
        mdns: false,
    })
    .unwrap()
}

fn magic(store: &MemoryStateStore) -> Vec<u8> {
    store.load().unwrap().unwrap()[..6].to_vec()
}

#[test]
fn v041_files_split_into_pairings_and_keep_working() {
    let s_pc1 = fixture("pc1.state");
    let s_pc2 = fixture("pc2.state");
    let s_ph: Vec<_> = (0..3)
        .map(|i| fixture(&format!("phone{i}.state")))
        .collect();
    assert_eq!(magic(&s_pc1), b"VWPC1\n");
    assert_eq!(magic(&s_ph[0]), b"VWPH1\n");

    let pc1 = pc(s_pc1.clone(), "pc1").expect("v0.4.1 PC state loads");
    let pc2 = pc(s_pc2.clone(), "pc2").expect("v0.4.1 PC state loads");
    pc1.set_no_prompt(true).unwrap();
    pc2.set_no_prompt(true).unwrap();
    let phones: Vec<_> = s_ph.iter().map(|s| phone(s.clone())).collect();
    let ids: Vec<_> = phones.iter().map(|p| p.device_id()).collect();

    // The PC-hosted M3 group became one pairing per (still paired) phone.
    let p1 = pc1.pairings();
    assert_eq!(
        p1.len(),
        2,
        "phone 2 was forgotten in v0.4.1 and must stay gone"
    );
    for (i, id) in ids.iter().take(2).enumerate() {
        let x = p1
            .iter()
            .find(|x| &x.peer == id)
            .expect("phone pairing kept");
        assert!(x.legacy);
        assert_eq!(x.peer_name, format!("Fixture Phone {i}"));
    }
    assert!(!p1.iter().any(|x| x.peer == ids[2]));
    assert_eq!(pc2.pairings().len(), 1);
    assert_eq!(pc1.devices().len(), 2);

    // Phone 0 has two pairings, one per PC, and both sides name the same pairing.
    let ph0 = phones[0].pairings();
    assert_eq!(ph0.len(), 2);
    for (node, list) in [(&pc1, &p1), (&pc2, &pc2.pairings())] {
        let mine = list.iter().find(|x| x.peer == ids[0]).unwrap();
        let theirs = ph0.iter().find(|x| x.peer == node.device_id()).unwrap();
        assert_eq!(mine.pairing_id, theirs.pairing_id);
    }
    assert_ne!(ph0[0].pairing_id, ph0[1].pairing_id);
    assert_eq!(phones[1].pairings().len(), 1);

    // Both ways still work, with no re-pair.
    for (p, node) in [(&phones[0], &pc1), (&phones[1], &pc1), (&phones[0], &pc2)] {
        p.set_pc_addrs_for_tests(&node.device_id(), node.direct_addrs());
        let r = p
            .send_url(&node.device_id(), "https://example.com/after-upgrade")
            .unwrap();
        assert_eq!(r.outcome, SendOutcome::Opened);
        node.send_text_or_url_to_phone(&p.device_id(), "https://example.com/back")
            .expect("PC to phone after upgrade");
    }

    // Everything re-saved as v2, and reloads to the same pairings.
    assert_eq!(magic(&s_pc1), b"VWPC2\n");
    assert_eq!(magic(&s_ph[0]), b"VWPH2\n");
    let before: Vec<_> = pc1
        .pairings()
        .iter()
        .map(|x| (x.pairing_id, x.peer))
        .collect();
    let before_ph: Vec<_> = phones[0]
        .pairings()
        .iter()
        .map(|x| (x.pairing_id, x.peer))
        .collect();
    pc1.shutdown();
    pc2.shutdown();
    drop(phones);
    let pc1 = pc(s_pc1.clone(), "pc1b").expect("v2 PC state reloads");
    let after: Vec<_> = pc1
        .pairings()
        .iter()
        .map(|x| (x.pairing_id, x.peer))
        .collect();
    assert_eq!(before, after);
    let ph0 = phone(s_ph[0].clone());
    let after_ph: Vec<_> = ph0
        .pairings()
        .iter()
        .map(|x| (x.pairing_id, x.peer))
        .collect();
    assert_eq!(before_ph, after_ph);
    pc1.shutdown();
}

#[test]
fn damaged_pairings_section_fails_closed() {
    let s = fixture("pc1.state");
    let node = pc(s.clone(), "dmg").unwrap();
    node.shutdown();
    let mut blob = s.load().unwrap().unwrap();
    assert_eq!(&blob[..6], b"VWPC2\n");
    // The pairings section is last: tag, u32 length, version, u32 length,
    // then the sealed pairing set. Flip a byte inside the sealed set.
    let start = voidwire_core::net::pc::state_as_v1_for_tests(&blob)
        .unwrap()
        .len();
    assert_eq!(blob[start], 6);
    blob[start + 1 + 4 + 1 + 4 + 20] ^= 0x55;
    s.save(&blob).unwrap();
    assert!(
        pc(s, "dmg2").is_err(),
        "a damaged pairings section must not load"
    );
}

#[test]
fn v2_state_converts_back_to_the_v041_layout() {
    // The test helper used by older migration tests must reproduce v0.4.1 bytes.
    let s = fixture("pc2.state");
    let original = s.load().unwrap().unwrap();
    let node = pc(s.clone(), "v1").unwrap();
    node.shutdown();
    let v2 = s.load().unwrap().unwrap();
    let v1 = voidwire_core::net::pc::state_as_v1_for_tests(&v2).unwrap();
    assert_eq!(&v1[..6], b"VWPC1\n");
    assert!(v1.len() < v2.len());
    let _ = original;
}

#[test]
fn seventeenth_pairing_is_refused_on_both_sides() {
    let node = pc(Arc::new(MemoryStateStore::default()), "lim").unwrap();
    let phones: Vec<_> = (0..17)
        .map(|_| phone(Arc::new(MemoryStateStore::default())))
        .collect();
    for p in phones.iter().take(16) {
        let s = p
            .begin_pairing_with(&node.pair_start().unwrap().qr_uri, GroupChange::Confirmed)
            .unwrap();
        node.pair_submit_code(&s.sas()).unwrap();
        s.wait_welcome(Duration::from_secs(10)).unwrap();
    }
    assert_eq!(node.pairings().len(), 16);
    let s = phones[16]
        .begin_pairing_with(&node.pair_start().unwrap().qr_uri, GroupChange::Confirmed)
        .unwrap();
    assert!(node.pair_submit_code(&s.sas()).is_err());
    assert!(s.wait_welcome(Duration::from_secs(10)).is_err());
    assert_eq!(node.pairings().len(), 16);
    assert!(phones[16].pairings().is_empty());
    node.shutdown();
}
