//! M4.2: the legacy hub split. Real v0.4.1 state (one PC with two phones;
//! phone 0 also paired with a second PC) moves to one v2 pairing per device
//! pair when the phone app opens: no re-pair, both ways keep working, a phone
//! that has not moved yet keeps working on the legacy group, and the moved
//! phone leaves the legacy group.
#![cfg(all(feature = "net", feature = "test-util"))]

use std::sync::Arc;
use voidwire_core::ids::DeviceId;
use voidwire_core::keys::Platform;
use voidwire_core::net::pc::{PcConfig, PcNode};
use voidwire_core::net::phone::{PhoneClient, PhoneConfig};
use voidwire_core::net::state::{MemoryStateStore, StateStore};
use voidwire_core::net::{NetError, SendOutcome};
use voidwire_core::test_util::SharedSpyOpener;

fn fixture(name: &str) -> Arc<MemoryStateStore> {
    let path = format!("{}/tests/fixtures/v041/{name}", env!("CARGO_MANIFEST_DIR"));
    let s = Arc::new(MemoryStateStore::default());
    s.save(&std::fs::read(path).expect("fixture")).unwrap();
    s
}

fn seen_path(tag: &str) -> std::path::PathBuf {
    use rand_core::RngCore;
    let n = rand_core::OsRng.next_u64();
    let d = std::env::temp_dir().join(format!("vw-m42-{tag}-{n:x}"));
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
    let n = PcNode::start(cfg)?;
    n.set_no_prompt(true).unwrap();
    Ok(n)
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

fn legacy_with(node: &PcNode, peer: &DeviceId) -> bool {
    node.pairings()
        .iter()
        .find(|x| x.peer == *peer)
        .expect("pairing kept")
        .legacy
}

fn both_ways(p: &PhoneClient, node: &PcNode, tag: &str) {
    let r = p
        .send_url(&node.device_id(), &format!("https://example.com/{tag}"))
        .unwrap();
    assert_eq!(r.outcome, SendOutcome::Opened);
    node.send_text_or_url_to_phone(&p.device_id(), &format!("https://example.com/{tag}-back"))
        .expect("PC to phone");
}

#[test]
fn v041_hub_splits_into_v2_pairings_without_re_pairing() {
    let s_pc1 = fixture("pc1.state");
    let s_pc2 = fixture("pc2.state");
    let s_ph0 = fixture("phone0.state");
    let s_ph1 = fixture("phone1.state");
    let pc1 = pc(s_pc1.clone(), "pc1").unwrap();
    let pc2 = pc(s_pc2.clone(), "pc2").unwrap();
    let ph0 = phone(s_ph0.clone());
    let ph1 = phone(s_ph1.clone());
    let (id0, id1) = (ph0.device_id(), ph1.device_id());
    for (p, n) in [(&ph0, &pc1), (&ph0, &pc2), (&ph1, &pc1)] {
        p.set_pc_addrs_for_tests(&n.device_id(), n.direct_addrs());
    }
    assert!(legacy_with(&pc1, &id0) && legacy_with(&pc1, &id1));
    let old_ids: Vec<_> = pc1.pairings().iter().map(|x| x.pairing_id).collect();

    // Phone 0 opens the app: both its PCs move it to v2 pairings.
    assert_eq!(ph0.split_legacy_pairings_now().unwrap(), 2);
    assert!(!legacy_with(&pc1, &id0));
    assert!(!legacy_with(&pc2, &id0));
    assert!(ph0.pairings().iter().all(|x| !x.legacy));
    assert_eq!(ph0.pairings().len(), 2);
    assert!(!old_ids.contains(
        &pc1.pairings()
            .iter()
            .find(|x| x.peer == id0)
            .unwrap()
            .pairing_id
    ));
    // One entry per device on the PC (no legacy + v2 duplicate).
    assert_eq!(pc1.devices().len(), 2);
    assert_eq!(pc1.pairings().len(), 2);
    both_ways(&ph0, &pc1, "moved-pc1");
    both_ways(&ph0, &pc2, "moved-pc2");

    // Phone 1 has not opened the app yet: the legacy group (now rekeyed
    // without phone 0) still works for it.
    assert!(legacy_with(&pc1, &id1));
    both_ways(&ph1, &pc1, "still-legacy");

    // A second try is a no-op (nothing legacy left / already tried).
    assert_eq!(ph0.split_legacy_pairings_now().unwrap(), 0);

    // Phone 1 moves too, but its SPLIT_DONE is lost: the PC keeps the
    // legacy membership until the phone's first message over the new
    // pairing, then drops it. The PC's legacy group is left with itself.
    ph1.skip_split_done_for_tests(true);
    assert_eq!(ph1.split_legacy_pairings_now().unwrap(), 1);
    assert!(ph1.pairings().iter().all(|x| !x.legacy));
    assert!(pc1.pairings().iter().any(|x| x.peer == id1 && x.legacy));
    let r = ph1
        .send_url(&pc1.device_id(), "https://example.com/first-v2")
        .unwrap();
    assert_eq!(r.outcome, SendOutcome::Opened);
    assert!(pc1.pairings().iter().all(|x| !x.legacy));
    assert_eq!(pc1.devices().len(), 2);
    both_ways(&ph1, &pc1, "moved-ph1");
    both_ways(&ph0, &pc1, "moved-again");

    // It all survives a restart of every device.
    let before: Vec<_> = pc1
        .pairings()
        .iter()
        .map(|x| (x.pairing_id, x.peer, x.legacy))
        .collect();
    pc1.shutdown();
    pc2.shutdown();
    drop((ph0, ph1));
    let pc1 = pc(s_pc1, "pc1b").unwrap();
    let after: Vec<_> = pc1
        .pairings()
        .iter()
        .map(|x| (x.pairing_id, x.peer, x.legacy))
        .collect();
    assert_eq!(before, after);
    let ph1 = phone(s_ph1);
    assert!(ph1.pairings().iter().all(|x| !x.legacy));
    ph1.set_pc_addrs_for_tests(&pc1.device_id(), pc1.direct_addrs());
    both_ways(&ph1, &pc1, "after-restart");
    pc1.shutdown();
}

#[test]
fn a_fresh_phone_pairing_with_a_v042_pc_has_nothing_to_split() {
    let pc1 = pc(fixture("pc2.state"), "fresh").unwrap();
    let ph = phone(Arc::new(MemoryStateStore::default()));
    assert_eq!(ph.split_legacy_pairings_now().unwrap(), 0);
    pc1.shutdown();
}
