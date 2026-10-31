//! Cross-pairing replay on the relay inbox path, both directions: after the
//! same phone and PC forget each other and pair again, envelopes sealed
//! under the first pairing (replayed, or never sent) are queued on the new
//! pairing's inbox and must open nothing; the new pairing still works.
mod common;
use common::*;
use voidwire_core::time::{Clock, SystemClock};

#[test]
fn m2_old_pairings_envelopes_open_nothing_after_pairing_again() {
    let root = temp_dir("m2-repair-replay");
    let home = RelayBox::start();
    let r = RelayBox::start();
    let a = pc("PC A", Some(home.url()), &root);
    let b = phone("Phone B", Some(home.url()), &root);
    pair(&a, &b, false, Some(r.rref()));
    let (ai, bi) = (a.id(), b.id());
    let (pcn, ph) = (pc_node(&a), phone_node(&b));
    let wall = || SystemClock.now().wall;

    // First pairing: one link each way goes through the inbox; one each
    // way is sealed and never sent.
    let pc_old = pcn
        .seal_url_for_tests(&bi, "https://example.com/l4/pc-old")
        .unwrap();
    let pc_unsent = pcn
        .seal_url_for_tests(&bi, "https://example.com/l4/pc-unsent")
        .unwrap();
    let old = ph.fake_peer_for_tests(&ai).expect("paired");
    let ph_old = old.frame("https://example.com/l4/ph-old", wall());
    let ph_unsent = old.frame("https://example.com/l4/ph-unsent", wall());
    ph.set_offline_for_tests(true);
    pcn.deliver_envelope_for_tests(&bi, &pc_old)
        .expect("queued");
    ph.set_offline_for_tests(false);
    assert_eq!(ph.pull_device_inbox_now().unwrap(), 1);
    assert!(b.got_url("https://example.com/l4/pc-old"));
    ph.queue_envelope_for_tests(&ai, &ph_old).expect("queued");
    assert_eq!(pcn.pull_pairing_inboxes_now().unwrap(), 1);
    assert!(a.got_url("https://example.com/l4/ph-old"));
    for i in ph.poll_incoming().items {
        ph.dismiss_incoming_item(i.item_id);
    }

    // Forget on both sides, then pair the same two devices again.
    ph.hold_unpair_send_for_tests(true);
    pcn.hold_unpair_send_for_tests(true);
    assert!(ph.forget_pc(&ai).unwrap());
    assert!(pcn.forget_device(&bi).unwrap());
    pair(&a, &b, false, Some(r.rref()));

    // PC to phone: queued on the new pairing's inbox, the phone shows none.
    ph.set_offline_for_tests(true);
    for env in [&pc_old, &pc_unsent] {
        let rep = pcn.deliver_envelope_for_tests(&bi, env).expect("queued");
        assert_eq!(
            rep.delivery_path,
            voidwire_core::net::DeliveryPath::QueuedInDeviceInbox
        );
    }
    ph.set_offline_for_tests(false);
    assert_eq!(
        ph.pull_device_inbox_now().unwrap_or(0),
        0,
        "phone added one"
    );
    assert!(
        ph.poll_incoming().items.is_empty(),
        "an old pairing's link shown"
    );

    // Phone to PC: the PC opens none.
    let opened = |d: &Dev| match d {
        Dev::Pc { spy, .. } => spy.count(),
        _ => unreachable!(),
    };
    let before = opened(&a);
    for env in [&ph_old, &ph_unsent] {
        ph.queue_envelope_for_tests(&ai, env).expect("queued");
    }
    assert_eq!(
        pcn.pull_pairing_inboxes_now().unwrap_or(0),
        0,
        "PC added one"
    );
    assert_eq!(opened(&a), before, "an old pairing's link opened");

    // The new pairing works both ways.
    ph.set_offline_for_tests(true);
    a.send_url(&bi, "https://example.com/l4/pc-new");
    ph.set_offline_for_tests(false);
    let _ = ph.pull_device_inbox_now();
    wait("new link on the phone", || {
        b.got_url("https://example.com/l4/pc-new")
    });
    let fresh = ph.fake_peer_for_tests(&ai).expect("re-paired");
    ph.queue_envelope_for_tests(&ai, &fresh.frame("https://example.com/l4/ph-new", wall()))
        .unwrap();
    let _ = pcn.pull_pairing_inboxes_now();
    wait("new link on the PC", || {
        a.got_url("https://example.com/l4/ph-new")
    });
}
