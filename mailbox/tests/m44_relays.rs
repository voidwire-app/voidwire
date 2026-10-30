//! M4.4 relays: live traffic on each pairing's own relay, phones holding
//! extra relays only while the app is open, the signed relay change, and
//! per-relay limits and backoff.

mod common;
use common::*;

use voidwire_core::net::relay_change::RelayChangeState;
use voidwire_core::net::relays::{RelayError, RelayStatus};

fn setup() {
    voidwire_core::net::away::set_away_idle_ms_for_tests(400);
}

fn summary_relay(d: &Dev, peer: &DeviceId) -> Option<String> {
    let v = match d {
        Dev::Pc { node, .. } => node.pairings(),
        Dev::Phone { node, .. } => node.pairings(),
    };
    v.into_iter()
        .find(|p| p.peer == *peer)
        .and_then(|p| p.relay_url)
        .map(|u| u.trim_end_matches('/').to_owned())
}

fn u(b: &RelayBox) -> Option<String> {
    Some(b.url().trim_end_matches('/').to_owned())
}

fn save_relay(d: &Dev, b: &RelayBox) {
    let m = b.server.device_id().to_hex();
    let r = match d {
        Dev::Pc { node, .. } => node.add_relay(&b.url(), &m, ""),
        Dev::Phone { node, .. } => node.add_relay(&b.url(), &m, ""),
    };
    assert!(matches!(r, Ok(()) | Err(RelayError::Duplicate)), "{r:?}");
}

#[test]
fn m44_relay_change_needs_both_devices_to_sign_and_moves_live_traffic() {
    setup();
    let root = temp_dir("m44-move");
    let home = RelayBox::start();
    let r1 = RelayBox::start();
    let r2 = RelayBox::start();
    let a = pc("PC A", Some(home.url()), &root);
    let b = phone("Phone B", Some(home.url()), &root);
    pair(&a, &b, false, Some(r1.rref()));
    for d in [&a, &b] {
        save_relay(d, &r1);
    }
    save_relay(&a, &r2);
    let (ai, bi) = (a.id(), b.id());
    wait("both on R1", || {
        r1.relay.has_peer(&ai) && r1.relay.has_peer(&bi)
    });

    // A proposes; nothing moves until B's user allows it.
    pc_node(&a).change_pairing_relay(&bi, &r2.url()).unwrap();
    let reqs = phone_node(&b).relay_change_requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].peer, ai);
    assert!(reqs[0].new_relay, "R2 isn't saved on B yet");
    assert_eq!(summary_relay(&a, &bi), u(&r1));
    assert_eq!(summary_relay(&b, &ai), u(&r1));
    let st = pc_node(&a).relay_change_statuses();
    assert_eq!(st[0].state, RelayChangeState::Waiting);

    phone_node(&b).answer_relay_change(&ai, true).unwrap();
    assert_eq!(summary_relay(&a, &bi), u(&r2));
    assert_eq!(summary_relay(&b, &ai), u(&r2));
    assert_eq!(
        pc_node(&a).relay_change_statuses()[0].state,
        RelayChangeState::Done
    );
    assert!(phone_node(&b).relay_change_requests().is_empty());
    assert!(
        phone_node(&b)
            .relays()
            .iter()
            .any(|r| r.url == r2.url().trim_end_matches('/')),
        "allowing saved the new relay"
    );

    // Live traffic now goes through R2 (both ways).
    wait("both on R2", || {
        r2.relay.has_peer(&ai) && r2.relay.has_peer(&bi)
    });
    let n = r2.relay.relayed_datagrams().len();
    a.send_url(&bi, "https://example.com/m44/moved");
    wait("url via R2", || b.got_url("https://example.com/m44/moved"));
    b.send_text(&ai, "m44 back via R2");
    wait("text via R2", || a.got_text("m44 back via R2"));
    assert!(r2.relay.relayed_datagrams().len() > n);

    // R1 no longer used: the away endpoints on it close.
    wait("off R1", || {
        !r1.relay.has_peer(&ai) && !r1.relay.has_peer(&bi)
    });
    // And it can now be removed.
    pc_node(&a).remove_relay(&r1.url()).unwrap();
}

#[test]
fn m44_declined_or_unanswered_change_moves_nothing() {
    setup();
    let root = temp_dir("m44-decline");
    let home = RelayBox::start();
    let r1 = RelayBox::start();
    let r2 = RelayBox::start();
    let a = pc("PC A", Some(home.url()), &root);
    let b = pc("PC B", Some(home.url()), &root);
    pair(&a, &b, false, Some(r1.rref()));
    save_relay(&a, &r2);
    let (ai, bi) = (a.id(), b.id());
    wait("both on R1", || {
        r1.relay.has_peer(&ai) && r1.relay.has_peer(&bi)
    });

    pc_node(&a).change_pairing_relay(&bi, &r2.url()).unwrap();
    assert_eq!(pc_node(&b).relay_change_requests().len(), 1);
    pc_node(&b).answer_relay_change(&ai, false).unwrap();
    assert!(pc_node(&b).relay_change_requests().is_empty());
    assert_eq!(
        pc_node(&a).relay_change_statuses()[0].state,
        RelayChangeState::Declined
    );
    assert_eq!(summary_relay(&a, &bi), u(&r1));
    assert_eq!(summary_relay(&b, &ai), u(&r1));
    // Answering a request that isn't there fails; nothing moves.
    assert!(pc_node(&b).answer_relay_change(&ai, true).is_err());
    assert_eq!(summary_relay(&b, &ai), u(&r1));

    // A relay that isn't saved can't be proposed.
    let r3 = RelayBox::start();
    assert_eq!(
        pc_node(&a).change_pairing_relay(&bi, &r3.url()),
        Err(RelayError::NotFound)
    );
    // Traffic still flows on R1.
    a.send_url(&bi, "https://example.com/m44/still-r1");
    wait("still on R1", || {
        b.got_url("https://example.com/m44/still-r1")
    });
}

#[test]
fn m44_phone_holds_extra_relays_only_while_the_app_is_open() {
    setup();
    let root = temp_dir("m44-bg");
    let home = RelayBox::start();
    let r1 = RelayBox::start();
    let a = pc("PC A", Some(home.url()), &root);
    let b = phone("Phone B", Some(home.url()), &root);
    pair(&a, &b, false, Some(r1.rref()));
    let (ai, bi) = (a.id(), b.id());
    wait("phone on R1 while open", || r1.relay.has_peer(&bi));

    // App closed: only the home relay stays.
    phone_node(&b).set_app_foreground(false);
    wait("phone off R1 in background", || !r1.relay.has_peer(&bi));
    assert!(home.relay.has_peer(&bi), "home relay stays");
    assert!(phone_node(&b).away_relays_for_tests().is_empty());
    let opened = phone_node(&b).away_opened_for_tests();

    // A send while the phone is in the background lands in its R1 inbox,
    // and a pull (an event) gets it without opening an away endpoint.
    a.send_url(&bi, "https://example.com/m44/bg");
    assert!(!b.got_url("https://example.com/m44/bg"));
    phone_node(&b).pull_device_inbox_now().unwrap();
    wait("inbox while background", || {
        b.got_url("https://example.com/m44/bg")
    });
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(phone_node(&b).away_opened_for_tests(), opened);
    assert!(!r1.relay.has_peer(&bi));

    // App open again: back on R1, live.
    phone_node(&b).set_app_foreground(true);
    wait("phone on R1 again", || r1.relay.has_peer(&bi));
    a.send_url(&bi, "https://example.com/m44/fg");
    wait("live while open", || {
        b.got_url("https://example.com/m44/fg")
    });
    let _ = ai;
}

#[test]
fn m44_phone_holds_at_most_two_extra_relays() {
    setup();
    let root = temp_dir("m44-cap");
    let home = RelayBox::start();
    let boxes = [RelayBox::start(), RelayBox::start(), RelayBox::start()];
    let b = phone("Phone B", Some(home.url()), &root);
    let pcs: Vec<Dev> = (0..3)
        .map(|i| pc(&format!("PC {i}"), Some(home.url()), &root))
        .collect();
    for (p, r) in pcs.iter().zip(&boxes) {
        pair(p, &b, false, Some(r.rref()));
    }
    let bi = b.id();
    wait("two away relays held", || {
        phone_node(&b)
            .away_relays_for_tests()
            .iter()
            .filter(|(_, held)| *held)
            .count()
            == 2
    });
    std::thread::sleep(Duration::from_millis(600));
    let on = boxes.iter().filter(|r| r.relay.has_peer(&bi)).count();
    assert_eq!(on, 2, "a phone holds 2 relays besides home");
    // A PC holds all three.
    let p0 = pcs[0].id();
    wait("pc holds its relay", || boxes[0].relay.has_peer(&p0));
}

#[test]
fn m44_unreachable_relay_only_affects_its_own_pairings() {
    setup();
    let root = temp_dir("m44-down");
    let home = RelayBox::start();
    let r1 = RelayBox::start();
    let r2 = RelayBox::start();
    let a = pc("PC A", Some(home.url()), &root);
    let b = pc("PC B", Some(home.url()), &root);
    let c = pc("PC C", Some(home.url()), &root);
    pair(&a, &b, false, Some(r1.rref()));
    pair(&a, &c, false, Some(r2.rref()));
    let (ai, ci) = (a.id(), c.id());
    wait("A on both", || {
        r1.relay.has_peer(&ai) && r2.relay.has_peer(&ai)
    });
    drop(r1);
    a.send_url(&ci, "https://example.com/m44/r2-fine");
    wait("R2 pairing unaffected", || {
        c.got_url("https://example.com/m44/r2-fine")
    });
}

#[test]
fn m44_event_pulls_are_gated_per_relay() {
    setup();
    let root = temp_dir("m44-gate");
    let home = RelayBox::start();
    let r1 = RelayBox::start();
    let a = pc("PC A", Some(home.url()), &root);
    let b = phone("Phone B", Some(home.url()), &root);
    pair(&a, &b, false, Some(r1.rref()));
    let p = phone_node(&b);
    p.pull_device_inbox_on_event(false).unwrap();
    let n = p.inbox_pulls_for_tests();
    assert!(
        p.event_pulled_relays()
            .iter()
            .any(|u| u.contains(&r1.relay.addr().port().to_string())),
        "pulled the pairing's relay: {:?}",
        p.event_pulled_relays()
    );
    // A second event right away is gated on every relay.
    p.pull_device_inbox_on_event(false).unwrap();
    assert_eq!(p.inbox_pulls_for_tests(), n);
    // Opening the app forces a pull.
    p.pull_device_inbox_on_event(true).unwrap();
    assert_eq!(p.inbox_pulls_for_tests(), n + 1);
}

#[test]
fn m44_relay_list_limits_and_links() {
    setup();
    let root = temp_dir("m44-list");
    let home = RelayBox::start();
    let a = pc("PC A", Some(home.url()), &root);
    let n = pc_node(&a);
    let start = n.relays().len();
    for i in start..8 {
        n.add_relay(&format!("https://r{i}.example"), "", "")
            .unwrap();
    }
    assert_eq!(n.relays().len(), 8);
    assert_eq!(
        n.add_relay("https://r99.example", "", ""),
        Err(RelayError::SavedFull)
    );
    let r = n
        .relays()
        .into_iter()
        .find(|r| !r.home && !r.builtin)
        .unwrap();
    assert_eq!(r.status, RelayStatus::Idle);
    n.remove_relay(&r.url).unwrap();
    n.add_relay_link(&r.link).unwrap();
    n.rename_relay(&r.url, "Friend").unwrap();
    assert!(n.relays().iter().any(|x| x.nickname == "Friend"));
    let home_row = n.relays().into_iter().find(|r| r.home).unwrap();
    assert_eq!(n.remove_relay(&home_row.url), Err(RelayError::InUse));
}

#[test]
fn m44_after_a_move_the_old_relay_inbox_is_still_drained() {
    setup();
    let root = temp_dir("m44-drain");
    let home = RelayBox::start();
    let r1 = RelayBox::start();
    let r2 = RelayBox::start();
    let a = pc("PC A", Some(home.url()), &root);
    let b = phone("Phone B", Some(home.url()), &root);
    pair(&a, &b, false, Some(r1.rref()));
    save_relay(&a, &r2);
    let (ai, bi) = (a.id(), b.id());
    // Queued on R1 while the phone's app was closed.
    phone_node(&b).set_app_foreground(false);
    wait("phone off R1", || !r1.relay.has_peer(&bi));
    a.send_url(&bi, "https://example.com/m44/queued-on-r1");
    phone_node(&b).set_app_foreground(true);
    wait("phone on R1", || r1.relay.has_peer(&bi));
    assert!(!b.got_url("https://example.com/m44/queued-on-r1"));
    // Move to R2; allowing pulls the old R1 inbox once.
    pc_node(&a).change_pairing_relay(&bi, &r2.url()).unwrap();
    phone_node(&b).answer_relay_change(&ai, true).unwrap();
    assert_eq!(summary_relay(&b, &ai), u(&r2));
    wait("old inbox drained", || {
        b.got_url("https://example.com/m44/queued-on-r1")
    });
}
