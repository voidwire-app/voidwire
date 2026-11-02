//! Settings → Relays on a phone follows each relay's status by events.
//!
//! The phone's relay rows (Connected, Connecting…, Can't reach, Idle) are
//! read on each core change event; nothing polls. Before this, a relay's
//! watch updated its status without an event, so after Make home the rows
//! sat at "Connecting…" until the screen was reopened.
mod common;
use common::*;
use std::sync::mpsc;
use voidwire_core::net::relays::{RelayError, RelayStatus};

fn status_of(p: &PhoneClient, url: &str) -> Option<RelayStatus> {
    let u = url.trim_end_matches('/');
    p.relays()
        .into_iter()
        .find(|r| r.url.trim_end_matches('/') == u)
        .map(|r| r.status)
}

/// Make home on a second relay while a pairing stays on the first: the
/// new home and the old one (now an extra relay for that pairing) both
/// reach Connected, and the app hears about it without reopening.
#[test]
fn make_home_rows_reach_connected_by_events() {
    voidwire_core::net::away::set_away_idle_ms_for_tests(60_000);
    let root = temp_dir("m46-status");
    let h = RelayBox::start();
    let v = RelayBox::start();
    let a = pc("PC A", Some(h.url()), &root);
    let p = phone("Phone A", Some(h.url()), &root);
    pair(&a, &p, false, Some(h.rref()));
    let Dev::Phone { node, .. } = &p else {
        unreachable!()
    };
    let r = node.add_relay(&v.url(), &v.server.device_id().to_hex(), "");
    assert!(matches!(r, Ok(()) | Err(RelayError::Duplicate)), "{r:?}");
    wait("home connected", || {
        status_of(node, &h.url()) == Some(RelayStatus::Connected)
    });

    let (tx, rx) = mpsc::channel::<()>();
    let tx = std::sync::Mutex::new(tx);
    node.set_change_listener(Some(Arc::new(move || {
        let _ = tx.lock().unwrap().send(());
    })));
    // Make home, as the Relays screen does.
    node.set_relay_url(Some(v.url())).unwrap();
    node.set_mailbox_id(Some(v.server.device_id())).unwrap();

    // Re-read only when an event arrives, like the screen.
    let both = |n: &PhoneClient| {
        (status_of(n, &v.url()), status_of(n, &h.url()))
            == (Some(RelayStatus::Connected), Some(RelayStatus::Connected))
    };
    let mut seen = (None, None);
    while !both(node) {
        if rx.recv_timeout(Duration::from_secs(15)).is_err() {
            panic!("no change event while the rows show {seen:?}");
        }
        seen = (status_of(node, &v.url()), status_of(node, &h.url()));
    }
    node.set_change_listener(None);
    drop(p);
    let Dev::Pc { node, .. } = a else {
        unreachable!()
    };
    node.shutdown();
}
