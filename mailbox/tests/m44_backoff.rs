//! M4.4: a relay that stays down is parked and retried slowly, per relay.

mod common;
use common::*;

use voidwire_core::net::relays::RelayStatus;
use voidwire_core::relay_supervisor::SupervisorConfig;

#[test]
fn m44_down_away_relay_is_parked_on_its_own_and_retried_on_request() {
    voidwire_core::net::relay_watch::set_supervisor_config_for_tests(Some(SupervisorConfig {
        park_after_ms: 1_500,
        unpark_grace_ms: 3_000,
        base_retry_ms: 60_000,
        max_retry_ms: 600_000,
        jitter_pct: 0,
    }));
    let root = temp_dir("m44-backoff");
    let home = RelayBox::start();
    let r1 = RelayBox::start();
    let r2 = RelayBox::start();
    let a = pc("PC A", Some(home.url()), &root);
    let b = pc("PC B", Some(home.url()), &root);
    let c = pc("PC C", Some(home.url()), &root);
    pair(&a, &b, false, Some(r1.rref()));
    pair(&a, &c, false, Some(r2.rref()));
    let n = pc_node(&a);
    for r in [&r1, &r2] {
        let _ = n.add_relay(&r.url(), &r.server.device_id().to_hex(), "");
    }
    let ai = a.id();
    wait("A on both", || {
        r1.relay.has_peer(&ai) && r2.relay.has_peer(&ai)
    });
    let r1_url = r1.url().trim_end_matches('/').to_owned();
    let r2_url = r2.url().trim_end_matches('/').to_owned();
    let status = |u: &str| n.relays().into_iter().find(|r| r.url == u).unwrap().status;
    assert_eq!(status(&r1_url), RelayStatus::Connected);
    drop(r1);
    wait(
        "R1 parked",
        || matches!(status(&r1_url), RelayStatus::Unreachable { since_ms } if since_ms > 0),
    );
    assert_eq!(status(&r2_url), RelayStatus::Connected, "only R1 is down");
    // Parked: no reconnect hammering. Retry is explicit and harmless.
    n.retry_relay(&r1_url);
    let ci = c.id();
    a.send_url(&ci, "https://example.com/m44/r2-while-r1-down");
    wait("R2 pairing works", || {
        c.got_url("https://example.com/m44/r2-while-r1-down")
    });
}
