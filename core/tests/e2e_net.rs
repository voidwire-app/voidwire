//! Headless end-to-end test over real UDP sockets (QUIC on loopback):
//! the PC node (desktop core service, no UI) and a Rust phone client.
//!
//! Covers: QR pairing with the typed 6-digit code, 20 sends with latency,
//! no-prompt delivery (the default) and "Ask before opening", and rejections over the
//! socket path (non-http(s), oversized, unpaired sender, replay, tampered,
//! wrong recipient key), plus "Forget this device" reaching the phone as a
//! signed remove op.
//!
//! Run with `--nocapture` to see the latency table.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use voidwire_core::envelope::MAX_ENVELOPE_LEN;
use voidwire_core::keys::Platform;
use voidwire_core::net::pc::{PairStatus, PcConfig, PcEvent, PcNode};
use voidwire_core::net::phone::{GroupChange, PhoneClient, PhoneConfig};
use voidwire_core::net::state::MemoryStateStore;
use voidwire_core::net::{NetError, SendOutcome};
use voidwire_core::ratelimit::RateLimit;
use voidwire_core::reject::RejectReason;
use voidwire_core::test_util::{FakePeer, SharedSpyOpener};
use voidwire_core::time::{Clock, Stopwatch, SystemClock};
use voidwire_core::verify::InboxConfig;

fn phone(name: &str) -> PhoneClient {
    PhoneClient::new(PhoneConfig {
        state: Arc::new(MemoryStateStore::default()),
        default_name: name.into(),
        platform: Platform::Android,
        mdns: false,
    })
    .expect("phone")
}

fn rejected(r: Result<impl std::fmt::Debug, NetError>) -> RejectReason {
    match r {
        Err(NetError::Rejected(r)) => r,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

fn rand_suffix() -> u64 {
    use rand_core::RngCore;
    rand_core::OsRng.next_u64()
}

fn wall() -> voidwire_core::time::UnixMillis {
    SystemClock.now().wall
}

#[test]
fn e2e_pair_send_reject_forget_over_real_sockets() {
    // ---- PC (headless desktop core) ----
    let spy = Arc::new(SharedSpyOpener::default());
    let events: Arc<Mutex<Vec<PcEvent>>> = Arc::default();
    let ev = events.clone();
    let mut cfg = PcConfig::new(
        "Test PC",
        Arc::new(MemoryStateStore::default()),
        spy.clone(),
    );
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    let roomy = RateLimit {
        burst: 200,
        per_minute: 600,
    };
    cfg.inbox = InboxConfig {
        pre_decrypt: roomy,
        per_device: roomy,
        global: roomy,
        ..InboxConfig::default()
    };
    cfg.events = Some(Arc::new(move |e| ev.lock().unwrap().push(e)));
    let pc = PcNode::start(cfg).expect("pc");
    let pc_id = pc.device_id();
    assert!(pc.no_prompt(), "fresh PC: no-prompt is the default");

    // ---- pairing: QR + typed code ----
    let t = Stopwatch::start();
    let inv = pc.pair_start().unwrap();
    assert!(inv.qr_uri.starts_with("voidwire:pair?"));
    assert!(inv.qr_uri.contains("&a=127.0.0.1"), "{}", inv.qr_uri);
    let p1 = phone("Test Phone");
    let session = p1.begin_pairing(&inv.qr_uri).expect("begin pairing");
    assert_eq!(session.pc_name(), "Test PC");
    assert_eq!(
        pc.pair_status(),
        PairStatus::AwaitingCode {
            device_name: "Test Phone".into()
        }
    );
    // The QR secret was consumed by that first attempt.
    let p_late = phone("Late Phone");
    assert_eq!(
        rejected(p_late.begin_pairing(&inv.qr_uri).map(|_| ())),
        RejectReason::PairingSecretUsed
    );
    let sas = session.sas();
    assert_eq!(sas.len(), 6);
    pc.pair_submit_code(&sas).expect("typed code accepted");
    let paired = session
        .wait_welcome(Duration::from_secs(10))
        .expect("welcome");
    let pairing_ms = t.elapsed_us() as f64 / 1000.0;
    assert_eq!(paired.id, pc_id);
    assert_eq!(paired.name, "Test PC");
    assert!(!paired.removed);
    let devs = pc.devices();
    assert_eq!(devs.len(), 1);
    assert_eq!(devs[0].id, p1.device_id());
    assert_eq!(devs[0].name, "Test Phone");
    assert_eq!(devs[0].platform, Some(Platform::Android));

    // Wrong code: one try, both sides told.
    let inv2 = pc.pair_start().unwrap();
    let p2 = phone("Wrong Code Phone");
    let s2 = p2.begin_pairing(&inv2.qr_uri).unwrap();
    let wrong = if s2.sas() == "000000" {
        "111111"
    } else {
        "000000"
    };
    assert_eq!(
        rejected(pc.pair_submit_code(wrong)),
        RejectReason::SasRejected
    );
    assert_eq!(
        rejected(s2.wait_welcome(Duration::from_secs(10))),
        RejectReason::SasRejected
    );
    assert_eq!(pc.devices().len(), 1);
    pc.pair_cancel();

    // ---- default mode (fresh state): opens at once, no prompt ----
    let r = p1.send_url(&pc_id, "https://example.com/first").unwrap();
    assert_eq!(r.outcome, SendOutcome::Opened);
    assert_eq!(spy.calls(), vec!["https://example.com/first".to_string()]);
    assert!(pc.pending().is_empty(), "no prompt in the default mode");
    assert!(events
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, PcEvent::Opened { .. })));

    // ---- "Ask before opening" on: prompt, then the user clicks Open ----
    pc.set_no_prompt(false).unwrap();
    let r = p1.send_url(&pc_id, "https://example.com/asked").unwrap();
    assert_eq!(r.outcome, SendOutcome::Prompted);
    assert_eq!(spy.count(), 1, "nothing opens before the click");
    let pending = pc.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].host, "example.com");
    assert_eq!(pending[0].from, "Test Phone");
    pc.decide(pending[0].id, true).unwrap();
    assert_eq!(spy.count(), 2);
    assert_eq!(spy.calls()[1], "https://example.com/asked");
    // Deciding it again (or any unknown id) has its own reason.
    assert_eq!(
        rejected(pc.decide(pending[0].id, true)),
        RejectReason::NoSuchPrompt
    );
    assert_eq!(
        rejected(pc.decide(9_999, false)),
        RejectReason::NoSuchPrompt
    );

    // ---- back to the default (no-prompt): 20 sends, measured ----
    pc.set_no_prompt(true).unwrap();
    let mut lat = Vec::new();
    for i in 0..20 {
        let url = format!("https://example.org/article/{i}?src=e2e");
        let r = p1.send_url(&pc_id, &url).unwrap();
        assert_eq!(r.outcome, SendOutcome::Opened);
        lat.push(r.latency_us as f64 / 1000.0);
    }
    assert_eq!(spy.count(), 22);
    let mut sorted = lat.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p = |q: f64| sorted[((sorted.len() as f64 - 1.0) * q).round() as usize];
    println!("E2E pairing (QR scan → welcome, code typed immediately): {pairing_ms:.1} ms");
    let shown: Vec<String> = lat.iter().map(|l| format!("{l:.2}")).collect();
    println!(
        "E2E 20 sends latency ms (send_url → PC opened): [{}]",
        shown.join(", ")
    );
    println!(
        "E2E latency min {:.2} / median {:.2} / p95 {:.2} / max {:.2} ms",
        sorted[0],
        p(0.5),
        p(0.95),
        sorted[sorted.len() - 1]
    );
    assert!(sorted[sorted.len() - 1] < 2000.0, "every send under 2 s");

    // ---- rejections over the real socket path ----
    let opened_before = spy.count();
    let fake: FakePeer = p1.fake_peer_for_tests(&pc_id).unwrap();

    // Non-http(s): refused locally by the phone, and by the PC when forced.
    assert_eq!(
        rejected(p1.send_url(&pc_id, "file:///etc/passwd")),
        RejectReason::SchemeNotAllowed
    );
    for bad in [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "ftp://example.com/x",
        "intent://x#Intent;end",
    ] {
        let env = fake.frame(bad, wall());
        assert_eq!(
            rejected(p1.send_envelope_for_tests(&pc_id, &env)),
            RejectReason::SchemeNotAllowed,
            "{bad}"
        );
    }

    // Oversized: a URL over 8 KiB inside a valid envelope...
    let long = format!("https://example.com/{}", "a".repeat(8200));
    let env = fake.frame(&long, wall());
    assert!(env.len() <= MAX_ENVELOPE_LEN);
    assert_eq!(
        rejected(p1.send_envelope_for_tests(&pc_id, &env)),
        RejectReason::UrlTooLong
    );
    // ...and a frame over the envelope cap, refused from its header alone.
    let mut raw = vec![0x12];
    raw.extend_from_slice(&((MAX_ENVELOPE_LEN + 1) as u32).to_be_bytes());
    raw.extend_from_slice(&vec![0u8; MAX_ENVELOPE_LEN + 1]);
    let (t, payload) = p1.raw_request_for_tests(&pc_id, &raw).unwrap();
    assert_eq!(t, 0x7F);
    assert_eq!(
        u16::from_be_bytes([payload[0], payload[1]]),
        RejectReason::MalformedFrame.code()
    );
    let mut huge = vec![0x12];
    huge.extend_from_slice(&u32::MAX.to_be_bytes());
    let (t, _) = p1.raw_request_for_tests(&pc_id, &huge).unwrap();
    assert_eq!(t, 0x7F);

    // Replay: the same envelope twice.
    let env = fake.frame("https://example.com/once", wall());
    assert_eq!(
        p1.send_envelope_for_tests(&pc_id, &env).unwrap().outcome,
        SendOutcome::Opened
    );
    assert_eq!(
        rejected(p1.send_envelope_for_tests(&pc_id, &env)),
        RejectReason::Replay
    );

    // Tampered: flip bits in the ciphertext, the tag and the header.
    let env = fake.frame("https://example.com/tamper", wall());
    for bit in [8 * 40, 8 * (env.len() - 1), 8 * 2 + 1] {
        let r = rejected(p1.send_envelope_for_tests(&pc_id, &FakePeer::bit_flip(&env, bit)));
        assert!(
            matches!(
                r,
                RejectReason::DecryptFailed
                    | RejectReason::UnsupportedVersion
                    | RejectReason::MalformedFrame
            ),
            "bit {bit}: {r:?}"
        );
    }

    // Sealed to the wrong receive key.
    let mut wrong_key = p1.fake_peer_for_tests(&pc_id).unwrap();
    wrong_key.seal_to = voidwire_core::keys::ReceiveKeypair::generate().public();
    assert_eq!(
        rejected(
            p1.send_envelope_for_tests(&pc_id, &wrong_key.frame("https://example.com/w", wall()))
        ),
        RejectReason::DecryptFailed
    );

    // Unpaired sender: a phone that never paired, pointed at the PC with
    // everything it would need except membership. Closed before any read.
    let stranger = phone("Stranger");
    stranger
        .adopt_pc_for_tests(
            p1.replica_ops_for_tests(&pc_id),
            pc_id,
            paired.addrs.clone(),
        )
        .unwrap();
    assert_eq!(
        rejected(stranger.send_url(&pc_id, "https://example.com/stranger")),
        RejectReason::NotInRoster
    );
    let fake_stranger = stranger.fake_peer_for_tests(&pc_id).unwrap();
    assert_eq!(
        rejected(stranger.send_envelope_for_tests(
            &pc_id,
            &fake_stranger.frame("https://example.com/s", wall())
        )),
        RejectReason::NotInRoster
    );

    assert_eq!(
        spy.count(),
        opened_before + 1,
        "only the first copy of the replayed link opened"
    );

    // ---- Forget this device: immediate, and the phone learns it ----
    assert!(pc.forget_device(&p1.device_id()).unwrap());
    assert!(pc.devices().is_empty());
    assert_eq!(
        rejected(p1.send_url(&pc_id, "https://example.com/after-forget")),
        RejectReason::Removed
    );
    assert!(
        p1.paired_pcs()[0].removed,
        "signed remove op reached the phone"
    );
    // Even a hand-built envelope with the old head is refused.
    let env = fake.frame("https://example.com/after-forget-raw", wall());
    assert_eq!(
        rejected(p1.send_envelope_for_tests(&pc_id, &env)),
        RejectReason::Removed
    );

    let (accepted, rejected_by) = pc.counters();
    println!("E2E PC counters: accepted {accepted}, rejected {rejected_by:?}");
    assert_eq!(
        accepted, 23,
        "1 default + 1 confirmed + 20 no-prompt + 1st copy of the replayed link"
    );
    let ev = events.lock().unwrap();
    assert!(ev.iter().any(|e| matches!(
        e,
        PcEvent::Rejected {
            reason: RejectReason::NotInRoster,
            ..
        }
    )));
    assert!(ev.iter().any(|e| matches!(e, PcEvent::PendingOpen { .. })));
    drop(ev);
    pc.shutdown();
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn pc_config(
    state: Arc<dyn voidwire_core::net::state::StateStore>,
    spy: Arc<SharedSpyOpener>,
    port: u16,
    seen: std::path::PathBuf,
) -> PcConfig {
    let mut cfg = PcConfig::new("Restart PC", state, spy);
    cfg.mdns = false;
    cfg.port = Some(port);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.seen_store_path = Some(seen);
    cfg
}

/// ENV-05 over the network: state and the fsync'd replay cache survive a
/// PC restart; a link captured before the restart can't be replayed after.
#[test]
fn e2e_restart_keeps_pairing_and_replay_cache() {
    let dir = std::env::temp_dir().join(format!("vw-e2e-restart-{:x}", rand_suffix()));
    let _ = std::fs::remove_dir_all(&dir);
    let state: Arc<dyn voidwire_core::net::state::StateStore> = Arc::new(
        voidwire_core::net::state::FileStateStore::new(dir.join("state.bin")),
    );
    let spy = Arc::new(SharedSpyOpener::default());
    let port = free_udp_port();
    let pc = PcNode::start(pc_config(
        state.clone(),
        spy.clone(),
        port,
        dir.join("seen.bin"),
    ))
    .unwrap();
    let pc_id = pc.device_id();
    pc.set_no_prompt(true).unwrap();
    let p1 = phone("Restart Phone");
    let s = p1.begin_pairing(&pc.pair_start().unwrap().qr_uri).unwrap();
    pc.pair_submit_code(&s.sas()).unwrap();
    s.wait_welcome(Duration::from_secs(10)).unwrap();
    let fake = p1.fake_peer_for_tests(&pc_id).unwrap();
    let env = fake.frame("https://example.com/before-restart", wall());
    assert_eq!(
        p1.send_envelope_for_tests(&pc_id, &env).unwrap().outcome,
        SendOutcome::Opened
    );
    pc.shutdown();

    let pc = PcNode::start(pc_config(
        state.clone(),
        spy.clone(),
        port,
        dir.join("seen.bin"),
    ))
    .unwrap();
    assert_eq!(pc.device_id(), pc_id, "same identity after restart");
    assert!(pc.no_prompt(), "setting persisted");
    // An explicit "Ask before opening" survives a restart too (saved state
    // keeps the user's choice; only a fresh state gets the new default).
    pc.set_no_prompt(false).unwrap();
    pc.shutdown();
    let pc = PcNode::start(pc_config(
        state.clone(),
        spy.clone(),
        port,
        dir.join("seen.bin"),
    ))
    .unwrap();
    assert!(!pc.no_prompt(), "explicit ask choice persisted");
    pc.set_no_prompt(true).unwrap();
    assert_eq!(pc.devices().len(), 1, "pairing persisted");
    // Stale cached connection → the client reconnects once.
    let r = p1
        .send_url(&pc_id, "https://example.com/after-restart")
        .unwrap();
    assert_eq!(r.outcome, SendOutcome::Opened);
    assert_eq!(
        rejected(p1.send_envelope_for_tests(&pc_id, &env)),
        RejectReason::Replay
    );
    assert_eq!(spy.count(), 2);
    pc.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

/// QA M1 re-check L2 over the real PC node: seen.bin truncated at a record
/// boundary between runs is caught by the high-water mark in state.bin; the
/// PC starts with the replay startup guard, so the captured link is refused.
#[test]
fn e2e_seen_file_truncated_at_record_boundary_fails_closed() {
    use voidwire_core::replay::StoreHealth;
    let dir = std::env::temp_dir().join(format!("vw-e2e-l2-{:x}", rand_suffix()));
    let _ = std::fs::remove_dir_all(&dir);
    let state: Arc<dyn voidwire_core::net::state::StateStore> = Arc::new(
        voidwire_core::net::state::FileStateStore::new(dir.join("state.bin")),
    );
    let spy = Arc::new(SharedSpyOpener::default());
    let port = free_udp_port();
    let seen = dir.join("seen.bin");
    let pc = PcNode::start(pc_config(state.clone(), spy.clone(), port, seen.clone())).unwrap();
    let pc_id = pc.device_id();
    pc.set_no_prompt(true).unwrap();
    let p1 = phone("L2 Phone");
    let s = p1.begin_pairing(&pc.pair_start().unwrap().qr_uri).unwrap();
    pc.pair_submit_code(&s.sas()).unwrap();
    s.wait_welcome(Duration::from_secs(10)).unwrap();
    let fake = p1.fake_peer_for_tests(&pc_id).unwrap();
    let first = fake.frame("https://example.com/l2-a", wall());
    let last = fake.frame("https://example.com/l2-b", wall());
    for env in [&first, &last] {
        assert_eq!(
            p1.send_envelope_for_tests(&pc_id, env).unwrap().outcome,
            SendOutcome::Opened
        );
    }
    pc.shutdown();

    // Clean restart first: no guard (no false alarm).
    let pc = PcNode::start(pc_config(state.clone(), spy.clone(), port, seen.clone())).unwrap();
    assert_eq!(
        pc.replay_cache_health(),
        Some(StoreHealth::Intact { torn_bytes: 0 })
    );
    pc.shutdown();

    // Cut seen.bin at a record boundary: drop the newest record.
    let bytes = std::fs::read(&seen).unwrap();
    let rec = 2 + 16 + 8 + 4;
    assert!(bytes.len() >= 8 + 2 * rec);
    std::fs::write(&seen, &bytes[..bytes.len() - rec]).unwrap();
    let pc = PcNode::start(pc_config(state, spy.clone(), port, seen)).unwrap();
    assert_eq!(pc.replay_cache_health(), Some(StoreHealth::Corrupt));
    for env in [&first, &last] {
        assert_eq!(
            rejected(p1.send_envelope_for_tests(&pc_id, env)),
            RejectReason::ReplayStartupGuard
        );
    }
    assert_eq!(spy.count(), 2, "nothing replayed");
    // New links still go through.
    assert_eq!(
        p1.send_url(&pc_id, "https://example.com/l2-new")
            .unwrap()
            .outcome,
        SendOutcome::Opened
    );
    pc.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Discovery without address hints: the phone finds the PC by mDNS/DNS-SD
/// only. Needs multicast on a real interface, so it's opt-in:
/// `VOIDWIRE_E2E_MDNS=1 cargo test -p voidwire-core --features net --test e2e_net`.
#[test]
fn e2e_mdns_discovery_without_hints() {
    if std::env::var("VOIDWIRE_E2E_MDNS").as_deref() != Ok("1") {
        eprintln!("skipped (set VOIDWIRE_E2E_MDNS=1)");
        return;
    }
    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new(
        "mDNS PC",
        Arc::new(MemoryStateStore::default()),
        spy.clone(),
    );
    cfg.port = Some(0);
    cfg.unchecked_inbox_for_tests = true;
    let pc = PcNode::start(cfg).unwrap();
    let pc_id = pc.device_id();
    pc.set_no_prompt(true).unwrap();
    let qr = pc.pair_start().unwrap().qr_uri;
    let qr = match qr.find("&a=") {
        Some(i) => qr[..i].to_string(),
        None => qr,
    };
    let phone_state: Arc<dyn voidwire_core::net::state::StateStore> =
        Arc::new(MemoryStateStore::default());
    let p = PhoneClient::new(PhoneConfig {
        state: phone_state.clone(),
        default_name: "mDNS Phone".into(),
        platform: Platform::Android,
        mdns: true,
    })
    .unwrap();
    let t = Stopwatch::start();
    let s = p.begin_pairing(&qr).expect("found the PC by mDNS");
    println!(
        "E2E mDNS: PC found and proof accepted in {:.1} ms",
        t.elapsed_us() as f64 / 1000.0
    );
    pc.pair_submit_code(&s.sas()).unwrap();
    s.wait_welcome(Duration::from_secs(10)).unwrap();
    let r = p.send_url(&pc_id, "https://example.com/mdns").unwrap();
    println!(
        "E2E mDNS: first send {:.2} ms",
        r.latency_us as f64 / 1000.0
    );
    assert_eq!(spy.count(), 1);

    // Poisoned cached address (another device answers there): the phone
    // falls back to a fresh mDNS lookup once, reaches the right PC, and
    // replaces the cached address.
    let rogue = PhoneClient::new(PhoneConfig {
        state: Arc::new(MemoryStateStore::default()),
        default_name: "Rogue".into(),
        platform: Platform::Android,
        mdns: false,
    })
    .unwrap();
    let rogue_port = rogue.bound_sockets_for_tests()[0].port();
    let poisoned: std::net::SocketAddr = ([127, 0, 0, 1], rogue_port).into();
    p.set_pc_addrs_for_tests(&pc_id, vec![poisoned]);
    let t = Stopwatch::start();
    let r = p
        .send_url(&pc_id, "https://example.com/after-poison")
        .expect("fell back to mDNS");
    println!(
        "E2E mDNS fallback after a poisoned address: {:.1} ms",
        t.elapsed_us() as f64 / 1000.0
    );
    assert_eq!(r.outcome, SendOutcome::Opened);
    assert_eq!(spy.count(), 2);
    let addrs = &p.paired_pcs()[0].addrs;
    assert!(
        !addrs.contains(&poisoned),
        "cached address replaced: {addrs:?}"
    );
    // A dead cached address (nothing listening) also falls back.
    p.set_pc_addrs_for_tests(&pc_id, vec![([127, 0, 0, 1], free_udp_port()).into()]);
    p.send_url(&pc_id, "https://example.com/after-dead")
        .expect("fell back to mDNS");
    assert_eq!(spy.count(), 3);

    // L3: a COLD process (the share sheet's usual case): a fresh phone
    // client whose cached address is answered fast by the wrong device.
    // mDNS has no answers yet; the fallback must wait (bounded) for one
    // instead of failing in ~20 ms.
    drop(p);
    let cold = PhoneClient::new(PhoneConfig {
        state: phone_state,
        default_name: "ignored".into(),
        platform: Platform::Android,
        mdns: true,
    })
    .unwrap();
    // QA's case: the cached address is another *PC* (TLS fails fast with
    // the wrong identity), not a dead port.
    let mut evil_cfg = PcConfig::new(
        "Evil PC",
        Arc::new(MemoryStateStore::default()),
        Arc::new(SharedSpyOpener::default()),
    );
    evil_cfg.mdns = false;
    let evil_port = free_udp_port();
    evil_cfg.port = Some(evil_port);
    evil_cfg.advertise_loopback = true;
    evil_cfg.unchecked_inbox_for_tests = true;
    let evil = PcNode::start(evil_cfg).unwrap();
    let evil_addr: std::net::SocketAddr = ([127, 0, 0, 1], evil_port).into();
    cold.set_pc_addrs_for_tests(&pc_id, vec![evil_addr]);
    let t = Stopwatch::start();
    let r = cold
        .send_url(&pc_id, "https://example.com/cold-fallback")
        .expect("cold process fell back to mDNS");
    let cold_ms = t.elapsed_us() as f64 / 1000.0;
    println!("E2E mDNS fallback from a cold process: {cold_ms:.1} ms");
    assert_eq!(r.outcome, SendOutcome::Opened);
    assert_eq!(spy.count(), 4);
    assert!(cold_ms < 2_000.0 + 8_000.0, "bounded");

    // The wait is bounded: an unknown PC gives up after MDNS_FALLBACK_WAIT.
    let nobody = voidwire_core::keys::DeviceKeypair::generate().device_id();
    let t = Stopwatch::start();
    let found = cold.discover_for_tests(&nobody, voidwire_core::net::phone::MDNS_FALLBACK_WAIT);
    let waited_ms = t.elapsed_us() / 1000;
    assert!(found.is_empty());
    assert!((1_900..3_000).contains(&waited_ms), "waited {waited_ms} ms");
    evil.shutdown();
    pc.shutdown();
}

/// L3 without multicast: with no address lookup configured, the fallback
/// helper returns at once (nothing to wait for).
#[test]
fn e2e_mdns_wait_without_lookup_returns_immediately() {
    let p = phone("No mDNS");
    let nobody = voidwire_core::keys::DeviceKeypair::generate().device_id();
    let t = Stopwatch::start();
    assert!(p
        .discover_for_tests(&nobody, Duration::from_secs(2))
        .is_empty());
    assert!(t.elapsed_us() < 500_000, "no lookup: no wait");
}

/// Pending prompts expire (QA M1 Low): an unanswered link can't be opened
/// later. The TTL is 2 min in the app; shortened here.
#[test]
fn e2e_pending_prompt_expires() {
    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new("TTL PC", Arc::new(MemoryStateStore::default()), spy.clone());
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.prompt_ttl_ms = 300;
    let pc = PcNode::start(cfg).unwrap();
    let pc_id = pc.device_id();
    pc.set_no_prompt(false).unwrap(); // "Ask before opening"
    let p = phone("TTL Phone");
    let s = p.begin_pairing(&pc.pair_start().unwrap().qr_uri).unwrap();
    pc.pair_submit_code(&s.sas()).unwrap();
    s.wait_welcome(Duration::from_secs(10)).unwrap();

    assert_eq!(
        p.send_url(&pc_id, "https://example.com/old")
            .unwrap()
            .outcome,
        SendOutcome::Prompted
    );
    let id = pc.pending()[0].id;
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(rejected(pc.decide(id, true)), RejectReason::PromptExpired);
    assert_eq!(spy.count(), 0, "an expired prompt never opens");
    // Expired prompts also drop out of the list on their own.
    p.send_url(&pc_id, "https://example.com/second").unwrap();
    assert_eq!(pc.pending().len(), 1);
    std::thread::sleep(Duration::from_millis(400));
    assert!(pc.pending().is_empty());
    // A fresh one still works.
    p.send_url(&pc_id, "https://example.com/fresh").unwrap();
    let id = pc.pending()[0].id;
    pc.decide(id, true).unwrap();
    assert_eq!(spy.calls(), vec!["https://example.com/fresh".to_string()]);
    pc.shutdown();
}

/// "Ask before opening" over the network: a prompt from a device that is
/// forgotten while the prompt is up never opens (the prompt is dropped and
/// the click finds nothing), and the device's next link is refused.
#[test]
fn e2e_ask_mode_prompt_from_forgotten_device_never_opens() {
    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new("Ask PC", Arc::new(MemoryStateStore::default()), spy.clone());
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    let pc = PcNode::start(cfg).unwrap();
    let pc_id = pc.device_id();
    pc.set_no_prompt(false).unwrap();
    let p = phone("Ask Phone");
    let s = p.begin_pairing(&pc.pair_start().unwrap().qr_uri).unwrap();
    pc.pair_submit_code(&s.sas()).unwrap();
    s.wait_welcome(Duration::from_secs(10)).unwrap();
    assert_eq!(
        p.send_url(&pc_id, "https://example.com/pending")
            .unwrap()
            .outcome,
        SendOutcome::Prompted
    );
    let id = pc.pending()[0].id;
    assert!(pc.forget_device(&p.device_id()).unwrap());
    assert!(pc.pending().is_empty());
    assert_eq!(rejected(pc.decide(id, true)), RejectReason::NoSuchPrompt);
    assert_eq!(
        rejected(p.send_url(&pc_id, "https://example.com/after")),
        RejectReason::Removed
    );
    assert_eq!(spy.count(), 0);
    pc.shutdown();
}

/// Every open emits `PcEvent::Opened` with the ASCII host and sender name only
/// (no path, query, fragment or port); rejects emit `PcEvent::Rejected` and
/// never `PcEvent::Opened`. (OS notifications were removed in M1.2 because OS
/// notification centers log toast payloads to disk.)
#[test]
fn e2e_every_no_prompt_open_notifies_host_and_device_only() {
    let spy = Arc::new(SharedSpyOpener::default());
    let events: Arc<Mutex<Vec<PcEvent>>> = Arc::default();
    let ev = events.clone();
    let mut cfg = PcConfig::new(
        "Notify PC",
        Arc::new(MemoryStateStore::default()),
        spy.clone(),
    );
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    let roomy = RateLimit {
        burst: 50,
        per_minute: 600,
    };
    cfg.inbox = InboxConfig {
        pre_decrypt: roomy,
        per_device: roomy,
        global: roomy,
        ..InboxConfig::default()
    };
    cfg.events = Some(Arc::new(move |e| ev.lock().unwrap().push(e)));
    let pc = PcNode::start(cfg).unwrap();
    let pc_id = pc.device_id();
    assert!(pc.no_prompt(), "default mode");
    let p = phone("Notify Phone");
    let s = p.begin_pairing(&pc.pair_start().unwrap().qr_uri).unwrap();
    pc.pair_submit_code(&s.sas()).unwrap();
    s.wait_welcome(Duration::from_secs(10)).unwrap();
    let notes = || -> Vec<String> {
        events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                PcEvent::Opened {
                    host,
                    from,
                    without_prompt: true,
                    ..
                } => Some(format!("Opened {host} from {from}")),
                _ => None,
            })
            .collect()
    };
    assert!(notes().is_empty(), "pairing raises no open notification");

    // Every no-prompt open notifies, host only.
    for url in [
        "https://example.com:8443/secret/path?token=s3cret#frag",
        "https://example.org/x?y=1",
        "https://example.com/again",
    ] {
        assert_eq!(
            p.send_url(&pc_id, url).unwrap().outcome,
            SendOutcome::Opened
        );
    }
    let fake = p.fake_peer_for_tests(&pc_id).unwrap();
    let env = fake.frame("https://example.net/replayed", wall());
    assert_eq!(
        p.send_envelope_for_tests(&pc_id, &env).unwrap().outcome,
        SendOutcome::Opened
    );
    let expected = [
        "Opened example.com from Notify Phone",
        "Opened example.org from Notify Phone",
        "Opened example.com from Notify Phone",
        "Opened example.net from Notify Phone",
    ];
    assert_eq!(notes(), expected);
    assert_eq!(spy.count(), 4);
    for n in notes() {
        for leak in [
            "/", "?", "#", ":8443", "secret", "token", "frag", "again", "replayed",
        ] {
            assert!(!n.contains(leak), "{leak:?} leaked into {n:?}");
        }
    }

    // Rejects raise nothing: a replay, a URL-policy refusal, and (below) a
    // removed device.
    assert!(p.send_envelope_for_tests(&pc_id, &env).is_err(), "replay");
    assert!(p.send_url(&pc_id, "https://user:pw@example.com/").is_err());
    // ...and the same URL hand-built past the phone's own check, refused by
    // the PC's verifier.
    let bad = fake.frame("https://user:pw@example.com/", wall());
    assert!(p.send_envelope_for_tests(&pc_id, &bad).is_err());
    // "Ask before opening": the user's own click raises nothing either.
    pc.set_no_prompt(false).unwrap();
    assert_eq!(
        p.send_url(&pc_id, "https://example.com/asked")
            .unwrap()
            .outcome,
        SendOutcome::Prompted
    );
    pc.decide(pc.pending()[0].id, true).unwrap();
    assert_eq!(spy.count(), 5);
    pc.set_no_prompt(true).unwrap();
    assert!(pc.forget_device(&p.device_id()).unwrap());
    assert_eq!(
        rejected(p.send_url(&pc_id, "https://example.com/after-forget")),
        RejectReason::Removed
    );
    assert_eq!(spy.count(), 5);
    assert_eq!(
        notes(),
        expected,
        "no notification for rejects or prompted opens"
    );
    let ev = events.lock().unwrap();
    let rejects = ev
        .iter()
        .filter(|e| matches!(e, PcEvent::Rejected { .. }))
        .count();
    assert!(rejects >= 2, "the rejects above were seen: {ev:?}");
    assert!(ev.iter().any(|e| matches!(
        e,
        PcEvent::Opened {
            without_prompt: false,
            ..
        }
    )));
    drop(ev);
    pc.shutdown();
}

/// OQ-9 / PAIR-11: a phone that already belongs to a group is warned before
/// joining a different one, and core refuses unless the user confirmed.
#[test]
fn e2e_joining_a_different_group_needs_confirmation() {
    let start = |name: &str| {
        let mut cfg = PcConfig::new(
            name,
            Arc::new(MemoryStateStore::default()),
            Arc::new(SharedSpyOpener::default()),
        );
        cfg.mdns = false;
        cfg.port = Some(0);
        cfg.advertise_loopback = true;
        cfg.unchecked_inbox_for_tests = true;
        PcNode::start(cfg).unwrap()
    };
    let home = start("Home PC");
    let other = start("Other PC");
    let p = phone("Group Phone");

    // First group: nothing to warn about.
    let qr = home.pair_start().unwrap().qr_uri;
    let c = p.inspect_invite(&qr).unwrap();
    assert!(!c.joins_different_group);
    assert_eq!(c.pc_name.as_deref(), Some("Home PC"));
    let s = p.begin_pairing(&qr).unwrap();
    home.pair_submit_code(&s.sas()).unwrap();
    s.wait_welcome(Duration::from_secs(10)).unwrap();

    // A QR for a different group: warned, and refused without confirmation
    // before any network traffic (the QR stays usable).
    let qr2 = other.pair_start().unwrap().qr_uri;
    let c = p.inspect_invite(&qr2).unwrap();
    assert!(c.joins_different_group);
    assert_eq!(c.pc_name.as_deref(), Some("Other PC"));
    assert_eq!(c.current_groups, vec!["Home PC".to_string()]);
    assert_eq!(
        rejected(p.begin_pairing(&qr2).map(|_| ())),
        RejectReason::GroupChangeNotConfirmed
    );
    assert!(
        matches!(other.pair_status(), PairStatus::WaitingForScan { .. }),
        "nothing reached the other PC"
    );
    // Confirmed: pairs, and the rosters stay separate.
    let s = p.begin_pairing_with(&qr2, GroupChange::Confirmed).unwrap();
    other.pair_submit_code(&s.sas()).unwrap();
    s.wait_welcome(Duration::from_secs(10)).unwrap();
    assert_eq!(p.paired_pcs().len(), 2);
    assert_eq!(home.devices().len(), 1);
    assert_eq!(other.devices().len(), 1);

    // Re-pairing with a PC of a group the phone is already in: no warning.
    let qr3 = home.pair_start().unwrap().qr_uri;
    assert!(!p.inspect_invite(&qr3).unwrap().joins_different_group);
    home.pair_cancel();

    // A QR whose name doesn't match the PC's certificate is refused.
    let qr4 = other.pair_start().unwrap().qr_uri;
    let forged = qr4.replace("&n=Other+PC", "&n=Home+PC");
    assert_ne!(forged, qr4);
    let fresh = phone("Fresh Phone");
    assert_eq!(
        rejected(fresh.begin_pairing(&forged).map(|_| ())),
        RejectReason::SenderMismatch
    );
    home.shutdown();
    other.shutdown();
}

/// QA M1 re-check PAIR-11 bypass: a fake PC that reuses the victim's group id
/// (it's printed in every pairing QR) and copies the PC name must NOT pass as
/// "same group". Same group is decided from the authenticated inviter
/// (owner/member of a signed log the phone already holds), and a duplicate PC
/// name is warned about as well.
#[test]
fn e2e_fake_pc_reusing_group_id_and_name_is_warned() {
    use voidwire_core::ids::GroupId;
    let start = |name: &str, group: Option<GroupId>| {
        let mut cfg = PcConfig::new(
            name,
            Arc::new(MemoryStateStore::default()),
            Arc::new(SharedSpyOpener::default()),
        );
        cfg.mdns = false;
        cfg.port = Some(0);
        cfg.advertise_loopback = true;
        cfg.unchecked_inbox_for_tests = true;
        cfg.genesis_group_for_tests = group;
        PcNode::start(cfg).unwrap()
    };
    let home = start("Home PC", None);
    let p = phone("Victim Phone");
    let qr = home.pair_start().unwrap().qr_uri;
    let s = p.begin_pairing(&qr).unwrap();
    home.pair_submit_code(&s.sas()).unwrap();
    s.wait_welcome(Duration::from_secs(10)).unwrap();

    // The attacker reads g= off the victim's QR (or any earlier one).
    let g_hex = qr
        .split(['?', '&'])
        .find_map(|kv| kv.strip_prefix("g="))
        .expect("g= in QR")
        .to_owned();
    let victim_group = GroupId::from_hex(&g_hex).expect("group hex");
    let evil = start("Home PC", Some(victim_group));
    let evil_qr = evil.pair_start().unwrap().qr_uri;
    assert!(
        evil_qr.contains(&format!("g={g_hex}")),
        "attacker reused g="
    );

    // Warned: different group (the inviter isn't in the signed log we hold)
    // and a duplicate name.
    let c = p.inspect_invite(&evil_qr).unwrap();
    assert!(
        c.joins_different_group,
        "group-id reuse must not count as same group"
    );
    assert!(c.duplicate_name, "second 'Home PC' must be flagged");
    assert_eq!(c.current_groups, vec!["Home PC".to_string()]);
    // Refused without confirmation, before any traffic.
    assert_eq!(
        rejected(p.begin_pairing(&evil_qr).map(|_| ())),
        RejectReason::GroupChangeNotConfirmed
    );
    assert!(matches!(
        evil.pair_status(),
        PairStatus::WaitingForScan { .. }
    ));
    assert_eq!(p.paired_pcs().len(), 1);

    // The same QR with n= stripped: still a different group (warned).
    let unnamed: String = evil_qr
        .split('&')
        .filter(|kv| !kv.starts_with("n="))
        .collect::<Vec<_>>()
        .join("&");
    let c = p.inspect_invite(&unnamed).unwrap();
    assert!(c.joins_different_group && c.pc_name.is_none());
    assert_eq!(
        rejected(p.begin_pairing(&unnamed).map(|_| ())),
        RejectReason::GroupChangeNotConfirmed
    );

    // Re-pairing with the real Home PC (authenticated owner): no warning.
    let qr_home = home.pair_start().unwrap().qr_uri;
    let c = p.inspect_invite(&qr_home).unwrap();
    assert!(!c.joins_different_group && !c.duplicate_name);
    home.pair_cancel();

    // A different PC with a different name in a different group: one
    // warning (group), no duplicate-name flag.
    let office = start("Office PC", None);
    let c = p
        .inspect_invite(&office.pair_start().unwrap().qr_uri)
        .unwrap();
    assert!(c.joins_different_group && !c.duplicate_name);
    office.pair_cancel();

    // Only an explicit confirmation pairs with the look-alike.
    let s = p
        .begin_pairing_with(&evil_qr, GroupChange::Confirmed)
        .unwrap();
    evil.pair_submit_code(&s.sas()).unwrap();
    s.wait_welcome(Duration::from_secs(10)).unwrap();
    assert_eq!(p.paired_pcs().len(), 2);
    home.shutdown();
    evil.shutdown();
    office.shutdown();
}

/// M1.1: the pair window's QR auto-refresh, driven through `PcNode` with an
/// injected clock (the phone side uses real sockets and the real clock).
#[test]
fn pair_qr_auto_refresh_pause_and_resume() {
    use voidwire_core::pairing::QrPause;
    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new("Refresh PC", Arc::new(MemoryStateStore::default()), spy);
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    let pc = PcNode::start(cfg).expect("pc");
    let t0 = SystemClock.now();
    let waiting = |s: PairStatus| match s {
        PairStatus::WaitingForScan { qr_seq, .. } => qr_seq,
        other => panic!("expected a live QR, got {other:?}"),
    };

    let first = pc.pair_start_at(t0).unwrap();
    assert_eq!(waiting(pc.pair_status_at(t0.plus(109_999))), first.qr_seq);
    // 10 s before expiry: a fresh QR, the old one revoked immediately.
    let seq2 = waiting(pc.pair_status_at(t0.plus(110_000)));
    assert_ne!(seq2, first.qr_seq);
    let second = pc.pair_qr().expect("live QR");
    assert_eq!(second.qr_seq, seq2);
    assert_ne!(second.qr_uri, first.qr_uri);
    assert_eq!(second.expires_at, t0.plus(230_000).wall, "full 120 s TTL");
    assert_eq!(
        rejected(
            phone("Old QR Phone")
                .begin_pairing(&first.qr_uri)
                .map(|_| ())
        ),
        RejectReason::PairingSecretUsed,
        "superseded QR refused"
    );

    // Hidden/minimized: paused, no live QR, the shown one revoked.
    pc.pair_pause_at(t0.plus(111_000));
    assert_eq!(
        pc.pair_status_at(t0.plus(111_000)),
        PairStatus::Paused {
            why: QrPause::NotVisible
        }
    );
    assert!(pc.pair_qr().is_none());
    assert_eq!(
        rejected(
            phone("Paused Phone")
                .begin_pairing(&second.qr_uri)
                .map(|_| ())
        ),
        RejectReason::PairingSecretUsed
    );

    // "Click to resume": a new QR and a new 10-minute budget, which ends in
    // a pause (no QR is live after the cap).
    let r = SystemClock.now();
    let resumed = pc.pair_start_at(r).unwrap();
    let mut t = r;
    let mut seqs = vec![resumed.qr_seq];
    let why = loop {
        t = t.plus(500);
        match pc.pair_status_at(t) {
            PairStatus::WaitingForScan { qr_seq, .. } => {
                if seqs.last() != Some(&qr_seq) {
                    seqs.push(qr_seq);
                }
            }
            PairStatus::Paused { why } => break why,
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(why, QrPause::TimeLimit);
    assert_eq!(t.mono.0 - r.mono.0, 600_000, "stops at 10 minutes");
    assert_eq!(seqs.len(), 6, "first QR + 5 refreshes");
    assert!(pc.pair_qr().is_none());

    // A live QR that nobody refreshed in time (window stopped polling)
    // pauses instead of refreshing late.
    let r = SystemClock.now();
    pc.pair_start_at(r).unwrap();
    assert_eq!(
        pc.pair_status_at(r.plus(120_000)),
        PairStatus::Paused {
            why: QrPause::NotVisible
        }
    );

    // Resumed for real: a phone pairs with the live QR as usual.
    let live = pc.pair_start().unwrap();
    let p = phone("Fresh Phone");
    let s = p.begin_pairing(&live.qr_uri).expect("live QR works");
    // A scan in progress is not interrupted by a pause.
    pc.pair_pause();
    pc.pair_submit_code(&s.sas()).expect("paired");
    s.wait_welcome(Duration::from_secs(10)).expect("welcome");
}

#[test]
fn e2e_relay_fallback_when_direct_udp_blocked_carries_ciphertext_only() {
    use voidwire_core::net::test_relay::TestRelay;
    use voidwire_core::net::DEFAULT_RELAY_URL;

    let relay = TestRelay::start();
    let spy = Arc::new(SharedSpyOpener::default());

    let mut cfg = PcConfig::new(
        "Relayed PC",
        Arc::new(MemoryStateStore::default()),
        spy.clone(),
    );
    // Verify default relay URL is https://relay.voidwire.app before overriding with local test relay
    assert_eq!(cfg.relay_url.as_deref(), Some(DEFAULT_RELAY_URL));
    cfg.relay_url = Some(relay.url());
    cfg.mdns = false;
    cfg.port = Some(0);
    // Do NOT advertise loopback or LAN addresses so the QR has ONLY the relay URL `r=`
    cfg.advertise_loopback = false;
    cfg.unchecked_inbox_for_tests = true;

    let pc = PcNode::start(cfg).expect("pc");
    let pc_id = pc.device_id();

    // Wait for PC to register on the relay
    let sw = Stopwatch::start();
    while !relay.has_peer(&pc_id) {
        assert!(
            sw.elapsed_us() < 5_000_000,
            "PC did not connect to test relay within 5s"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let inv = pc.pair_start().expect("pair_start");
    assert!(
        inv.qr_uri.contains("&r=http%3A%2F%2F127.0.0.1"),
        "QR must include relay URL r=: {}",
        inv.qr_uri
    );
    // Strip any `&a=` address hints so the phone has ZERO direct UDP path to the PC
    let relay_only_qr: String = inv
        .qr_uri
        .split('&')
        .filter(|part| !part.starts_with("a="))
        .collect::<Vec<_>>()
        .join("&");
    assert!(!relay_only_qr.contains("&a="), "{relay_only_qr}");

    let p = phone("Relayed Phone");
    p.set_relay_url(Some(relay.url())).expect("set_relay_url");
    let session = p
        .begin_pairing(&relay_only_qr)
        .expect("begin_pairing over relay with direct UDP absent");
    assert_eq!(session.pc_name(), "Relayed PC");
    pc.pair_submit_code(&session.sas()).expect("submit code");
    let paired = session
        .wait_welcome(Duration::from_secs(10))
        .expect("welcome over relay");
    assert_eq!(paired.id, pc_id);
    assert!(
        paired.addrs.is_empty(),
        "paired via relay without direct addrs"
    );

    // Also test direct UDP blocked/unreachable fallback: set a dead UDP address on the phone
    // so direct UDP fails and traffic must flow over the relay.
    p.set_pc_addrs_for_tests(&pc_id, vec!["127.0.0.1:9".parse().unwrap()]);

    let secret_url = "https://secret-relay-check.example.com/private-token-998877?mode=relay";
    let report = p
        .send_url(&pc_id, secret_url)
        .expect("send_url via relay fallback when direct UDP is blocked");
    assert_eq!(report.outcome, SendOutcome::Opened);
    assert_eq!(spy.calls(), vec![secret_url.to_string()]);

    // Inspect captured packets on the relay path:
    // 1. Traffic genuinely flowed through the relay.
    let datagrams = relay.relayed_datagrams();
    assert!(
        !datagrams.is_empty(),
        "expected relayed QUIC datagrams through TestRelay"
    );
    // 2. No plaintext URL bytes (or host/path fragments) appear in any relayed packet.
    let mut combined = Vec::new();
    for d in &datagrams {
        combined.extend_from_slice(d);
    }
    for needle in [
        b"secret-relay-check".as_slice(),
        b"private-token-998877".as_slice(),
        b"example.com".as_slice(),
        b"https://".as_slice(),
    ] {
        assert!(
            !combined.windows(needle.len()).any(|w| w == needle),
            "plaintext needle {:?} leaked on relay path!",
            std::str::from_utf8(needle)
        );
    }
    // 3. Captive-portal plaintext port-80 probe was never sent.
    assert_eq!(
        relay.captive_portal_hits(),
        0,
        "captive_portal_check must be false"
    );
}

/// M2.2: `WELCOME` carries sealed `gs_e` to paired phones, and `forget_device`
/// rotates `e -> e+1`, wraps `gs_{e+1}` to remaining members, and denies the
/// removed phone access to `gs_{e+1}`.
#[test]
fn e2e_m2_welcome_delivers_gs_e_and_forget_rotates_epoch_for_remaining_members() {
    use voidwire_core::grouplog::Membership;
    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new("M2 Epoch PC", Arc::new(MemoryStateStore::default()), spy);
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some("off".into());
    let pc = PcNode::start(cfg).expect("pc");
    let pc_id = pc.device_id();
    assert_eq!(pc.epoch(), 0);
    let mb_0 = pc.current_mailbox_id();

    let pair_with = |pc: &PcNode, ph: &PhoneClient| {
        let inv = pc.pair_start().expect("pair_start");
        let s = ph.begin_pairing(&inv.qr_uri).expect("begin_pairing");
        pc.pair_submit_code(&s.sas()).expect("submit");
        s.wait_welcome(Duration::from_secs(5)).expect("welcome")
    };

    let p1 = phone("Phone One");
    let p2 = phone("Phone Two");
    let p1_id = pair_with(&pc, &p1).id;
    let p2_id = pair_with(&pc, &p2).id;
    assert_eq!(p1_id, pc_id);
    assert_eq!(p2_id, pc_id);

    // Both phones received sealed gs_0 in WELCOME and derive the identical mailbox_id.
    assert_eq!(p1.pc_epoch(&pc_id), Some(0));
    assert_eq!(p2.pc_epoch(&pc_id), Some(0));
    assert_eq!(p1.pc_mailbox_id(&pc_id), Some(mb_0));
    assert_eq!(p2.pc_mailbox_id(&pc_id), Some(mb_0));

    // Forget Phone One: PC increments epoch 0 -> 1, draws gs_1, and appends RemoveDevice + Rekey.
    assert!(pc.forget_device(&p1.device_id()).expect("forget p1"));
    assert_eq!(pc.epoch(), 1);
    let mb_1 = pc.current_mailbox_id();
    assert_ne!(mb_1, mb_0, "new epoch must derive a distinct mailbox_id");

    // Phone Two syncs and unwraps gs_1 -> derives mb_1.
    assert_eq!(p2.sync(&pc_id).expect("p2 sync"), Membership::Member);
    assert_eq!(p2.pc_epoch(&pc_id), Some(1));
    assert_eq!(p2.pc_mailbox_id(&pc_id), Some(mb_1));

    // Phone One syncs: learns it is Removed and has NO gs_1.
    assert_eq!(p1.sync(&pc_id).expect("p1 sync"), Membership::Removed);
    assert_eq!(p1.pc_epoch(&pc_id), Some(1));
    assert_eq!(p1.pc_mailbox_id(&pc_id), None);
}

/// M2.2: Upgrading from an M1 `state.bin` (without `STATE_SECTION_MAILBOX`)
/// draws `gs_0` and `owner_seal_root`, persists them sealed under the identity key,
/// preserves them across restarts, and never writes `gs_e` or `owner_seal_root` in
/// plaintext to `state.bin`.
#[test]
fn e2e_m1_state_bin_migration_draws_epoch_secrets_and_never_stores_plaintext_gs_on_disk() {
    use voidwire_core::net::state::StateStore;
    let store = Arc::new(MemoryStateStore::default());
    let spy = Arc::new(SharedSpyOpener::default());

    let mut cfg1 = PcConfig::new("Migrate PC", store.clone(), spy.clone());
    cfg1.mdns = false;
    cfg1.port = Some(0);
    cfg1.advertise_loopback = true;
    cfg1.unchecked_inbox_for_tests = true;
    cfg1.relay_url = Some("off".into());
    let pc1 = PcNode::start(cfg1).expect("pc1");
    let pc_id = pc1.device_id();
    drop(pc1);

    // Strip STATE_SECTION_MAILBOX (tag 3) and STATE_SECTION_FILE_STATS (tag 4) from the saved state blob to simulate an M1 state.bin.
    let full_blob = store.load().unwrap().expect("saved state");
    // In our test config with relay="off" (None), no high_water, and disabled conn_stats (bytes16 of &[0]),
    // STATE_SECTION_FILE_STATS is 1 + 8 + 2 + 1 = 12 bytes, and STATE_SECTION_MAILBOX is 1 + 8 + 72 + 72 + 2 = 155 bytes.
    let m2_file_stats_len = 1 + 8 + 2 + 1;
    let m2_mailbox_len = 1 + 8 + 72 + 72 + 2;
    let m2_section_len = m2_mailbox_len + m2_file_stats_len;
    assert!(full_blob.len() > m2_section_len);
    assert_eq!(full_blob[full_blob.len() - m2_section_len], 3u8);
    assert_eq!(full_blob[full_blob.len() - m2_file_stats_len], 4u8);
    let m1_blob = full_blob[..full_blob.len() - m2_section_len].to_vec();
    store.save(&m1_blob).expect("save simulated M1 state.bin");

    // Start PcNode on the M1 state.bin: it must migrate cleanly, draw gs_0 + owner_seal_root, and save.
    let mut cfg2 = PcConfig::new("Migrate PC", store.clone(), spy.clone());
    cfg2.mdns = false;
    cfg2.port = Some(0);
    cfg2.advertise_loopback = true;
    cfg2.unchecked_inbox_for_tests = true;
    cfg2.relay_url = Some("off".into());
    let pc2 = PcNode::start(cfg2).expect("pc2 migrated from M1 state.bin");
    assert_eq!(pc2.device_id(), pc_id);
    assert_eq!(pc2.epoch(), 0);
    let migrated_mb = pc2.current_mailbox_id();
    let migrated_seal_v = pc2.owner_seal_verifier(0);
    let (raw_gs, raw_osr) = pc2.mailbox_raw_secrets_for_tests();
    drop(pc2);

    // Inspect the persisted state.bin bytes: neither raw_gs nor raw_osr may appear in clear!
    let upgraded_blob = store.load().unwrap().expect("upgraded state.bin");
    assert!(
        !upgraded_blob.windows(32).any(|w| w == raw_gs),
        "gs_e must never be stored in plaintext in state.bin"
    );
    assert!(
        !upgraded_blob.windows(32).any(|w| w == raw_osr),
        "owner_seal_root must never be stored in plaintext in state.bin"
    );

    // Restart again and verify the migrated secrets persist identically across restarts.
    let mut cfg3 = PcConfig::new("Migrate PC", store.clone(), spy);
    cfg3.mdns = false;
    cfg3.port = Some(0);
    cfg3.advertise_loopback = true;
    cfg3.unchecked_inbox_for_tests = true;
    cfg3.relay_url = Some("off".into());
    let pc3 = PcNode::start(cfg3).expect("pc3 restart");
    assert_eq!(pc3.current_mailbox_id(), migrated_mb);
    assert_eq!(pc3.owner_seal_verifier(0), migrated_seal_v);
}

/// M2.4: When a mailbox peer is configured and unreachable on the relay,
/// `pull-before-trust` fails open (`PROTOCOL.md` §7.1(e)): `send_url` still
/// succeeds over LAN/relay and sets `"Couldn't check for removals since ... UTC"`.
#[test]
fn e2e_m2_mailbox_fail_open_warning_when_unreachable() {
    use voidwire_core::net::test_relay::TestRelay;
    let relay = TestRelay::start();
    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new(
        "FailOpen PC",
        Arc::new(MemoryStateStore::default()),
        spy.clone(),
    );
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some(relay.url());
    let pc = PcNode::start(cfg).expect("pc");
    let pc_id = pc.device_id();

    let p = phone("FailOpen Phone");
    p.set_relay_url(Some(relay.url())).expect("set_relay_url");
    let inv = pc.pair_start().expect("pair_start");
    let sess = p.begin_pairing(&inv.qr_uri).expect("begin_pairing");
    pc.pair_submit_code(&sess.sas()).expect("submit");
    sess.wait_welcome(Duration::from_secs(5)).expect("welcome");

    // Configure an unreachable mailbox peer id so pull_mailbox fails when attempting to dial
    let unreachable_mb =
        voidwire_core::keys::DeviceKeypair::from_secret_bytes(&[0x99u8; 32]).device_id();
    p.set_mailbox_peer(Some(unreachable_mb));

    let url = "https://example.com/fail-open-allowed";
    let report = p
        .send_url(&pc_id, url)
        .expect("send_url must fail open when mailbox is unreachable");
    assert_eq!(report.outcome, SendOutcome::Opened);
    assert_eq!(spy.calls(), vec![url.to_string()]);
    let warn = p
        .removal_check_warning()
        .expect("removal_check_warning must be populated on fail-open");
    assert!(
        warn.starts_with("Couldn't check for removals since "),
        "unexpected warning: {warn}"
    );
}

fn temp_test_dir(tag: &str) -> std::path::PathBuf {
    let tid = voidwire_core::file_transfer::TransferId::random().to_hex();
    let dir = std::env::temp_dir().join(format!("voidwire-m26-{tag}-{tid}"));
    std::fs::create_dir_all(&dir).expect("create_dir_all");
    dir
}

/// M2.6: Multi-chunk file transfer with artificial disconnect mid-stream (`stop_after_chunks: Some(2)`)
/// leaves `<transfer_id>.part` + `<transfer_id>.part.meta` on disk, and re-sending the same
/// `transfer_id` resumes from `chunk 2` (`resumed_from_chunk == 2`) and verifies `blake3_root`.
#[test]
fn e2e_m26_file_transfer_part_resume_and_blake3_verification() {
    use voidwire_core::file_transfer::{RelayPromptDecision, TransferId};
    let dir = temp_test_dir("resume");
    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new("File PC", Arc::new(MemoryStateStore::default()), spy)
        .with_download_dir(dir.clone())
        .with_auto_accept_files(true);
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some("off".into());
    let pc = PcNode::start(cfg).expect("pc");
    let pc_id = pc.device_id();

    let p = phone("File Phone");
    let inv = pc.pair_start().expect("pair_start");
    let sess = p.begin_pairing(&inv.qr_uri).expect("begin_pairing");
    pc.pair_submit_code(&sess.sas()).expect("submit");
    sess.wait_welcome(Duration::from_secs(5)).expect("welcome");

    // 700 KiB payload -> 3 chunks (256 KiB, 256 KiB, 188 KiB padded to 256 KiB bucket)
    let mut data = vec![0u8; 700 * 1024];
    for (i, b) in data.iter_mut().enumerate() {
        *b = ((i * 31 + 7) & 0xff) as u8;
    }
    let expected_root = *blake3::hash(&data).as_bytes();
    let tid = TransferId::from_bytes([0x42u8; 16]);

    // 1. Interrupt after 2 chunks
    let err = p
        .send_file_bytes_with_options(
            &pc_id,
            tid,
            "report.pdf",
            "application/pdf",
            &data,
            Some(RelayPromptDecision::WaitForDirect),
            Some(2),
            None,
        )
        .expect_err("must stop after 2 chunks");
    assert!(
        format!("{err:?}").contains("simulated_mid_stream_drop"),
        "unexpected err: {err:?}"
    );

    // Verify .part and .part.meta exist on disk in download_dir
    let part_path = dir.join(format!("{}.part", tid.to_hex()));
    let meta_path = dir.join(format!("{}.part.meta", tid.to_hex()));
    assert!(part_path.exists(), ".part file must remain for resume");
    assert!(meta_path.exists(), ".part.meta file must remain for resume");

    // 2. Resume with the same transfer_id -> must resume from chunk 2 and complete cleanly
    pc.set_keep_file_history(true).expect("enable file history");
    let report = p
        .send_file_bytes_with_options(
            &pc_id,
            tid,
            "report.pdf",
            "application/pdf",
            &data,
            Some(RelayPromptDecision::WaitForDirect),
            None,
            None,
        )
        .expect("resumed send_file must succeed");
    assert_eq!(report.transfer_id, tid);
    assert_eq!(
        report.resumed_from_chunk, 2,
        "must resume from chunk 2 without re-sending chunks 0..2"
    );
    assert_eq!(
        report.chunks_sent, 1,
        "only final chunk 2 should be sent on resume"
    );
    assert!(!part_path.exists(), ".part must be finalized and removed");
    assert!(
        !meta_path.exists(),
        ".part.meta must be removed on completion"
    );

    let completed = pc.completed_files();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].filename, "report.pdf");
    assert_eq!(completed[0].size, data.len() as u64);
    assert!(
        completed[0].allow_open,
        "PDF is non-executable and allows Open"
    );
    let disk_bytes = std::fs::read(&completed[0].path).expect("read saved file");
    assert_eq!(*blake3::hash(&disk_bytes).as_bytes(), expected_root);
    let _ = std::fs::remove_dir_all(&dir);
}

/// M2.6: Tampered chunk is rejected immediately and cleans up `.part` and `.part.meta`;
/// canceling an in-progress transfer also deletes `.part` and `.part.meta` immediately.
#[test]
fn e2e_m26_file_transfer_tamper_rejected_and_cancel_deletes_part_immediately() {
    use voidwire_core::file_transfer::{RelayPromptDecision, TransferId};
    let dir = temp_test_dir("tamper");
    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new("Tamper PC", Arc::new(MemoryStateStore::default()), spy)
        .with_download_dir(dir.clone())
        .with_auto_accept_files(true);
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some("off".into());
    let pc = PcNode::start(cfg).expect("pc");
    let pc_id = pc.device_id();

    let p = phone("Tamper Phone");
    let inv = pc.pair_start().expect("pair_start");
    let sess = p.begin_pairing(&inv.qr_uri).expect("begin_pairing");
    pc.pair_submit_code(&sess.sas()).expect("submit");
    sess.wait_welcome(Duration::from_secs(5)).expect("welcome");

    let data = vec![0x5Au8; 600 * 1024]; // 3 chunks
    let tid_tamper = TransferId::from_bytes([0xAAu8; 16]);

    // 1. Tamper chunk 1 -> must be rejected immediately and clean up .part + .part.meta
    let err = p
        .send_file_bytes_with_options(
            &pc_id,
            tid_tamper,
            "installer.exe",
            "application/octet-stream",
            &data,
            Some(RelayPromptDecision::WaitForDirect),
            None,
            Some(1),
        )
        .expect_err("tampered chunk must fail");
    assert!(
        format!("{err:?}").contains("Protocol"),
        "unexpected err: {err:?}"
    );
    let tamper_part = dir.join(format!("{}.part", tid_tamper.to_hex()));
    let tamper_meta = dir.join(format!("{}.part.meta", tid_tamper.to_hex()));
    assert!(
        !tamper_part.exists(),
        "tampered transfer must delete .part immediately"
    );
    assert!(
        !tamper_meta.exists(),
        "tampered transfer must delete .part.meta immediately"
    );
    assert!(pc.completed_files().is_empty());

    // 2. Interrupt after 1 chunk, then send FILE_CANCEL -> deletes .part and .part.meta immediately
    let tid_cancel = TransferId::from_bytes([0xBBu8; 16]);
    let _ = p.send_file_bytes_with_options(
        &pc_id,
        tid_cancel,
        "archive.bin",
        "application/octet-stream",
        &data,
        Some(RelayPromptDecision::WaitForDirect),
        Some(1),
        None,
    );
    let cancel_part = dir.join(format!("{}.part", tid_cancel.to_hex()));
    let cancel_meta = dir.join(format!("{}.part.meta", tid_cancel.to_hex()));
    assert!(cancel_part.exists(), ".part exists before cancel");
    p.cancel_file_transfer(&pc_id, &tid_cancel)
        .expect("cancel_file_transfer");

    // Wait briefly for async frame processing
    let sw = Stopwatch::start();
    while sw.elapsed_us() < 2_000_000 && (cancel_part.exists() || cancel_meta.exists()) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !cancel_part.exists(),
        "cancel must delete .part immediately"
    );
    assert!(
        !cancel_meta.exists(),
        "cancel must delete .part.meta immediately"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// M2.6: Relay data-minimization policy (`M2-PLAN.md` §6a.1 & §6b) + on-device connection stats (§6a.3):
/// - Over a relay-only path:
///   - Small files (`<= 256 KiB`) auto-relay without prompting.
///   - Larger files (`> 256 KiB` up to effective cap) require `RelayPromptDecision::SendViaRelay`
///     (returning `Prompt required` if `WaitForDirect` or `None` is passed).
///   - Files `> effective_cap` are refused over the relay (`ExceedsRelayCap`).
/// - Connection stats:
///   - Off by default -> records nothing.
///   - Opt-in -> records coarse UTC day-granularity counts and bytes (`direct` vs `relay`).
///   - Toggling off or `forget_device` / `forget_pc` immediately purges saved stats.
#[test]
fn e2e_m26_relay_policy_and_connection_stats_privacy() {
    use voidwire_core::file_transfer::{RelayPromptDecision, TransferId, TransportPathKind};
    use voidwire_core::net::test_relay::TestRelay;

    let relay = TestRelay::start();
    let dir = temp_test_dir("relay-policy");
    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new("RelayPolicy PC", Arc::new(MemoryStateStore::default()), spy)
        .with_download_dir(dir.clone())
        .with_auto_accept_files(true);
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = false; // Do not put direct IP hints in QR -> relay-only
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some(relay.url());
    let pc = PcNode::start(cfg).expect("pc");
    let pc_id = pc.device_id();

    let sw = Stopwatch::start();
    while !relay.has_peer(&pc_id) {
        assert!(
            sw.elapsed_us() < 5_000_000,
            "PC did not connect to test relay within 5s"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let p = phone("RelayPolicy Phone");
    p.set_relay_url(Some(relay.url())).expect("set_relay_url");
    let inv = pc.pair_start().expect("pair_start");
    let relay_only_qr: String = inv
        .qr_uri
        .split('&')
        .filter(|part| !part.starts_with("a="))
        .collect::<Vec<_>>()
        .join("&");
    let sess = p.begin_pairing(&relay_only_qr).expect("begin_pairing");
    pc.pair_submit_code(&sess.sas()).expect("submit");
    sess.wait_welcome(Duration::from_secs(10)).expect("welcome");

    // Verify stats are OFF by default and record nothing during small file transfer
    assert!(!p.connection_stats_enabled());
    assert!(!pc.connection_stats_enabled());

    // 1. Small file (100 KiB <= 256 KiB) auto-relays even with None / WaitForDirect
    let small_data = vec![0x11u8; 100 * 1024];
    let rep_small = p
        .send_file_bytes(
            &pc_id,
            TransferId::from_bytes([0x01u8; 16]),
            "note.txt",
            "text/plain",
            &small_data,
            None,
        )
        .expect("<= 256 KiB file must auto-relay");
    assert_eq!(
        rep_small.path_kind,
        TransportPathKind::Relayed,
        "must use relay when direct IP is omitted"
    );
    assert!(
        p.connection_stats().is_empty(),
        "stats off by default must record nothing"
    );
    assert!(
        pc.connection_stats().is_empty(),
        "stats off by default must record nothing"
    );

    // 2. Enable stats on both sides and test > 256 KiB (300 KiB) over relay:
    //    - With None -> fails with prompt required
    //    - With SendViaRelay -> succeeds and records day-granularity relay stats
    p.set_connection_stats_enabled(true)
        .expect("enable phone stats");
    pc.set_connection_stats_enabled(true)
        .expect("enable pc stats");

    let med_data = vec![0x22u8; 300 * 1024];
    let err_prompt = p
        .send_file_bytes(
            &pc_id,
            TransferId::from_bytes([0x02u8; 16]),
            "photo.png",
            "image/png",
            &med_data,
            None,
        )
        .expect_err("> 256 KiB over relay without SendViaRelay must require prompt");
    assert!(
        format!("{err_prompt:?}").contains("relay_prompt_required"),
        "unexpected err: {err_prompt:?}"
    );

    let rep_med = p
        .send_file_bytes(
            &pc_id,
            TransferId::from_bytes([0x02u8; 16]),
            "photo.png",
            "image/png",
            &med_data,
            Some(RelayPromptDecision::SendViaRelay),
        )
        .expect("> 256 KiB with SendViaRelay must succeed");
    assert_eq!(rep_med.path_kind, TransportPathKind::Relayed);

    let p_stats = p.connection_stats();
    assert_eq!(p_stats.len(), 1);
    assert_eq!(p_stats[0].0, pc_id);
    assert_eq!(p_stats[0].1.relay_count, 1);
    assert_eq!(p_stats[0].1.relay_bytes, med_data.len() as u64);
    assert_eq!(
        p_stats[0].1.prompts_shown, 1,
        "M26-M4: prompts_shown must be recorded once on None -> RelayPromptNeeded, not double-counted on SendViaRelay"
    );
    assert_eq!(p_stats[0].1.prompts_accepted, 1);

    let pc_stats = pc.connection_stats();
    assert_eq!(pc_stats.len(), 1);
    assert_eq!(pc_stats[0].1.relay_count, 1);
    assert_eq!(pc_stats[0].1.relay_bytes, med_data.len() as u64);

    // 3. Lower user relay cap to 280 KiB -> 300 KiB file exceeds effective cap even with SendViaRelay
    p.set_user_relay_cap_bytes(280 * 1024).expect("set cap");
    let err_cap = p
        .send_file_bytes(
            &pc_id,
            TransferId::from_bytes([0x03u8; 16]),
            "too_big_for_relay.bin",
            "application/octet-stream",
            &med_data,
            Some(RelayPromptDecision::SendViaRelay),
        )
        .expect_err("file > effective_cap must be refused over relay");
    assert!(
        format!("{err_cap:?}").contains("exceeds_relay_cap"),
        "unexpected err: {err_cap:?}"
    );

    // 3b. M29-L2: When PC has "Never send files over relay" enabled (cap=0) or a lower relay cap,
    //     PC's FILE_OFFER_ACK rejection preserves `cap=<eff_cap>` in PhoneClient's error string.
    p.set_never_send_files_over_relay(false)
        .expect("reset phone cap");
    pc.set_never_send_files_over_relay(true)
        .expect("pc never send over relay");
    let err_pc_never = p
        .send_file_bytes(
            &pc_id,
            TransferId::from_bytes([0x04u8; 16]),
            "note2.txt",
            "text/plain",
            &small_data,
            None,
        )
        .expect_err("PC with never_send_files_over_relay must reject relayed offer");
    let err_pc_never_str = format!("{err_pc_never:?}");
    assert!(
        err_pc_never_str.contains("file_offer_rejected: exceeds_relay_cap: cap=0"),
        "expected cap=0 in PC rejection error, got: {err_pc_never_str}"
    );
    pc.set_never_send_files_over_relay(false)
        .expect("restore pc relay files");
    pc.set_user_relay_cap_bytes(50 * 1024)
        .expect("set pc cap 50 KiB");
    let err_pc_cap = p
        .send_file_bytes(
            &pc_id,
            TransferId::from_bytes([0x05u8; 16]),
            "note3.txt",
            "text/plain",
            &small_data,
            None,
        )
        .expect_err("PC with 50 KiB cap must reject 100 KiB relayed offer");
    let err_pc_cap_str = format!("{err_pc_cap:?}");
    assert!(
        err_pc_cap_str.contains("file_offer_rejected: exceeds_relay_cap: cap=51200"),
        "expected cap=51200 in PC rejection error, got: {err_pc_cap_str}"
    );

    // 4. Toggling stats off on Phone immediately purges Phone stats;
    //    forgetting device on PC immediately purges PC stats.
    p.set_connection_stats_enabled(false)
        .expect("disable phone stats");
    assert!(
        p.connection_stats().is_empty(),
        "disabling stats must purge immediately"
    );

    let phone_id = pc.devices()[0].id;
    pc.forget_device(&phone_id).expect("forget_device");
    assert!(
        pc.connection_stats().is_empty(),
        "forget_device must purge peer stats immediately"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// M2.6 QA Audit regression test covering:
/// - M26-H1: Default `auto_accept_files == false` creates ZERO `.part` / `.part.meta` files on disk
///   until `pc.accept_file(&tid)` is explicitly called; replay cache (`seen.bin`) rejects completed
///   or canceled `transfer_id`s with `RejectReason::Replay`;
/// - M26-H2: `PhoneClient::send_file_with_transfer_id` streams directly from `std::fs::File` on disk
///   in 256 KiB chunks without loading the whole file into memory;
/// - M26-M4: Mid-stream direct-to-relay transition (`set_force_relay_at_chunk_for_test(Some(1))`)
///   pauses at chunk boundary 1 with `relay_prompt_required`, preserves `.part` on disk at chunk 1,
///   and resumes from chunk 1 when `Some(RelayPromptDecision::SendViaRelay)` is passed.
#[test]
fn e2e_m26_security_h1_h2_m4_audit_regressions() {
    use voidwire_core::file_transfer::{RelayPromptDecision, TransferId, TransportPathKind};
    let dir = temp_test_dir("m26-audit");
    let src_dir = temp_test_dir("m26-audit-src");
    let spy = Arc::new(SharedSpyOpener::default());
    // Default PcConfig has auto_accept_files == false!
    let mut cfg = PcConfig::new("Audit PC", Arc::new(MemoryStateStore::default()), spy)
        .with_download_dir(dir.clone());
    assert!(
        !cfg.auto_accept_files,
        "M26-H1: PcConfig::default must have auto_accept_files == false"
    );
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = false; // Full Inbox::verify_file_offer enforcement!
    cfg.relay_url = Some("off".into());
    let pc = PcNode::start(cfg).expect("pc");
    let pc_id = pc.device_id();

    let p = phone("Audit Phone");
    let inv = pc.pair_start().expect("pair_start");
    let sess = p.begin_pairing(&inv.qr_uri).expect("begin_pairing");
    pc.pair_submit_code(&sess.sas()).expect("submit");
    sess.wait_welcome(Duration::from_secs(5)).expect("welcome");

    // Write a 600 KiB source file on disk (3 chunks: 256 KiB + 256 KiB + 88 KiB) for M26-H2 streaming
    let src_file = src_dir.join("Confidential Report.pdf");
    let mut file_bytes = vec![0u8; 600 * 1024];
    for (i, b) in file_bytes.iter_mut().enumerate() {
        *b = ((i * 19 + 3) & 0xff) as u8;
    }
    std::fs::write(&src_file, &file_bytes).expect("write src file");
    let expected_root = *blake3::hash(&file_bytes).as_bytes();

    // 1. M26-H1: With auto_accept_files == false, initial FILE_OFFER is held in memory only
    //    (status = 1 -> file_offer_pending_accept) and creates ZERO files on disk!
    let tid1 = TransferId::from_bytes([0x71u8; 16]);
    let err_pending = p
        .send_file_with_transfer_id(&pc_id, tid1, &src_file, "application/pdf", None)
        .expect_err("must pause awaiting recipient consent when auto_accept_files == false");
    assert!(
        format!("{err_pending:?}").contains("file_offer_pending_accept"),
        "unexpected err: {err_pending:?}"
    );
    let part1 = dir.join(format!("{}.part", tid1.to_hex()));
    let meta1 = dir.join(format!("{}.part.meta", tid1.to_hex()));
    assert!(
        !part1.exists() && !meta1.exists(),
        "M26-H1: ZERO .part or .part.meta files may exist on disk before accept_file!"
    );
    let incoming = pc.incoming_files();
    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].transfer_id, tid1);
    assert!(!incoming[0].accepted);

    // 2. Accept the file on PC -> creates .part and .part.meta on disk
    pc.accept_file(&tid1).expect("accept_file");
    assert!(
        part1.exists() && meta1.exists(),
        "accept_file must initialize .part and .part.meta on disk"
    );

    // 3. M26-M4: Simulate direct-to-relay drop at chunk 1 (after chunk 0 is written)
    p.set_connection_stats_enabled(true).expect("enable stats");
    p.set_force_relay_at_chunk_for_test(Some(1));
    let err_mid_relay = p
        .send_file_with_transfer_id(&pc_id, tid1, &src_file, "application/pdf", None)
        .expect_err("must pause at chunk 1 when direct connection drops to relay mid-stream");
    assert!(
        format!("{err_mid_relay:?}").contains("relay_prompt_required: mid_stream_chunk=1"),
        "unexpected mid-stream relay err: {err_mid_relay:?}"
    );
    assert!(
        part1.exists() && meta1.exists(),
        ".part must remain on disk at chunk 1 after mid-stream pause"
    );

    // 4. Resume with SendViaRelay -> resumes from chunk 1 and finishes streaming from disk!
    p.set_force_relay_at_chunk_for_test(Some(1));
    pc.set_keep_file_history(true).expect("enable file history");
    let rep = p
        .send_file_with_transfer_id(
            &pc_id,
            tid1,
            &src_file,
            "application/pdf",
            Some(RelayPromptDecision::SendViaRelay),
        )
        .expect("resume with SendViaRelay must succeed");
    p.set_force_relay_at_chunk_for_test(None);
    assert_eq!(rep.resumed_from_chunk, 1);
    assert_eq!(rep.chunks_sent, 2);
    assert_eq!(rep.blake3_root, expected_root);
    assert_eq!(rep.path_kind, TransportPathKind::Relayed);
    let done = pc.completed_files();
    assert_eq!(done.len(), 1);
    let saved = std::fs::read(&done[0].path).expect("read saved file");
    assert_eq!(saved, file_bytes);

    // Verify prompts_shown is 1 (not double-counted) and prompts_accepted is 1
    let p_stats = p.connection_stats();
    assert_eq!(p_stats.len(), 1);
    assert_eq!(p_stats[0].1.prompts_shown, 1);
    assert_eq!(p_stats[0].1.prompts_accepted, 1);

    // 5. M26-H1: Replaying completed tid1 must be rejected by ReplayCache (seen.bin)!
    let err_replay = p
        .send_file_with_transfer_id(
            &pc_id,
            tid1,
            &src_file,
            "application/pdf",
            Some(RelayPromptDecision::SendViaRelay),
        )
        .expect_err("replaying completed transfer_id must be rejected");
    assert!(
        format!("{err_replay:?}").contains("replay")
            || format!("{err_replay:?}").contains("rejected: status=2"),
        "unexpected replay err: {err_replay:?}"
    );

    // 6. M26-H1: Declining/canceling an unaccepted offer writes zero .part files and records
    //    transfer_id in ReplayCache so it cannot be replayed!
    let tid_decline = TransferId::from_bytes([0x72u8; 16]);
    let _ = p.send_file_with_transfer_id(&pc_id, tid_decline, &src_file, "application/pdf", None);
    let part_dec = dir.join(format!("{}.part", tid_decline.to_hex()));
    assert!(!part_dec.exists(), "declined offer must never touch disk");
    assert!(
        pc.cancel_file(&tid_decline),
        "cancel_file must remove pending offer"
    );
    let err_declined_replay = p
        .send_file_with_transfer_id(&pc_id, tid_decline, &src_file, "application/pdf", None)
        .expect_err("replaying canceled/declined transfer_id must be rejected");
    assert!(
        format!("{err_declined_replay:?}").contains("declined by recipient")
            || format!("{err_declined_replay:?}").contains("replay")
            || format!("{err_declined_replay:?}").contains("rejected: status=2"),
        "unexpected declined replay err: {err_declined_replay:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&src_dir);
}

#[test]
fn m27_h1_m1_pending_accept_polling_decline_and_cancel_short_circuit() {
    use voidwire_core::file_transfer::{RelayPromptDecision, TransferId};

    let dir = temp_test_dir("m27-e2e");
    let src_dir = temp_test_dir("m27-src");

    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new("M27 Audit PC", Arc::new(MemoryStateStore::default()), spy)
        .with_download_dir(dir.clone());
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = false; // Full Inbox::verify_file_offer rate-limit enforcement!
    cfg.relay_url = Some("off".into());
    let pc = Arc::new(PcNode::start(cfg).expect("start pc"));
    let pc_id = pc.device_id();

    let p = phone("PhoneM27");
    let inv = pc.pair_start().expect("pair_start");
    let sess = p.begin_pairing(&inv.qr_uri).expect("begin_pairing");
    pc.pair_submit_code(&sess.sas()).expect("submit");
    sess.wait_welcome(Duration::from_secs(5)).expect("welcome");

    let src_file = src_dir.join("archive.zip");
    let payload = vec![0x5au8; 64 * 1024];
    std::fs::write(&src_file, &payload).expect("write src_file");

    // 1. M27-M1: RelayPromptDecision::Cancel short-circuits immediately before touching disk or network.
    let nonexistent = src_dir.join("does-not-exist.bin");
    let cancel_err = p
        .send_file_with_transfer_id(
            &pc_id,
            TransferId::from_bytes([0x80u8; 16]),
            &nonexistent,
            "application/octet-stream",
            Some(RelayPromptDecision::Cancel),
        )
        .expect_err("Cancel decision must return NetError::Cancelled immediately");
    assert!(
        matches!(cancel_err, NetError::Cancelled),
        "expected NetError::Cancelled, got {cancel_err:?}"
    );

    // 2. M27-H1: Polling >25 times while auto_accept_files == false must NOT exhaust
    //    `global` (burst 20, 20/min) or `pre_decrypt` (burst 20, 60/min), and once the PC
    //    calls `accept_file`, `send_file_awaiting_accept` completes the transfer cleanly!
    let tid_poll = TransferId::from_bytes([0x81u8; 16]);
    for i in 0..25 {
        let e = p
            .send_file_with_transfer_id(&pc_id, tid_poll, &src_file, "application/zip", None)
            .expect_err("must remain pending before accept_file");
        assert!(
            format!("{e:?}").contains("file_offer_pending_accept"),
            "poll {i} must return file_offer_pending_accept, got {e:?}"
        );
    }

    let pc_for_accept = pc.clone();
    let accepter = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(120));
        pc_for_accept
            .accept_file(&tid_poll)
            .expect("accept_file after 25+ polls");
    });
    pc.set_keep_file_history(true).expect("enable file history");
    let rep = p
        .send_file_awaiting_accept(
            &pc_id,
            tid_poll,
            &src_file,
            "application/zip",
            None,
            40,
            Duration::from_millis(25),
        )
        .expect("send_file_awaiting_accept must succeed once PC accepts");
    accepter.join().expect("join accepter");
    assert_eq!(rep.size, payload.len() as u64);
    assert_eq!(pc.completed_files().len(), 1);

    // 3. M27-M1: When PC declines (`cancel_file`), next poll returns clean `declined by recipient`, not `Replay`.
    let tid_dec = TransferId::from_bytes([0x82u8; 16]);
    let e_init = p
        .send_file_with_transfer_id(&pc_id, tid_dec, &src_file, "application/zip", None)
        .expect_err("initial offer waits for accept");
    assert!(format!("{e_init:?}").contains("file_offer_pending_accept"));
    assert!(pc.cancel_file(&tid_dec), "decline pending offer");

    let e_after_decline = p
        .send_file_awaiting_accept(
            &pc_id,
            tid_dec,
            &src_file,
            "application/zip",
            None,
            10,
            Duration::from_millis(20),
        )
        .expect_err("declined offer must abort immediately on poll");
    let msg = format!("{e_after_decline:?}");
    assert!(
        msg.contains("declined by recipient")
            && msg.contains("canceled_by_recipient")
            && !msg.contains("Replay"),
        "expected 'declined by recipient' and 'canceled_by_recipient' without Replay, got {msg}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&src_dir);
}

#[test]
fn m28_hardware_feedback_fixes_e2e() {
    use voidwire_core::file_transfer::{
        RelayPolicyOutcome, RelayPromptDecision, TransferId, LARGE_RELAY_WARNING_BYTES,
        MAX_FILE_SIZE,
    };
    use voidwire_core::time::{Clock, SystemClock, UnixMillis};

    let dir = temp_test_dir("m28");
    let spy = Arc::new(SharedSpyOpener::default());
    let store = Arc::new(MemoryStateStore::default());
    let mut cfg = PcConfig::new("Office Desktop", store.clone(), spy.clone())
        .with_download_dir(dir.clone())
        .with_auto_accept_files(false);
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some("off".into());

    let pc = Arc::new(PcNode::start(cfg).expect("start pc"));
    let pc_id = pc.device_id();
    let p = phone("Pixel 9 Pro");

    // Pair phone and PC
    let inv = pc.pair_start().expect("pair_start");
    let sess = p.begin_pairing(&inv.qr_uri).expect("begin_pairing");
    pc.pair_submit_code(&sess.sas()).expect("submit");
    sess.wait_welcome(Duration::from_secs(5)).expect("welcome");

    // 1. Default keep_file_history is false: completed files are NOT retained in memory unless enabled
    assert!(!pc.keep_file_history());
    pc.set_auto_accept_files(true);
    let src_small = dir.join("note.txt");
    std::fs::write(&src_small, b"hello m28").expect("write small");
    p.send_file(&pc_id, &src_small, "text/plain", None)
        .expect("send small file");
    assert!(
        pc.completed_files().is_empty(),
        "completed_files must remain empty when keep_file_history is false"
    );

    // Enabling keep_file_history retains subsequent completed transfers; disabling clears immediately
    pc.set_keep_file_history(true).expect("enable history");
    assert!(pc.keep_file_history());
    p.send_file(&pc_id, &src_small, "text/plain", None)
        .expect("send small file 2");
    assert_eq!(pc.completed_files().len(), 1);
    pc.set_keep_file_history(false).expect("disable history");
    assert!(
        pc.completed_files().is_empty(),
        "turning off keep_file_history must clear completed_files immediately"
    );

    // 2. Server-enforced & server-advertised relay cap (25 MiB default, checked up front before prompting)
    assert!(!p.never_send_files_over_relay());
    assert!(!pc.never_send_files_over_relay());
    assert_eq!(LARGE_RELAY_WARNING_BYTES, 25 * 1024 * 1024);
    let pol = p.relay_policy();
    let forty_mb = 40 * 1024 * 1024;
    // With default 25 MiB server cap, 40 MB is rejected up front BEFORE prompting!
    assert_eq!(
        pol.evaluate(
            forty_mb,
            voidwire_core::file_transfer::TransportPathKind::Relayed,
            None
        ),
        RelayPolicyOutcome::ExceedsRelayCap {
            size: forty_mb,
            effective_cap: voidwire_core::file_transfer::DEFAULT_RELAY_FILE_CAP_BYTES,
        }
    );
    // When server advertises 0 (unlimited up to 2 GiB), 40 MB prompts first and proceeds once confirmed
    p.set_relay_server_cap_bytes(0)
        .expect("set unlimited relay cap");
    assert_eq!(
        p.relay_policy().evaluate(
            forty_mb,
            voidwire_core::file_transfer::TransportPathKind::Relayed,
            None
        ),
        RelayPolicyOutcome::PromptSender {
            size: forty_mb,
            effective_cap: MAX_FILE_SIZE,
        }
    );
    assert_eq!(
        p.relay_policy().evaluate(
            forty_mb,
            voidwire_core::file_transfer::TransportPathKind::Relayed,
            Some(RelayPromptDecision::SendViaRelay),
        ),
        RelayPolicyOutcome::ProceedViaRelay
    );
    p.set_relay_server_cap_bytes(voidwire_core::file_transfer::DEFAULT_RELAY_FILE_CAP_BYTES)
        .expect("restore default relay cap");
    // Turning on "Never send files over relay" blocks relayed files up front with NeverSendOverRelay
    p.set_never_send_files_over_relay(true)
        .expect("set never send over relay");
    assert!(p.never_send_files_over_relay());
    assert_eq!(
        p.relay_policy().evaluate(
            1024,
            voidwire_core::file_transfer::TransportPathKind::Relayed,
            None
        ),
        RelayPolicyOutcome::NeverSendOverRelay
    );
    p.set_never_send_files_over_relay(false)
        .expect("restore relay files");

    // 3. PC rename propagates through signed group log to phone on sync
    pc.rename_device("Living Room Workstation")
        .expect("rename pc");
    assert_eq!(pc.device_name(), "Living Room Workstation");
    p.sync(&pc_id).expect("sync after rename");
    let pcs = p.paired_pcs();
    assert_eq!(pcs.len(), 1);
    assert_eq!(pcs[0].name, "Living Room Workstation");

    // 4. Stalled transfer timeout: accepted session times out after 45s while preserving .part on disk for resume
    let tid_stall = TransferId::from_bytes([0x94u8; 16]);
    let big_bytes: Vec<u8> = (0..(600 * 1024)).map(|i| (i % 251) as u8).collect();
    let src_big = dir.join("stalled_resume.bin");
    std::fs::write(&src_big, &big_bytes).expect("write big");
    let err_drop = p
        .send_file_bytes_with_options(
            &pc_id,
            tid_stall,
            "stalled_resume.bin",
            "application/octet-stream",
            &big_bytes,
            Some(RelayPromptDecision::WaitForDirect),
            Some(1),
            None,
        )
        .expect_err("stop after 1 chunk");
    assert!(format!("{err_drop:?}").contains("simulated_mid_stream_drop"));
    assert_eq!(pc.incoming_files().len(), 1);

    let future_wall = UnixMillis(SystemClock.now().wall.0 + 46_000);
    let stalled = pc.sweep_stalled_transfers(future_wall);
    assert_eq!(stalled, vec![tid_stall]);
    assert!(
        pc.incoming_files().is_empty(),
        "stalled transfer must be removed from active incoming_files"
    );
    // And resuming with the same TransferId still resumes from chunk 1 using the preserved .part file!
    pc.set_keep_file_history(true).expect("enable history");
    let rep_resumed = p
        .send_file_with_transfer_id(
            &pc_id,
            tid_stall,
            &src_big,
            "application/octet-stream",
            None,
        )
        .expect("resume after stalled sweep must succeed from .part");
    assert_eq!(rep_resumed.resumed_from_chunk, 1);
    assert_eq!(rep_resumed.chunks_sent, 2);
    assert_eq!(pc.completed_files().len(), 1);

    // 5. M28-L1: Automatic chunk retry advances across remaining backoff windows when the first
    // fresh get_conn(..., true) fails (e.g., while cellular is still coming online after a handoff).
    let tid_l1 = TransferId::from_bytes([0x95u8; 16]);
    p.set_transient_drop_for_test(Some(1), 1);
    let rep_l1 = p
        .send_file_with_transfer_id(&pc_id, tid_l1, &src_big, "application/octet-stream", None)
        .expect("chunk retry must try remaining backoff windows after first get_conn failure");
    p.set_transient_drop_for_test(None, 0);
    assert_eq!(rep_l1.resumed_from_chunk, 0);
    assert_eq!(rep_l1.chunks_sent, 3);
    assert_eq!(pc.completed_files().len(), 2);

    // 6. M28-L2 & M28-N1: Calling cancel_file_transfer while send_file_awaiting_accept is blocked
    // immediately aborts the blocked send with NetError::Cancelled AND removes the pending offer
    // on the PC (even if the cached connection was stale/broken).
    pc.set_auto_accept_files(false);
    let tid_l2 = TransferId::from_bytes([0x96u8; 16]);
    let p_cancel = p.clone();
    let src_small_clone = src_small.clone();
    let send_handle = std::thread::spawn(move || {
        p_cancel.send_file_awaiting_accept(
            &pc_id,
            tid_l2,
            &src_small_clone,
            "text/plain",
            None,
            150,
            Duration::from_millis(400),
        )
    });
    // Wait until PC sees the pending offer
    let mut saw_pending = false;
    for _ in 0..40 {
        if pc.incoming_files().iter().any(|f| f.transfer_id == tid_l2) {
            saw_pending = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        saw_pending,
        "PC must observe pending file offer before cancel"
    );
    p.poison_cached_conn_for_test(&pc_id);
    p.cancel_file_transfer(&pc_id, &tid_l2)
        .expect("cancel_file_transfer must succeed via fresh-conn fallback");
    let send_res = send_handle.join().expect("join send_handle");
    assert!(
        matches!(send_res, Err(voidwire_core::net::NetError::Cancelled)),
        "blocked send_file_awaiting_accept must abort immediately with NetError::Cancelled, got {send_res:?}"
    );
    assert!(
        pc.incoming_files().iter().all(|f| f.transfer_id != tid_l2),
        "PC must remove cancelled offer"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// M3.1: Bidirectional clipboard text (inline & streamed >7.5 KiB), auto-copy setting,
/// and live PC -> Phone URL, clipboard text, and file transfers.
#[test]
fn e2e_m31_bidirectional_clipboard_and_pc_to_phone_transfers() {
    use voidwire_core::net::phone::IncomingItemKind;

    let dir = temp_test_dir("m31-bidir");
    let pc_dl = dir.join("pc_downloads");
    let phone_dl = dir.join("phone_downloads");
    std::fs::create_dir_all(&pc_dl).expect("pc_dl");
    std::fs::create_dir_all(&phone_dl).expect("phone_dl");

    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new("Bidir PC", Arc::new(MemoryStateStore::default()), spy)
        .with_download_dir(pc_dl.clone());
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some("off".into());
    let pc = Arc::new(PcNode::start(cfg).expect("pc"));
    let pc_id = pc.device_id();

    let p = phone("Bidir Phone");
    p.set_download_dir(phone_dl.clone());
    let inv = pc.pair_start().expect("pair_start");
    let sess = p.begin_pairing(&inv.qr_uri).expect("begin_pairing");
    pc.pair_submit_code(&sess.sas()).expect("submit");
    sess.wait_welcome(Duration::from_secs(5)).expect("welcome");
    let phone_id = p.device_id();

    // 1. Phone -> PC inline ClipboardText with default auto_copy_clipboard == false (prompted)
    assert!(!pc.auto_copy_clipboard());
    let rep1 = p
        .send_text_or_url(&pc_id, "Meeting notes: launch on Friday at 10am")
        .expect("send inline clipboard text");
    assert_eq!(rep1.outcome, SendOutcome::Prompted);
    let pending = pc.pending_clipboards();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].from, "Bidir Phone");
    assert_eq!(pending[0].text, "Meeting notes: launch on Friday at 10am");
    assert!(!pending[0].sensitive);
    let accepted = pc
        .decide_clipboard(pending[0].id, true)
        .expect("accept clipboard")
        .expect("pending existed");
    assert_eq!(accepted.text, "Meeting notes: launch on Friday at 10am");
    assert!(pc.pending_clipboards().is_empty());

    // 2. Phone -> PC inline ClipboardText with auto_copy_clipboard == true
    pc.set_auto_copy_clipboard(true)
        .expect("enable auto_copy_clipboard");
    assert!(pc.auto_copy_clipboard());
    let secret_token = "sk-live-9876543210abcdef9876543210abcdef";
    let rep2 = p
        .send_clipboard_text(&pc_id, secret_token)
        .expect("send secret clipboard");
    assert_eq!(rep2.outcome, SendOutcome::Opened);
    assert!(pc.pending_clipboards().is_empty());

    // 3. Phone -> PC streamed ClipboardText (> 7,680 B) over CLIPBOARD_STREAM_MIME
    pc.set_auto_copy_clipboard(false)
        .expect("disable auto_copy_clipboard");
    let large_text: String = "Line of multi-kilobyte clipboard text 0123456789.\n".repeat(220);
    assert!(large_text.len() > voidwire_core::limits::MAX_INLINE_CLIPBOARD_BYTES);
    let rep3 = p
        .send_clipboard_text(&pc_id, &large_text)
        .expect("send streamed clipboard text > 7.5 KiB");
    assert_eq!(rep3.outcome, SendOutcome::Prompted);
    let pending3 = pc.pending_clipboards();
    assert_eq!(pending3.len(), 1);
    assert_eq!(pending3[0].text, large_text);
    let _ = pc
        .decide_clipboard(pending3[0].id, false)
        .expect("dismiss streamed clipboard");

    // 4. PC -> Phone live URL and ClipboardText (learned phone direct address from connection)
    let pc_url_rep = pc
        .send_text_or_url_to_phone(&phone_id, "https://example.com/from-pc?x=1")
        .expect("pc send_url_to_phone");
    assert_eq!(
        pc_url_rep.delivery_path,
        voidwire_core::net::DeliveryPath::Direct
    );

    let pc_clip_rep = pc
        .send_text_or_url_to_phone(&phone_id, "ghp_1234567890abcdefghijklmnopqrstuvwx")
        .expect("pc send_clipboard_to_phone");
    assert_eq!(
        pc_clip_rep.delivery_path,
        voidwire_core::net::DeliveryPath::Direct
    );

    let batch = p.poll_incoming();
    assert_eq!(batch.items.len(), 2);
    assert_eq!(batch.items[0].kind, IncomingItemKind::Url);
    assert_eq!(
        batch.items[0].payload_text,
        "https://example.com/from-pc?x=1"
    );
    assert_eq!(batch.items[0].host_display.as_deref(), Some("example.com"));
    assert_eq!(batch.items[1].kind, IncomingItemKind::ClipboardText);
    assert_eq!(
        batch.items[1].payload_text,
        "ghp_1234567890abcdefghijklmnopqrstuvwx"
    );
    assert!(batch.items[1].sensitive_hint);

    assert!(p.dismiss_incoming_item(batch.items[0].item_id));
    assert_eq!(p.poll_incoming().items.len(), 1);

    // 5. PC -> Phone live file transfer (offer -> phone accept -> stream chunks -> verify BLAKE3)
    let src_file = dir.join("from-pc-notes.txt");
    let file_payload = b"Hello from PC to Phone over direct QUIC!";
    std::fs::write(&src_file, file_payload).expect("write src_file");

    let pc_clone = pc.clone();
    let src_clone = src_file.clone();
    let send_file_thread = std::thread::spawn(move || {
        pc_clone.send_file_to_phone(&phone_id, &src_clone, "text/plain", None)
    });

    // Wait for phone to see the incoming file offer and accept it
    let mut offer_tid = None;
    for _ in 0..60 {
        let b = p.poll_incoming();
        if let Some(f) = b.files.first() {
            offer_tid = Some(f.transfer_id);
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let tid = offer_tid.expect("phone must receive live FILE_OFFER from PC");
    let saved_path = p
        .accept_incoming_file(&tid, Some(&phone_dl), None)
        .expect("accept_incoming_file on phone");

    let pc_file_rep = send_file_thread
        .join()
        .expect("join pc send_file_to_phone")
        .expect("pc send_file_to_phone succeeded");
    assert_eq!(
        pc_file_rep.delivery_path,
        voidwire_core::net::DeliveryPath::Direct
    );
    assert_eq!(
        std::fs::read(&saved_path).expect("read saved phone file"),
        file_payload
    );

    // 6. M3.1.1 custom shortcut accelerator + offline FileWake relay-policy enforcement
    assert_eq!(pc.send_clipboard_shortcut_accel(), "Ctrl+Shift+V");
    pc.set_send_clipboard_shortcut_accel("Ctrl+Alt+V")
        .expect("set custom shortcut accel");
    assert_eq!(pc.send_clipboard_shortcut_accel(), "Ctrl+Alt+V");
    pc.set_send_clipboard_shortcut_accel("Ctrl+Shift+V")
        .expect("reset default shortcut accel");
    assert_eq!(pc.send_clipboard_shortcut_accel(), "Ctrl+Shift+V");

    // Put the phone offline so the cached direct connection on `pc` fails and
    // `send_file_to_phone` falls back to the offline FileWake path, which must
    // enforce RelayPolicy (prompt required for > 256 KiB when decision is None;
    // never_send_files_over_relay when enabled).
    p.set_offline_for_tests(true);
    let medium_file = dir.join("offline-medium.bin");
    std::fs::write(&medium_file, vec![b'x'; 300 * 1024]).expect("write medium_file");
    let wake_err = pc
        .send_file_to_phone(&phone_id, &medium_file, "application/octet-stream", None)
        .expect_err("offline FileWake fallback without relay decision must require relay prompt");
    assert!(
        wake_err.to_string().contains("relay_prompt_required"),
        "expected relay_prompt_required on stale/offline fallback, got: {wake_err}"
    );

    pc.set_never_send_files_over_relay(true)
        .expect("enable never_send_files_over_relay");
    let blocked_err = pc
        .send_file_to_phone(
            &phone_id,
            &medium_file,
            "application/octet-stream",
            Some(voidwire_core::file_transfer::RelayPromptDecision::SendViaRelay),
        )
        .expect_err("offline FileWake must respect never_send_files_over_relay");
    assert!(
        blocked_err
            .to_string()
            .contains("never_send_files_over_relay"),
        "expected never_send_files_over_relay on offline fallback, got: {blocked_err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
