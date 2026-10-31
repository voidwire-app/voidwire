//! Security end-to-end tests over real UDP sockets (QUIC on loopback), on
//! v2 pairings: a PC node and a Rust phone client paired the v2 way.
//!
//! Covers: sends, "Ask before opening", rejections on the socket path
//! (non-http(s), oversized, unpaired sender, replay, tampered, wrong
//! recipient key), unpairing, and the replay cache across restarts
//! (including a replay file cut at a record boundary).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use voidwire_core::envelope::MAX_ENVELOPE_LEN;
use voidwire_core::keys::Platform;
use voidwire_core::net::pc::{PcConfig, PcEvent, PcNode};
use voidwire_core::net::phone::{PhoneClient, PhoneConfig};
use voidwire_core::net::state::{MemoryStateStore, StateStore};
use voidwire_core::net::{pair_v2_for_tests, NetError, SendOutcome, V2Node};
use voidwire_core::ratelimit::RateLimit;
use voidwire_core::reject::RejectReason;
use voidwire_core::test_util::{FakePeer, SharedSpyOpener};
use voidwire_core::time::{Clock, SystemClock};
use voidwire_core::verify::InboxConfig;

fn phone_on(name: &str, state: Arc<dyn StateStore>) -> PhoneClient {
    let p = PhoneClient::new(PhoneConfig {
        state,
        default_name: name.into(),
        platform: Platform::Android,
        mdns: false,
    })
    .expect("phone");
    p.set_relay_url(Some("off".into())).unwrap();
    p
}

fn phone(name: &str) -> PhoneClient {
    phone_on(name, Arc::new(MemoryStateStore::default()))
}

fn loopback(v: Vec<SocketAddr>) -> Vec<SocketAddr> {
    v.into_iter()
        .filter(|a| a.is_ipv4())
        .map(|a| SocketAddr::from(([127, 0, 0, 1], a.port())))
        .collect()
}

/// A v2 pairing between `pc` and `p` over loopback.
fn pair(pc: &PcNode, p: &PhoneClient) {
    pair_v2_for_tests(
        V2Node::Pc(pc),
        loopback(pc.bound_sockets()),
        V2Node::Phone(p),
        loopback(p.bound_sockets_for_tests()),
        None,
    )
    .expect("v2 pair");
}

fn rejected(r: Result<impl std::fmt::Debug, NetError>) -> RejectReason {
    match r {
        Err(NetError::Rejected(r)) => r,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

fn wall() -> voidwire_core::time::UnixMillis {
    SystemClock.now().wall
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let uniq = voidwire_core::keys::DeviceKeypair::generate()
        .device_id()
        .to_hex();
    let d = std::env::temp_dir().join(format!("vw-e2e2-{tag}-{}", &uniq[..16]));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn pc_config(
    name: &str,
    state: Arc<dyn StateStore>,
    spy: Arc<SharedSpyOpener>,
    port: u16,
    seen: Option<std::path::PathBuf>,
) -> PcConfig {
    let mut cfg = PcConfig::new(name, state, spy);
    cfg.mdns = false;
    cfg.port = Some(port);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some("off".into());
    cfg.seen_store_path = seen;
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
    cfg
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn v2_send_reject_and_unpair_over_real_sockets() {
    let spy = Arc::new(SharedSpyOpener::default());
    let events: Arc<Mutex<Vec<PcEvent>>> = Arc::default();
    let ev = events.clone();
    let mut cfg = pc_config(
        "Test PC",
        Arc::new(MemoryStateStore::default()),
        spy.clone(),
        0,
        None,
    );
    cfg.events = Some(Arc::new(move |e| ev.lock().unwrap().push(e)));
    let pc = PcNode::start(cfg).expect("pc");
    let pc_id = pc.device_id();
    assert!(pc.no_prompt(), "fresh PC: no-prompt is the default");
    let p1 = phone("Test Phone");
    pair(&pc, &p1);
    let devs = pc.devices();
    assert_eq!(devs.len(), 1);
    assert_eq!(devs[0].id, p1.device_id());

    // Default mode: opens at once, no prompt.
    let r = p1.send_url(&pc_id, "https://example.com/first").unwrap();
    assert_eq!(r.outcome, SendOutcome::Opened);
    assert_eq!(spy.calls(), vec!["https://example.com/first".to_string()]);
    assert!(pc.pending().is_empty());

    // "Ask before opening": prompt, then the user clicks Open.
    pc.set_no_prompt(false).unwrap();
    let r = p1.send_url(&pc_id, "https://example.com/asked").unwrap();
    assert_eq!(r.outcome, SendOutcome::Prompted);
    assert_eq!(spy.count(), 1, "nothing opens before the click");
    let pending = pc.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].host, "example.com");
    pc.decide(pending[0].id, true).unwrap();
    assert_eq!(spy.count(), 2);
    assert_eq!(
        rejected(pc.decide(pending[0].id, true)),
        RejectReason::NoSuchPrompt
    );
    pc.set_no_prompt(true).unwrap();

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

    // Signed by a device that isn't in the pairing: a stranger's key with
    // everything else (pairing id, head, the PC's receive key) copied.
    let mut stranger = p1.fake_peer_for_tests(&pc_id).unwrap();
    stranger.key = voidwire_core::keys::DeviceKeypair::generate();
    let r = rejected(p1.send_envelope_for_tests(
        &pc_id,
        &stranger.frame("https://example.com/stranger", wall()),
    ));
    assert_eq!(r, RejectReason::SenderMismatch);

    // Another group's id (a pairing this phone doesn't have with this PC).
    let mut other_group = p1.fake_peer_for_tests(&pc_id).unwrap();
    other_group.group = voidwire_core::ids::GroupId([0x42; 32]);
    let r = rejected(p1.send_envelope_for_tests(
        &pc_id,
        &other_group.frame("https://example.com/other-group", wall()),
    ));
    assert_eq!(r, RejectReason::WrongGroup);

    // Unpaired sender: a phone holding a pairing the PC never accepted,
    // with everything it would need except the PC's side of it.
    let outsider = phone("Outsider");
    let (pk, pcert) = pc.v2_identity_for_tests();
    let (ok, ocert) = outsider.v2_identity_for_tests();
    let (_, theirs) = voidwire_core::pairwise::v2::pair_for_tests(&pk, pcert, &ok, ocert, None);
    outsider
        .adopt_v2_pairing_for_tests(theirs, loopback(pc.bound_sockets()))
        .unwrap();
    let r = rejected(outsider.send_url(&pc_id, "https://example.com/outsider"));
    assert_eq!(r, RejectReason::NotInRoster);
    let fake_outsider = outsider.fake_peer_for_tests(&pc_id).unwrap();
    assert_eq!(
        rejected(outsider.send_envelope_for_tests(
            &pc_id,
            &fake_outsider.frame("https://example.com/o", wall())
        )),
        RejectReason::NotInRoster
    );

    assert_eq!(
        spy.count(),
        opened_before + 1,
        "only the first copy of the replayed link opened"
    );
    // The outsider was turned away at the connection, before any read.
    assert!(events.lock().unwrap().iter().any(|e| matches!(
        e,
        PcEvent::Rejected {
            reason: RejectReason::NotInRoster,
            from: None,
        }
    )));

    // ---- Forget this device: immediate, and the phone learns it ----
    assert!(pc.forget_device(&p1.device_id()).unwrap());
    assert!(pc.devices().is_empty());
    // The phone got the unpair notice and dropped the pairing; a PC that
    // no longer holds a pairing refuses it (the outsider case above).
    assert!(matches!(
        p1.send_url(&pc_id, "https://example.com/after-forget"),
        Err(NetError::UnknownDevice)
    ));
    let env = fake.frame("https://example.com/after-forget-raw", wall());
    assert!(matches!(
        p1.send_envelope_for_tests(&pc_id, &env),
        Err(NetError::UnknownDevice)
    ));
    assert_eq!(
        spy.count(),
        opened_before + 1,
        "nothing opened after forget"
    );
    pc.shutdown();
}

/// The pairing and the per-pairing replay cache survive a PC restart; a
/// link captured before the restart can't be replayed after it.
#[test]
fn v2_restart_keeps_pairing_and_replay_cache() {
    let dir = temp_dir("restart");
    let state: Arc<dyn StateStore> = Arc::new(voidwire_core::net::state::FileStateStore::new(
        dir.join("state.bin"),
    ));
    let spy = Arc::new(SharedSpyOpener::default());
    let port = free_udp_port();
    let seen = Some(dir.join("seen.bin"));
    let start = || {
        PcNode::start(pc_config(
            "Restart PC",
            state.clone(),
            spy.clone(),
            port,
            seen.clone(),
        ))
        .unwrap()
    };
    let pc = start();
    let pc_id = pc.device_id();
    let p1 = phone("Restart Phone");
    pair(&pc, &p1);
    let fake = p1.fake_peer_for_tests(&pc_id).unwrap();
    let env = fake.frame("https://example.com/before-restart", wall());
    assert_eq!(
        p1.send_envelope_for_tests(&pc_id, &env).unwrap().outcome,
        SendOutcome::Opened
    );
    pc.shutdown();

    let pc = start();
    assert_eq!(pc.device_id(), pc_id, "same identity after restart");
    assert_eq!(pc.devices().len(), 1, "pairing persisted");
    // Stale cached connection: the client reconnects once.
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

/// A pairing's replay file cut at a record boundary (or deleted) between
/// runs is caught: the PC refuses links it can't prove are new until they
/// age out, so a captured link is never opened twice.
#[test]
fn v2_replay_file_cut_or_deleted_fails_closed() {
    for cut in [true, false] {
        let dir = temp_dir("cut");
        let state: Arc<dyn StateStore> = Arc::new(voidwire_core::net::state::FileStateStore::new(
            dir.join("state.bin"),
        ));
        let spy = Arc::new(SharedSpyOpener::default());
        let port = free_udp_port();
        let seen = Some(dir.join("seen.bin"));
        let start = || {
            PcNode::start(pc_config(
                "Cut PC",
                state.clone(),
                spy.clone(),
                port,
                seen.clone(),
            ))
            .unwrap()
        };
        let pc = start();
        let pc_id = pc.device_id();
        let p1 = phone("Cut Phone");
        pair(&pc, &p1);
        let fake = p1.fake_peer_for_tests(&pc_id).unwrap();
        let first = fake.frame("https://example.com/cut-a", wall());
        let last = fake.frame("https://example.com/cut-b", wall());
        for env in [&first, &last] {
            assert_eq!(
                p1.send_envelope_for_tests(&pc_id, env).unwrap().outcome,
                SendOutcome::Opened
            );
        }
        pc.shutdown();

        // A clean restart refuses neither replay nor new links wrongly.
        let pc = start();
        assert_eq!(
            rejected(p1.send_envelope_for_tests(&pc_id, &last)),
            RejectReason::Replay
        );
        pc.shutdown();

        let file = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("seen-"))
            })
            .expect("the pairing's replay file");
        if cut {
            let bytes = std::fs::read(&file).unwrap();
            let rec = 2 + 16 + 8 + 4;
            assert!(bytes.len() >= 8 + 2 * rec);
            std::fs::write(&file, &bytes[..bytes.len() - rec]).unwrap();
        } else {
            std::fs::remove_file(&file).unwrap();
        }
        let pc = start();
        for env in [&first, &last] {
            assert_eq!(
                rejected(p1.send_envelope_for_tests(&pc_id, env)),
                RejectReason::ReplayStartupGuard,
                "cut={cut}"
            );
        }
        assert_eq!(spy.count(), 2, "cut={cut}: nothing replayed");
        // New links still go through.
        assert_eq!(
            p1.send_url(&pc_id, "https://example.com/cut-new")
                .unwrap()
                .outcome,
            SendOutcome::Opened
        );
        pc.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
