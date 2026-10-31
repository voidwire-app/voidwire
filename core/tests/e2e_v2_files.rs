//! File transfer, clipboard and hardware-feedback end-to-end tests over real
//! UDP sockets (QUIC on loopback), on v2 pairings.
//!
//! Covers: sends, "Ask before opening", rejections on the socket path
//! (non-http(s), oversized, unpaired sender, replay, tampered, wrong
//! recipient key), unpairing, and the replay cache across restarts
//! (including a replay file cut at a record boundary).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use voidwire_core::keys::Platform;
use voidwire_core::net::pc::{PcConfig, PcNode};
use voidwire_core::net::phone::{PhoneClient, PhoneConfig};
use voidwire_core::net::state::{MemoryStateStore, StateStore};
use voidwire_core::net::{pair_v2_for_tests, NetError, SendOutcome, V2Node};
use voidwire_core::ratelimit::RateLimit;
use voidwire_core::test_util::SharedSpyOpener;
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
        ..InboxConfig::default()
    };
    cfg
}

use std::time::Duration;
use voidwire_core::time::Stopwatch;

/// Tests that use a checked inbox take turns: one live Inbox per process.
static CHECKED_INBOX: Mutex<()> = Mutex::new(());

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
    pair(&pc, &p);

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
    pair(&pc, &p);

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
    pair_v2_for_tests(
        V2Node::Pc(&pc),
        Vec::new(),
        V2Node::Phone(&p),
        Vec::new(),
        Some(voidwire_core::pairwise::RelayRef::new(relay.url(), None)),
    )
    .expect("v2 pair over the relay");

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
    let _turn = CHECKED_INBOX.lock().unwrap_or_else(|e| e.into_inner());
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
    pair(&pc, &p);

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
    let _turn = CHECKED_INBOX.lock().unwrap_or_else(|e| e.into_inner());
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
    pair(&pc, &p);

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
    //    `per_device` or `pre_decrypt` (burst 20, 60/min), and once the PC
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
    pair(&pc, &p);

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

    // 3. Renames reaching the peer: v2_pc_rename_reaches_the_phone and the
    // tests after it.

    // 4. Stalled transfer timeout: an accepted session times out after 45s and (v0.7.1) its
    // .part and .part.meta are deleted, so a re-send starts over
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
    let (stall_part, stall_meta) =
        voidwire_core::file_transfer::part_paths(&pc.download_dir(), &tid_stall);
    assert!(
        !stall_part.exists() && !stall_meta.exists(),
        "a timed-out transfer leaves no .part or .part.meta"
    );
    // That transfer is over: its id is spent (a re-send is a new transfer).
    pc.set_keep_file_history(true).expect("enable history");

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
    assert_eq!(pc.completed_files().len(), 1);

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
    pair(&pc, &p);
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

    // 5a. M3.1.3: PC -> Phone live file offer where PC initiates outbound QUIC connection
    // (`get_phone_conn` after clearing cached conns) and phone declines (`cancel_incoming_file`):
    // PC must receive `FILE_CANCEL` on that outbound connection and immediately clear `outgoing_files()`.
    pc.set_phone_addrs_for_tests(&phone_id, pc.phone_addrs_for_tests(&phone_id));
    let declined_file = dir.join("from-pc-decline.bin");
    std::fs::write(&declined_file, vec![b'd'; 320 * 1024]).expect("write declined_file");
    let decline_rep = pc
        .send_file_to_phone(&phone_id, &declined_file, "application/octet-stream", None)
        .expect("pc send_file_to_phone awaiting accept");
    assert!(
        decline_rep.awaiting_accept,
        "offer must return awaiting_accept when auto_accept_files is false"
    );
    assert_eq!(pc.outgoing_files().len(), 1);
    let decline_batch = p.poll_incoming();
    assert_eq!(decline_batch.files.len(), 1);
    let decline_tid = decline_batch.files[0].transfer_id;
    assert!(
        p.cancel_incoming_file(&decline_tid),
        "phone cancel_incoming_file must succeed"
    );
    let mut cleared = false;
    for _ in 0..40 {
        let out = pc.outgoing_files();
        if out
            .iter()
            .all(|o| o.ended == Some(voidwire_core::net::pc::OutboundEnd::Declined))
        {
            cleared = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        cleared,
        "PC outgoing row must end as Declined immediately when phone declines live FILE_OFFER"
    );

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

/// Wait (bounded, count-based) until `f` holds.
fn wait_for(what: &str, f: impl Fn() -> bool) {
    for _ in 0..500 {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

fn rename_pc(name: &str) -> PcNode {
    PcNode::start(pc_config(
        name,
        Arc::new(MemoryStateStore::default()),
        Arc::new(SharedSpyOpener::default()),
        0,
        None,
    ))
    .unwrap()
}

fn phone_sees(p: &PhoneClient, name: &str) -> bool {
    p.paired_pcs().first().is_some_and(|x| x.name == name)
}

fn pc_sees(pc: &PcNode, name: &str) -> bool {
    pc.devices().first().is_some_and(|d| d.name == name)
}

/// Renaming the PC reaches its phones (M4.5): a self-signed `Rename` op on
/// each pairing log, sent on the next connection (here the phone's).
#[test]
fn v2_pc_rename_reaches_the_phone() {
    let pc = rename_pc("Office Desktop");
    let pc_id = pc.device_id();
    let p = phone("Rename Phone");
    pair(&pc, &p);
    pc.rename_device("Living Room Workstation")
        .expect("rename pc");
    assert_eq!(pc.device_name(), "Living Room Workstation");
    assert!(phone_sees(&p, "Office Desktop"), "nothing sent yet");
    p.sync(&pc_id).expect("sync after rename");
    wait_for("the phone to show the new PC name", || {
        phone_sees(&p, "Living Room Workstation")
    });
    assert_eq!(p.paired_pcs().len(), 1);
    // On a connection that is already up, a rename goes out at once.
    pc.rename_device("Den PC").expect("rename again");
    wait_for("the second rename", || phone_sees(&p, "Den PC"));
    pc.shutdown();
}

/// The other way: a phone renamed before any connection (twice: only the
/// latest waits) and restarted still reaches the PC on its next dial.
#[test]
fn v2_phone_rename_reaches_the_pc_after_a_restart() {
    let pc = rename_pc("Office Desktop");
    let pc_id = pc.device_id();
    let state: Arc<dyn StateStore> = Arc::new(MemoryStateStore::default());
    let p = phone_on("Old Phone Name", state.clone());
    pair(&pc, &p);
    assert!(pc_sees(&pc, "Old Phone Name"));
    p.set_device_name("Kitchen Tablet").expect("rename");
    p.set_device_name("Hall Tablet").expect("rename again");
    drop(p);
    let p = phone_on("ignored default", state);
    assert_eq!(p.device_name(), "Hall Tablet");
    assert!(pc_sees(&pc, "Old Phone Name"), "nothing sent yet");
    // Live addresses aren't kept across a restart (mDNS or the relay finds
    // the PC); with both off here, give the phone the loopback address.
    p.set_pc_addrs_for_tests(&pc_id, loopback(pc.bound_sockets()));
    p.sync(&pc_id).expect("sync");
    wait_for("the PC to show the new phone name", || {
        pc_sees(&pc, "Hall Tablet")
    });
    pc.shutdown();
}

/// Both devices renamed while apart: when they meet, each shows the
/// other's new name (one rename loses the race and is re-signed).
#[test]
fn v2_renames_on_both_sides_both_land() {
    let pc = rename_pc("Office Desktop");
    let pc_id = pc.device_id();
    let p = phone("Old Phone Name");
    pair(&pc, &p);
    pc.rename_device("Den PC").expect("rename pc");
    p.set_device_name("Hall Tablet").expect("rename phone");
    p.sync(&pc_id).expect("sync");
    wait_for("both renames", || {
        phone_sees(&p, "Den PC") && pc_sees(&pc, "Hall Tablet")
    });
    pc.shutdown();
}

/// No timers when idle: the stall watch blocks without a deadline while no
/// transfer is in flight (zero wakeups), arms the 45 s deadline once one is,
/// and a timed-out transfer is swept by the watch itself.
#[test]
fn stall_watch_idle_wakes_nothing_and_arms_only_in_flight() {
    use voidwire_core::file_transfer::{RelayPromptDecision, TransferId};
    use voidwire_core::time::{Clock, SystemClock};

    let dir = temp_test_dir("stall-watch");
    let spy = Arc::new(SharedSpyOpener::default());
    let store = Arc::new(MemoryStateStore::default());
    let mut cfg = PcConfig::new("Office Desktop", store, spy)
        .with_download_dir(dir.clone())
        .with_auto_accept_files(true);
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some("off".into());
    let pc = Arc::new(PcNode::start(cfg).expect("start pc"));
    let p = phone("Pixel 9 Pro");
    pair(&pc, &p);

    let watch_pc = pc.clone();
    let watch = std::thread::spawn(move || {
        let mut swept = Vec::new();
        while let Some(t) = watch_pc.wait_stalled_transfers() {
            swept.extend(t);
        }
        swept
    });
    std::thread::sleep(std::time::Duration::from_millis(700));
    assert_eq!(pc.stall_deadline(), None, "idle: no deadline armed");
    assert_eq!(pc.stall_wakeups(), 0, "idle: the stall watch must not wake");

    // A transfer that stops after one chunk is in flight: a deadline is armed
    // ~45 s out and the watch was woken to take it.
    let tid = TransferId::from_bytes([0x97u8; 16]);
    let bytes: Vec<u8> = (0..(600 * 1024)).map(|i| (i % 251) as u8).collect();
    let before = SystemClock.now().wall.0;
    let _ = p
        .send_file_bytes_with_options(
            &pc.device_id(),
            tid,
            "stall_watch.bin",
            "application/octet-stream",
            &bytes,
            Some(RelayPromptDecision::WaitForDirect),
            Some(1),
            None,
        )
        .expect_err("stop after 1 chunk");
    let d = pc.stall_deadline().expect("in flight: deadline armed").0;
    assert!(
        d >= before + 44_000 && d <= SystemClock.now().wall.0 + 45_000,
        "deadline {d}"
    );
    for _ in 0..100 {
        if pc.stall_wakeups() > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(pc.stall_wakeups() >= 1, "a new transfer wakes the watch");
    let woke = pc.stall_wakeups();
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert_eq!(
        pc.stall_wakeups(),
        woke,
        "armed: no wakeups before the deadline"
    );

    // The transfer leaves (cancelled): idle again, nothing armed.
    assert!(pc.cancel_file(&tid));
    assert_eq!(pc.stall_deadline(), None);
    pc.stop_stall_watch();
    assert!(watch.join().expect("watch").is_empty());
}

/// Two PCs paired over loopback (PC A sends, PC B receives and asks first).
fn two_pcs(tag: &str) -> (Arc<PcNode>, Arc<PcNode>, std::path::PathBuf) {
    let dir = temp_test_dir(tag);
    let start = |name: &str, sub: &str| {
        let d = dir.join(sub);
        std::fs::create_dir_all(&d).expect("dir");
        let cfg = pc_config(
            name,
            Arc::new(MemoryStateStore::default()),
            Arc::new(SharedSpyOpener::default()),
            0,
            None,
        )
        .with_download_dir(d);
        Arc::new(PcNode::start(cfg).expect("start pc"))
    };
    let a = start("Desk A", "a");
    let b = start("Desk B", "b");
    pair_v2_for_tests(
        V2Node::Pc(&a),
        loopback(a.bound_sockets()),
        V2Node::Pc(&b),
        loopback(b.bound_sockets()),
        None,
    )
    .expect("v2 pair pcs");
    (a, b, dir)
}

/// v0.9.0 test sheet step 13: PC B declines a file from PC A. The decline
/// reaches PC A, whose outgoing row ends as Declined (instead of "sending"
/// until the offer expires an hour later), then goes away.
#[test]
fn pc_to_pc_decline_reaches_the_sender() {
    use voidwire_core::net::pc::OutboundEnd;
    let (a, b, dir) = two_pcs("pc-decline");
    let src = dir.join("plans.bin");
    std::fs::write(&src, vec![7u8; 300 * 1024]).expect("write");
    let rep = a
        .send_file_to_phone(&b.device_id(), &src, "application/octet-stream", None)
        .expect("offer to PC B");
    assert!(rep.awaiting_accept, "PC B asks first");
    wait_for("PC B sees the offer", || b.incoming_files().len() == 1);
    let out = a.outgoing_files();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].ended, None);

    assert!(b.cancel_file(&rep.transfer_id), "PC B declines");
    wait_for("the decline reaches PC A", || {
        a.outgoing_files()
            .iter()
            .any(|o| o.transfer_id == rep.transfer_id && o.ended == Some(OutboundEnd::Declined))
    });
    assert_eq!(a.outgoing_files().len(), 1, "only the ended row");
    assert_eq!(a.stall_deadline(), None, "nothing left to watch on PC A");
}

/// v0.9.0 test sheet step 13, second bug: the stall watch only covered
/// incoming transfers, so a PC sender's unaccepted offer never got a
/// pre-accept deadline. It now arms (and wakes the watch) when the offer
/// goes out, expires it after 120 s as Not accepted, and disarms once the
/// recipient accepts.
#[test]
fn pc_to_pc_pre_accept_stall_expires_on_the_sender() {
    use voidwire_core::net::pc::OutboundEnd;
    use voidwire_core::time::{Clock, SystemClock};
    let (a, b, dir) = two_pcs("pc-preaccept");
    let watch_pc = a.clone();
    let watch = std::thread::spawn(move || {
        let mut swept = Vec::new();
        while let Some(t) = watch_pc.wait_stalled_transfers() {
            swept.extend(t);
        }
        swept
    });
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(a.stall_deadline(), None, "idle: nothing armed");
    assert_eq!(a.stall_wakeups(), 0);

    let src = dir.join("never.bin");
    std::fs::write(&src, vec![3u8; 300 * 1024]).expect("write");
    let before = SystemClock.now().wall.0;
    let rep = a
        .send_file_to_phone(&b.device_id(), &src, "application/octet-stream", None)
        .expect("offer");
    assert!(rep.awaiting_accept);
    let d = a
        .stall_deadline()
        .expect("sender pre-accept deadline armed")
        .0;
    assert!(
        d >= before + 120_000 && d <= SystemClock.now().wall.0 + 120_000,
        "deadline {d}"
    );
    wait_for("the offer wakes the watch", || a.stall_wakeups() >= 1);

    let late = voidwire_core::time::UnixMillis(d + 1);
    assert_eq!(a.sweep_stalled_transfers(late), vec![rep.transfer_id]);
    let out = a.outgoing_files();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].ended, Some(OutboundEnd::NotAccepted));
    assert_eq!(a.stall_deadline(), None);

    // Accepted in time: the pull disarms the deadline and the file lands.
    let src2 = dir.join("wanted.bin");
    std::fs::write(&src2, vec![4u8; 300 * 1024]).expect("write");
    let rep2 = a
        .send_file_to_phone(&b.device_id(), &src2, "application/octet-stream", None)
        .expect("offer 2");
    wait_for("PC B sees offer 2", || {
        b.incoming_files()
            .iter()
            .any(|f| f.transfer_id == rep2.transfer_id)
    });
    b.accept_file(&rep2.transfer_id).expect("accept");
    wait_for("the file lands on PC B", || {
        dir.join("b").join("wanted.bin").exists()
    });
    wait_for("PC A's row finished", || {
        a.outgoing_files()
            .iter()
            .all(|o| o.transfer_id != rep2.transfer_id)
    });
    assert_eq!(a.stall_deadline(), None, "accepted and done: nothing armed");

    a.stop_stall_watch();
    let _ = watch.join().expect("watch");
}

/// The sender's in-flight stall watch: once the receiver has accepted, a
/// transfer with no chunk for 45 s ends as Stalled on the sender, like the
/// receiver's own 45 s watch. Armed only while in flight.
#[test]
fn pc_to_pc_in_flight_stall_expires_on_the_sender() {
    use voidwire_core::net::pc::{OutboundEnd, STALLED_ACCEPTED_FILE_TIMEOUT_MS};
    use voidwire_core::time::{Clock, SystemClock};
    let (a, b, dir) = two_pcs("pc-inflight");
    assert_eq!(a.stall_deadline(), None, "idle: nothing armed");

    let src = dir.join("slow.bin");
    std::fs::write(&src, vec![5u8; 2 * 1024 * 1024]).expect("write");
    a.hold_outbound_chunks_for_tests(true);
    let created = SystemClock.now().wall.0;
    let rep = a
        .send_file_to_phone(&b.device_id(), &src, "application/octet-stream", None)
        .expect("offer");
    wait_for("PC B sees the offer", || {
        b.incoming_files()
            .iter()
            .any(|f| f.transfer_id == rep.transfer_id)
    });
    let accepted = SystemClock.now().wall.0;
    b.accept_file(&rep.transfer_id).expect("accept");
    // The pull swaps the 120 s pre-accept deadline for the 45 s in-flight one.
    wait_for("the in-flight deadline is armed", || {
        a.stall_deadline()
            .is_some_and(|d| d.0 < created + 120_000 - 30_000)
    });
    let d = a.stall_deadline().expect("armed").0;
    assert!(
        d >= accepted + STALLED_ACCEPTED_FILE_TIMEOUT_MS
            && d <= SystemClock.now().wall.0 + STALLED_ACCEPTED_FILE_TIMEOUT_MS,
        "deadline {d}"
    );
    assert!(a
        .sweep_stalled_transfers(voidwire_core::time::UnixMillis(d - 1))
        .is_empty());

    assert_eq!(
        a.sweep_stalled_transfers(voidwire_core::time::UnixMillis(d + 1)),
        vec![rep.transfer_id]
    );
    let out = a.outgoing_files();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].ended, Some(OutboundEnd::Stalled));
    assert_eq!(a.stall_deadline(), None, "ended: nothing armed");
    a.hold_outbound_chunks_for_tests(false);
}

/// M2: Forget on the PC drops everything the forgotten phone left behind at
/// once: its pending clipboard prompts, its pending file offers, and an
/// accepted transfer's `.part` / `.part.meta` files on disk.
#[test]
fn v2_pc_forget_purges_the_peers_pending_items_and_part_files() {
    use voidwire_core::file_transfer::TransferId;
    let dir = temp_test_dir("forget-purge-pc");
    let src_dir = temp_test_dir("forget-purge-pc-src");
    let pc = PcNode::start(
        pc_config(
            "Purge PC",
            Arc::new(MemoryStateStore::default()),
            Arc::new(SharedSpyOpener::default()),
            0,
            None,
        )
        .with_download_dir(dir.clone()),
    )
    .expect("pc");
    let pc_id = pc.device_id();
    let p = phone("Purge Phone");
    pair(&pc, &p);
    let phone_id = p.device_id();

    let rep = p.send_text_or_url(&pc_id, "a note").expect("clipboard");
    assert_eq!(rep.outcome, SendOutcome::Prompted);
    let src = src_dir.join("f.bin");
    std::fs::write(&src, vec![7u8; 300 * 1024]).unwrap();
    let (t1, t2) = (
        TransferId::from_bytes([0x41; 16]),
        TransferId::from_bytes([0x42; 16]),
    );
    for t in [t1, t2] {
        let e = p
            .send_file_with_transfer_id(&pc_id, t, &src, "application/octet-stream", None)
            .expect_err("held for consent");
        assert!(
            format!("{e:?}").contains("file_offer_pending_accept"),
            "{e:?}"
        );
    }
    pc.accept_file(&t1).expect("accept");
    let part = dir.join(format!("{}.part", t1.to_hex()));
    let meta = dir.join(format!("{}.part.meta", t1.to_hex()));
    assert!(part.exists() && meta.exists());
    assert_eq!(pc.pending_clipboards().len(), 1);
    assert_eq!(pc.incoming_files().len(), 2);

    assert!(pc.forget_device(&phone_id).expect("forget"));
    assert!(pc.pending_clipboards().is_empty(), "clipboard prompt kept");
    assert!(pc.incoming_files().is_empty(), "file offers kept");
    assert!(!part.exists() && !meta.exists(), ".part files kept");
    pc.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&src_dir);
}

/// M2: Forget on the phone drops what the forgotten PC sent and nobody has
/// acted on yet: listed URLs and clipboard items, and pending file offers.
#[test]
fn v2_phone_forget_purges_the_pcs_items_and_file_offers() {
    let dir = temp_test_dir("forget-purge-phone");
    let pc = PcNode::start(pc_config(
        "Purge PC",
        Arc::new(MemoryStateStore::default()),
        Arc::new(SharedSpyOpener::default()),
        0,
        None,
    ))
    .expect("pc");
    let pc_id = pc.device_id();
    let p = phone("Purge Phone");
    p.set_download_dir(dir.join("dl"));
    pair(&pc, &p);
    let phone_id = p.device_id();
    pc.send_url_to_phone(&phone_id, "https://example.com/x")
        .expect("url");
    pc.send_clipboard_to_phone(&phone_id, "a note")
        .expect("clipboard");
    let src = dir.join("f.bin");
    std::fs::write(&src, vec![3u8; 300 * 1024]).unwrap();
    let rep = pc
        .send_file_to_phone(&phone_id, &src, "application/octet-stream", None)
        .expect("offer");
    assert!(rep.awaiting_accept);
    let before = p.poll_incoming();
    assert_eq!((before.items.len(), before.files.len()), (2, 1));

    assert!(p.forget_pc(&pc_id).expect("forget"));
    let after = p.poll_incoming();
    assert!(after.items.is_empty(), "items kept");
    assert!(after.files.is_empty(), "file offers kept");
    pc.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

/// No polling: the phone tells the app when something arrives. A URL, a
/// clipboard item and a file offer from the PC each fire the change listener
/// before the app has read anything; one read then shows them.
#[test]
fn v2_phone_change_listener_fires_on_each_arrival() {
    use std::sync::Condvar;
    #[derive(Default)]
    struct Count(Mutex<usize>, Condvar);
    impl Count {
        fn get(&self) -> usize {
            *self.0.lock().unwrap()
        }
        /// Block (no polling) until the count passes `seen`, or `ms`.
        fn wait_past(&self, seen: usize, ms: u64) -> usize {
            let g = self.0.lock().unwrap();
            let (g, _) = self
                .1
                .wait_timeout_while(g, Duration::from_millis(ms), |n| *n <= seen)
                .unwrap();
            *g
        }
    }
    let dir = temp_test_dir("change-listener");
    let pc = PcNode::start(pc_config(
        "Event PC",
        Arc::new(MemoryStateStore::default()),
        Arc::new(SharedSpyOpener::default()),
        0,
        None,
    ))
    .expect("pc");
    let p = phone("Event Phone");
    p.set_download_dir(dir.join("dl"));
    pair(&pc, &p);
    let phone_id = p.device_id();
    let fired = Arc::new(Count::default());
    let f = fired.clone();
    p.set_change_listener(Some(Arc::new(move || {
        *f.0.lock().unwrap() += 1;
        f.1.notify_all();
    })));
    let src = dir.join("f.bin");
    std::fs::write(&src, vec![5u8; 300 * 1024]).unwrap();
    let mut seen = fired.get();
    let sends: [&dyn Fn(); 3] = [
        &|| {
            pc.send_url_to_phone(&phone_id, "https://example.com/e")
                .expect("url");
        },
        &|| {
            pc.send_clipboard_to_phone(&phone_id, "a note")
                .expect("clip");
        },
        &|| {
            pc.send_file_to_phone(&phone_id, &src, "application/octet-stream", None)
                .expect("offer");
        },
    ];
    for (i, send) in sends.iter().enumerate() {
        send();
        let now = fired.wait_past(seen, 5_000);
        assert!(now > seen, "arrival {i} did not fire the listener");
        seen = now;
    }
    let b = p.poll_incoming();
    assert_eq!((b.items.len(), b.files.len()), (2, 1));
    p.set_change_listener(None);
    // Settle any late call for the offer, then check a cleared listener stays quiet.
    seen = fired.wait_past(seen, 300);
    pc.send_url_to_phone(&phone_id, "https://example.com/f")
        .expect("url");
    assert_eq!(fired.wait_past(seen, 300), seen, "cleared listener fired");
    pc.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

/// N5: a Forget racing a receive. Whether it lands after the keys are read
/// or after the message is verified, nothing from the forgotten PC shows up,
/// the old keys are not cached again, and its replay file is gone.
#[test]
fn v2_phone_forget_racing_a_receive_keeps_nothing() {
    for stage in [1u8, 2] {
        let dir = temp_test_dir(&format!("forget-race-{stage}"));
        let pc = PcNode::start(pc_config(
            "Race PC",
            Arc::new(MemoryStateStore::default()),
            Arc::new(SharedSpyOpener::default()),
            0,
            None,
        ))
        .expect("pc");
        let pc_id = pc.device_id();
        let p = phone("Race Phone");
        let data = dir.join("data");
        p.set_data_dir(data.clone());
        pair(&pc, &p);
        let phone_id = p.device_id();
        pc.send_url_to_phone(&phone_id, "https://example.com/first")
            .expect("first url");
        let seen_file = data.join(format!("seen-{}.bin", pc_id.to_hex()));
        assert!(seen_file.exists(), "stage {stage}: replay file written");
        assert_eq!(p.poll_incoming().items.len(), 1);
        p.dismiss_incoming_item(p.poll_incoming().items[0].item_id);

        p.race_forget_for_tests(stage);
        let _ = pc.send_url_to_phone(&phone_id, "https://example.com/raced");
        assert!(p.paired_pcs().is_empty(), "stage {stage}: forget ran");
        assert!(
            p.poll_incoming().items.is_empty(),
            "stage {stage}: item verified with the old keys landed after Forget"
        );
        assert!(
            !p.inbox_cached_for_tests(&pc_id),
            "stage {stage}: old keys cached after Forget"
        );
        assert!(!seen_file.exists(), "stage {stage}: replay file kept");
        pc.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// M2 (phone): Forget during an accepted transfer from the PC deletes the
/// transfer's partial files on the phone before it returns.
#[test]
fn v2_phone_forget_mid_transfer_deletes_the_part_files() {
    let dir = temp_test_dir("forget-mid-phone");
    let pc = PcNode::start(pc_config(
        "Mid PC",
        Arc::new(MemoryStateStore::default()),
        Arc::new(SharedSpyOpener::default()),
        0,
        None,
    ))
    .expect("pc");
    let pc_id = pc.device_id();
    let p = phone("Mid Phone");
    let dl = dir.join("dl");
    p.set_download_dir(dl.clone());
    pair(&pc, &p);
    let src = dir.join("big.bin");
    std::fs::write(&src, vec![7u8; 2 * 1024 * 1024]).unwrap();
    pc.hold_outbound_chunks_for_tests(true);
    let rep = pc
        .send_file_to_phone(&p.device_id(), &src, "application/octet-stream", None)
        .expect("offer");
    let leftovers = || -> Vec<String> {
        std::fs::read_dir(&dl)
            .map(|r| {
                r.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.contains(".part"))
                    .collect()
            })
            .unwrap_or_default()
    };
    std::thread::scope(|sc| {
        // The accept waits on the held chunks; Forget ends it.
        let accept = sc.spawn(|| p.accept_incoming_file(&rep.transfer_id, None, None));
        wait_for("the phone has a partial file", || !leftovers().is_empty());
        assert!(p.forget_pc(&pc_id).expect("forget"));
        assert_eq!(leftovers(), Vec::<String>::new(), "part files kept");
        assert!(p.poll_incoming().files.is_empty());
        pc.hold_outbound_chunks_for_tests(false);
        let _ = accept.join();
    });
    assert_eq!(
        leftovers(),
        Vec::<String>::new(),
        "part files back after the accept ended"
    );
    pc.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

/// One refresh path: each call that changes what the app shows (rename, a
/// relay added, a relay move asked, an item dismissed, Forget) tells the
/// change listener, without the app polling.
#[test]
fn v2_phone_state_changes_the_app_shows_fire_the_listener() {
    let pc = PcNode::start(pc_config(
        "Ui PC",
        Arc::new(MemoryStateStore::default()),
        Arc::new(SharedSpyOpener::default()),
        0,
        None,
    ))
    .expect("pc");
    let pc_id = pc.device_id();
    let p = phone("Ui Phone");
    pair(&pc, &p);
    pc.send_url_to_phone(&p.device_id(), "https://example.com/ui")
        .expect("url");
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let tx = Mutex::new(tx);
    p.set_change_listener(Some(Arc::new(move || {
        let _ = tx.lock().unwrap().send(());
    })));
    let expect_event = |what: &str| {
        // Blocks until the event (no polling); then drops folded extras.
        rx.recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("{what}: no change event"));
        while rx.try_recv().is_ok() {}
    };
    let quiet = |what: &str| {
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "{what}: event with no change"
        );
    };
    quiet("idle");
    // Reads never fire (the app reads on each event: that must not loop).
    let item = p.poll_incoming().items[0].item_id;
    let _ = (
        p.paired_pcs(),
        p.pairings(),
        p.relays(),
        p.relay_change_statuses(),
        p.relay_change_requests(),
    );
    quiet("reads");
    assert!(p.dismiss_incoming_item(item));
    expect_event("item dismissed");
    p.set_device_name("Renamed Phone").expect("rename");
    expect_event("rename");
    p.add_relay("https://ui-relay.example", &"c1".repeat(32), "Lab")
        .expect("add relay");
    expect_event("relay added");
    let _ = p.change_pairing_relay(&pc_id, "https://ui-relay.example");
    expect_event("relay move asked");
    assert!(p.forget_pc(&pc_id).expect("forget"));
    expect_event("forget");
    p.set_change_listener(None);
    pc.shutdown();
}
