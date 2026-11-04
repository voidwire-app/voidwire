//! The desktop UI has no timer: it re-reads when the core emits a PcEvent.
//! These check the events it relies on, and that receive progress stays
//! bounded (one event per whole percent, not one per chunk).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use voidwire_core::file_transfer::{RelayPromptDecision, TransferId};
use voidwire_core::keys::Platform;
use voidwire_core::net::pc::{PcConfig, PcEvent, PcNode};
use voidwire_core::net::phone::{PhoneClient, PhoneConfig};
use voidwire_core::net::state::MemoryStateStore;
use voidwire_core::net::{pair_v2_for_tests, V2Node};
use voidwire_core::test_util::SharedSpyOpener;

fn loopback(v: Vec<SocketAddr>) -> Vec<SocketAddr> {
    v.into_iter()
        .filter(|a| a.is_ipv4())
        .map(|a| SocketAddr::from(([127, 0, 0, 1], a.port())))
        .collect()
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "voidwire-events-{tag}-{}",
        TransferId::random().to_hex()
    ));
    std::fs::create_dir_all(&dir).expect("dir");
    dir
}

fn setup(
    tag: &str,
) -> (
    PcNode,
    PhoneClient,
    Arc<Mutex<Vec<PcEvent>>>,
    std::path::PathBuf,
) {
    let dir = temp_dir(tag);
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let mut cfg = PcConfig::new(
        "Events PC",
        Arc::new(MemoryStateStore::default()),
        Arc::new(SharedSpyOpener::default()),
    )
    .with_download_dir(dir.clone())
    .with_auto_accept_files(true);
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some("off".into());
    cfg.events = Some(Arc::new(move |e| sink.lock().unwrap().push(e)));
    let pc = PcNode::start(cfg).expect("pc");
    let p = PhoneClient::new(PhoneConfig {
        state: Arc::new(MemoryStateStore::default()),
        default_name: "Events Phone".into(),
        platform: Platform::Android,
        mdns: false,
    })
    .expect("phone");
    p.set_relay_url(Some("off".into())).unwrap();
    pair_v2_for_tests(
        V2Node::Pc(&pc),
        loopback(pc.bound_sockets()),
        V2Node::Phone(&p),
        loopback(p.bound_sockets_for_tests()),
        None,
    )
    .expect("pair");
    (pc, p, events, dir)
}

#[test]
fn incoming_progress_is_one_event_per_percent_not_per_chunk() {
    let (pc, p, events, dir) = setup("progress");
    // 150 chunks of 256 KiB: per-chunk events would be 149 before the end.
    let data: Vec<u8> = (0..150 * 256 * 1024).map(|i| (i * 7 + 3) as u8).collect();
    let tid = TransferId::random();
    p.send_file_bytes_with_options(
        &pc.device_id(),
        tid,
        "big.bin",
        "application/octet-stream",
        &data,
        Some(RelayPromptDecision::WaitForDirect),
        None,
        None,
    )
    .expect("send");
    let ev = events.lock().unwrap().clone();
    let progress: Vec<u64> = ev
        .iter()
        .filter_map(|e| match e {
            PcEvent::IncomingFileProgress {
                transfer_id,
                next_chunk,
                chunk_count,
            } if *transfer_id == tid => {
                assert_eq!(*chunk_count, 150);
                Some(*next_chunk)
            }
            _ => None,
        })
        .collect();
    assert!(
        (50..=100).contains(&progress.len()),
        "{} progress events",
        progress.len()
    );
    assert!(progress.windows(2).all(|w| w[0] < w[1]), "in order");
    assert!(ev
        .iter()
        .any(|e| matches!(e, PcEvent::FileCompleted { transfer_id, .. } if *transfer_id == tid)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_send_to_the_phone_tells_the_ui_its_row_appeared() {
    let (pc, p, events, dir) = setup("send");
    let phone_id = p.device_id();
    let _ = pc.send_file_bytes_to_phone(
        &phone_id,
        TransferId::random(),
        "note.txt",
        "text/plain",
        b"hello",
        Some(RelayPromptDecision::WaitForDirect),
    );
    let ev = events.lock().unwrap().clone();
    assert!(
        ev.iter().any(|e| matches!(e, PcEvent::TransfersChanged)),
        "events: {ev:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
