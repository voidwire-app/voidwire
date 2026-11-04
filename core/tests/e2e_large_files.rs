//! Files past 2 GiB over loopback, from sparse sources: hash pages across
//! the 2 GiB and 4 GiB marks, resume in the middle of a page, and memory that
//! stays flat while the file grows.
//!
//! Ignored by default (they write about 6 GiB). Run with:
//! `CARGO_PROFILE_DEV_OPT_LEVEL=2 cargo test -p voidwire-core --test e2e_large_files -- --ignored --test-threads=1 --nocapture`

use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use voidwire_core::file_transfer::{
    chunk_count_for_size, RelayPromptDecision, TransferId, HASH_PAGE_CHUNKS,
};
use voidwire_core::keys::Platform;
use voidwire_core::net::pc::{PcConfig, PcNode};
use voidwire_core::net::phone::{PhoneClient, PhoneConfig};
use voidwire_core::net::state::MemoryStateStore;
use voidwire_core::net::{pair_v2_for_tests, V2Node};
use voidwire_core::test_util::SharedSpyOpener;

const GIB: u64 = 1024 * 1024 * 1024;

fn phone(name: &str) -> PhoneClient {
    let p = PhoneClient::new(PhoneConfig {
        state: Arc::new(MemoryStateStore::default()),
        default_name: name.into(),
        platform: Platform::Android,
        mdns: false,
    })
    .expect("phone");
    p.set_relay_url(Some("off".into())).unwrap();
    p
}

fn loopback(v: Vec<SocketAddr>) -> Vec<SocketAddr> {
    v.into_iter()
        .filter(|a| a.is_ipv4())
        .map(|a| SocketAddr::from(([127, 0, 0, 1], a.port())))
        .collect()
}

fn pc_and_phone(tag: &str, dir: &Path) -> (Arc<PcNode>, PhoneClient) {
    let spy = Arc::new(SharedSpyOpener::default());
    let mut cfg = PcConfig::new(tag, Arc::new(MemoryStateStore::default()), spy)
        .with_download_dir(dir.join("pc"))
        .with_auto_accept_files(true);
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.advertise_loopback = true;
    cfg.unchecked_inbox_for_tests = true;
    cfg.relay_url = Some("off".into());
    let pc = Arc::new(PcNode::start(cfg).expect("pc"));
    let p = phone("Large Phone");
    pair_v2_for_tests(
        V2Node::Pc(&pc),
        loopback(pc.bound_sockets()),
        V2Node::Phone(&p),
        loopback(p.bound_sockets_for_tests()),
        None,
    )
    .expect("v2 pair");
    (pc, p)
}

/// A temp dir removed when the test ends, pass or fail (files here are GiBs).
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl std::ops::Deref for TempDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

fn temp_dir(tag: &str) -> TempDir {
    let d = std::env::temp_dir().join(format!(
        "vw-large-{tag}-{:x}",
        rand_core::RngCore::next_u64(&mut rand_core::OsRng)
    ));
    std::fs::create_dir_all(d.join("pc")).unwrap();
    std::fs::create_dir_all(d.join("phone")).unwrap();
    TempDir(d)
}

/// A sparse file of `size` bytes with marker bytes around the page, 2 GiB
/// and 4 GiB edges so a misplaced chunk changes the content.
fn sparse(path: &Path, size: u64) {
    let mut f = std::fs::File::create(path).unwrap();
    f.set_len(size).unwrap();
    let page_bytes = HASH_PAGE_CHUNKS * 256 * 1024;
    for at in [
        0,
        page_bytes - 1,
        page_bytes,
        2 * GIB - 1,
        2 * GIB,
        4 * GIB,
        size - 1,
    ] {
        if at < size {
            f.seek(SeekFrom::Start(at)).unwrap();
            f.write_all(&[(at % 251) as u8 + 1]).unwrap();
        }
    }
}

fn same_content(a: &Path, b: &Path) {
    let (mut fa, mut fb) = (
        std::fs::File::open(a).unwrap(),
        std::fs::File::open(b).unwrap(),
    );
    assert_eq!(fa.metadata().unwrap().len(), fb.metadata().unwrap().len());
    let (mut ba, mut bb) = (vec![0u8; 8 << 20], vec![0u8; 8 << 20]);
    loop {
        let n = fa.read(&mut ba).unwrap();
        if n == 0 {
            break;
        }
        fb.read_exact(&mut bb[..n]).unwrap();
        assert!(ba[..n] == bb[..n], "received file differs");
    }
}

/// Peak resident set (`VmHWM`) in KiB, Linux only.
fn peak_rss_kib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = s.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Phone → PC, 2 GiB + 3 chunks + 5 bytes (9 pages), dropped at chunk 1,034
/// (inside page 1) and resumed: the sender re-sends page 1 first, then
/// crosses the 2 GiB mark, and the result matches the source byte for byte.
#[test]
#[ignore = "writes GiBs to disk; CI runs it in the large-files job with --ignored"]
fn phone_to_pc_past_2_gib_resumes_in_the_middle_of_a_page() {
    let dir = temp_dir("resume");
    let (pc, p) = pc_and_phone("Large PC", &dir);
    let size = 2 * GIB + 3 * 256 * 1024 + 5;
    let src = dir.join("disk.img");
    sparse(&src, size);
    let chunks = chunk_count_for_size(size);
    assert_eq!(chunks, 8196);
    let stop = HASH_PAGE_CHUNKS + 10;
    let tid = TransferId::from_bytes([0x5A; 16]);

    let err = p
        .send_file_path_with_options(
            &pc.device_id(),
            tid,
            &src,
            "application/octet-stream",
            Some(RelayPromptDecision::WaitForDirect),
            Some(stop),
        )
        .expect_err("must stop mid-page");
    assert!(
        format!("{err:?}").contains("simulated_mid_stream_drop"),
        "{err:?}"
    );
    let part = dir.join("pc").join(format!("{}.part", tid.to_hex()));
    assert!(part.exists(), ".part stays for resume");

    pc.set_keep_file_history(true).unwrap();
    let report = p
        .send_file_path_with_options(
            &pc.device_id(),
            tid,
            &src,
            "application/octet-stream",
            Some(RelayPromptDecision::WaitForDirect),
            None,
        )
        .expect("resume");
    assert_eq!(report.resumed_from_chunk, stop);
    assert_eq!(report.chunks_sent, chunks - stop);
    assert!(!part.exists());
    let done = pc.completed_files();
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].size, size);
    same_content(&src, &done[0].path);
}

/// PC → phone, 4 GiB + 1 byte (17 pages, the last holds one chunk). Peak RSS
/// across the whole transfer, both peers in this process, stays far below
/// the file size.
#[test]
#[ignore = "writes GiBs to disk; CI runs it in the large-files job with --ignored"]
fn pc_to_phone_4_gib_sparse_file_with_flat_memory() {
    let dir = temp_dir("4g");
    let (pc, p) = pc_and_phone("Large PC 4G", &dir);
    let size = 4 * GIB + 1;
    let src = dir.join("backup.tar");
    sparse(&src, size);
    let before = peak_rss_kib();

    let phone_id = p.device_id();
    let pc2 = pc.clone();
    let src2 = src.clone();
    let sender = std::thread::spawn(move || {
        pc2.send_file_to_phone(&phone_id, &src2, "application/x-tar", None)
    });
    let mut tid = None;
    for _ in 0..2_400 {
        if let Some(f) = p.poll_incoming().files.first() {
            tid = Some(f.transfer_id);
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let tid = tid.expect("phone sees the offer");
    let saved = p
        .accept_incoming_file(&tid, Some(&dir.join("phone")), None)
        .expect("phone accepts and receives");
    sender.join().unwrap().expect("pc send");
    same_content(&src, &saved);

    if let (Some(b), Some(a)) = (before, peak_rss_kib()) {
        eprintln!("peak RSS: {b} KiB before, {a} KiB after a 4 GiB transfer");
        assert!(
            a < b + 256 * 1024,
            "peak RSS grew by {} KiB for a 4 GiB file",
            a - b
        );
    }
}
