//! v0.7.1: the download folder picked in Settings survives restarts. The
//! desktop app passes its default folder on every start
//! (`with_download_dir`), which used to replace the saved choice.
//!
//! Also the VWPC3 state switch (M4-ROSTER-REMOVAL step 5):
//! tests/fixtures/custom_folder holds real VWPC2 files written by v0.5.1,
//! v0.6.2 and v0.7.0. They are not read: the PC starts fresh with a new
//! identity, keeps nothing of the old file and flags "Pair again".
#![cfg(all(feature = "net", feature = "test-util"))]

use std::path::PathBuf;
use std::sync::Arc;
use voidwire_core::keys::DeviceKeypair;
use voidwire_core::net::pc::{PcConfig, PcNode};
use voidwire_core::net::state::{FileStateStore, MemoryStateStore, StateStore};
use voidwire_core::test_util::SharedSpyOpener;

const CUSTOM: &str = "/tmp/vw-fx-custom/My Files";

fn fixture(version: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/custom_folder/pc-{version}.state",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).expect("fixture")
}

fn start(store: Arc<dyn StateStore>, default: &std::path::Path) -> PcNode {
    try_start(store, default).expect("pc node")
}

fn try_start(
    store: Arc<dyn StateStore>,
    default: &std::path::Path,
) -> Result<PcNode, voidwire_core::net::NetError> {
    let mut cfg = PcConfig::new("PC", store, Arc::new(SharedSpyOpener::default()))
        .with_download_dir(default.to_path_buf());
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.relay_url = Some("off".into());
    cfg.unchecked_inbox_for_tests = true;
    PcNode::start(cfg)
}

fn temp_default() -> PathBuf {
    use rand_core::RngCore;
    let n = rand_core::OsRng.next_u64();
    std::env::temp_dir().join(format!("vw-m431-default-{n:x}"))
}

#[test]
fn custom_download_folder_survives_restarts() {
    let default = temp_default();
    let store = Arc::new(MemoryStateStore::default());
    let pc = start(store.clone(), &default);
    pc.set_download_dir(PathBuf::from(CUSTOM)).unwrap();
    drop(pc);
    // Two starts (the old bug also re-saved the default over the choice).
    for round in 0..2 {
        let pc = start(store.clone(), &default);
        assert_eq!(
            pc.download_dir(),
            PathBuf::from(CUSTOM),
            "start {round}: the picked folder is kept"
        );
        assert_eq!(pc.default_download_dir(), default);
    }
    // Reset in Settings still goes back to the default, and stays there.
    let pc = start(store.clone(), &default);
    pc.reset_download_dir().unwrap();
    drop(pc);
    assert_eq!(start(store, &default).download_dir(), default);
}

#[test]
fn vwpc2_files_start_fresh_and_flag_repair() {
    let default = temp_default();
    for v in ["v0.5.1", "v0.6.2", "v0.7.0"] {
        let old = fixture(v);
        assert_eq!(&old[..6], b"VWPC2\n", "{v}");
        let mut old_id = [0u8; 32];
        old_id.copy_from_slice(&old[6..38]);
        let mut old_rx = [0u8; 32];
        old_rx.copy_from_slice(&old[38..70]);
        let store = Arc::new(MemoryStateStore::default());
        store.save(&old).unwrap();
        let pc = start(store.clone(), &default);
        assert!(pc.old_pairings_dropped(), "{v}: says Pair again");
        assert!(pc.pairings().is_empty(), "{v}");
        assert_ne!(
            pc.device_id(),
            DeviceKeypair::from_secret_bytes(&old_id).device_id(),
            "{v}: a new identity"
        );
        assert_eq!(pc.download_dir(), default, "{v}: nothing of the old file");
        drop(pc);
        // The old file was replaced (one atomic save), and no old secret
        // is in the new one.
        let new = store.load().unwrap().unwrap();
        assert_eq!(&new[..6], b"VWPC3\n", "{v}");
        for secret in [&old_id, &old_rx] {
            assert!(
                !new.windows(32).any(|w| w == secret),
                "{v}: old secret reused"
            );
        }
        // The flag survives a restart.
        assert!(start(store, &default).old_pairings_dropped(), "{v}");
    }
}

/// L5: the VWPC2 reset through the real file store. The new state replaces
/// the old file in one rename (no temp file left, even a stale one holding
/// an old secret), and no file in the folder holds an old secret.
#[test]
fn vwpc2_reset_on_disk_is_atomic_and_keeps_no_old_secret() {
    let default = temp_default();
    let dir = temp_default().with_extension("state");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("pc.state");
    let old = fixture("v0.7.0");
    let (old_id, old_rx) = (old[6..38].to_vec(), old[38..70].to_vec());
    let store = Arc::new(FileStateStore::new(&path));
    store.save(&old).unwrap();
    // A crash in an earlier save left a temp file with the old secrets.
    std::fs::write(path.with_extension("tmp"), &old).unwrap();

    let pc = start(store.clone(), &default);
    assert!(pc.old_pairings_dropped());
    drop(pc);
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(!names.iter().any(|n| n.ends_with(".tmp")), "{names:?}");
    let new = store.load().unwrap().unwrap();
    assert_eq!(&new[..6], b"VWPC3\n");
    for entry in std::fs::read_dir(&dir).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        for secret in [&old_id, &old_rx] {
            assert!(
                !bytes.windows(32).any(|w| w == &secret[..]),
                "old secret on disk"
            );
        }
    }
    for secret in [&old_id, &old_rx] {
        assert!(
            !new.windows(32).any(|w| w == &secret[..]),
            "old secret kept"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// L5: a reset whose save fails does not start and leaves the old file as
/// it was (nothing half-written).
#[test]
fn vwpc2_reset_with_failing_save_keeps_the_old_file() {
    struct NoSave(MemoryStateStore);
    impl StateStore for NoSave {
        fn load(&self) -> Result<Option<Vec<u8>>, String> {
            self.0.load()
        }
        fn save(&self, _: &[u8]) -> Result<(), String> {
            Err("disk full".into())
        }
    }
    let old = fixture("v0.7.0");
    let mem = MemoryStateStore::default();
    mem.save(&old).unwrap();
    let store = Arc::new(NoSave(mem));
    assert!(try_start(store.clone(), &temp_default()).is_err());
    assert_eq!(store.load().unwrap().unwrap(), old);
}
