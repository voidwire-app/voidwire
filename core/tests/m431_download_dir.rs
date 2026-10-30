//! v0.7.1: the download folder picked in Settings survives an upgrade.
//! tests/fixtures/custom_folder holds real state files written by v0.5.1,
//! v0.6.2 and v0.7.0 after picking "/tmp/vw-fx-custom/My Files". The desktop
//! app passes its default folder on every start (`with_download_dir`), which
//! used to replace the saved choice.
#![cfg(all(feature = "net", feature = "test-util"))]

use std::path::PathBuf;
use std::sync::Arc;
use voidwire_core::net::pc::{PcConfig, PcNode};
use voidwire_core::net::state::{MemoryStateStore, StateStore};
use voidwire_core::test_util::SharedSpyOpener;

const CUSTOM: &str = "/tmp/vw-fx-custom/My Files";

fn fixture(version: &str) -> Arc<MemoryStateStore> {
    let path = format!(
        "{}/tests/fixtures/custom_folder/pc-{version}.state",
        env!("CARGO_MANIFEST_DIR")
    );
    let s = Arc::new(MemoryStateStore::default());
    s.save(&std::fs::read(path).expect("fixture")).unwrap();
    s
}

fn start(store: Arc<MemoryStateStore>, default: &std::path::Path) -> PcNode {
    let mut cfg = PcConfig::new("PC", store, Arc::new(SharedSpyOpener::default()))
        .with_download_dir(default.to_path_buf());
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.relay_url = Some("off".into());
    PcNode::start(cfg).expect("start")
}

#[test]
fn custom_download_folder_survives_upgrades_from_0_5_0_6_and_0_7() {
    use rand_core::RngCore;
    let n = rand_core::OsRng.next_u64();
    let default = std::env::temp_dir().join(format!("vw-m431-default-{n:x}"));
    for v in ["v0.5.1", "v0.6.2", "v0.7.0"] {
        let store = fixture(v);
        // First start of the new version, then a second one (the old bug
        // also re-saved the default over the choice).
        for round in 0..2 {
            let pc = start(store.clone(), &default);
            assert_eq!(
                pc.download_dir(),
                PathBuf::from(CUSTOM),
                "{v}, start {round}: the picked folder is kept"
            );
            assert_eq!(pc.default_download_dir(), default);
        }
        // Reset in Settings still goes back to the default, and stays there.
        let pc = start(store.clone(), &default);
        pc.reset_download_dir().unwrap();
        drop(pc);
        assert_eq!(start(store, &default).download_dir(), default, "{v}");
    }
}
