//! User settings live in their own file (`settings.bin`, versioned, only
//! migrated forward) and survive a pairing/identity reset: here an older
//! state format (VWPC2), which starts the PC fresh with a new identity and
//! the re-pair notice, keeps the relay list and every preference.
#![cfg(all(feature = "net", feature = "test-util"))]

use std::path::PathBuf;
use std::sync::Arc;
use voidwire_core::net::pc::{PcConfig, PcNode};
use voidwire_core::net::state::{FileStateStore, MemoryStateStore, StateStore, SETTINGS_FILE};
use voidwire_core::test_util::SharedSpyOpener;

fn start(store: Arc<dyn StateStore>, default: &std::path::Path) -> PcNode {
    let mut cfg = PcConfig::new("PC", store, Arc::new(SharedSpyOpener::default()))
        .with_download_dir(default.to_path_buf());
    cfg.mdns = false;
    cfg.port = Some(0);
    cfg.relay_url = Some("off".into());
    cfg.unchecked_inbox_for_tests = true;
    PcNode::start(cfg).expect("pc node")
}

fn temp(tag: &str) -> PathBuf {
    use rand_core::RngCore;
    std::env::temp_dir().join(format!(
        "vw-settings-{tag}-{:x}",
        rand_core::OsRng.next_u64()
    ))
}

fn vwpc2() -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/custom_folder/pc-v0.7.0.state",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture")
}

const RELAYS: usize = 7;
const ACCEL: &str = "Ctrl+Alt+K";

fn customise(pc: &PcNode, folder: &std::path::Path) {
    for i in 0..RELAYS {
        pc.add_relay(
            &format!("https://relay{i}.example.net"),
            "",
            &format!("Relay {i}"),
        )
        .expect("add relay");
    }
    pc.set_no_prompt(false).unwrap();
    pc.set_keep_file_history(true).unwrap();
    pc.set_auto_copy_clipboard(true).unwrap();
    pc.set_send_clipboard_shortcut(true).unwrap();
    pc.set_send_clipboard_shortcut_accel(ACCEL).unwrap();
    pc.set_download_dir(folder.to_path_buf()).unwrap();
    pc.rename_device("Studio").unwrap();
    pc.set_connection_stats_enabled(true).unwrap();
    pc.set_never_send_files_over_relay(true).unwrap();
}

fn assert_kept(pc: &PcNode, folder: &std::path::Path, what: &str) {
    let custom: Vec<_> = pc
        .saved_relays()
        .into_iter()
        .filter(|r| !r.builtin)
        .collect();
    assert_eq!(custom.len(), RELAYS, "{what}: every custom relay kept");
    assert!(custom
        .iter()
        .any(|r| r.nickname == "Relay 6" && r.url == "https://relay6.example.net"));
    assert!(!pc.no_prompt(), "{what}: ask-first kept");
    assert!(pc.keep_file_history(), "{what}");
    assert!(pc.auto_copy_clipboard(), "{what}");
    assert!(pc.send_clipboard_shortcut(), "{what}");
    assert_eq!(pc.send_clipboard_shortcut_accel(), ACCEL, "{what}");
    assert_eq!(pc.download_dir(), folder, "{what}");
    assert_eq!(pc.device_name(), "Studio", "{what}: the PC name");
    assert!(pc.connection_stats_enabled(), "{what}");
    assert!(pc.never_send_files_over_relay(), "{what}");
}

#[test]
fn a_pairing_format_reset_keeps_the_settings() {
    let default = temp("default");
    let folder = temp("picked");
    let store = Arc::new(MemoryStateStore::default());
    let pc = start(store.clone(), &default);
    let old_id = pc.device_id();
    customise(&pc, &folder);
    drop(pc);

    // An upgrade finds an older state format: identity and pairings reset.
    store.save(&vwpc2()).unwrap();
    let pc = start(store.clone(), &default);
    assert!(pc.old_pairings_dropped(), "the re-pair notice shows");
    assert_ne!(pc.device_id(), old_id, "a new identity");
    assert_kept(&pc, &folder, "after the reset");
    drop(pc);
    // And on the start after that.
    assert_kept(&start(store, &default), &folder, "next start");
}

#[test]
fn a_damaged_state_file_replaced_by_the_user_keeps_the_settings() {
    // On disk: settings.bin is its own file next to state.bin; deleting
    // state.bin (a full pairing reset) leaves it alone.
    let dir = temp("disk");
    std::fs::create_dir_all(&dir).unwrap();
    let default = dir.join("downloads");
    let folder = temp("picked2");
    let state: Arc<dyn StateStore> = Arc::new(FileStateStore::new(dir.join("state.bin")));
    let pc = start(state.clone(), &default);
    customise(&pc, &folder);
    drop(pc);
    assert!(dir.join(SETTINGS_FILE).is_file(), "settings.bin written");
    std::fs::remove_file(dir.join("state.bin")).unwrap();
    let pc = start(state, &default);
    assert_kept(&pc, &folder, "after state.bin was deleted");
    drop(pc);
    let _ = std::fs::remove_dir_all(&dir);
}
