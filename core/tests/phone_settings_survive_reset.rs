//! Phone user settings live in their own file (`settings.bin` next to the
//! phone state; on Android `phone-settings.bin`): versioned, only migrated
//! forward, never reset. A phone state reset (an older state format, or the
//! state file gone) gives the phone a new identity and the re-pair notice,
//! and keeps the relay list, relay URL, file cap, mailbox and name.
#![cfg(all(feature = "net", feature = "test-util"))]

use std::sync::Arc;
use voidwire_core::ids::DeviceId;
use voidwire_core::keys::{DeviceKeypair, Platform};
use voidwire_core::net::phone::{PhoneClient, PhoneConfig};
use voidwire_core::net::state::{MemoryStateStore, StateStore};

fn phone(store: Arc<MemoryStateStore>) -> PhoneClient {
    PhoneClient::new(PhoneConfig {
        state: store,
        default_name: "Phone".into(),
        platform: Platform::Android,
        mdns: false,
    })
    .expect("phone")
}

fn vwph2() -> Vec<u8> {
    let mut old = b"VWPH2\n".to_vec();
    old.extend_from_slice(&[0x11; 32]);
    old.extend_from_slice(&[0x22; 32]);
    old.extend_from_slice(&[5, b'P', b'h', b'o', b'n', b'e', 0]);
    old
}

const RELAYS: usize = 7;

fn mailbox() -> DeviceId {
    DeviceKeypair::from_secret_bytes(&[0x42; 32]).device_id()
}

fn customise(p: &PhoneClient) {
    for i in 0..RELAYS {
        p.add_relay(
            &format!("https://relay{i}.example.net"),
            "",
            &format!("Relay {i}"),
        )
        .expect("add relay");
    }
    p.set_relay_url(Some("off".into())).unwrap(); // relays off (not the default)
    p.set_never_send_files_over_relay(true).unwrap();
    p.set_mailbox_id(Some(mailbox())).unwrap();
    p.set_device_name("Field phone").unwrap();
    p.set_connection_stats_enabled(true).unwrap();
}

fn assert_kept(p: &PhoneClient, what: &str) {
    let custom: Vec<_> = p
        .saved_relays()
        .into_iter()
        .filter(|r| !r.builtin)
        .collect();
    assert_eq!(custom.len(), RELAYS, "{what}: every custom relay kept");
    assert!(custom
        .iter()
        .any(|r| r.nickname == "Relay 6" && r.url == "https://relay6.example.net"));
    assert_eq!(p.relay_url(), None, "{what}: relay URL choice kept");
    assert!(p.never_send_files_over_relay(), "{what}: file cap kept");
    assert_eq!(p.mailbox_id(), Some(mailbox()), "{what}: mailbox kept");
    assert_eq!(p.device_name(), "Field phone", "{what}: name kept");
    assert!(p.connection_stats_enabled(), "{what}");
}

#[test]
fn a_phone_state_reset_keeps_every_setting() {
    let store = Arc::new(MemoryStateStore::default());
    let p = phone(store.clone());
    let old_id = p.device_id();
    customise(&p);
    drop(p);

    // Old state format: identity and pairings reset.
    store.save(&vwph2()).unwrap();
    let p = phone(store.clone());
    assert!(p.old_pairings_dropped(), "the re-pair notice shows");
    assert_ne!(p.device_id(), old_id, "a new identity");
    assert_kept(&p, "after the reset");
    drop(p);
    assert_kept(&phone(store.clone()), "next start");
}

#[test]
fn settings_stay_out_of_reach_of_the_state_file() {
    // The settings file is its own blob: the state store never holds the
    // only copy, and the settings blob has its own magic and version.
    let store = Arc::new(MemoryStateStore::default());
    customise(&phone(store.clone()));
    let settings = store
        .settings()
        .unwrap()
        .load()
        .unwrap()
        .expect("settings saved");
    assert_eq!(&settings[..7], b"VWSET\n\x01");
    assert!(settings
        .windows(b"Field phone".len())
        .any(|w| w == b"Field phone"));
}
