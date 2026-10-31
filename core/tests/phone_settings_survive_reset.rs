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

/// Storage that can turn read-only (android-qa's chmod 500 no_backup),
/// for the state and the settings file alike.
#[derive(Default)]
struct Flaky {
    inner: MemoryStateStore,
    fail: Arc<std::sync::atomic::AtomicBool>,
}

impl StateStore for Flaky {
    fn load(&self) -> Result<Option<Vec<u8>>, String> {
        self.inner.load()
    }
    fn save(&self, data: &[u8]) -> Result<(), String> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("Permission denied (test)".into());
        }
        self.inner.save(data)
    }
    fn settings(&self) -> Option<Arc<dyn StateStore>> {
        let s = self.inner.settings()?;
        Some(Arc::new(FlakySettings(s, self.fail.clone())))
    }
}

struct FlakySettings(Arc<dyn StateStore>, Arc<std::sync::atomic::AtomicBool>);

impl StateStore for FlakySettings {
    fn load(&self) -> Result<Option<Vec<u8>>, String> {
        self.0.load()
    }
    fn save(&self, data: &[u8]) -> Result<(), String> {
        if self.1.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("Permission denied (test)".into());
        }
        self.0.save(data)
    }
}

/// Starting writes nothing when nothing changed, so a phone whose storage
/// went read-only still starts (and keeps its settings).
#[test]
fn a_read_only_phone_still_starts() {
    let store = Arc::new(Flaky::default());
    let start = |s: Arc<Flaky>| {
        PhoneClient::new(PhoneConfig {
            state: s,
            default_name: "Phone".into(),
            platform: Platform::Android,
            mdns: false,
        })
    };
    let p = start(store.clone()).expect("phone");
    customise(&p);
    drop(p);
    store.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let p = start(store.clone()).expect("starts on read-only storage");
    assert_kept(&p, "read-only start");
}
