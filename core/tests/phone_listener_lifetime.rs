//! QA S3 (S24): the app's change listener may call back into the phone and
//! clear itself, and setting/clearing it leaves no `voidwire-notify` thread
//! behind. Its own test binary, so no other test's phone owns a notify thread.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use voidwire_core::keys::Platform;
use voidwire_core::net::phone::{PhoneClient, PhoneConfig};
use voidwire_core::net::state::MemoryStateStore;

/// The tests count process-wide threads: one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn phone() -> Arc<PhoneClient> {
    let p = PhoneClient::new(PhoneConfig {
        state: Arc::new(MemoryStateStore::default()),
        default_name: "Listener Phone".into(),
        platform: Platform::Android,
        mdns: false,
    })
    .expect("phone");
    p.set_relay_url(Some("off".into())).unwrap();
    Arc::new(p)
}

fn wait_until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..500 {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out: {what}");
}

#[test]
fn the_listener_can_read_and_clear_itself_from_inside_the_call() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let p = phone();
    let calls = Arc::new(AtomicUsize::new(0));
    let weak: Weak<PhoneClient> = Arc::downgrade(&p);
    let c = calls.clone();
    p.set_change_listener(Some(Arc::new(move || {
        c.fetch_add(1, Ordering::SeqCst);
        let Some(p) = weak.upgrade() else { return };
        // What the app reads on a change, from the notify thread.
        let _ = p.poll_incoming();
        let _ = p.paired_pcs();
        let _ = p.pairings();
        let _ = p.relays();
        p.set_change_listener(None);
    })));
    p.set_device_name("Renamed Phone").expect("rename");
    wait_until("first call", || calls.load(Ordering::SeqCst) >= 1);
    let after_clear = calls.load(Ordering::SeqCst);
    // Cleared from inside: later changes call nobody.
    p.set_device_name("Renamed Again").expect("rename");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(calls.load(Ordering::SeqCst), after_clear);
}

#[cfg(target_os = "linux")]
fn notify_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .expect("tasks")
        .filter_map(|t| std::fs::read_to_string(t.ok()?.path().join("comm")).ok())
        .filter(|c| c.trim() == "voidwire-notify")
        .count()
}

#[cfg(target_os = "linux")]
#[test]
fn setting_and_clearing_twenty_times_leaves_no_notify_thread() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    wait_until("no notify thread before", || notify_threads() == 0);
    let p = phone();
    for _ in 0..20 {
        p.set_change_listener(Some(Arc::new(|| {})));
        p.set_change_listener(None);
    }
    wait_until("cycles leave none", || notify_threads() == 0);
    p.set_change_listener(Some(Arc::new(|| {})));
    wait_until("one while set", || notify_threads() == 1);
    drop(p);
    wait_until("none after the phone is dropped", || notify_threads() == 0);
}
