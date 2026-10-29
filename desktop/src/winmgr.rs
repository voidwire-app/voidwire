//! Window handling that is safe to call from tray/menu/network handlers
//! (M1.1, prevents nested WebView2 creation inside tray dispatch).
//!
//! * Handlers never build a window inline. `request` posts the work to the
//!   event loop from a helper thread, so it runs after the current tray or
//!   menu dispatch has returned (Tauri's `run_on_main_thread` runs inline
//!   when called on the main thread, which would nest WebView2's creation
//!   message pump inside the tray's window procedure).
//! * Create-once: a window that exists is shown; one being created is left
//!   alone (`Slots`), so a burst of clicks can't double-create a label.
//! * No unwrap/expect/panic anywhere on these paths.

use std::collections::HashSet;
use std::sync::Mutex;

/// What `show_window` should do for a label.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Begin {
    /// Not there: create it (call `Slots::end` afterwards).
    Create,
    /// Already there: show/focus it.
    ShowExisting,
    /// Being created right now (a re-entrant call): do nothing.
    AlreadyCreating,
}

/// Labels whose window is being created.
#[derive(Default, Debug)]
pub struct Slots {
    creating: HashSet<String>,
}

impl Slots {
    pub fn begin(&mut self, label: &str, exists: bool) -> Begin {
        if self.creating.contains(label) {
            Begin::AlreadyCreating
        } else if exists {
            Begin::ShowExisting
        } else {
            self.creating.insert(label.to_owned());
            Begin::Create
        }
    }

    pub fn end(&mut self, label: &str) {
        self.creating.remove(label);
    }
}

static SLOTS: std::sync::LazyLock<Mutex<Slots>> = std::sync::LazyLock::new(Mutex::default);

pub fn slots() -> std::sync::MutexGuard<'static, Slots> {
    SLOTS.lock().unwrap_or_else(|e| e.into_inner())
}

/// The tray menu's items (ids as registered in `main.rs`).
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MenuAction {
    ShowPair,
    ShowPair2,
    ShowDevices,
    ShowSettings,
    SendClipboardToPhone(Option<String>),
    SendFileToPhone(Option<String>),
    Quit,
}

pub fn menu_action(id: &str) -> Option<MenuAction> {
    if let Some(dev_id) = id.strip_prefix("send_clipboard:") {
        return Some(MenuAction::SendClipboardToPhone(
            (!dev_id.is_empty()).then(|| dev_id.to_owned()),
        ));
    }
    if let Some(dev_id) = id.strip_prefix("send_file:") {
        return Some(MenuAction::SendFileToPhone(
            (!dev_id.is_empty()).then(|| dev_id.to_owned()),
        ));
    }
    match id {
        "pair" => Some(MenuAction::ShowPair),
        "pair2" => Some(MenuAction::ShowPair2),
        "devices" => Some(MenuAction::ShowDevices),
        "settings" => Some(MenuAction::ShowSettings),
        "send_clipboard" => Some(MenuAction::SendClipboardToPhone(None)),
        "send_file" => Some(MenuAction::SendFileToPhone(None)),
        "quit" => Some(MenuAction::Quit),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_once_under_a_burst_and_reentrancy() {
        let mut s = Slots::default();
        assert_eq!(s.begin("pair", false), Begin::Create);
        // Re-entrant requests while WebView2 is still being created.
        for _ in 0..100 {
            assert_eq!(s.begin("pair", false), Begin::AlreadyCreating);
        }
        // Another window is independent.
        assert_eq!(s.begin("devices", false), Begin::Create);
        s.end("pair");
        assert_eq!(s.begin("pair", true), Begin::ShowExisting);
        // Destroyed (closed) windows are created again.
        assert_eq!(s.begin("pair", false), Begin::Create);
        s.end("pair");
        s.end("pair"); // double end is harmless
        s.end("devices");
    }

    #[test]
    fn tray_event_stress_never_double_creates() {
        // Simulated rapid left/right/double clicks and menu picks, with the
        // window shown/hidden/closed while events keep coming.
        let mut s = Slots::default();
        let mut exists = std::collections::HashMap::<&str, bool>::new();
        let mut creates = 0;
        let mut seed: u32 = 0x1234_5678;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        let mut in_flight: Vec<&str> = Vec::new();
        for _ in 0..100_000 {
            let label = if rnd() % 2 == 0 { "pair" } else { "devices" };
            match rnd() % 6 {
                // menu pick (left or right click opened the menu)
                0..=2 => match s.begin(label, *exists.get(label).unwrap_or(&false)) {
                    Begin::Create => {
                        creates += 1;
                        in_flight.push(label);
                    }
                    Begin::ShowExisting | Begin::AlreadyCreating => {}
                },
                // a creation finishes
                3 => {
                    if let Some(l) = in_flight.pop() {
                        assert!(!exists.get(l).unwrap_or(&false), "double create of {l}");
                        exists.insert(l, true);
                        s.end(l);
                    }
                }
                // user closes the window
                4 => {
                    if !in_flight.contains(&label) {
                        exists.insert(label, false);
                    }
                }
                // unknown menu ids / clicks that aren't menu picks do nothing
                _ => assert_eq!(menu_action("bogus"), None),
            }
        }
        assert!(creates > 0);
    }

    #[test]
    fn menu_ids() {
        assert_eq!(menu_action("pair"), Some(MenuAction::ShowPair));
        assert_eq!(menu_action("pair2"), Some(MenuAction::ShowPair2));
        assert_eq!(menu_action("devices"), Some(MenuAction::ShowDevices));
        assert_eq!(menu_action("settings"), Some(MenuAction::ShowSettings));
        assert_eq!(
            menu_action("send_clipboard"),
            Some(MenuAction::SendClipboardToPhone(None))
        );
        assert_eq!(
            menu_action("send_clipboard:abcd"),
            Some(MenuAction::SendClipboardToPhone(Some("abcd".to_owned())))
        );
        assert_eq!(
            menu_action("send_file"),
            Some(MenuAction::SendFileToPhone(None))
        );
        assert_eq!(
            menu_action("send_file:abcd"),
            Some(MenuAction::SendFileToPhone(Some("abcd".to_owned())))
        );
        assert_eq!(menu_action("quit"), Some(MenuAction::Quit));
        // The disabled status header does nothing.
        assert_eq!(menu_action("header"), None);
        assert_eq!(menu_action(""), None);
    }
}
