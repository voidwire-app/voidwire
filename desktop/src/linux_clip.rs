//! Linux: text Voidwire puts on the clipboard (pairing codes, received
//! clipboard items) carries `x-kde-passwordManagerHint: secret`, so Klipper
//! and the GNOME clipboard managers that honour it keep it out of their
//! history (M5.1; parity with the Windows monitor-exclusion marker).
//!
//! Reads (M5.1, L4): GNOME on Wayland only hands the clipboard to the focused
//! app. A shortcut or tray send with none of our windows focused shows a
//! small window for a moment, reads once it has focus, and closes it; the
//! read is held for that one send. Elsewhere the read works unfocused.

use std::path::PathBuf;
use std::sync::Mutex;

use gtk::prelude::*;
use tauri::AppHandle;

/// The target clipboard managers look for, and its value.
pub const SECRET_HINT_TARGET: &str = "x-kde-passwordManagerHint";
pub const SECRET_HINT_VALUE: &[u8] = b"secret";

/// The text targets offered alongside the hint (what `set_text` offers).
const TEXT_TARGETS: [(&str, u32); 5] = [
    ("UTF8_STRING", 0),
    ("text/plain;charset=utf-8", 1),
    ("text/plain", 2),
    ("STRING", 3),
    ("TEXT", 4),
];
const HINT_INFO: u32 = 5;

/// Own the clipboard with `text` plus the secret hint. Call on the GTK main
/// thread. `false` when GTK refused.
pub fn put_secret(cb: &gtk::Clipboard, text: &str) -> bool {
    use gtk::{TargetEntry, TargetFlags};
    let mut targets: Vec<TargetEntry> = TEXT_TARGETS
        .iter()
        .map(|(t, info)| TargetEntry::new(t, TargetFlags::empty(), *info))
        .collect();
    targets.push(TargetEntry::new(
        SECRET_HINT_TARGET,
        TargetFlags::empty(),
        HINT_INFO,
    ));
    let text = text.to_owned();
    cb.set_with_data(&targets, move |_, sd, info| {
        if info == HINT_INFO {
            sd.set(
                &gtk::gdk::Atom::intern(SECRET_HINT_TARGET),
                8,
                SECRET_HINT_VALUE,
            );
        } else {
            sd.set_text(&text);
        }
    })
}

/// The clipboard's file (a copied file in Files / Dolphin), if any. GTK
/// main thread.
pub fn read_file(cb: &gtk::Clipboard) -> Option<PathBuf> {
    for atom_name in ["x-special/gnome-copied-files", "text/uri-list"] {
        let atom = gtk::gdk::Atom::intern(atom_name);
        if let Some(sel) = cb.wait_for_contents(&atom) {
            if let Ok(s) = std::str::from_utf8(&sel.data()) {
                if let Some(p) = voidwire_os_theme::parse_clipboard_file_uri_list(s) {
                    if p.is_file() {
                        return Some(p);
                    }
                }
            }
        }
    }
    cb.wait_for_uris()
        .iter()
        .filter_map(|uri| voidwire_os_theme::parse_clipboard_file_uri_list(uri.as_str()))
        .find(|p| p.is_file())
}

/// The clipboard's text, if any. GTK main thread.
pub fn read_text(cb: &gtk::Clipboard) -> Option<String> {
    cb.wait_for_text().map(|s| s.to_string())
}

/// Runs `f` with the default clipboard on the GTK main thread and waits
/// (bounded) for its answer. Call off the main thread.
pub fn on_main<T: Send + 'static>(
    app: &AppHandle,
    f: impl FnOnce(&gtk::Clipboard) -> Option<T> + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    app.run_on_main_thread(move || {
        let v = gtk::gdk::Display::default()
            .and_then(|d| gtk::Clipboard::default(&d))
            .and_then(|cb| f(&cb));
        let _ = tx.send(v);
    })
    .ok()?;
    rx.recv_timeout(std::time::Duration::from_secs(2))
        .ok()
        .flatten()
}

/// GNOME on Wayland: the clipboard is only readable while focused (L4).
pub fn needs_focus() -> bool {
    voidwire_os_theme::wayland_session()
        && std::env::var("XDG_CURRENT_DESKTOP")
            .is_ok_and(|d| d.split(':').any(|p| p.eq_ignore_ascii_case("GNOME")))
}

/// What one send read while focused.
struct Held {
    file: Option<PathBuf>,
    text: Option<String>,
}
static HELD: Mutex<Option<Held>> = Mutex::new(None);

/// Keeps a focused read for one send; dropping it forgets the read.
pub struct HoldGuard(());
impl Drop for HoldGuard {
    fn drop(&mut self) {
        if let Ok(mut h) = HELD.lock() {
            *h = None;
        }
    }
}

/// The held read's file, while a send holds one.
pub fn held_file() -> Option<Option<PathBuf>> {
    HELD.lock().ok()?.as_ref().map(|h| h.file.clone())
}

/// The held read's text, while a send holds one.
pub fn held_text() -> Option<Option<String>> {
    HELD.lock().ok()?.as_ref().map(|h| h.text.clone())
}

thread_local! {
    static FLASH: std::cell::RefCell<Option<gtk::Window>> = const { std::cell::RefCell::new(None) };
}

/// For a shortcut or tray send: on GNOME Wayland with none of our windows
/// focused, show a small window, read file and text once it has focus,
/// close it, and hold the read until the guard drops. `None` (and nothing
/// shown) elsewhere. Call off the main thread.
pub fn hold_focused_read(app: &AppHandle) -> Option<HoldGuard> {
    if !needs_focus() {
        return None;
    }
    let token = voidwire_os_theme::take_shortcut_activation_token();
    let (tx, rx) = std::sync::mpsc::channel::<Option<Held>>();
    app.run_on_main_thread(move || {
        let ours_focused = gtk::Window::list_toplevels()
            .iter()
            .filter_map(|w| w.downcast_ref::<gtk::Window>())
            .any(|w| w.is_active());
        if ours_focused {
            let _ = tx.send(None);
            return;
        }
        let win = gtk::Window::new(gtk::WindowType::Toplevel);
        win.set_title("Voidwire");
        win.set_decorated(false);
        win.set_resizable(false);
        win.set_default_size(1, 1);
        win.set_skip_taskbar_hint(true);
        win.set_skip_pager_hint(true);
        if let Some(t) = token.as_deref() {
            win.set_startup_id(t);
        }
        let tx = std::cell::RefCell::new(Some(tx));
        win.connect_focus_in_event(move |w, _| {
            if let Some(tx) = tx.borrow_mut().take() {
                let w = w.clone();
                gtk::glib::idle_add_local_once(move || {
                    let held = gtk::Clipboard::default(&WidgetExt::display(&w)).map(|cb| Held {
                        file: read_file(&cb),
                        text: read_text(&cb).filter(|t| !t.is_empty()),
                    });
                    let _ = tx.send(held);
                    FLASH.with(|f| f.borrow_mut().take());
                    w.close();
                });
            }
            gtk::glib::Propagation::Proceed
        });
        win.present();
        FLASH.with(|f| *f.borrow_mut() = Some(win));
    })
    .ok()?;
    let held = match rx.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(h) => h?,
        Err(_) => {
            // Never got focus: close the window; the send reads unfocused.
            let _ = app.run_on_main_thread(|| {
                if let Some(w) = FLASH.with(|f| f.borrow_mut().take()) {
                    w.close();
                }
            });
            return None;
        }
    };
    *HELD.lock().ok()? = Some(held);
    Some(HoldGuard(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hint_has_its_own_info_id() {
        assert!(TEXT_TARGETS.iter().all(|(_, i)| *i != HINT_INFO));
        assert_eq!(SECRET_HINT_VALUE, b"secret");
    }

    #[test]
    fn a_held_read_lasts_until_the_guard_drops() {
        *HELD.lock().unwrap() = Some(Held {
            file: None,
            text: Some("x".into()),
        });
        let g = HoldGuard(());
        assert_eq!(held_text(), Some(Some("x".into())));
        assert_eq!(held_file(), Some(None));
        drop(g);
        assert_eq!(held_text(), None);
    }
}
