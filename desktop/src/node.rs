//! Starts the core PC node with the app's data dir and wires its events to
//! windows. Data: `<app data dir>/state.bin` (DPAPI on Windows, 0600 on
//! Linux), `seen.bin` (fsync'd replay cache) and `instance.lock` (empty;
//! one running app per data dir). `VOIDWIRE_DATA_DIR` overrides the
//! directory (QA: two instances on one machine). Logs and crash files only
//! with Diagnostics on (`diag.rs`).

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use tauri::{AppHandle, Manager};
use voidwire_core::keys::valid_device_name;
use voidwire_core::net::pc::{PcConfig, PcEvent, PcNode};
use voidwire_core::net::state::FileStateStore;
use voidwire_core::opener::SystemOpener;
use voidwire_core::replay::StoreHealth;
use voidwire_core::time::{Clock, SystemClock};

use crate::CONFIRM_WINDOW;

/// The app's one node (one `Inbox` per process, R1).
static NODE: OnceLock<Result<Arc<PcNode>, String>> = OnceLock::new();

/// L4: `<data dir>/voidwire.log`, written ONLY while Diagnostics are on
/// (M1.1 privacy rule; off by default, no file at all when off). Never
/// contains a link (only reason labels and device names). Rotated to
/// `voidwire.log.old` at 256 KiB.
const LOG_MAX_BYTES: u64 = 256 * 1024;

/// Held for the life of the process: one running app per data dir.
static INSTANCE_LOCK: OnceLock<std::fs::File> = OnceLock::new();

/// Another copy of the app already runs on this data dir.
pub const ALREADY_RUNNING: &str = "already running";

/// Replay protection was restarted at startup (seen.bin missing/damaged).
static REPLAY_GUARD_AT_START: OnceLock<bool> = OnceLock::new();

/// Fallback in-memory clipboard buffer when no display server is attached.
static FALLBACK_CLIPBOARD: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Last phone card hovered or targeted by a drag operation in the Devices window.
static DROP_TARGET_PHONE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub fn set_drop_target_phone(id: Option<String>) {
    if let Ok(mut g) = DROP_TARGET_PHONE.lock() {
        *g = id.filter(|s| !s.trim().is_empty());
    }
}

pub fn get_drop_target_phone() -> Option<String> {
    DROP_TARGET_PHONE.lock().ok().and_then(|g| g.clone())
}

pub fn get_os_clipboard_file(app: &AppHandle) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let (tx, rx) = std::sync::mpsc::channel();
        if app
            .run_on_main_thread(move || {
                let mut found: Option<PathBuf> = None;
                if let Some(cb) =
                    gtk::gdk::Display::default().and_then(|d| gtk::Clipboard::default(&d))
                {
                    for atom_name in ["x-special/gnome-copied-files", "text/uri-list"] {
                        let atom = gtk::gdk::Atom::intern(atom_name);
                        if let Some(sel) = cb.wait_for_contents(&atom) {
                            if let Ok(s) = std::str::from_utf8(&sel.data()) {
                                if let Some(p) = voidwire_os_theme::parse_clipboard_file_uri_list(s)
                                {
                                    if p.is_file() {
                                        found = Some(p);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if found.is_none() {
                        for uri in cb.wait_for_uris() {
                            if let Some(p) =
                                voidwire_os_theme::parse_clipboard_file_uri_list(uri.as_str())
                            {
                                if p.is_file() {
                                    found = Some(p);
                                    break;
                                }
                            }
                        }
                    }
                }
                let _ = tx.send(found);
            })
            .is_ok()
        {
            if let Ok(Some(p)) = rx.recv_timeout(std::time::Duration::from_secs(2)) {
                return Some(p);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = app;
        if let Some(p) = voidwire_os_theme::get_clipboard_file() {
            return Some(p);
        }
    }
    None
}

/// Pending send error raised by a background tray or shortcut action so the
/// Devices window can open the relay confirmation / cap modal immediately.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PendingUiSendError {
    pub error: String,
    /// The device the failed send was for (M4.2: a PC or a phone).
    pub device_id: String,
    pub file_path: Option<String>,
    pub retry_text: Option<String>,
}

static PENDING_UI_SEND_ERROR: std::sync::Mutex<Option<PendingUiSendError>> =
    std::sync::Mutex::new(None);

pub fn set_pending_ui_send_error(err: PendingUiSendError) {
    if let Ok(mut g) = PENDING_UI_SEND_ERROR.lock() {
        *g = Some(err);
    }
}

pub fn take_pending_ui_send_error() -> Option<PendingUiSendError> {
    PENDING_UI_SEND_ERROR.lock().ok().and_then(|mut g| g.take())
}

pub fn sync_clipboard_hotkey(app: &AppHandle, enabled: bool, accel: &str) -> Result<(), String> {
    let h = app.clone();
    voidwire_os_theme::set_send_clipboard_hotkey_with_accel(
        enabled,
        accel,
        Arc::new(move || {
            let h2 = h.clone();
            let _ = tauri::async_runtime::spawn_blocking(move || {
                crate::ipc::hotkey_send_clipboard(&h2)
            });
        }),
    )
}

pub fn set_os_clipboard(app: &AppHandle, text: &str) {
    if let Ok(mut g) = FALLBACK_CLIPBOARD.lock() {
        *g = Some(text.to_owned());
    }
    #[cfg(target_os = "linux")]
    {
        let owned = text.to_owned();
        let _ = app.run_on_main_thread(move || {
            if let Some(display) = gtk::gdk::Display::default() {
                if let Some(cb) = gtk::Clipboard::default(&display) {
                    cb.set_text(&owned);
                }
            }
        });
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = app;
        let _ = voidwire_os_theme::set_clipboard_text(text);
    }
}

pub fn get_os_clipboard(app: &AppHandle) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let (tx, rx) = std::sync::mpsc::channel();
        if app
            .run_on_main_thread(move || {
                let val = gtk::gdk::Display::default()
                    .and_then(|d| gtk::Clipboard::default(&d))
                    .and_then(|cb| cb.wait_for_text())
                    .map(|s| s.to_string());
                let _ = tx.send(val);
            })
            .is_ok()
        {
            if let Ok(Some(s)) = rx.recv_timeout(std::time::Duration::from_secs(2)) {
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = app;
        if let Some(s) = voidwire_os_theme::get_clipboard_text() {
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    FALLBACK_CLIPBOARD.lock().ok().and_then(|g| g.clone())
}

pub fn log(msg: &str) {
    eprintln!("{msg}");
    let Some(path) = crate::diag::log_path() else {
        return;
    };
    let path = &path;
    if std::fs::metadata(path).is_ok_and(|m| m.len() > LOG_MAX_BYTES) {
        let _ = std::fs::rename(path, path.with_extension("log.old"));
    }
    let line = format!("{} {msg}\n", utc_stamp(SystemClock.now().wall.0));
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    if let Ok(mut f) = o.open(path) {
        use std::io::Write;
        let _ = f.write_all(line.as_bytes());
    }
}

/// `YYYY-MM-DD HH:MM:SSZ` from unix milliseconds (no date crate needed).
fn utc_stamp(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Howard Hinnant's civil_from_days.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

const ENV_PREFIX: &str = env!("VOIDWIRE_BRAND_ENV_PREFIX");

pub fn get(_app: &AppHandle) -> Option<Arc<PcNode>> {
    NODE.get().and_then(|r| r.as_ref().ok().cloned())
}

/// Why the node isn't running, if it isn't.
pub fn start_error() -> Option<String> {
    NODE.get().and_then(|r| r.as_ref().err().cloned())
}

/// A device name for our certificate: the computer name, if usable.
pub fn pc_name() -> String {
    let raw = std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_default();
    sanitize_name(&raw)
}

pub fn sanitize_name(raw: &str) -> String {
    let n: String = raw.trim().chars().take(40).collect();
    if valid_device_name(&n) {
        n
    } else {
        "My PC".to_owned()
    }
}

fn data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    if let Ok(d) = std::env::var(format!("{ENV_PREFIX}_DATA_DIR")) {
        if !d.is_empty() {
            return Ok(PathBuf::from(d));
        }
    }
    app.path()
        .app_data_dir()
        .map_err(|e| format!("no app data dir: {e}"))
}

pub fn start(app: &AppHandle) {
    let res = (|| {
        let dir = data_dir(app)?;
        // 0700 on Linux; a protected current-user (+SYSTEM) DACL on Windows.
        voidwire_core::net::state::private_dir(&dir)
            .map_err(|e| format!("create {}: {e}", dir.display()))?;
        crate::diag::init(&dir);
        // One app per data dir: a second launch must not run a second
        // inbox on the same state.bin/seen.bin.
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("instance.lock"))
            .map_err(|e| format!("instance lock: {e}"))?;
        match lock.try_lock() {
            Ok(()) => {
                let _ = INSTANCE_LOCK.set(lock);
            }
            Err(std::fs::TryLockError::WouldBlock) => return Err(ALREADY_RUNNING.to_owned()),
            Err(std::fs::TryLockError::Error(e)) => return Err(format!("instance lock: {e}")),
        }
        log("starting"); // not the data dir: its path names the OS user
        let mut cfg = PcConfig::new(
            pc_name(),
            Arc::new(FileStateStore::new(dir.join("state.bin"))),
            Arc::new(SystemOpener),
        );
        cfg.seen_store_path = Some(dir.join("seen.bin"));
        let dl_dir = app
            .path()
            .download_dir()
            .map(|d| d.join("Voidwire"))
            .unwrap_or_else(|_| dir.join("downloads"));
        cfg.download_dir = Some(dl_dir);
        cfg.auto_accept_files = false;
        let handle = app.clone();
        cfg.events = Some(Arc::new(move |e| on_event(&handle, e)));
        let node = PcNode::start(cfg).map_err(|e| {
            let e = e.to_string();
            if e.contains("replay cache") {
                // Recovery (docs/M1-TEST-SHEET.md, THREAT-MODEL.md): quit,
                // delete seen.bin in the data dir, start again.
                format!(
                    "{e}; to recover, quit and delete seen.bin in {}",
                    dir.display()
                )
            } else {
                e
            }
        })?;
        if let Some(h) = node.replay_cache_health() {
            let guard = !matches!(h, StoreHealth::Intact { .. } | StoreHealth::FirstRun);
            let _ = REPLAY_GUARD_AT_START.set(guard);
            if guard {
                log(&format!(
                    "replay cache {h:?}: replay protection restarted; for 20 minutes only links sent after startup are accepted (phones see 'replay_startup_guard')"
                ));
            }
        }
        let node = Arc::new(node);
        if let Err(e) = sync_clipboard_hotkey(
            app,
            node.send_clipboard_shortcut(),
            &node.send_clipboard_shortcut_accel(),
        ) {
            log(&format!("clipboard hotkey at startup: {e}"));
        }
        let sweep_node = node.clone();
        let sweep_app = app.clone();
        let _ = std::thread::Builder::new()
            .name("voidwire-stall-sweep".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let timed_out = sweep_node.sweep_stalled_transfers(SystemClock.now().wall);
                if !timed_out.is_empty() {
                    let h = sweep_app.clone();
                    let _ = sweep_app.run_on_main_thread(move || {
                        if let Some(n) = get(&h) {
                            if n.pending().is_empty()
                                && n.incoming_files().is_empty()
                                && n.pending_clipboards().is_empty()
                            {
                                if let Some(w) = h.get_webview_window(CONFIRM_WINDOW) {
                                    let _ = w.hide();
                                }
                            }
                        }
                    });
                }
            });
        Ok(node)
    })();
    let ok = res.is_ok();
    match &res {
        Ok(_) => log("network service started"),
        Err(e) => log(&format!("network service not started: {e}")),
    }
    let _ = NODE.set(res);
    if ok {
        crate::ipc::spawn_ipc_server(app.clone());
        if let Some(startup_file) = crate::ipc::take_startup_send_file() {
            let _ = crate::ipc::handle_send_file_in_app(app, startup_file, None);
        }
    }
}

pub fn shutdown(_app: &AppHandle) {
    // The endpoint closes when the process exits; nothing to flush (state
    // and the replay cache are written synchronously).
}

pub fn tooltip(app: &AppHandle, name: &str) -> String {
    match (get(app), start_error()) {
        (Some(n), _) if REPLAY_GUARD_AT_START.get() == Some(&true) => format!(
            "{name} – {} (replay protection restarted: older links refused for 20 min)",
            n.device_name()
        ),
        (Some(n), _) => format!("{name} – {}", n.device_name()),
        (None, Some(e)) => format!("{name} – not listening ({e})"),
        _ => name.to_owned(),
    }
}

/// The disabled first line of the tray menu (SPEC 2.1), e.g.
/// "Voidwire · WORKSTATION · listening".
pub fn menu_header(app: &AppHandle, name: &str) -> String {
    match get(app) {
        Some(n) => format!("{name} · {} · listening", n.device_name()),
        None => format!("{name} · not listening"),
    }
}

pub fn tray_send_labels_with_copied_file(
    device_names: &[String],
    copied_filename: Option<&str>,
) -> (String, String) {
    let clean_file = copied_filename.map(str::trim).filter(|s| !s.is_empty());
    if device_names.len() == 1 {
        let phone = &device_names[0];
        let clip = match clean_file {
            Some(fname) => format!("Send copied file ({fname}) to {phone}"),
            None => format!("Send clipboard to {phone}"),
        };
        (clip, format!("Choose file to send to {phone}…"))
    } else {
        let clip = match clean_file {
            Some(fname) => format!("Send copied file ({fname}) to your device"),
            None => "Send clipboard to your device".to_owned(),
        };
        (clip, "Choose file to send to your device…".to_owned())
    }
}

#[cfg(test)]
pub fn tray_send_labels(device_names: &[String]) -> (String, String) {
    tray_send_labels_with_copied_file(device_names, None)
}

pub fn menu_send_labels(app: &AppHandle) -> (String, String) {
    let names: Vec<String> = get(app)
        .map(|n| n.devices().into_iter().map(|d| d.name).collect())
        .unwrap_or_default();
    let copied = get_os_clipboard_file(app)
        .and_then(|p| p.file_name().and_then(|s| s.to_str()).map(|s| s.to_owned()));
    tray_send_labels_with_copied_file(&names, copied.as_deref())
}

pub fn confirm_window_title(app: &AppHandle) -> String {
    let name = app.package_info().name.clone();
    let Some(n) = get(app) else {
        return format!("{name} – Open link?");
    };
    if !n.pending().is_empty() {
        format!("{name} – Open link?")
    } else if !n.pending_clipboards().is_empty() {
        format!("{name} – Incoming clipboard")
    } else if !n.incoming_files().is_empty() {
        format!("{name} – Incoming file")
    } else {
        format!("{name} – Open link?")
    }
}

fn on_event(app: &AppHandle, e: PcEvent) {
    match e {
        PcEvent::PendingOpen { .. }
        | PcEvent::FileOfferPending { .. }
        | PcEvent::ClipboardPending { .. } => {
            crate::request_window(app, CONFIRM_WINDOW);
        }
        PcEvent::ClipboardAutoCopied { text, .. } => {
            set_os_clipboard(app, &text);
        }
        PcEvent::FileCompleted { .. } | PcEvent::FileCancelled { .. } => {
            let h = app.clone();
            let _ = app.run_on_main_thread(move || {
                if let Some(n) = get(&h) {
                    if n.pending().is_empty()
                        && n.incoming_files().is_empty()
                        && n.pending_clipboards().is_empty()
                    {
                        if let Some(w) = h.get_webview_window(CONFIRM_WINDOW) {
                            let _ = w.hide();
                        }
                    }
                }
                if let Some(w) = h.get_webview_window(crate::DEVICES_WINDOW) {
                    let _ = w.eval(
                        "if(typeof window.vwCheckPendingSendError==='function')window.vwCheckPendingSendError();",
                    );
                }
            });
        }
        // Privacy: the reason only, never the device name.
        PcEvent::Rejected { reason, .. } => {
            log(&format!("refused a link: {}", reason.label()));
        }
        PcEvent::PairingChanged | PcEvent::DevicesChanged => crate::refresh_tray(app),
        PcEvent::RelayChangeChanged => {
            // A paired device asks to move a pairing: show the Devices
            // window, which asks the user (no toast, no notification).
            if get(app).is_some_and(|n| !n.relay_change_requests().is_empty()) {
                crate::request_window(app, crate::DEVICES_WINDOW);
            }
            if let Some(w) = app.get_webview_window(crate::DEVICES_WINDOW) {
                let _ =
                    w.eval("if(typeof window.vwRelayChanges==='function')window.vwRelayChanges();");
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_names_are_sanitized() {
        assert_eq!(sanitize_name("  DESKTOP-ABC123\n"), "DESKTOP-ABC123");
        assert_eq!(sanitize_name(""), "My PC");
        assert_eq!(sanitize_name("bad\u{202e}name"), "My PC");
        assert_eq!(sanitize_name(&"x".repeat(100)).len(), 40);
    }

    #[test]
    fn tray_send_labels_name_single_paired_phone_and_fallback_otherwise() {
        assert_eq!(
            tray_send_labels(&[]),
            (
                "Send clipboard to your device".to_owned(),
                "Choose file to send to your device…".to_owned()
            )
        );
        assert_eq!(
            tray_send_labels(&["Pixel 9".to_owned()]),
            (
                "Send clipboard to Pixel 9".to_owned(),
                "Choose file to send to Pixel 9…".to_owned()
            )
        );
        assert_eq!(
            tray_send_labels_with_copied_file(&["Pixel 9".to_owned()], Some("report.pdf")),
            (
                "Send copied file (report.pdf) to Pixel 9".to_owned(),
                "Choose file to send to Pixel 9…".to_owned()
            )
        );
        assert_eq!(
            tray_send_labels(&["Pixel 9".to_owned(), "Galaxy S25".to_owned()]),
            (
                "Send clipboard to your device".to_owned(),
                "Choose file to send to your device…".to_owned()
            )
        );
    }

    #[test]
    fn log_stamps_are_utc_dates() {
        assert_eq!(utc_stamp(0), "1970-01-01 00:00:00Z");
        assert_eq!(utc_stamp(951_782_400_000), "2000-02-29 00:00:00Z");
        assert_eq!(utc_stamp(1_791_644_399_000), "2026-10-10 14:59:59Z");
    }
}
