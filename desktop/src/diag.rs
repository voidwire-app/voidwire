//! Diagnostics (M1.1, privacy rule): OFF by default. While off, nothing is
//! written to disk: no `voidwire.log`, no crash file. Turning it on (Paired
//! devices window → "Diagnostics") creates the marker file `diagnostics.on`
//! in the data dir; turning it off deletes the marker, the log and every
//! crash file. Nothing is ever uploaded: these files stay on this PC until
//! the user sends one on purpose.
//!
//! Crash capture: a panic hook writes `crash-<unix ms>.txt` (message,
//! location, thread, backtrace; never a link) when diagnostics are on, keeps
//! the newest `MAX_CRASH_FILES`, then hands over to the default hook.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

pub const MARKER: &str = "diagnostics.on";
pub const LOG: &str = "voidwire.log";
pub const LOG_OLD: &str = "voidwire.log.old";
/// The in-app Theme setting (SPEC 2.6): absent = Dark (the default),
/// otherwise the file holds `system` or `light`. Not diagnostics, but it lives
/// here because this module owns the app's small settings files.
pub const THEME_FILE: &str = "theme";
/// M3.2: OS file manager right-click `"Send with Voidwire"` setting.
/// Absent = enabled (default, writes nothing to disk); present = disabled.
pub const CONTEXT_MENU_OFF_FILE: &str = "context-menu.off";

/// Whether the OS file manager `"Send with Voidwire"` context menu is enabled (`M3.2`).
pub fn context_menu_enabled() -> bool {
    dir().is_none_or(context_menu_enabled_in)
}

pub(crate) fn context_menu_enabled_in(d: &Path) -> bool {
    !d.join(CONTEXT_MENU_OFF_FILE).is_file()
}

/// Enable or disable the OS file manager `"Send with Voidwire"` context menu (`M3.2`).
pub fn set_context_menu_enabled(on: bool) -> std::io::Result<()> {
    let Some(d) = dir() else {
        return Err(std::io::Error::other("no data dir"));
    };
    set_context_menu_enabled_in(d, on)?;
    voidwire_os_theme::set_file_context_menu_enabled(on)
}

pub(crate) fn set_context_menu_enabled_in(d: &Path, on: bool) -> std::io::Result<()> {
    let f = d.join(CONTEXT_MENU_OFF_FILE);
    if on {
        match std::fs::remove_file(&f) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    } else {
        write_private(&f, b"")
    }
}

/// Theme setting: `None` = System, `Some(true)` = Light, `Some(false)` = Dark.
pub fn theme() -> Option<bool> {
    dir().and_then(theme_in)
}

pub(crate) fn theme_in(d: &Path) -> Option<bool> {
    match std::fs::read_to_string(d.join(THEME_FILE)) {
        Ok(s) if s.trim() == "light" => Some(true),
        Ok(s) if s.trim() == "system" => None,
        // Dark is the default: no file (or anything else) means dark.
        _ => Some(false),
    }
}

/// Store the Theme setting ("system" | "dark" | "light"). Dark, the
/// default, deletes the file.
pub fn set_theme(mode: &str) -> std::io::Result<()> {
    let Some(d) = dir() else {
        return Err(std::io::Error::other("no data dir"));
    };
    set_theme_in(d, mode)
}

pub(crate) fn set_theme_in(d: &Path, mode: &str) -> std::io::Result<()> {
    let f = d.join(THEME_FILE);
    match mode {
        "dark" => match std::fs::remove_file(&f) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
        "system" | "light" => write_private(&f, mode.as_bytes()),
        _ => Err(std::io::Error::other("unknown theme")),
    }
}
/// The send-clipboard hotkey's fixed device (M4.5): absent = ask each time
/// (the default), otherwise the file holds that device's hex id (no name).
pub const HOTKEY_DEVICE_FILE: &str = "hotkey-device";

/// The hotkey's fixed device id, if one is set.
pub fn hotkey_device() -> Option<String> {
    dir().and_then(hotkey_device_in)
}

pub(crate) fn hotkey_device_in(d: &Path) -> Option<String> {
    let s = std::fs::read_to_string(d.join(HOTKEY_DEVICE_FILE)).ok()?;
    let id = s.trim();
    (id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())).then(|| id.to_ascii_lowercase())
}

/// Set (Some hex id) or clear (None = ask each time) the hotkey's device.
pub fn set_hotkey_device(id: Option<&str>) -> std::io::Result<()> {
    let Some(d) = dir() else {
        return Err(std::io::Error::other("no data dir"));
    };
    set_hotkey_device_in(d, id)
}

pub(crate) fn set_hotkey_device_in(d: &Path, id: Option<&str>) -> std::io::Result<()> {
    let f = d.join(HOTKEY_DEVICE_FILE);
    match id.map(str::trim).filter(|s| !s.is_empty()) {
        None => match std::fs::remove_file(&f) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
        Some(id) if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) => {
            write_private(&f, id.to_ascii_lowercase().as_bytes())
        }
        Some(_) => Err(std::io::Error::other("bad device id")),
    }
}

const CRASH_PREFIX: &str = "crash-";
const MAX_CRASH_FILES: usize = 5;

static DIR: OnceLock<PathBuf> = OnceLock::new();
static ON: AtomicBool = AtomicBool::new(false);

/// Read the setting from `dir` (call once, at startup).
pub fn init(dir: &Path) {
    // M1.2: remove any leftover M1.1 open-notice marker file.
    let _ = std::fs::remove_file(dir.join("notify.off"));
    let _ = DIR.set(dir.to_path_buf());
    ON.store(dir.join(MARKER).is_file(), Ordering::SeqCst);
    voidwire_os_theme::sync_os_integrations(context_menu_enabled_in(dir));
}

pub fn enabled() -> bool {
    ON.load(Ordering::SeqCst)
}

pub fn dir() -> Option<&'static Path> {
    DIR.get().map(PathBuf::as_path)
}

/// The log file, only while diagnostics are on.
pub fn log_path() -> Option<PathBuf> {
    enabled().then(|| dir().map(|d| d.join(LOG))).flatten()
}

/// Turn diagnostics on or off. Off deletes everything they wrote.
pub fn set(on: bool) -> std::io::Result<()> {
    let Some(d) = dir() else {
        return Err(std::io::Error::other("no data dir"));
    };
    set_in(d, on)?;
    ON.store(on, Ordering::SeqCst);
    Ok(())
}

pub(crate) fn set_in(d: &Path, on: bool) -> std::io::Result<()> {
    if on {
        write_private(&d.join(MARKER), b"")?;
    } else {
        remove_all(d)?;
    }
    Ok(())
}

/// Delete the marker, the log and every crash file.
pub(crate) fn remove_all(d: &Path) -> std::io::Result<()> {
    for name in [MARKER, LOG, LOG_OLD] {
        match std::fs::remove_file(d.join(name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    for f in crash_files(d) {
        let _ = std::fs::remove_file(f);
    }
    Ok(())
}

fn crash_files(d: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(CRASH_PREFIX) && n.ends_with(".txt"))
        })
        .collect();
    v.sort();
    v
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    use std::io::Write;
    o.open(path)?.write_all(bytes)
}

/// The crash report text (pure; unit-tested).
pub(crate) fn crash_text(stamp_ms: u64, thread: &str, info: &str, backtrace: &str) -> String {
    format!(
        "{} crash report (diagnostics on; stays on this PC)\nversion: {}\nos: {}\nunix_ms: {stamp_ms}\nthread: {thread}\npanic: {info}\n\nbacktrace:\n{backtrace}\n",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
    )
}

/// Write a crash file into `d` (diagnostics on only) and prune old ones.
pub(crate) fn write_crash(d: &Path, stamp_ms: u64, text: &str) -> Option<PathBuf> {
    let path = d.join(format!("{CRASH_PREFIX}{stamp_ms}.txt"));
    write_private(&path, text.as_bytes()).ok()?;
    let files = crash_files(d);
    if files.len() > MAX_CRASH_FILES {
        for old in &files[..files.len() - MAX_CRASH_FILES] {
            let _ = std::fs::remove_file(old);
        }
    }
    Some(path)
}

/// Install the panic hook (once, first thing in `main`). With diagnostics
/// off it only defers to the default hook: no file.
pub fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if enabled() {
            if let Some(d) = dir() {
                let stamp = voidwire_core::time::Clock::now(&voidwire_core::time::SystemClock)
                    .wall
                    .0;
                let thread = std::thread::current()
                    .name()
                    .unwrap_or("unnamed")
                    .to_owned();
                let bt = std::backtrace::Backtrace::force_capture().to_string();
                let _ = write_crash(
                    d,
                    stamp,
                    &crash_text(stamp, &thread, &info.to_string(), &bt),
                );
            }
        }
        default(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("vw-diag-{}", rand_suffix()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rand_suffix() -> u64 {
        use std::hash::{BuildHasher, Hasher};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u8(0);
        h.finish()
    }

    #[test]
    fn off_means_no_files_and_turning_off_deletes_them() {
        let d = tmp();
        set_in(&d, true).unwrap();
        assert!(d.join(MARKER).is_file());
        std::fs::write(d.join(LOG), b"x").unwrap();
        std::fs::write(d.join(LOG_OLD), b"x").unwrap();
        write_crash(&d, 1, "boom").unwrap();
        set_in(&d, false).unwrap();
        let left: Vec<_> = std::fs::read_dir(&d).unwrap().flatten().collect();
        assert!(left.is_empty(), "{left:?}");
        // Off again (nothing there) is fine.
        set_in(&d, false).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn crash_files_are_bounded_and_carry_no_link() {
        let d = tmp();
        for i in 0..8 {
            write_crash(&d, 1000 + i, &crash_text(1000 + i, "main", "boom", "bt")).unwrap();
        }
        let files = crash_files(&d);
        assert_eq!(files.len(), MAX_CRASH_FILES);
        assert!(files[0].ends_with("crash-1003.txt"));
        let t = std::fs::read_to_string(&files[0]).unwrap();
        assert!(t.contains("panic: boom") && t.contains("thread: main"));
        assert!(!t.contains("http"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn hotkey_device_defaults_to_ask_and_ask_stores_nothing() {
        let d = std::env::temp_dir().join(format!("vw-hotkey-{}", rand_suffix()));
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(hotkey_device_in(&d), None, "default: ask each time");
        let id = "AB".repeat(32);
        set_hotkey_device_in(&d, Some(&id)).unwrap();
        assert_eq!(hotkey_device_in(&d), Some("ab".repeat(32)));
        assert!(set_hotkey_device_in(&d, Some("not-an-id")).is_err());
        assert_eq!(hotkey_device_in(&d), Some("ab".repeat(32)));
        set_hotkey_device_in(&d, None).unwrap();
        assert!(!d.join(HOTKEY_DEVICE_FILE).exists());
        set_hotkey_device_in(&d, Some("")).unwrap(); // empty = ask, idempotent
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn theme_setting_defaults_to_dark_and_dark_deletes_the_file() {
        let d = std::env::temp_dir().join(format!("vw-theme-{}", rand_suffix()));
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(theme_in(&d), Some(false), "default: Dark");
        set_theme_in(&d, "light").unwrap();
        assert_eq!(theme_in(&d), Some(true));
        set_theme_in(&d, "system").unwrap();
        assert_eq!(theme_in(&d), None);
        assert!(set_theme_in(&d, "purple").is_err());
        set_theme_in(&d, "dark").unwrap();
        assert_eq!(theme_in(&d), Some(false));
        assert!(!d.join(THEME_FILE).exists(), "Dark stores nothing");
        set_theme_in(&d, "dark").unwrap(); // idempotent
        std::fs::remove_dir_all(&d).unwrap();
    }
}
