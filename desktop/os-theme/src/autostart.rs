//! "Start Voidwire when I sign in" (desktop Settings, off by default). The
//! entry starts the app with [`ARG`], so it opens in the tray with no
//! window. Nothing is cached: the switch shows whether the entry is really
//! there, so one removed by hand (or turned off in the OS's own list) reads
//! as off.
//!
//! - Windows: `HKCU\…\CurrentVersion\Run` value named after the app. Task
//!   Manager's Startup tab turns entries off in `StartupApproved\Run` (odd
//!   first byte); that reads as off, and turning the switch on clears it.
//! - macOS: `~/Library/LaunchAgents/<bundle id>.plist` (RunAtLoad).
//! - Linux: `$XDG_CONFIG_HOME/autostart/<name>.desktop` (XDG Autostart).
//!   AppImage: points at `$APPIMAGE`, not the temporary mount; deb: the
//!   installed binary. `TryExec` makes the session skip it once the app is
//!   uninstalled. `Hidden=true` or `X-GNOME-Autostart-enabled=false` (set by
//!   the desktop's startup-apps settings) read as off.

// Each OS uses only its own helpers; all of them are tested everywhere.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The command-line flag the sign-in entry passes: start in the tray, no
/// window. A second launch with it does nothing.
pub const ARG: &str = "--autostart";

/// Every file we write carries this line, so removal never takes a
/// same-named file the user made.
const MARK: &str = "Voidwire sign-in entry";

/// What the entry starts.
pub struct Entry<'a> {
    /// Product name ("Voidwire"): the Run value name and the entry's Name.
    pub name: &'a str,
    /// Bundle identifier: the macOS LaunchAgent label.
    pub id: &'a str,
    /// The program to start (see `native_host_exe_path`).
    pub exe: &'a Path,
}

/// The Linux autostart file name for `name` ("Voidwire" -> "voidwire.desktop").
pub(crate) fn linux_file_name(name: &str) -> String {
    let stem: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect::<String>()
        .to_ascii_lowercase();
    format!("{}.desktop", if stem.is_empty() { "app" } else { &stem })
}

/// A quoted argument for a desktop-entry `Exec=` line (Desktop Entry spec;
/// the key-file layer then needs each backslash doubled again).
pub(crate) fn exec_quote(s: &str) -> String {
    let mut q = String::from("\"");
    for c in s.chars() {
        match c {
            '"' | '`' | '$' | '\\' => {
                q.push_str(r"\\");
                q.push(c);
            }
            '%' => q.push_str("%%"),
            '\n' | '\r' => {}
            _ => q.push(c),
        }
    }
    q.push('"');
    q
}

/// A desktop-entry string value (`\s`-free escapes: backslash, newlines).
fn key_file_value(s: &str) -> String {
    s.replace('\\', r"\\").replace(['\n', '\r'], "")
}

pub(crate) fn render_linux(name: &str, exe: &Path) -> String {
    let exe = exe.to_string_lossy();
    format!(
        "# {MARK}. Turn it off in {name}'s settings.\n[Desktop Entry]\nType=Application\nName={}\nComment=Start in the tray when you sign in\nTryExec={}\nExec={} {ARG}\nIcon=voidwire\nTerminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n",
        key_file_value(name),
        key_file_value(&exe),
        exec_quote(&exe),
    )
}

/// Whether a desktop entry's text asks the session to start it.
pub(crate) fn linux_entry_enabled(text: &str) -> bool {
    let mut in_entry = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        if (k == "Hidden" && v.eq_ignore_ascii_case("true"))
            || (k == "X-GNOME-Autostart-enabled" && v.eq_ignore_ascii_case("false"))
        {
            return false;
        }
    }
    text.lines().any(|l| l.trim() == "[Desktop Entry]")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub(crate) fn render_mac(id: &str, exe: &Path) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<!-- {MARK}. Turn it off in the app's settings. -->\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>{}</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>{}</string>\n    <string>{ARG}</string>\n  </array>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>ProcessType</key>\n  <string>Interactive</string>\n</dict>\n</plist>\n",
        xml_escape(id),
        xml_escape(&exe.to_string_lossy()),
    )
}

/// Windows Run value data: the quoted program and [`ARG`].
pub(crate) fn render_windows(exe: &Path) -> String {
    format!("\"{}\" {ARG}", exe.display())
}

/// Windows `StartupApproved\Run` data: absent or an even first byte is on;
/// an odd first byte (Task Manager "Disabled") is off.
pub(crate) fn windows_approved(data: Option<&[u8]>) -> bool {
    data.and_then(|d| d.first()).is_none_or(|b| b & 1 == 0)
}

fn is_ours(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|s| s.lines().take(4).any(|l| l.contains(MARK)))
}

/// Write `body` to `path` (atomically, via a temporary file next to it).
fn write_file(path: &Path, body: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("voidwire-tmp");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path)
}

/// Turn a file entry on (write ours over whatever is there) or off (remove
/// ours; a same-named file we didn't write is left alone and reported).
fn set_file(path: &Path, body: Option<&str>) -> std::io::Result<()> {
    match body {
        Some(b) => write_file(path, b),
        None if !path.exists() => Ok(()),
        None if is_ours(path) => std::fs::remove_file(path),
        None => Err(std::io::Error::other(format!(
            "{} wasn't made by this app; remove it there.",
            path.display()
        ))),
    }
}

/// `$XDG_CONFIG_HOME`, else `~/.config`.
pub(crate) fn config_home() -> Option<PathBuf> {
    match std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
        Some(p) if p.is_absolute() => Some(p),
        _ => std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")),
    }
}

pub(crate) fn linux_path(config_home: &Path, name: &str) -> PathBuf {
    config_home.join("autostart").join(linux_file_name(name))
}

pub(crate) fn linux_is_enabled(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|t| linux_entry_enabled(&t))
}

pub(crate) fn linux_set(path: &Path, e: &Entry, on: bool) -> std::io::Result<()> {
    let body = on.then(|| render_linux(e.name, e.exe));
    set_file(path, body.as_deref())
}

/// Ours, on, and pointing somewhere else (the AppImage moved): rewrite it.
pub(crate) fn linux_refresh(path: &Path, e: &Entry) -> std::io::Result<()> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(());
    };
    let want = render_linux(e.name, e.exe);
    if is_ours(path) && linux_entry_enabled(&text) && text != want {
        write_file(path, &want)?;
    }
    Ok(())
}

pub(crate) fn mac_path(home: &Path, id: &str) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{id}.plist"))
}

pub(crate) fn mac_set(path: &Path, e: &Entry, on: bool) -> std::io::Result<()> {
    let body = on.then(|| render_mac(e.id, e.exe));
    set_file(path, body.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        // One fixed dir per test (test names are unique), emptied first.
        let d = std::env::temp_dir().join(format!("vw-autostart-test-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn entry(exe: &Path) -> Entry<'_> {
        Entry {
            name: "Voidwire",
            id: "app.voidwire.desktop",
            exe,
        }
    }

    #[test]
    fn linux_entry_points_at_the_appimage_and_starts_in_the_tray() {
        let t = render_linux("Voidwire", Path::new("/home/u/Apps/Voidwire 1.1.AppImage"));
        assert!(t.contains("\nExec=\"/home/u/Apps/Voidwire 1.1.AppImage\" --autostart\n"));
        assert!(t.contains("\nTryExec=/home/u/Apps/Voidwire 1.1.AppImage\n"));
        assert!(t.contains("\nType=Application\n"));
        assert!(!t.contains("/tmp/.mount"));
        assert!(linux_entry_enabled(&t));
        assert_eq!(linux_file_name("Voidwire"), "voidwire.desktop");
        let deb = render_linux("Voidwire", Path::new("/usr/bin/voidwire"));
        assert!(deb.contains("\nExec=\"/usr/bin/voidwire\" --autostart\n"));
    }

    #[test]
    fn linux_on_off_and_external_changes_read_back() {
        let d = tmp("linux");
        let exe = PathBuf::from("/usr/bin/voidwire");
        let e = entry(&exe);
        let p = linux_path(&d, e.name);
        assert!(!linux_is_enabled(&p), "off by default");
        linux_set(&p, &e, true).unwrap();
        assert!(linux_is_enabled(&p));
        assert_eq!(p, d.join("autostart/voidwire.desktop"));
        // Turned off in the desktop's startup-apps settings.
        let t = std::fs::read_to_string(&p).unwrap();
        std::fs::write(
            &p,
            t.replace(
                "X-GNOME-Autostart-enabled=true",
                "X-GNOME-Autostart-enabled=false",
            ),
        )
        .unwrap();
        assert!(!linux_is_enabled(&p));
        std::fs::write(&p, format!("{t}Hidden=true\n")).unwrap();
        assert!(!linux_is_enabled(&p));
        // On again rewrites it; removed by hand reads as off.
        linux_set(&p, &e, true).unwrap();
        assert!(linux_is_enabled(&p));
        std::fs::remove_file(&p).unwrap();
        assert!(!linux_is_enabled(&p));
        // Off removes ours.
        linux_set(&p, &e, true).unwrap();
        linux_set(&p, &e, false).unwrap();
        assert!(!p.exists());
        linux_set(&p, &e, false).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn linux_moved_appimage_is_followed_and_a_users_file_is_kept() {
        let d = tmp("refresh");
        let old = PathBuf::from("/home/u/Old/Voidwire.AppImage");
        let new = PathBuf::from("/home/u/Apps/Voidwire.AppImage");
        let p = linux_path(&d, "Voidwire");
        linux_set(&p, &entry(&old), true).unwrap();
        linux_refresh(&p, &entry(&new)).unwrap();
        assert!(std::fs::read_to_string(&p)
            .unwrap()
            .contains("\"/home/u/Apps/Voidwire.AppImage\""));
        // A same-named file the user made: shown as on, never removed.
        let mine = "[Desktop Entry]\nType=Application\nExec=voidwire\n";
        std::fs::write(&p, mine).unwrap();
        assert!(linux_is_enabled(&p));
        linux_refresh(&p, &entry(&new)).unwrap();
        assert!(linux_set(&p, &entry(&new), false).is_err());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), mine);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn mac_launch_agent_runs_the_app_at_load_in_the_tray() {
        let t = render_mac(
            "app.voidwire.desktop",
            Path::new("/Applications/Voidwire & Co.app/Contents/MacOS/voidwire"),
        );
        assert!(t.contains("<string>app.voidwire.desktop</string>"));
        assert!(t.contains("<string>/Applications/Voidwire &amp; Co.app/Contents/MacOS/voidwire</string>\n    <string>--autostart</string>"));
        assert!(t.contains("<key>RunAtLoad</key>\n  <true/>"));
        assert_eq!(
            mac_path(Path::new("/Users/u"), "app.voidwire.desktop"),
            PathBuf::from("/Users/u/Library/LaunchAgents/app.voidwire.desktop.plist")
        );
        let d = tmp("mac");
        let p = mac_path(&d, "app.voidwire.desktop");
        let exe = PathBuf::from("/Applications/Voidwire.app/Contents/MacOS/voidwire");
        mac_set(&p, &entry(&exe), true).unwrap();
        assert!(is_ours(&p));
        mac_set(&p, &entry(&exe), false).unwrap();
        assert!(!p.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn windows_run_value_and_task_manager_state() {
        assert_eq!(
            render_windows(Path::new(r"C:\Program Files\Voidwire\voidwire.exe")),
            r#""C:\Program Files\Voidwire\voidwire.exe" --autostart"#
        );
        assert!(windows_approved(None));
        assert!(windows_approved(Some(&[2, 0, 0, 0])));
        assert!(windows_approved(Some(&[6, 0])));
        assert!(!windows_approved(Some(&[3, 0, 0, 0])));
        assert!(!windows_approved(Some(&[7])));
    }
}
