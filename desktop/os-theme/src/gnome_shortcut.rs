//! GNOME without the GlobalShortcuts portal (GNOME 46 on Wayland): the app
//! can't grab keys there, so Settings offers "Add shortcut in GNOME
//! settings". That adds one custom keybinding, the same kind as Settings ›
//! Keyboard › Custom Shortcuts, running `<this app> --send-clipboard`:
//!
//! - `org.gnome.settings-daemon.plugins.media-keys custom-keybindings` gets
//!   our path appended; every other entry is kept as it is.
//! - `…media-keys.custom-keybinding:<PATH>` holds name, command, binding.
//!
//! Removing takes only our path out of the list and resets our three keys.
//! GSettings runs in process (gio); the schemas are looked up first, so a
//! desktop without them gets no button rather than a crash.

use gio::prelude::*;
use std::path::Path;

const SCHEMA: &str = "org.gnome.settings-daemon.plugins.media-keys";
const LIST_KEY: &str = "custom-keybindings";
const ENTRY_SCHEMA: &str = "org.gnome.settings-daemon.plugins.media-keys.custom-keybinding";
/// Our entry. Any path works for GNOME Settings, which lists and edits it
/// like the ones it made itself.
pub(crate) const PATH: &str =
    "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/voidwire-send-clipboard/";
const NAME: &str = "Voidwire: send clipboard";

/// The list with our path added at the end (once).
pub(crate) fn with_ours(mut paths: Vec<String>) -> Vec<String> {
    if !paths.iter().any(|p| p == PATH) {
        paths.push(PATH.to_owned());
    }
    paths
}

/// The list without our path (nothing else changes).
pub(crate) fn without_ours(paths: Vec<String>) -> Vec<String> {
    paths.into_iter().filter(|p| p != PATH).collect()
}

/// `Ctrl+Shift+Alt+V` -> `<Control><Shift><Alt>v` (GTK accelerator syntax).
pub(crate) fn binding(accel: &str) -> Option<String> {
    let xdg = crate::portal_shortcut::preferred_trigger(accel)?;
    let mut mods = String::new();
    let mut key = None;
    for t in xdg.split('+') {
        match t {
            "CTRL" => mods.push_str("<Control>"),
            "SHIFT" => mods.push_str("<Shift>"),
            "ALT" => mods.push_str("<Alt>"),
            "LOGO" => mods.push_str("<Super>"),
            k => key = Some(k.to_owned()),
        }
    }
    Some(format!("{mods}{}", key?))
}

/// The command GNOME runs (it splits it like a shell, no expansion).
pub(crate) fn command(exe: &Path) -> String {
    let exe = exe.to_string_lossy();
    format!("'{}' --send-clipboard", exe.replace('\'', r"'\''"))
}

fn has_schema(id: &str, key: &str) -> bool {
    gio::SettingsSchemaSource::default()
        .and_then(|src| src.lookup(id, true))
        .is_some_and(|schema| schema.has_key(key))
}

fn err(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

fn list_settings() -> gio::Settings {
    gio::Settings::new(SCHEMA)
}

fn entry_settings() -> gio::Settings {
    gio::Settings::with_path(ENTRY_SCHEMA, PATH)
}

fn read_list() -> Vec<String> {
    list_settings()
        .strv(LIST_KEY)
        .iter()
        .map(|p| p.as_str().to_owned())
        .collect()
}

fn write_list(paths: &[String]) -> std::io::Result<()> {
    let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    list_settings().set_strv(LIST_KEY, refs).map_err(err)
}

/// A GNOME session with both media-keys schemas (checked once).
pub(crate) fn available() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        let gnome = std::env::var("XDG_CURRENT_DESKTOP")
            .is_ok_and(|d| d.split(':').any(|p| p.eq_ignore_ascii_case("GNOME")));
        gnome && schemas_present()
    })
}

fn schemas_present() -> bool {
    has_schema(SCHEMA, LIST_KEY) && has_schema(ENTRY_SCHEMA, "binding")
}

/// Our entry's keys as the app shows them ("Ctrl+Shift+Alt+V"), if it is in
/// the list. Changed in GNOME Settings: shows what GNOME has.
pub(crate) fn status() -> Option<String> {
    if !schemas_present() || !read_list().iter().any(|p| p == PATH) {
        return None;
    }
    let b = entry_settings().string("binding");
    Some(if b.is_empty() {
        String::new()
    } else {
        crate::portal_shortcut::readable_trigger(&b)
    })
}

/// Add (or update) our entry with `accel`, running `exe --send-clipboard`.
pub(crate) fn add(accel: &str, exe: &Path) -> std::io::Result<String> {
    if !schemas_present() {
        return Err(err("GNOME's keyboard settings aren't installed."));
    }
    let b = binding(accel).ok_or_else(|| err(format!("GNOME can't use the keys {accel}.")))?;
    // The entry first, then the list: GNOME never sees a half-made one.
    let e = entry_settings();
    e.set_string("name", NAME).map_err(err)?;
    e.set_string("command", &command(exe)).map_err(err)?;
    e.set_string("binding", &b).map_err(err)?;
    write_list(&with_ours(read_list()))?;
    gio::Settings::sync();
    Ok(crate::portal_shortcut::readable_trigger(&b))
}

/// Take our entry out; other custom shortcuts stay.
pub(crate) fn remove() -> std::io::Result<()> {
    if !schemas_present() {
        return Ok(());
    }
    let list = read_list();
    if list.iter().any(|p| p == PATH) {
        write_list(&without_ours(list))?;
    }
    let e = entry_settings();
    for k in ["name", "command", "binding"] {
        e.reset(k);
    }
    gio::Settings::sync();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_edits_keep_other_shortcuts() {
        let theirs = vec![
            "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom0/".to_owned(),
            "/x/custom1/".to_owned(),
        ];
        let added = with_ours(theirs.clone());
        assert_eq!(added[..2], theirs[..]);
        assert_eq!(added[2], PATH);
        assert_eq!(with_ours(added.clone()), added, "added once");
        assert_eq!(without_ours(added), theirs);
        assert_eq!(with_ours(vec![]), vec![PATH.to_owned()]);
    }

    #[test]
    fn binding_and_command() {
        assert_eq!(
            binding("Ctrl+Shift+Alt+V").as_deref(),
            Some("<Control><Shift><Alt>v")
        );
        assert_eq!(
            binding("Ctrl+Shift+V").as_deref(),
            Some("<Control><Shift>v")
        );
        assert_eq!(binding("Super+F5").as_deref(), Some("<Super>F5"));
        assert_eq!(binding("Ctrl+Bogus"), None);
        assert_eq!(
            command(Path::new("/home/u/Apps/Voidwire.AppImage")),
            "'/home/u/Apps/Voidwire.AppImage' --send-clipboard"
        );
        assert_eq!(
            command(Path::new("/a/it's")),
            r"'/a/it'\''s' --send-clipboard"
        );
    }

    /// Real GSettings schemas, in-memory backend (nothing written to the
    /// user's dconf): `GSETTINGS_BACKEND=memory cargo test -p
    /// voidwire-os-theme gnome -- --ignored` (needs the gnome-settings-daemon
    /// schemas installed; CI linux-smoke installs them).
    #[test]
    #[ignore = "needs the GNOME media-keys GSettings schemas"]
    fn add_and_remove_against_gsettings() {
        // Never the user's real dconf: the memory backend or nothing.
        if std::env::var("GSETTINGS_BACKEND").as_deref() != Ok("memory") {
            eprintln!("skipped: run with GSETTINGS_BACKEND=memory");
            return;
        }
        assert!(schemas_present(), "media-keys schemas not installed");
        let theirs = vec![
            "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom0/".to_owned(),
        ];
        write_list(&theirs).unwrap();
        let shown = add("Ctrl+Shift+Alt+V", Path::new("/usr/bin/voidwire")).unwrap();
        assert_eq!(shown, "Ctrl+Shift+Alt+V");
        let l = read_list();
        assert_eq!(l.len(), 2);
        assert_eq!(l[1], PATH);
        assert_eq!(
            entry_settings().string("command").as_str(),
            "'/usr/bin/voidwire' --send-clipboard"
        );
        assert_eq!(
            entry_settings().string("binding").as_str(),
            "<Control><Shift><Alt>v"
        );
        assert_eq!(status().as_deref(), Some("Ctrl+Shift+Alt+V"));
        // Twice: still one entry.
        add("Ctrl+Shift+Alt+V", Path::new("/usr/bin/voidwire")).unwrap();
        assert_eq!(read_list().len(), 2);
        remove().unwrap();
        assert_eq!(read_list(), theirs);
        assert_eq!(status(), None);
        assert_eq!(entry_settings().string("binding").as_str(), "");
    }
}
