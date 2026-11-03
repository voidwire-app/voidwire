//! KDE Plasma on Wayland where the GlobalShortcuts portal doesn't bind
//! (Plasma before 6.5, see `portal_shortcut::portal_binds`): Settings offers
//! "Add shortcut in KDE settings". That adds one command shortcut, the same
//! kind as System Settings › Shortcuts › Add New › Command:
//!
//! - `~/.local/share/applications/voidwire-send-clipboard.desktop`, hidden
//!   from menus, running `<this app> --send-clipboard`.
//! - kglobalaccel (session D-Bus `org.kde.kglobalaccel`) is asked to read
//!   that file and given the keys. It keeps them over sign-ins and, on a
//!   press, starts the command with an activation token, which the app
//!   passes to the running copy so its window may come to the front.
//!
//! Removing takes the keys and the file away; other shortcuts stay.

use std::path::{Path, PathBuf};

use zbus::blocking::Connection;

/// The desktop file and kglobalaccel component name (".desktop" makes
/// kglobalaccel treat it as a command shortcut).
pub(crate) const FILE: &str = "voidwire-send-clipboard.desktop";
const NAME: &str = "Voidwire: send clipboard";
/// kglobalaccel's action for a command shortcut's main command.
const LAUNCH: &str = "_launch";
/// Every file we write carries this line; another file is never touched.
const MARK: &str = "Voidwire send-clipboard shortcut";

const DEST: &str = "org.kde.kglobalaccel";
const PATH: &str = "/kglobalaccel";
const IFACE: &str = "org.kde.KGlobalAccel";
/// `setShortcut` flag: set exactly these keys (not the saved ones).
const NO_AUTOLOADING: u32 = 4;

// Qt key codes (Qt::KeyboardModifier and Qt::Key).
const QT_SHIFT: i32 = 0x0200_0000;
const QT_CTRL: i32 = 0x0400_0000;
const QT_ALT: i32 = 0x0800_0000;
const QT_META: i32 = 0x1000_0000;
const QT_MODS: i32 = QT_SHIFT | QT_CTRL | QT_ALT | QT_META;

/// Named keys: our accel name, Qt's portable text, Qt key code.
const NAMED: &[(&str, &str, i32)] = &[
    ("space", "Space", 0x20),
    ("tab", "Tab", 0x0100_0001),
    ("backspace", "Backspace", 0x0100_0003),
    ("enter", "Return", 0x0100_0004),
    ("return", "Return", 0x0100_0004),
    ("insert", "Ins", 0x0100_0006),
    ("delete", "Del", 0x0100_0007),
    ("home", "Home", 0x0100_0010),
    ("end", "End", 0x0100_0011),
    ("left", "Left", 0x0100_0012),
    ("up", "Up", 0x0100_0013),
    ("right", "Right", 0x0100_0014),
    ("down", "Down", 0x0100_0015),
    ("pageup", "PgUp", 0x0100_0016),
    ("pagedown", "PgDown", 0x0100_0017),
];

/// The app's names for named keys, as shown ("Ctrl+PageDown").
const SHOWN: &[(i32, &str)] = &[
    (0x20, "Space"),
    (0x0100_0001, "Tab"),
    (0x0100_0003, "Backspace"),
    (0x0100_0004, "Enter"),
    (0x0100_0006, "Insert"),
    (0x0100_0007, "Delete"),
    (0x0100_0010, "Home"),
    (0x0100_0011, "End"),
    (0x0100_0012, "Left"),
    (0x0100_0013, "Up"),
    (0x0100_0014, "Right"),
    (0x0100_0015, "Down"),
    (0x0100_0016, "PageUp"),
    (0x0100_0017, "PageDown"),
];

/// `Ctrl+Shift+Alt+V` -> (Qt key code, Qt portable text "Ctrl+Alt+Shift+V").
pub(crate) fn qt_key(accel: &str) -> Option<(i32, String)> {
    let (mut mods, mut key) = (0i32, None::<(i32, String)>);
    for tok in accel.split('+').map(str::trim).filter(|t| !t.is_empty()) {
        let low = tok.to_ascii_lowercase();
        match low.as_str() {
            "ctrl" | "control" => mods |= QT_CTRL,
            "alt" => mods |= QT_ALT,
            "shift" => mods |= QT_SHIFT,
            "win" | "super" | "meta" => mods |= QT_META,
            _ if key.is_some() => return None,
            k if k.len() == 1 && k.is_ascii() => {
                let c = k.as_bytes()[0].to_ascii_uppercase();
                if !(c.is_ascii_alphanumeric() || b";=,-./`[\\]'".contains(&c)) {
                    return None;
                }
                key = Some((i32::from(c), (c as char).to_string()));
            }
            k if k.len() >= 2 && k.starts_with('f') => {
                let n: i32 = k[1..].parse().ok().filter(|n| (1..=24).contains(n))?;
                key = Some((0x0100_0030 + n - 1, format!("F{n}")));
            }
            k => {
                let (_, text, code) = NAMED.iter().find(|(n, _, _)| *n == k)?;
                key = Some((*code, (*text).to_owned()));
            }
        }
    }
    let (code, text) = key?;
    let mut parts: Vec<&str> = Vec::new();
    for (bit, name) in [
        (QT_CTRL, "Ctrl"),
        (QT_ALT, "Alt"),
        (QT_SHIFT, "Shift"),
        (QT_META, "Meta"),
    ] {
        if mods & bit != 0 {
            parts.push(name);
        }
    }
    parts.push(&text);
    Some((mods | code, parts.join("+")))
}

/// A Qt key code the way the app shows keys ("Ctrl+Shift+Alt+V").
pub(crate) fn shown(code: i32) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (bit, name) in [
        (QT_CTRL, "Ctrl"),
        (QT_SHIFT, "Shift"),
        (QT_ALT, "Alt"),
        (QT_META, "Super"),
    ] {
        if code & bit != 0 {
            parts.push(name.to_owned());
        }
    }
    let k = code & !QT_MODS;
    let key = if let Some((_, n)) = SHOWN.iter().find(|(c, _)| *c == k) {
        (*n).to_owned()
    } else if (0x0100_0030..0x0100_0030 + 24).contains(&k) {
        format!("F{}", k - 0x0100_0030 + 1)
    } else if (0x21..0x7f).contains(&k) {
        ((k as u8) as char).to_string()
    } else {
        format!("key {k:#x}")
    };
    parts.push(key);
    parts.join("+")
}

/// The command shortcut's desktop file.
pub(crate) fn render(exe: &Path, keys_text: &str) -> String {
    let exe = crate::autostart::exec_quote(&exe.to_string_lossy());
    format!(
        "# {MARK}. Remove it in Voidwire's settings.\n[Desktop Entry]\nType=Application\nName={NAME}\nExec={exe} --send-clipboard\nIcon=voidwire\nNoDisplay=true\nX-KDE-GlobalAccel-CommandShortcut=true\nX-KDE-Shortcuts={keys_text}\n"
    )
}

/// The `Exec=` value of a desktop file's text.
fn exec_of(text: &str) -> Option<&str> {
    text.lines().find_map(|l| l.trim().strip_prefix("Exec="))
}

fn err(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// `$XDG_DATA_HOME/applications`, else `~/.local/share/applications`.
fn apps_dir() -> Option<PathBuf> {
    let data = match std::env::var_os("XDG_DATA_HOME").map(PathBuf::from) {
        Some(p) if p.is_absolute() => p,
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".local/share"),
    };
    Some(data.join("applications"))
}

fn file_path() -> Option<PathBuf> {
    apps_dir().map(|d| d.join(FILE))
}

fn ours(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .filter(|t| t.lines().take(3).any(|l| l.contains(MARK)))
}

fn action_id() -> [&'static str; 4] {
    [FILE, LAUNCH, NAME, NAME]
}

fn bus() -> std::io::Result<Connection> {
    Connection::session().map_err(|_| err("No session bus."))
}

fn call<B>(conn: &Connection, method: &str, body: &B) -> std::io::Result<zbus::message::Message>
where
    B: zbus::export::serde::Serialize + zbus::zvariant::DynamicType,
{
    conn.call_method(Some(DEST), PATH, Some(IFACE), method, body)
        .map_err(|e| match e {
            zbus::Error::MethodError(name, m, _) => err(format!(
                "KDE's shortcut service said {name}{}",
                m.map(|m| format!(": {m}")).unwrap_or_default()
            )),
            e => err(format!("KDE's shortcut service didn't answer ({e})")),
        })
}

/// KDE Plasma with kglobalaccel on the session bus (checked once).
pub(crate) fn available() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        crate::portal_shortcut::kde_desktop()
            && Connection::session().is_ok_and(|c| {
                c.call_method(
                    Some("org.freedesktop.DBus"),
                    "/org/freedesktop/DBus",
                    Some("org.freedesktop.DBus"),
                    "NameHasOwner",
                    &(DEST,),
                )
                .and_then(|m| m.body().deserialize::<bool>())
                .unwrap_or(false)
            })
    })
}

/// kglobalaccel reads the desktop file when a component of that name is
/// first registered (what System Settings does after "Add New › Command").
fn load_component(conn: &Connection) -> std::io::Result<()> {
    let probe = [FILE, "", NAME, ""];
    call(conn, "doRegister", &(probe.as_slice(),))?;
    call(conn, "unRegister", &(probe.as_slice(),))?;
    Ok(())
}

fn keys_now(conn: &Connection) -> std::io::Result<Vec<i32>> {
    call(conn, "shortcut", &(action_id().as_slice(),))?
        .body()
        .deserialize::<Vec<i32>>()
        .map_err(err)
}

/// Our shortcut's keys as the app shows them, if it was added. Changed in
/// System Settings: shows what KDE has.
pub(crate) fn status() -> Option<String> {
    ours(&file_path()?)?;
    let keys = bus().and_then(|c| keys_now(&c)).unwrap_or_default();
    Some(
        keys.iter()
            .find(|k| **k != 0)
            .map(|k| shown(*k))
            .unwrap_or_default(),
    )
}

fn bind(conn: &Connection, code: i32, accel: &str) -> std::io::Result<String> {
    load_component(conn)?;
    let set: Vec<i32> = call(
        conn,
        "setShortcut",
        &(action_id().as_slice(), vec![code], NO_AUTOLOADING),
    )?
    .body()
    .deserialize()
    .map_err(err)?;
    if !set.contains(&code) {
        return Err(err(format!(
            "KDE didn't take {accel}: another shortcut uses those keys. Pick other keys above, or set them in System Settings › Shortcuts."
        )));
    }
    Ok(shown(code))
}

/// Add (or update) our command shortcut with `accel`, running `exe
/// --send-clipboard`. Returns the keys KDE took.
pub(crate) fn add(accel: &str, exe: &Path) -> std::io::Result<String> {
    let (code, text) =
        qt_key(accel).ok_or_else(|| err(format!("KDE can't use the keys {accel}.")))?;
    let path = file_path().ok_or_else(|| err("No home folder."))?;
    if path.exists() && ours(&path).is_none() {
        return Err(err(format!("{} wasn't made by this app.", path.display())));
    }
    let conn = bus()?;
    write(&path, &render(exe, &text))?;
    bind(&conn, code, accel).inspect_err(|_| {
        let _ = std::fs::remove_file(&path);
    })
}

fn write(path: &Path, body: &str) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("voidwire-tmp");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path)
}

/// Take our shortcut out; other shortcuts stay.
pub(crate) fn remove() -> std::io::Result<()> {
    let Some(path) = file_path() else {
        return Ok(());
    };
    if ours(&path).is_none() {
        return Ok(());
    }
    if let Ok(conn) = bus() {
        let _ = call(
            &conn,
            "setShortcut",
            &(action_id().as_slice(), Vec::<i32>::new(), NO_AUTOLOADING),
        );
        let _ = call(&conn, "unregister", &(FILE, LAUNCH));
    }
    std::fs::remove_file(&path)
}

/// At start: our shortcut follows the app when it moved (AppImage renamed
/// by an update). KDE reads the new command at the next sign-in at the
/// latest.
pub(crate) fn refresh(exe: &Path) {
    let Some(path) = file_path() else { return };
    let Some(text) = ours(&path) else { return };
    let want = render(exe, "");
    if exec_of(&text) == exec_of(&want) {
        return;
    }
    let keys_text = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("X-KDE-Shortcuts="))
        .unwrap_or("")
        .to_owned();
    let _ = write(&path, &render(exe, &keys_text));
    if let (Ok(conn), Some((code, _))) = (bus(), qt_key(&keys_text)) {
        let _ = bind(&conn, code, &keys_text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accel_becomes_qt_keys() {
        assert_eq!(
            qt_key("Ctrl+Shift+Alt+V"),
            Some((0x0E00_0056, "Ctrl+Alt+Shift+V".to_owned()))
        );
        assert_eq!(
            qt_key("Super+F5"),
            Some((0x1100_0034, "Meta+F5".to_owned()))
        );
        assert_eq!(
            qt_key("Ctrl+PageDown"),
            Some((0x0500_0017, "Ctrl+PgDown".to_owned()))
        );
        assert_eq!(qt_key("Alt+;"), Some((0x0800_003b, "Alt+;".to_owned())));
        assert_eq!(qt_key("Ctrl+1"), Some((0x0400_0031, "Ctrl+1".to_owned())));
        assert_eq!(qt_key("Ctrl+Bogus"), None);
        assert_eq!(qt_key("Ctrl+A+B"), None);
        assert_eq!(qt_key("Ctrl+Shift"), None);
    }

    #[test]
    fn qt_keys_read_like_the_app() {
        assert_eq!(shown(0x0E00_0056), "Ctrl+Shift+Alt+V");
        assert_eq!(shown(0x1100_0034), "Super+F5");
        assert_eq!(shown(0x0500_0017), "Ctrl+PageDown");
        for a in [
            "Ctrl+Shift+Alt+V",
            "Alt+Space",
            "Ctrl+Delete",
            "Super+F12",
            "Ctrl+/",
        ] {
            assert_eq!(shown(qt_key(a).unwrap().0), a, "round trip {a}");
        }
    }

    #[test]
    fn desktop_file() {
        let t = render(
            Path::new("/home/u/Apps/Voidwire_1.1_amd64.AppImage"),
            "Ctrl+Alt+Shift+V",
        );
        assert!(t.starts_with(&format!("# {MARK}.")));
        assert!(
            t.contains("\nExec=\"/home/u/Apps/Voidwire_1.1_amd64.AppImage\" --send-clipboard\n")
        );
        assert!(t.contains("\nX-KDE-Shortcuts=Ctrl+Alt+Shift+V\n"));
        assert!(t.contains("\nNoDisplay=true\n"));
        assert_eq!(
            exec_of(&t),
            Some("\"/home/u/Apps/Voidwire_1.1_amd64.AppImage\" --send-clipboard")
        );
    }
}
