//! Linux: the "may take focus" proof a desktop hands to a launched app
//! (xdg-activation token on Wayland, startup id on X11).
//!
//! Wayland lets a window come to the front only with a token from the
//! desktop. A KDE command shortcut and a desktop-file launch put one in the
//! new process's environment (`XDG_ACTIVATION_TOKEN`, `DESKTOP_STARTUP_ID`);
//! the portal shortcut's `Activated` carries one. A second launch hands it
//! to the running copy (single-instance argv, [`ARG_PREFIX`]), which keeps
//! it here for the window it shows next. GNOME custom shortcuts and tray
//! menu items give none.

use std::sync::Mutex;

/// The argument a second launch adds for the running copy.
pub const ARG_PREFIX: &str = "--activation-token=";
/// Each raise takes it out; a stale one is only refused by the compositor.
static SLOT: Mutex<Option<String>> = Mutex::new(None);

/// Tokens are short opaque ASCII strings; anything else is ignored.
pub(crate) fn valid(t: &str) -> bool {
    !t.is_empty() && t.len() <= 256 && t.bytes().all(|b| b.is_ascii_graphic())
}

/// Keep `t` for the next window shown (replaces an older one).
pub fn put(t: &str) {
    if valid(t) {
        *SLOT.lock().unwrap_or_else(|e| e.into_inner()) = Some(t.to_owned());
    }
}

/// The kept token, once.
pub fn take() -> Option<String> {
    SLOT.lock().unwrap_or_else(|e| e.into_inner()).take()
}

/// The token this process was started with, if any.
pub fn from_env() -> Option<String> {
    ["XDG_ACTIVATION_TOKEN", "DESKTOP_STARTUP_ID"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .find(|t| valid(t))
}

/// `argv` without our token argument, and the token it carried.
pub fn strip_arg(argv: Vec<String>) -> (Vec<String>, Option<String>) {
    let mut token = None;
    let rest = argv
        .into_iter()
        .filter(|a| match a.strip_prefix(ARG_PREFIX) {
            Some(t) => {
                if valid(t) {
                    token = Some(t.to_owned());
                }
                false
            }
            None => true,
        })
        .collect();
    (rest, token)
}

/// The single-instance plugin's D-Bus object path for `name`.
pub(crate) fn bus_path(name: &str) -> String {
    format!("/{}", name.replace('.', "/").replace('-', "_"))
}

/// Before Tauri starts: hand `argv` plus `token` to a running copy over the
/// single-instance plugin's D-Bus method (the plugin itself forwards argv
/// only, and the token lives in the environment). `false`: no running copy
/// answered; start normally (GTK then uses the token for the first window).
pub fn hand_over(identifier: &str, argv: &[String], token: &str) -> bool {
    let Ok(conn) = zbus::blocking::Connection::session() else {
        return false;
    };
    let name = format!("{identifier}.SingleInstance");
    let mut args: Vec<String> = argv.to_vec();
    args.push(format!("{ARG_PREFIX}{token}"));
    let cwd = std::env::current_dir().unwrap_or_default();
    conn.call_method(
        Some(name.as_str()),
        bus_path(&name).as_str(),
        Some("org.SingleInstance.DBus"),
        "ExecuteCallback",
        &(args, cwd.to_string_lossy().as_ref()),
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_arg_is_taken_out_of_argv() {
        let (rest, t) = strip_arg(vec![
            "voidwire".into(),
            "--send-clipboard".into(),
            "--activation-token=kwin-42_x".into(),
        ]);
        assert_eq!(
            rest,
            vec!["voidwire".to_owned(), "--send-clipboard".to_owned()]
        );
        assert_eq!(t.as_deref(), Some("kwin-42_x"));
        let (rest, t) = strip_arg(vec!["voidwire".into(), "--activation-token=a b".into()]);
        assert_eq!(
            rest,
            vec!["voidwire".to_owned()],
            "a bad token is still removed"
        );
        assert_eq!(t, None);
        let (rest, t) = strip_arg(vec!["voidwire".into()]);
        assert_eq!((rest.len(), t), (1, None));
    }

    #[test]
    fn slot_gives_a_token_once() {
        put("tok-1");
        assert_eq!(take().as_deref(), Some("tok-1"));
        assert_eq!(take(), None);
        put("");
        assert_eq!(take(), None);
    }

    #[test]
    fn plugin_object_path() {
        assert_eq!(
            bus_path("app.voidwire.desktop.SingleInstance"),
            "/app/voidwire/desktop/SingleInstance"
        );
        assert_eq!(bus_path("a.b-c.SingleInstance"), "/a/b_c/SingleInstance");
    }
}
