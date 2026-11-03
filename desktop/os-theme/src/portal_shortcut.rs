//! Linux Wayland: the global send-clipboard shortcut through the desktop's
//! GlobalShortcuts portal (M5.1, L3). Apps can't grab keys on Wayland; the
//! portal shows the system's own dialog, the user confirms (or picks other
//! keys there), and the desktop sends `Activated` when the keys are pressed.
//!
//! zbus (pure Rust, already in the build through the single-instance plugin)
//! talks to `org.freedesktop.portal.Desktop` on the session bus. One reader
//! thread blocks on portal signals: no polling, no timers. Nothing about the
//! user is logged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use zbus::blocking::{Connection, MessageIterator};
use zbus::message::Type as MsgType;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::MatchRule;

const DEST: &str = "org.freedesktop.portal.Desktop";
const PATH: &str = "/org/freedesktop/portal/desktop";
const IFACE: &str = "org.freedesktop.portal.GlobalShortcuts";
/// The one shortcut Voidwire asks for.
pub(crate) const SHORTCUT_ID: &str = "send-clipboard";
const DESCRIPTION: &str = "Send clipboard with Voidwire";

/// Why a bind didn't happen, as shown under the shortcut setting.
pub(crate) const CANCELLED: &str = "Shortcut not set: the system dialog was closed.";
pub(crate) const REFUSED: &str = "The desktop didn't set the shortcut.";
pub(crate) const UNAVAILABLE: &str = "Not available on this desktop";

/// `REFUSED` with what the desktop said, so the setting shows the real cause.
fn refused(detail: impl std::fmt::Display) -> String {
    format!("{} ({detail})", REFUSED.trim_end_matches('.'))
}

/// A D-Bus failure as its error name and message (never user data).
fn dbus_detail(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, Some(m), _) => format!("{name}: {m}"),
        zbus::Error::MethodError(name, None, _) => name.to_string(),
        e => e.to_string(),
    }
}

/// KDE Plasma (`XDG_CURRENT_DESKTOP` has KDE).
pub(crate) fn kde_desktop() -> bool {
    std::env::var("XDG_CURRENT_DESKTOP")
        .is_ok_and(|d| d.split(':').any(|p| p.eq_ignore_ascii_case("KDE")))
}

/// Plasma's portal before 6.1 takes BindShortcuts but never registers the
/// shortcut (xdg-desktop-portal-kde registers only what CreateSession
/// listed, and the portal frontend drops that list); it opens System
/// Settings › Shortcuts instead, which has no entry for the app. Its
/// interface says version 1 there and on Plasma 6.1 to 6.4 too (so those
/// can't be told apart); 6.5+ says 2. On KDE with 1 the app uses a KDE
/// command shortcut instead (`kde_shortcut`), which works on all of them.
pub(crate) fn portal_binds(version: u32, kde: bool) -> bool {
    !kde || version >= 2
}

/// A Wayland session, where key grabs don't work and the portal is the way.
/// `XDG_SESSION_TYPE` decides; without it, `WAYLAND_DISPLAY`.
pub(crate) fn wayland_session() -> bool {
    match std::env::var("XDG_SESSION_TYPE") {
        Ok(t) if !t.is_empty() => t.eq_ignore_ascii_case("wayland"),
        _ => std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty()),
    }
}

type OnPress = Arc<dyn Fn() + Send + Sync>;

struct Active {
    session: String,
    trigger: String,
    on_press: OnPress,
}

struct Portal {
    conn: Connection,
    active: Mutex<Option<Active>>,
}

static PORTAL: OnceLock<Result<Arc<Portal>, String>> = OnceLock::new();
static TOKEN_SEQ: Mutex<u32> = Mutex::new(0);

fn portal() -> Result<Arc<Portal>, String> {
    PORTAL
        .get_or_init(|| {
            let conn = Connection::session().map_err(|_| UNAVAILABLE.to_owned())?;
            open(conn)
        })
        .clone()
}

/// Checks the portal offers GlobalShortcuts and starts the signal reader.
fn open(conn: Connection) -> Result<Arc<Portal>, String> {
    let version: Result<u32, _> = conn
        .call_method(
            Some(DEST),
            PATH,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &(IFACE, "version"),
        )
        .and_then(|m| m.body().deserialize::<OwnedValue>())
        .map_err(|_| ())
        .and_then(|v| u32::try_from(v).map_err(|_| ()));
    match version {
        Ok(v) if portal_binds(v, kde_desktop()) => {}
        _ => return Err(UNAVAILABLE.to_owned()),
    }
    let rule = MatchRule::builder()
        .msg_type(MsgType::Signal)
        .interface(IFACE)
        .map_err(|e| e.to_string())?
        .path(PATH)
        .map_err(|e| e.to_string())?
        .build();
    let signals = MessageIterator::for_match_rule(rule, &conn, Some(16))
        .map_err(|_| UNAVAILABLE.to_owned())?;
    let p = Arc::new(Portal {
        conn,
        active: Mutex::new(None),
    });
    let reader = Arc::clone(&p);
    std::thread::Builder::new()
        .name("portal-shortcut".into())
        .spawn(move || read_signals(&reader, signals))
        .map_err(|e| e.to_string())?;
    Ok(p)
}

fn read_signals(p: &Portal, signals: MessageIterator) {
    for msg in signals.flatten() {
        let hdr = msg.header();
        let Some(member) = hdr.member() else { continue };
        match member.as_str() {
            "Activated" => {
                let Ok((session, id, _ts, opts)) =
                    msg.body()
                        .deserialize::<(OwnedObjectPath, String, u64, HashMap<String, OwnedValue>)>(
                        )
                else {
                    continue;
                };
                if id != SHORTCUT_ID {
                    continue;
                }
                let on_press = p.active.lock().ok().and_then(|a| {
                    a.as_ref()
                        .filter(|a| a.session == session.as_str())
                        .map(|a| Arc::clone(&a.on_press))
                });
                if let Some(f) = on_press {
                    // Portal v2+: lets the window shown for it take focus.
                    if let Some(t) = opts
                        .get("activation_token")
                        .and_then(|v| String::try_from(v.try_clone().ok()?).ok())
                    {
                        crate::activation::put(&t);
                    }
                    f();
                }
            }
            "ShortcutsChanged" => {
                let Ok((session, list)) = msg
                    .body()
                    .deserialize::<(OwnedObjectPath, Vec<(String, HashMap<String, OwnedValue>)>)>()
                else {
                    continue;
                };
                if let Ok(mut a) = p.active.lock() {
                    if let Some(a) = a.as_mut().filter(|a| a.session == session.as_str()) {
                        if let Some(t) = trigger_of(&list) {
                            a.trigger = t;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn trigger_of(list: &[(String, HashMap<String, OwnedValue>)]) -> Option<String> {
    list.iter()
        .find(|(id, _)| id == SHORTCUT_ID)
        .and_then(|(_, m)| m.get("trigger_description"))
        .and_then(|v| String::try_from(v.try_clone().ok()?).ok())
        .map(|t| readable_trigger(&t))
}

/// GNOME describes the trigger in GTK accelerator syntax ("Press
/// <Shift><Control>v"); show it the way the rest of the app does ("Press
/// Ctrl+Shift+V"). Text without `<...>` (KDE: "Ctrl+Shift+V") is unchanged.
pub(crate) fn readable_trigger(desc: &str) -> String {
    let mut out = String::new();
    let mut rest = desc;
    while let Some(i) = rest.find('<') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let mut mods: Vec<&'static str> = Vec::new();
        while let Some(tok) = rest.strip_prefix('<').and_then(|r| r.split_once('>')) {
            let m = match tok.0.to_ascii_lowercase().as_str() {
                "control" | "ctrl" | "primary" => "Ctrl",
                "alt" | "mod1" => "Alt",
                "shift" => "Shift",
                "super" | "logo" | "meta" | "mod4" => "Super",
                "hyper" => "Hyper",
                _ => break,
            };
            if !mods.contains(&m) {
                mods.push(m);
            }
            rest = tok.1;
        }
        if mods.is_empty() {
            // Not an accelerator: keep the '<' and go on.
            out.push('<');
            rest = &rest[1..];
            continue;
        }
        // The app's order (its default is Ctrl+Shift+Alt+V).
        const ORDER: [&str; 5] = ["Ctrl", "Shift", "Alt", "Super", "Hyper"];
        mods.sort_by_key(|m| ORDER.iter().position(|o| o == m));
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let key = &rest[..end];
        rest = &rest[end..];
        out.push_str(&mods.join("+"));
        if !key.is_empty() {
            out.push('+');
            let mut c = key.chars();
            match (c.next(), c.next()) {
                (Some(k), None) => out.extend(k.to_uppercase()),
                _ => out.push_str(&key.replace('_', " ")),
            }
        }
    }
    out.push_str(rest);
    out
}

fn next_token() -> String {
    let mut n = TOKEN_SEQ.lock().unwrap_or_else(|e| e.into_inner());
    *n += 1;
    // Unique per connection is enough: the request path carries our bus name.
    format!("voidwire{}", *n)
}

/// Calls a portal method that answers through a Request object, and waits
/// for its `Response` (the user may be looking at a dialog; no timeout).
fn request(
    conn: &Connection,
    method: &str,
    body: &(impl zbus::export::serde::Serialize + zbus::zvariant::DynamicType),
    token: &str,
) -> Result<HashMap<String, OwnedValue>, String> {
    let sender = conn
        .unique_name()
        .ok_or_else(|| UNAVAILABLE.to_owned())?
        .trim_start_matches(':')
        .replace('.', "_");
    let req_path = format!("{PATH}/request/{sender}/{token}");
    let rule = MatchRule::builder()
        .msg_type(MsgType::Signal)
        .interface("org.freedesktop.portal.Request")
        .and_then(|b| b.member("Response"))
        .and_then(|b| b.path(req_path.as_str()))
        .map_err(|e| e.to_string())?
        .build();
    let mut responses = MessageIterator::for_match_rule(rule, conn, Some(1))
        .map_err(|e| refused(format!("{method}: {}", dbus_detail(&e))))?;
    conn.call_method(Some(DEST), PATH, Some(IFACE), method, body)
        .map_err(|e| refused(format!("{method}: {}", dbus_detail(&e))))?;
    let msg = responses
        .next()
        .ok_or_else(|| refused(format!("{method}: no answer")))?
        .map_err(|e| refused(format!("{method}: {}", dbus_detail(&e))))?;
    let (code, results) = msg
        .body()
        .deserialize::<(u32, HashMap<String, OwnedValue>)>()
        .map_err(|_| refused(format!("{method}: unreadable answer")))?;
    response(method, code).map(|()| results)
}

/// A portal Request's response code: 0 done, 1 cancelled by the user,
/// 2 ended some other way.
fn response(method: &str, code: u32) -> Result<(), String> {
    match code {
        0 => Ok(()),
        1 => Err(CANCELLED.to_owned()),
        c => Err(refused(format!("{method} ended with response {c}"))),
    }
}

fn close_session(conn: &Connection, session: &str) {
    if let Ok(path) = ObjectPath::try_from(session) {
        let _ = conn.call_method(
            Some(DEST),
            path,
            Some("org.freedesktop.portal.Session"),
            "Close",
            &(),
        );
    }
}

/// `Ctrl+Shift+V` -> `CTRL+SHIFT+v` (the XDG shortcuts format the portal's
/// `preferred_trigger` takes). Keys come from `parse_hotkey_accel`'s set.
pub(crate) fn preferred_trigger(accel: &str) -> Option<String> {
    let mut out = Vec::new();
    for tok in accel.split('+').map(str::trim).filter(|t| !t.is_empty()) {
        let t = match tok.to_ascii_lowercase().as_str() {
            "ctrl" | "control" => "CTRL".to_owned(),
            "alt" => "ALT".to_owned(),
            "shift" => "SHIFT".to_owned(),
            "win" | "super" | "meta" => "LOGO".to_owned(),
            k if k.len() == 1 && k.chars().all(|c| c.is_ascii_alphanumeric()) => k.to_owned(),
            k if k.len() >= 2 && k.starts_with('f') && k[1..].parse::<u8>().is_ok() => {
                tok.to_ascii_uppercase()
            }
            k => match k {
                "space" => "space",
                "tab" => "Tab",
                "enter" | "return" => "Return",
                "backspace" => "BackSpace",
                "insert" => "Insert",
                "delete" => "Delete",
                "home" => "Home",
                "end" => "End",
                "pageup" => "Page_Up",
                "pagedown" => "Page_Down",
                "up" => "Up",
                "down" => "Down",
                "left" => "Left",
                "right" => "Right",
                ";" => "semicolon",
                "=" => "equal",
                "," => "comma",
                "-" => "minus",
                "." => "period",
                "/" => "slash",
                "`" => "grave",
                "[" => "bracketleft",
                "\\" => "backslash",
                "]" => "bracketright",
                "'" => "apostrophe",
                _ => return None,
            }
            .to_owned(),
        };
        out.push(t);
    }
    (!out.is_empty()).then(|| out.join("+"))
}

/// Whether this desktop's portal offers global shortcuts.
#[cfg(test)]
fn available() -> bool {
    portal().is_ok()
}

/// The portal check's answer, once it has run (`None` before).
pub(crate) fn checked() -> Option<bool> {
    PORTAL.get().map(Result::is_ok)
}

/// The keys the desktop bound, as it describes them ("Ctrl+Shift+V"), while
/// the shortcut is on.
pub(crate) fn trigger() -> Option<String> {
    let p = PORTAL.get()?.as_ref().ok()?;
    let a = p.active.lock().ok()?;
    a.as_ref().map(|a| a.trigger.clone())
}

/// Turns the portal shortcut on (blocks while the system dialog is open) or
/// off. Returns the bound keys' description when on.
pub(crate) fn set(enabled: bool, accel: &str, on_press: OnPress) -> Result<Option<String>, String> {
    if !enabled {
        if let Ok(p) = portal() {
            let old = p.active.lock().ok().and_then(|mut a| a.take());
            if let Some(old) = old {
                close_session(&p.conn, &old.session);
            }
        }
        return Ok(None);
    }
    let p = portal()?;
    set_on(&p, accel, on_press).map(Some)
}

fn set_on(p: &Portal, accel: &str, on_press: OnPress) -> Result<String, String> {
    let old = p.active.lock().ok().and_then(|mut a| a.take());
    if let Some(old) = old {
        close_session(&p.conn, &old.session);
    }
    let token = next_token();
    let session_token = next_token();
    let opts: HashMap<&str, Value> = HashMap::from([
        ("handle_token", Value::from(token.as_str())),
        ("session_handle_token", Value::from(session_token.as_str())),
    ]);
    let res = request(&p.conn, "CreateSession", &(opts,), &token)?;
    let session = res
        .get("session_handle")
        .and_then(|v| {
            let v = v.try_clone().ok()?;
            String::try_from(v.try_clone().ok()?)
                .ok()
                .or_else(|| OwnedObjectPath::try_from(v).ok().map(|o| o.to_string()))
        })
        .ok_or_else(|| refused("CreateSession: no session"))?;
    let session_path = ObjectPath::try_from(session.as_str())
        .map_err(|_| refused("CreateSession: bad session"))?;
    let mut props: HashMap<&str, Value> =
        HashMap::from([("description", Value::from(DESCRIPTION))]);
    if let Some(t) = preferred_trigger(accel) {
        props.insert("preferred_trigger", Value::from(t));
    }
    let token = next_token();
    let opts: HashMap<&str, Value> = HashMap::from([("handle_token", Value::from(token.as_str()))]);
    let shortcuts = vec![(SHORTCUT_ID, props)];
    let bound = request(
        &p.conn,
        "BindShortcuts",
        &(session_path, shortcuts, "", opts),
        &token,
    );
    let res = match bound {
        Ok(r) => r,
        Err(e) => {
            close_session(&p.conn, &session);
            return Err(e);
        }
    };
    let list: Vec<(String, HashMap<String, OwnedValue>)> = res
        .get("shortcuts")
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| Vec::try_from(v).ok())
        .unwrap_or_default();
    if !list.iter().any(|(id, _)| id == SHORTCUT_ID) {
        close_session(&p.conn, &session);
        return Err(refused("BindShortcuts returned no shortcut"));
    }
    let trigger = trigger_of(&list).unwrap_or_default();
    if let Ok(mut a) = p.active.lock() {
        *a = Some(Active {
            session,
            trigger: trigger.clone(),
            on_press,
        });
    }
    Ok(trigger)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gtk_trigger_description_reads_like_the_app() {
        assert_eq!(
            readable_trigger("Press <Shift><Control>v"),
            "Press Ctrl+Shift+V"
        );
        assert_eq!(readable_trigger("<Alt>F5"), "Alt+F5");
        assert_eq!(readable_trigger("<Super>space"), "Super+space");
        assert_eq!(readable_trigger("<Control>Page_Down"), "Ctrl+Page Down");
        assert_eq!(readable_trigger("Ctrl+Shift+V"), "Ctrl+Shift+V");
        assert_eq!(
            readable_trigger("<Control><Shift><Alt>v"),
            "Ctrl+Shift+Alt+V"
        );
        assert_eq!(
            preferred_trigger("Ctrl+Shift+Alt+V").as_deref(),
            Some("CTRL+SHIFT+ALT+v")
        );
        assert_eq!(
            readable_trigger("Press <Primary>a or <Shift><Alt>b"),
            "Press Ctrl+A or Shift+Alt+B"
        );
        assert_eq!(readable_trigger("a <b> c"), "a <b> c");
        assert_eq!(readable_trigger(""), "");
    }

    #[test]
    fn plasma_before_6_5_does_not_bind() {
        assert!(!portal_binds(1, true), "Plasma 5.27-6.4 portal");
        assert!(portal_binds(2, true));
        assert!(portal_binds(1, false), "GNOME 48 and others");
    }

    #[test]
    fn refusals_say_what_the_desktop_said() {
        assert_eq!(response("BindShortcuts", 0), Ok(()));
        assert_eq!(response("BindShortcuts", 1), Err(CANCELLED.to_owned()));
        assert_eq!(
            response("BindShortcuts", 2).unwrap_err(),
            "The desktop didn't set the shortcut (BindShortcuts ended with response 2)"
        );
    }

    #[test]
    fn accel_becomes_xdg_trigger() {
        assert_eq!(
            preferred_trigger("Ctrl+Shift+V").as_deref(),
            Some("CTRL+SHIFT+v")
        );
        assert_eq!(preferred_trigger("Alt+F5").as_deref(), Some("ALT+F5"));
        assert_eq!(
            preferred_trigger("Win+Space").as_deref(),
            Some("LOGO+space")
        );
        assert_eq!(
            preferred_trigger("Ctrl+PageDown").as_deref(),
            Some("CTRL+Page_Down")
        );
        assert_eq!(
            preferred_trigger("Ctrl+;").as_deref(),
            Some("CTRL+semicolon")
        );
        assert_eq!(preferred_trigger("Ctrl+Bogus"), None);
    }

    /// Against a stand-in portal (scripts/qa/portal-stub.py) on a private
    /// session bus: `dbus-run-session -- sh -c 'python3 scripts/qa/portal-stub.py &
    /// sleep 1; cargo test -p voidwire-os-theme portal -- --ignored'`.
    #[test]
    #[ignore = "needs a session bus with scripts/qa/portal-stub.py"]
    fn portal_bind_press_and_unbind() {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let tx = Mutex::new(tx);
        assert!(available());
        let trig = set(
            true,
            "Ctrl+Shift+Alt+V",
            Arc::new(move || {
                let _ = tx.lock().unwrap().send(());
            }),
        )
        .unwrap();
        assert_eq!(trig.as_deref(), Some("Ctrl+Shift+Alt+V (stub)"));
        assert_eq!(trigger().as_deref(), Some("Ctrl+Shift+Alt+V (stub)"));
        // The stub emits Activated when asked through its Press method.
        let p = portal().unwrap();
        stub(&p, "Press");
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("Activated reached on_press");
        assert_eq!(crate::activation::take().as_deref(), Some("stub-token"));
        assert_eq!(set(false, "", Arc::new(|| {})).unwrap(), None);
        assert_eq!(trigger(), None);
        let closed: bool = stub(&p, "Closed").body().deserialize().unwrap();
        assert!(closed, "session closed on the portal side");
    }

    fn stub(p: &Portal, method: &str) -> zbus::message::Message {
        p.conn
            .call_method(
                Some("org.voidwire.PortalStub"),
                "/stub",
                Some("org.voidwire.PortalStub"),
                method,
                &(),
            )
            .unwrap()
    }
}
