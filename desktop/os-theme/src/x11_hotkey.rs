//! Linux X11: the global send-clipboard shortcut (M5.1). `XGrabKey` on the
//! root window through x11rb's pure-Rust protocol (no unsafe, no libX11).
//! Wayland sessions get no grab here (apps can't grab keys there; the portal
//! comes later, L3; until then `--send-clipboard`, L5).
//!
//! One blocking reader thread per active shortcut, woken only by X events:
//! no polling, no timers. Nothing about the user is logged.

use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use x11rb::connection::Connection;
use x11rb::protocol::xproto::{
    AtomEnum, ClientMessageEvent, ConnectionExt as _, CreateWindowAux, EventMask, GrabMode,
    ModMask, Window, WindowClass,
};
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;

// Win32 modifier flags used by `parse_hotkey_accel`.
const W_ALT: u32 = 0x1;
const W_CONTROL: u32 = 0x2;
const W_SHIFT: u32 = 0x4;
const W_WIN: u32 = 0x8;

// X11 modifier bits.
const X_SHIFT: u16 = 1;
const X_LOCK: u16 = 1 << 1;
const X_CONTROL: u16 = 1 << 2;
const X_MOD1_ALT: u16 = 1 << 3;
const X_MOD2_NUMLOCK: u16 = 1 << 4;
const X_MOD4_SUPER: u16 = 1 << 6;

/// Win32 `fsModifiers` -> X11 modifier mask (Alt = Mod1, Super = Mod4).
pub(crate) fn x_mods(win_mods: u32) -> u16 {
    let mut m = 0;
    if win_mods & W_SHIFT != 0 {
        m |= X_SHIFT;
    }
    if win_mods & W_CONTROL != 0 {
        m |= X_CONTROL;
    }
    if win_mods & W_ALT != 0 {
        m |= X_MOD1_ALT;
    }
    if win_mods & W_WIN != 0 {
        m |= X_MOD4_SUPER;
    }
    m
}

/// The Win32 virtual key `parse_hotkey_accel` returns -> the X11 keysym.
pub(crate) fn keysym_for_vk(vk: u32) -> Option<u32> {
    Some(match vk {
        0x41..=0x5A => vk + 0x20,            // A–Z -> lowercase keysyms
        0x30..=0x39 => vk,                   // 0–9
        0x70..=0x7B => 0xFFBE + (vk - 0x70), // F1–F12
        0x20 => 0x20,
        0x09 => 0xFF09,
        0x0D => 0xFF0D,
        0x08 => 0xFF08,
        0x2D => 0xFF63,
        0x2E => 0xFFFF,
        0x24 => 0xFF50,
        0x23 => 0xFF57,
        0x21 => 0xFF55,
        0x22 => 0xFF56,
        0x26 => 0xFF52,
        0x28 => 0xFF54,
        0x25 => 0xFF51,
        0x27 => 0xFF53,
        0xBA => 0x3B,
        0xBB => 0x3D,
        0xBC => 0x2C,
        0xBD => 0x2D,
        0xBE => 0x2E,
        0xBF => 0x2F,
        0xC0 => 0x60,
        0xDB => 0x5B,
        0xDC => 0x5C,
        0xDD => 0x5D,
        0xDE => 0x27,
        _ => return None,
    })
}

/// The grab plus the lock-key variants, so Caps Lock / Num Lock don't break it.
fn grab_variants(mods: u16) -> [u16; 4] {
    [
        mods,
        mods | X_LOCK,
        mods | X_MOD2_NUMLOCK,
        mods | X_LOCK | X_MOD2_NUMLOCK,
    ]
}

struct Active {
    conn: Arc<RustConnection>,
    wake: Window,
    reader: JoinHandle<()>,
}

static ACTIVE: Mutex<Option<Active>> = Mutex::new(None);

fn is_wayland_session() -> bool {
    crate::portal_shortcut::wayland_session()
}

/// Replace the active shortcut. `enabled == false` just removes it.
pub(crate) fn set(
    enabled: bool,
    (win_mods, vk): (u32, u32),
    accel: &str,
    on_press: Arc<dyn Fn() + Send + Sync>,
) -> Result<(), String> {
    let mut slot = ACTIVE
        .lock()
        .map_err(|_| "Shortcut state unavailable.".to_owned())?;
    if let Some(old) = slot.take() {
        stop(old);
    }
    if !enabled || is_wayland_session() || std::env::var_os("DISPLAY").is_none() {
        return Ok(());
    }
    let keysym =
        keysym_for_vk(vk).ok_or_else(|| format!("Unsupported key in shortcut '{accel}'."))?;
    let (conn, screen) =
        RustConnection::connect(None).map_err(|_| "Could not reach the X display.".to_owned())?;
    let conn = Arc::new(conn);
    let root = conn.setup().roots[screen].root;
    let keycode = keycode_for(&conn, keysym)
        .ok_or_else(|| format!("That shortcut ({accel}) has no key on this keyboard layout."))?;

    let mods = x_mods(win_mods);
    for (i, m) in grab_variants(mods).into_iter().enumerate() {
        let ok = conn
            .grab_key(
                false,
                root,
                ModMask::from(m),
                keycode,
                GrabMode::ASYNC,
                GrabMode::ASYNC,
            )
            .map_err(|_| ())
            .and_then(|c| c.check().map_err(|_| ()));
        if ok.is_err() {
            for prev in grab_variants(mods).into_iter().take(i) {
                let _ = conn.ungrab_key(keycode, root, ModMask::from(prev));
            }
            let _ = conn.flush();
            return Err(format!(
                "That shortcut ({accel}) is already in use by another app — pick a different key combination."
            ));
        }
    }

    // An unmapped input-only window of our own: `stop` sends it a client
    // message so the blocked reader wakes up and exits.
    let wake = conn
        .generate_id()
        .map_err(|_| "Could not set up the shortcut.".to_owned())?;
    conn.create_window(
        0,
        wake,
        root,
        0,
        0,
        1,
        1,
        0,
        WindowClass::INPUT_ONLY,
        0,
        &CreateWindowAux::new(),
    )
    .map_err(|_| "Could not set up the shortcut.".to_owned())?;
    conn.flush()
        .map_err(|_| "Could not set up the shortcut.".to_owned())?;

    let rc = Arc::clone(&conn);
    let reader = std::thread::Builder::new()
        .name("x11-hotkey".into())
        .spawn(move || read_events(&rc, keycode, wake, &*on_press))
        .map_err(|_| "Could not set up the shortcut.".to_owned())?;
    *slot = Some(Active { conn, wake, reader });
    Ok(())
}

fn keycode_for(conn: &RustConnection, keysym: u32) -> Option<u8> {
    let (min, max) = (conn.setup().min_keycode, conn.setup().max_keycode);
    let map = conn
        .get_keyboard_mapping(min, max - min + 1)
        .ok()?
        .reply()
        .ok()?;
    let per = usize::from(map.keysyms_per_keycode).max(1);
    map.keysyms
        .chunks(per)
        .position(|syms| syms.contains(&keysym))
        .and_then(|i| u8::try_from(usize::from(min) + i).ok())
}

fn read_events(
    conn: &RustConnection,
    keycode: u8,
    wake: Window,
    on_press: &(dyn Fn() + Send + Sync),
) {
    // X auto-repeat sends release+press pairs with the same timestamp; only
    // the first press of a hold sends (as MOD_NOREPEAT does on Windows).
    let mut last_release: Option<u32> = None;
    loop {
        match conn.wait_for_event() {
            Ok(Event::KeyPress(e)) if e.detail == keycode => {
                if last_release != Some(e.time) {
                    on_press();
                }
            }
            Ok(Event::KeyRelease(e)) if e.detail == keycode => last_release = Some(e.time),
            Ok(Event::ClientMessage(e)) if e.window == wake => return,
            Ok(_) => {}
            Err(_) => return,
        }
    }
}

fn stop(a: Active) {
    // Closing the connection also drops the grabs; wake the reader first so
    // it lets go of its handle.
    let msg = ClientMessageEvent::new(32, a.wake, AtomEnum::NONE, [0u32; 5]);
    let _ = a.conn.send_event(false, a.wake, EventMask::NO_EVENT, msg);
    let _ = a.conn.flush();
    let _ = a.reader.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accelerators_map_to_x11() {
        let (m, vk) = crate::parse_hotkey_accel("Ctrl+Shift+V").unwrap();
        assert_eq!(x_mods(m), X_CONTROL | X_SHIFT);
        assert_eq!(keysym_for_vk(vk), Some(0x76)); // XK_v
        let (m, vk) = crate::parse_hotkey_accel("Alt+Super+F9").unwrap();
        assert_eq!(x_mods(m), X_MOD1_ALT | X_MOD4_SUPER);
        assert_eq!(keysym_for_vk(vk), Some(0xFFC6)); // XK_F9
        assert_eq!(
            keysym_for_vk(crate::parse_hotkey_accel("Ctrl+7").unwrap().1),
            Some(0x37)
        );
        assert_eq!(
            keysym_for_vk(crate::parse_hotkey_accel("Ctrl+Space").unwrap().1),
            Some(0x20)
        );
    }

    #[test]
    fn every_parsable_key_has_a_keysym() {
        let keys =
            "A Z 0 9 F1 F12 Space Tab Enter Backspace Insert Delete Home End PageUp PageDown \
                    Up Down Left Right ; = , - . / ` [ \\ ] '";
        for k in keys.split(' ').filter(|k| !k.is_empty()) {
            let (_, vk) = crate::parse_hotkey_accel(&format!("Ctrl+{k}")).unwrap();
            assert!(keysym_for_vk(vk).is_some(), "{k}");
        }
    }

    #[test]
    fn lock_keys_are_grabbed_too() {
        let v = grab_variants(X_CONTROL);
        assert!(v.contains(&(X_CONTROL | X_LOCK | X_MOD2_NUMLOCK)));
        assert_eq!(v[0], X_CONTROL);
    }

    /// Needs an X display with XTEST (CI linux-smoke runs it under Xvfb):
    /// the grab fires once per press, a second grab of the same keys by
    /// another client is refused, and turning it off releases the keys.
    #[test]
    #[ignore = "needs an X display"]
    fn grab_fires_on_key_press_under_x() {
        use std::sync::mpsc;
        let (tx, rx) = mpsc::channel::<()>();
        let tx = Mutex::new(tx);
        let parsed = crate::parse_hotkey_accel("Ctrl+Shift+V").unwrap();
        set(
            true,
            parsed,
            "Ctrl+Shift+V",
            Arc::new(move || {
                let _ = tx.lock().unwrap().send(());
            }),
        )
        .unwrap();
        // Synthetic key presses through XTEST (no child process).
        let (fake, fscreen) = RustConnection::connect(None).unwrap();
        let froot = fake.setup().roots[fscreen].root;
        let keys: Vec<u8> = [0xFFE3, 0xFFE1, 0x76] // Control_L, Shift_L, v
            .into_iter()
            .map(|k| keycode_for(&fake, k).unwrap())
            .collect();
        let press = || {
            use x11rb::protocol::xtest::ConnectionExt as _;
            for &k in &keys {
                fake.xtest_fake_input(2, k, 0, froot, 0, 0, 0).unwrap();
            }
            for &k in keys.iter().rev() {
                fake.xtest_fake_input(3, k, 0, froot, 0, 0, 0).unwrap();
            }
            fake.flush().unwrap();
        };
        press();
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("first press");
        // A real second press, not an auto-repeat (same timestamp as the release).
        std::thread::sleep(std::time::Duration::from_millis(50));
        press();
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("second press");

        // Another client can't take the same keys while ours is active.
        let (other, screen) = RustConnection::connect(None).unwrap();
        let root = other.setup().roots[screen].root;
        let kc = keycode_for(&other, 0x76).unwrap();
        let mods = ModMask::from(X_CONTROL | X_SHIFT);
        let taken = other
            .grab_key(false, root, mods, kc, GrabMode::ASYNC, GrabMode::ASYNC)
            .unwrap()
            .check();
        assert!(taken.is_err());

        set(false, parsed, "Ctrl+Shift+V", Arc::new(|| {})).unwrap();
        let free = other
            .grab_key(false, root, mods, kc, GrabMode::ASYNC, GrabMode::ASYNC)
            .unwrap()
            .check();
        assert!(free.is_ok());
    }
}
