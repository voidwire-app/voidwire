//! Linux: text Voidwire puts on the clipboard (pairing codes, received
//! clipboard items) carries `x-kde-passwordManagerHint: secret`, so Klipper
//! and the GNOME clipboard managers that honour it keep it out of their
//! history (M5.1; parity with the Windows monitor-exclusion marker).

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hint_has_its_own_info_id() {
        assert!(TEXT_TARGETS.iter().all(|(_, i)| *i != HINT_INFO));
        assert_eq!(SECRET_HINT_VALUE, b"secret");
    }
}
