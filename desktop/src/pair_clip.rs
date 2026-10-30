//! v0.7.1: "Copy" for the pairing code this PC shows.
//!
//! The code is copied marked private on Windows (no clipboard history, no
//! cloud sync, skipped by clipboard monitors). When the pairing completes, is
//! cancelled, expires, gets replaced by a new code or the window closes, the
//! clipboard is emptied, but only if it still holds that exact code, so
//! something the user copied since is never wiped. Only the code the core
//! handed out can be copied: the window can't put arbitrary text there.

use std::sync::Mutex;
use tauri::AppHandle;

/// The system clipboard, as far as this module needs it.
pub trait Board {
    /// Copy `text` marked private. `false` when it couldn't.
    fn put_private(&self, text: &str) -> bool;
    /// Empty the clipboard if it still holds exactly `text`.
    fn clear_if(&self, text: &str);
}

/// The shown code and the code we put on the clipboard.
#[derive(Default)]
pub struct CodeClip {
    shown: Option<String>,
    copied: Option<String>,
}

impl CodeClip {
    /// A new code is on screen (`None`: QR only). An older copied code goes.
    pub fn show(&mut self, b: &dyn Board, code: Option<String>) {
        self.finish(b);
        self.shown = code;
    }

    pub fn copy(&mut self, b: &dyn Board) -> Result<(), String> {
        let code = self.shown.clone().ok_or("There's no code to copy.")?;
        if !b.put_private(&code) {
            return Err("Couldn't copy the code. Type it on the other device instead.".into());
        }
        self.copied = Some(code);
        Ok(())
    }

    /// The code is done with (paired, cancelled, expired, window closed).
    pub fn finish(&mut self, b: &dyn Board) {
        self.shown = None;
        if let Some(c) = self.copied.take() {
            b.clear_if(&c);
        }
    }
}

static CLIP: Mutex<CodeClip> = Mutex::new(CodeClip {
    shown: None,
    copied: None,
});

struct Os<'a>(&'a AppHandle);

impl Board for Os<'_> {
    fn put_private(&self, text: &str) -> bool {
        #[cfg(windows)]
        {
            let _ = self.0;
            voidwire_os_theme::set_private_clipboard_text(text)
        }
        #[cfg(target_os = "linux")]
        {
            // GTK wants its main thread; nothing here waits on it, so this
            // is safe to call from the main thread too.
            let text = text.to_owned();
            self.0
                .run_on_main_thread(move || {
                    if let Some(cb) =
                        gtk::gdk::Display::default().and_then(|d| gtk::Clipboard::default(&d))
                    {
                        cb.set_text(&text);
                    }
                })
                .is_ok()
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = (self.0, text);
            false
        }
    }

    fn clear_if(&self, text: &str) {
        #[cfg(windows)]
        {
            let _ = self.0;
            voidwire_os_theme::clear_clipboard_if_text(text);
        }
        #[cfg(target_os = "linux")]
        {
            let text = text.to_owned();
            let _ = self.0.run_on_main_thread(move || {
                if let Some(cb) =
                    gtk::gdk::Display::default().and_then(|d| gtk::Clipboard::default(&d))
                {
                    if cb.wait_for_text().as_deref() == Some(text.as_str()) {
                        cb.set_text("");
                        cb.clear();
                    }
                }
            });
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = (self.0, text);
        }
    }
}

fn with<R>(f: impl FnOnce(&mut CodeClip) -> R) -> R {
    f(&mut CLIP.lock().unwrap_or_else(|p| p.into_inner()))
}

pub fn shown(app: &AppHandle, code: Option<String>) {
    with(|c| c.show(&Os(app), code));
}

pub fn copy(app: &AppHandle) -> Result<(), String> {
    with(|c| c.copy(&Os(app)))
}

pub fn finish(app: &AppHandle) {
    with(|c| c.finish(&Os(app)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Fake {
        text: RefCell<Option<String>>,
        refuse: bool,
    }
    impl Board for Fake {
        fn put_private(&self, text: &str) -> bool {
            if !self.refuse {
                *self.text.borrow_mut() = Some(text.into());
            }
            !self.refuse
        }
        fn clear_if(&self, text: &str) {
            let mut t = self.text.borrow_mut();
            if t.as_deref() == Some(text) {
                *t = None;
            }
        }
    }

    #[test]
    fn copied_code_is_cleared_when_done_unless_something_else_was_copied() {
        let b = Fake::default();
        let mut c = CodeClip::default();
        assert!(c.copy(&b).is_err(), "nothing shown yet");
        c.show(&b, Some("VW-AAAA".into()));
        c.copy(&b).unwrap();
        assert_eq!(b.text.borrow().as_deref(), Some("VW-AAAA"));
        c.finish(&b);
        assert_eq!(*b.text.borrow(), None, "cleared when paired or cancelled");
        assert!(c.copy(&b).is_err(), "a finished code can't be copied again");

        c.show(&b, Some("VW-BBBB".into()));
        c.copy(&b).unwrap();
        *b.text.borrow_mut() = Some("the user's own text".into());
        c.finish(&b);
        assert_eq!(b.text.borrow().as_deref(), Some("the user's own text"));

        // A new code replaces the old one: the old copy goes.
        c.show(&b, Some("VW-CCCC".into()));
        c.copy(&b).unwrap();
        c.show(&b, Some("VW-DDDD".into()));
        assert_eq!(*b.text.borrow(), None);
        c.show(&b, None);
        assert!(c.copy(&b).is_err(), "QR only: nothing to copy");
    }

    #[test]
    fn a_refused_copy_says_so_and_clears_nothing() {
        let b = Fake {
            refuse: true,
            ..Default::default()
        };
        *b.text.borrow_mut() = Some("mine".into());
        let mut c = CodeClip::default();
        c.show(&b, Some("VW-EEEE".into()));
        assert!(c.copy(&b).unwrap_err().contains("Couldn't copy"));
        c.finish(&b);
        assert_eq!(b.text.borrow().as_deref(), Some("mine"));
    }
}
