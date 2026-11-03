//! macOS (M5.2): AppKit pasteboard, open panels, appearance, the Carbon
//! global shortcut and the Finder "Send with Voidwire" service. All AppKit
//! UI calls hop to the main thread (`run_on_main`); nothing here polls.

use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject};
use objc2::{define_class, msg_send, ClassType, MainThreadMarker};
use objc2_app_kit::{
    NSApplication, NSModalResponseOK, NSOpenPanel, NSPasteboard, NSPasteboardTypeFileURL,
    NSPasteboardTypeString,
};
use objc2_foundation::{
    NSData, NSDistributedNotificationCenter, NSNotification, NSString, NSUserDefaults, NSURL,
};

/// nspasteboard.org markers: clipboard managers and Universal Clipboard
/// skip a concealed item; transient ones are not kept in history.
const CONCEALED_TYPE: &str = "org.nspasteboard.ConcealedType";
const TRANSIENT_TYPE: &str = "org.nspasteboard.TransientType";

fn general() -> Retained<NSPasteboard> {
    NSPasteboard::generalPasteboard()
}

fn string_type() -> &'static NSString {
    // SAFETY: an AppKit constant, valid for the life of the process.
    unsafe { NSPasteboardTypeString }
}

pub fn get_clipboard_text() -> Option<String> {
    general()
        .stringForType(string_type())
        .map(|s| s.to_string())
}

pub fn set_clipboard_text(text: &str) -> bool {
    let pb = general();
    pb.clearContents();
    pb.setString_forType(&NSString::from_str(text), string_type())
}

/// Pairing codes: the text plus the concealed and transient markers.
pub fn set_private_clipboard_text(text: &str) -> bool {
    let pb = general();
    pb.clearContents();
    if !pb.setString_forType(&NSString::from_str(text), string_type()) {
        return false;
    }
    let empty = NSData::new();
    for t in [CONCEALED_TYPE, TRANSIENT_TYPE] {
        pb.setData_forType(Some(&empty), &NSString::from_str(t));
    }
    true
}

pub fn clipboard_is_private() -> bool {
    let Some(types) = general().types() else {
        return false;
    };
    let want = NSString::from_str(CONCEALED_TYPE);
    types.iter().any(|t| *t == *want)
}

/// Clear only while the pasteboard still holds exactly `text`.
pub fn clear_clipboard_if_text(text: &str) -> bool {
    let pb = general();
    if pb
        .stringForType(string_type())
        .map(|s| s.to_string())
        .as_deref()
        != Some(text)
    {
        return false;
    }
    pb.clearContents();
    true
}

/// A file copied in Finder (`public.file-url`), read when asked: macOS has no
/// change event for the pasteboard, and polling it is not allowed here.
pub fn get_clipboard_file() -> Option<PathBuf> {
    // SAFETY: an AppKit constant, valid for the life of the process.
    let t = unsafe { NSPasteboardTypeFileURL };
    let url = general().stringForType(t)?.to_string();
    super::parse_clipboard_file_uri_list(&url).filter(|p| p.is_file())
}

fn file_url(dir: &Path) -> Option<Retained<NSURL>> {
    let s = dir.to_str()?;
    Some(NSURL::fileURLWithPath_isDirectory(
        &NSString::from_str(s),
        true,
    ))
}

fn pick(initial: Option<&Path>, folder: bool) -> Option<PathBuf> {
    let initial = initial.map(Path::to_path_buf);
    dispatch2::run_on_main(move |mtm| {
        let app = NSApplication::sharedApplication(mtm);
        // A menu bar app is not active: bring the panel to the front.
        #[allow(deprecated)]
        app.activateIgnoringOtherApps(true);
        let panel = NSOpenPanel::openPanel(mtm);
        panel.setCanChooseFiles(!folder);
        panel.setCanChooseDirectories(folder);
        panel.setAllowsMultipleSelection(false);
        if folder {
            panel.setCanCreateDirectories(true);
            panel.setPrompt(Some(&NSString::from_str("Select")));
        } else {
            panel.setPrompt(Some(&NSString::from_str("Send")));
        }
        if let Some(u) = initial.filter(|d| d.is_dir()).as_deref().and_then(file_url) {
            panel.setDirectoryURL(Some(&u));
        }
        if panel.runModal() != NSModalResponseOK {
            return None;
        }
        let url = panel.URL()?;
        url.path().map(|p| PathBuf::from(p.to_string()))
    })
}

pub fn pick_folder(initial: Option<&Path>) -> Option<PathBuf> {
    pick(initial, true)
}

pub fn pick_file(initial: Option<&Path>) -> Option<PathBuf> {
    pick(initial, false)
}

/// Light unless the user picked Dark (`AppleInterfaceStyle` = `Dark`;
/// Auto writes it too while dark). Our own windows' forced theme doesn't
/// touch this global setting.
pub fn apps_are_light() -> bool {
    let style = NSUserDefaults::standardUserDefaults()
        .stringForKey(&NSString::from_str("AppleInterfaceStyle"))
        .map(|s| s.to_string());
    !matches!(style.as_deref(), Some(s) if s.eq_ignore_ascii_case("dark"))
}

/// Call `on_change` when the system appearance flips (the distributed
/// `AppleInterfaceThemeChangedNotification`). Event-driven, set up once.
pub fn watch_theme_changes(on_change: Arc<dyn Fn() + Send + Sync>) {
    static STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    dispatch2::run_on_main(move |_mtm| {
        let block = block2::RcBlock::new(move |_n: NonNull<NSNotification>| {
            on_change();
            // The notification can arrive a moment before the new value is
            // readable; one late re-check (not a poll) catches that.
            let again = on_change.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(600));
                again();
            });
        });
        let center = NSDistributedNotificationCenter::defaultCenter();
        // SAFETY: a nil object and queue (deliver on the posting run loop,
        // the main one); the block is `Send + Sync` and lives in the
        // observer, which is kept for the life of the process.
        let observer = unsafe {
            center.addObserverForName_object_queue_usingBlock(
                Some(&NSString::from_str(
                    "AppleInterfaceThemeChangedNotification",
                )),
                None,
                None,
                &block,
            )
        };
        std::mem::forget(observer);
    });
}

// --- Carbon global shortcut (RegisterEventHotKey) -------------------------

type OSStatus = i32;
type EventTargetRef = *mut std::ffi::c_void;
type EventHandlerRef = *mut std::ffi::c_void;
type EventHotKeyRef = *mut std::ffi::c_void;
type EventRef = *mut std::ffi::c_void;
type EventHandlerCallRef = *mut std::ffi::c_void;
type EventHandlerUPP =
    extern "C" fn(EventHandlerCallRef, EventRef, *mut std::ffi::c_void) -> OSStatus;

#[repr(C)]
struct EventTypeSpec {
    event_class: u32,
    event_kind: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EventHotKeyID {
    signature: u32,
    id: u32,
}

#[link(name = "Carbon", kind = "framework")]
extern "C" {
    fn GetApplicationEventTarget() -> EventTargetRef;
    fn InstallEventHandler(
        target: EventTargetRef,
        handler: EventHandlerUPP,
        num_types: u32,
        list: *const EventTypeSpec,
        user_data: *mut std::ffi::c_void,
        out_ref: *mut EventHandlerRef,
    ) -> OSStatus;
    fn RegisterEventHotKey(
        key_code: u32,
        modifiers: u32,
        id: EventHotKeyID,
        target: EventTargetRef,
        options: u32,
        out_ref: *mut EventHotKeyRef,
    ) -> OSStatus;
    fn UnregisterEventHotKey(hot_key: EventHotKeyRef) -> OSStatus;
}

const K_EVENT_CLASS_KEYBOARD: u32 = u32::from_be_bytes(*b"keyb");
const K_EVENT_HOT_KEY_PRESSED: u32 = 5;
const EVENT_HOT_KEY_EXISTS_ERR: OSStatus = -9878;

struct HotkeyState {
    /// The registered key, as an address (a raw pointer isn't `Send`).
    registered: usize,
    on_press: Option<Arc<dyn Fn() + Send + Sync>>,
    handler_installed: bool,
}

static HOTKEY: Mutex<HotkeyState> = Mutex::new(HotkeyState {
    registered: 0,
    on_press: None,
    handler_installed: false,
});

extern "C" fn hotkey_pressed(
    _next: EventHandlerCallRef,
    _event: EventRef,
    _user: *mut std::ffi::c_void,
) -> OSStatus {
    let cb = HOTKEY.lock().ok().and_then(|g| g.on_press.clone());
    if let Some(cb) = cb {
        cb();
    }
    0
}

/// Register (or drop) the one send-clipboard shortcut. `parsed` is the
/// Win32-style pair from `parse_hotkey_accel`, mapped to Carbon here.
pub fn set_send_clipboard_hotkey(
    enabled: bool,
    parsed: (u32, u32),
    accel: &str,
    on_press: Arc<dyn Fn() + Send + Sync>,
) -> Result<(), String> {
    let key = super::mac_key_code(parsed.1);
    let mods = super::mac_modifiers(parsed.0);
    let accel = accel.to_owned();
    dispatch2::run_on_main(move |_mtm| {
        let mut g = HOTKEY
            .lock()
            .map_err(|_| "shortcut state poisoned".to_owned())?;
        if g.registered != 0 {
            // SAFETY: a ref RegisterEventHotKey returned and not yet released.
            unsafe { UnregisterEventHotKey(g.registered as EventHotKeyRef) };
            g.registered = 0;
        }
        g.on_press = None;
        if !enabled {
            return Ok(());
        }
        let Some(key) = key else {
            return Err(format!("That shortcut ({accel}) can't be used on a Mac — pick a different key combination."));
        };
        // SAFETY: Carbon event calls on the main thread with valid out
        // pointers; the handler is a plain `extern "C"` fn with no user data.
        unsafe {
            let target = GetApplicationEventTarget();
            if !g.handler_installed {
                let spec = EventTypeSpec {
                    event_class: K_EVENT_CLASS_KEYBOARD,
                    event_kind: K_EVENT_HOT_KEY_PRESSED,
                };
                let mut h: EventHandlerRef = std::ptr::null_mut();
                if InstallEventHandler(
                    target,
                    hotkey_pressed,
                    1,
                    &spec,
                    std::ptr::null_mut(),
                    &mut h,
                ) != 0
                {
                    return Err("The shortcut couldn't be set up on this Mac.".into());
                }
                g.handler_installed = true;
            }
            let id = EventHotKeyID {
                signature: u32::from_be_bytes(*b"VWHK"),
                id: 1,
            };
            let mut r: EventHotKeyRef = std::ptr::null_mut();
            match RegisterEventHotKey(key, mods, id, target, 0, &mut r) {
                0 => {}
                EVENT_HOT_KEY_EXISTS_ERR => {
                    return Err(format!("That shortcut ({accel}) is already in use by another app — pick a different key combination."))
                }
                _ => return Err("The shortcut couldn't be set up on this Mac.".into()),
            }
            g.registered = r as usize;
        }
        g.on_press = Some(on_press);
        Ok(())
    })
}

// --- Finder service: "Send with Voidwire" (M2) ----------------------------

type SendFileCallback = Arc<dyn Fn(PathBuf) + Send + Sync>;
static SEND_FILE: Mutex<Option<SendFileCallback>> = Mutex::new(None);

define_class!(
    // SAFETY: NSObject has no subclassing rules; no ivars, no Drop.
    #[unsafe(super(NSObject))]
    #[name = "VoidwireServicesProvider"]
    struct ServicesProvider;

    impl ServicesProvider {
        /// `NSMessage` = `sendWithVoidwire` in Info.plist `NSServices`.
        #[unsafe(method(sendWithVoidwire:userData:error:))]
        fn send_with_voidwire(
            &self,
            pboard: &NSPasteboard,
            _user_data: Option<&NSString>,
            _error: *mut *mut NSString,
        ) {
            let Some(cb) = SEND_FILE.lock().ok().and_then(|g| g.clone()) else {
                return;
            };
            // SAFETY: an AppKit constant, valid for the life of the process.
            let t = unsafe { NSPasteboardTypeFileURL };
            let Some(items) = pboard.pasteboardItems() else {
                return;
            };
            for item in items.iter() {
                if let Some(url) = item.stringForType(t) {
                    if let Some(p) = super::parse_clipboard_file_uri_list(&url.to_string()) {
                        cb(p);
                    }
                }
            }
        }
    }
);

/// Offer "Send with Voidwire" in Finder's Services / Quick Actions menu:
/// each chosen file goes to `on_file`. Call once, after the app starts.
pub fn register_services(on_file: SendFileCallback) {
    if let Ok(mut g) = SEND_FILE.lock() {
        *g = Some(on_file);
    }
    dispatch2::run_on_main(|mtm: MainThreadMarker| {
        // SAFETY: `new` on an NSObject subclass with no ivars.
        let provider: Retained<ServicesProvider> =
            unsafe { msg_send![ServicesProvider::class(), new] };
        let app = NSApplication::sharedApplication(mtm);
        let obj: &AnyObject = &provider;
        // SAFETY: AppKit keeps a weak-ish reference; we leak `provider` so
        // it outlives the app.
        unsafe { app.setServicesProvider(Some(obj)) };
        std::mem::forget(provider);
        objc2_app_kit::NSUpdateDynamicServices();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes the real pasteboard, so it runs only where asked:
    /// `cargo test -p voidwire-os-theme -- --ignored` (macos-qa does).
    #[test]
    #[ignore = "uses the real pasteboard; macos-qa runs it"]
    fn private_text_is_concealed_and_cleared_only_while_unchanged() {
        assert!(set_private_clipboard_text("VW-TEST-1234"));
        assert!(clipboard_is_private());
        assert_eq!(get_clipboard_text().as_deref(), Some("VW-TEST-1234"));
        assert!(!clear_clipboard_if_text("something else"));
        assert!(clear_clipboard_if_text("VW-TEST-1234"));
        assert_eq!(get_clipboard_text(), None);

        assert!(set_clipboard_text("plain"));
        assert!(!clipboard_is_private());
        assert_eq!(get_clipboard_text().as_deref(), Some("plain"));
        assert!(clear_clipboard_if_text("plain"));
    }
}
