//! OS queries for the tray icon (C2 Relay icon set): is the Windows taskbar
//! light or dark, what is the system DPI, and block until the taskbar theme
//! setting changes. All the unsafe Win32 calls live here, so the tray app
//! (`voidwire-desktop`) keeps `#![forbid(unsafe_code)]`.
//!
//! Off Windows every query answers `None`: Linux reads its theme through GTK
//! in the app itself, and macOS uses a template image the system recolours.

/// Tray frames shipped in `desktop/icons/tray/` (px).
pub const TRAY_FRAMES: [u32; 6] = [16, 20, 24, 32, 40, 48];

/// The tray frame for a DPI: Windows draws the tray at 16 px × (dpi / 96).
/// Picks the nearest shipped frame (ties go to the larger one, which Windows
/// scales down more cleanly than up).
pub fn tray_frame_for_dpi(dpi: u32) -> u32 {
    let want = 16.0 * dpi.max(1) as f64 / 96.0;
    let mut best = TRAY_FRAMES[0];
    for f in TRAY_FRAMES {
        if (f as f64 - want).abs() <= (best as f64 - want).abs() {
            best = f;
        }
    }
    best
}

/// `SystemUsesLightTheme` (DWORD) → is the taskbar light? Missing → dark,
/// which is the Windows default.
pub fn taskbar_light_from_value(v: Option<u32>) -> bool {
    v == Some(1)
}

/// `AppsUseLightTheme` (DWORD) → should apps be light? Only an explicit 1
/// is light; missing/unknown → dark (dark by default unless the
/// OS explicitly says light).
pub fn apps_light_from_value(v: Option<u32>) -> bool {
    v == Some(1)
}

pub mod autostart;
#[cfg(target_os = "linux")]
mod gnome_shortcut;
#[cfg(target_os = "linux")]
mod linux_fm;
#[cfg(target_os = "macos")]
mod mac;
#[cfg(target_os = "linux")]
mod portal_shortcut;
#[cfg(target_os = "linux")]
mod x11_hotkey;

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, FALSE};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegGetValueW, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER,
        KEY_NOTIFY, KEY_READ, REG_NOTIFY_CHANGE_LAST_SET, RRF_RT_REG_DWORD,
    };
    use windows_sys::Win32::UI::HiDpi::GetDpiForSystem;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
    const VALUE: &str = "SystemUsesLightTheme";
    const APPS_VALUE: &str = "AppsUseLightTheme";

    pub fn system_uses_light_theme() -> Option<u32> {
        read_dword(VALUE)
    }

    pub fn apps_use_light_theme() -> Option<u32> {
        read_dword(APPS_VALUE)
    }

    fn read_dword(name: &str) -> Option<u32> {
        let (key, value) = (wide(KEY), wide(name));
        let mut data: u32 = 0;
        let mut len = std::mem::size_of::<u32>() as u32;
        // SAFETY: valid NUL-terminated wide strings; `data`/`len` describe a
        // 4-byte buffer and RRF_RT_REG_DWORD restricts the value to a DWORD.
        let rc = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                (&mut data as *mut u32).cast(),
                &mut len,
            )
        };
        (rc == ERROR_SUCCESS).then_some(data)
    }

    pub fn system_dpi() -> u32 {
        // SAFETY: no arguments; returns 96 when DPI awareness is unavailable.
        unsafe { GetDpiForSystem() }
    }

    /// Block until something under the Personalize key changes. `false` if the
    /// key can't be watched (then the caller stops watching).
    pub fn wait_for_change() -> bool {
        let key = wide(KEY);
        let mut h: HKEY = std::ptr::null_mut();
        // SAFETY: valid wide string; `h` receives the opened key.
        let rc = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                0,
                KEY_NOTIFY | KEY_READ,
                &mut h,
            )
        };
        if rc != ERROR_SUCCESS {
            return false;
        }
        // SAFETY: `h` is an open key; synchronous wait (no event handle).
        let rc = unsafe {
            RegNotifyChangeKeyValue(
                h,
                FALSE,
                REG_NOTIFY_CHANGE_LAST_SET,
                std::ptr::null_mut(),
                FALSE,
            )
        };
        // SAFETY: `h` was opened above and is closed exactly once.
        unsafe { RegCloseKey(h) };
        rc == ERROR_SUCCESS
    }

    pub fn pick_folder(initial_dir: Option<&std::path::Path>) -> Option<std::path::PathBuf> {
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::Foundation::MAX_PATH;
        use windows_sys::Win32::System::Com::{
            CoInitializeEx, CoTaskMemFree, COINIT_APARTMENTTHREADED,
        };
        use windows_sys::Win32::UI::Shell::{
            SHBrowseForFolderW, SHGetPathFromIDListW, BIF_NEWDIALOGSTYLE, BIF_RETURNONLYFSDIRS,
            BROWSEINFOW,
        };

        let _ = initial_dir;
        // SAFETY: initializes COM in STA mode on the calling worker thread; harmless if already initialized.
        let _ = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
        let title = wide("Choose download folder for incoming Voidwire files");
        let mut display_buf = [0u16; MAX_PATH as usize];
        let bi = BROWSEINFOW {
            hwndOwner: std::ptr::null_mut(),
            pidlRoot: std::ptr::null_mut(),
            pszDisplayName: display_buf.as_mut_ptr(),
            lpszTitle: title.as_ptr(),
            ulFlags: BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE,
            lpfn: None,
            lParam: 0,
            iImage: 0,
        };
        // SAFETY: `bi` points to valid stack buffers for the duration of the modal dialog.
        let pidl = unsafe { SHBrowseForFolderW(&bi) };
        if pidl.is_null() {
            return None;
        }
        let mut path_buf = [0u16; (MAX_PATH as usize) * 4];
        // SAFETY: `pidl` is non-null from SHBrowseForFolderW and `path_buf` is a writable wide buffer.
        let ok = unsafe { SHGetPathFromIDListW(pidl, path_buf.as_mut_ptr()) };
        // SAFETY: `pidl` was allocated by the Shell allocator and must be freed via CoTaskMemFree.
        unsafe { CoTaskMemFree(pidl.cast()) };
        if ok == FALSE {
            return None;
        }
        let len = path_buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(path_buf.len());
        if len == 0 {
            return None;
        }
        Some(std::path::PathBuf::from(std::ffi::OsString::from_wide(
            &path_buf[..len],
        )))
    }

    pub fn pick_file(initial_dir: Option<&std::path::Path>) -> Option<std::path::PathBuf> {
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::Foundation::MAX_PATH;
        use windows_sys::Win32::UI::Controls::Dialogs::{
            GetOpenFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST,
            OPENFILENAMEW,
        };

        let init_wide = initial_dir.and_then(|p| p.to_str()).map(wide);
        let title = wide("Choose file to send via Voidwire");
        let mut file_buf = [0u16; (MAX_PATH as usize) * 4];
        let mut ofn = OPENFILENAMEW {
            lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
            hwndOwner: std::ptr::null_mut(),
            hInstance: std::ptr::null_mut(),
            lpstrFilter: std::ptr::null(),
            lpstrCustomFilter: std::ptr::null_mut(),
            nMaxCustFilter: 0,
            nFilterIndex: 0,
            lpstrFile: file_buf.as_mut_ptr(),
            nMaxFile: file_buf.len() as u32,
            lpstrFileTitle: std::ptr::null_mut(),
            nMaxFileTitle: 0,
            lpstrInitialDir: init_wide.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
            lpstrTitle: title.as_ptr(),
            Flags: OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
            nFileOffset: 0,
            nFileExtension: 0,
            lpstrDefExt: std::ptr::null(),
            lCustData: 0,
            lpfnHook: None,
            lpTemplateName: std::ptr::null(),
            pvReserved: std::ptr::null_mut(),
            dwReserved: 0,
            FlagsEx: 0,
        };
        // SAFETY: `ofn` points to valid stack buffers for the duration of the modal dialog.
        let ok = unsafe { GetOpenFileNameW(&mut ofn) };
        if ok == FALSE {
            return None;
        }
        let len = file_buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(file_buf.len());
        if len == 0 {
            return None;
        }
        Some(std::path::PathBuf::from(std::ffi::OsString::from_wide(
            &file_buf[..len],
        )))
    }

    pub fn get_clipboard_text() -> Option<String> {
        use windows_sys::Win32::System::DataExchange::{
            CloseClipboard, GetClipboardData, OpenClipboard,
        };
        use windows_sys::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
        use windows_sys::Win32::System::Ole::CF_UNICODETEXT;

        // SAFETY: Opens the system clipboard for the current task.
        if unsafe { OpenClipboard(std::ptr::null_mut()) } == FALSE {
            return None;
        }
        let out = (|| {
            // SAFETY: Clipboard is open; CF_UNICODETEXT returns an HGLOBAL of UTF-16LE words.
            let h = unsafe { GetClipboardData(CF_UNICODETEXT as u32) };
            if h.is_null() {
                return None;
            }
            let byte_size = unsafe { GlobalSize(h) };
            if byte_size < 2 {
                return None;
            }
            let ptr = unsafe { GlobalLock(h) } as *const u16;
            if ptr.is_null() {
                return None;
            }
            let max_words = byte_size / 2;
            // SAFETY: `ptr` is locked global memory of at least `max_words` u16 elements.
            let slice = unsafe { std::slice::from_raw_parts(ptr, max_words) };
            let len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
            let s = String::from_utf16(&slice[..len]).ok();
            unsafe {
                let _ = GlobalUnlock(h);
            }
            s
        })();
        // SAFETY: Closes the clipboard opened above.
        unsafe {
            let _ = CloseClipboard();
        }
        out
    }

    pub fn set_clipboard_text(text: &str) -> bool {
        use windows_sys::Win32::Foundation::GlobalFree;
        use windows_sys::Win32::System::DataExchange::{
            CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
        };
        use windows_sys::Win32::System::Memory::{
            GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
        };
        use windows_sys::Win32::System::Ole::CF_UNICODETEXT;

        let wide_buf = wide(text);
        let byte_len = wide_buf.len() * 2;
        // SAFETY: Opens the system clipboard for the current task.
        if unsafe { OpenClipboard(std::ptr::null_mut()) } == FALSE {
            return false;
        }
        let ok = (|| {
            if unsafe { EmptyClipboard() } == FALSE {
                return false;
            }
            // SAFETY: Allocates moveable global memory for the UTF-16LE buffer.
            let h = unsafe { GlobalAlloc(GMEM_MOVEABLE, byte_len) };
            if h.is_null() {
                return false;
            }
            let dst = unsafe { GlobalLock(h) } as *mut u16;
            if dst.is_null() {
                unsafe {
                    let _ = GlobalFree(h);
                }
                return false;
            }
            // SAFETY: `dst` has capacity for `wide_buf.len()` u16 elements.
            unsafe {
                std::ptr::copy_nonoverlapping(wide_buf.as_ptr(), dst, wide_buf.len());
                let _ = GlobalUnlock(h);
            }
            // SAFETY: Transfers ownership of `h` to the system clipboard on success.
            let set_res = unsafe { SetClipboardData(CF_UNICODETEXT as u32, h) };
            if set_res.is_null() {
                unsafe {
                    let _ = GlobalFree(h);
                }
                return false;
            }
            true
        })();
        // SAFETY: Closes the clipboard opened above.
        unsafe {
            let _ = CloseClipboard();
        }
        ok
    }
    /// Put `bytes` on the open clipboard as `format`. The clipboard must be
    /// open and emptied by this task.
    fn put_clipboard_bytes(format: u32, bytes: &[u8]) -> bool {
        use windows_sys::Win32::Foundation::GlobalFree;
        use windows_sys::Win32::System::DataExchange::SetClipboardData;
        use windows_sys::Win32::System::Memory::{
            GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
        };
        // SAFETY: Allocates moveable global memory for `bytes` (at least 1 byte).
        let h = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1)) };
        if h.is_null() {
            return false;
        }
        let dst = unsafe { GlobalLock(h) } as *mut u8;
        if dst.is_null() {
            unsafe {
                let _ = GlobalFree(h);
            }
            return false;
        }
        // SAFETY: `dst` has room for `bytes.len()` bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
            let _ = GlobalUnlock(h);
        }
        // SAFETY: Hands `h` to the clipboard on success; freed here otherwise.
        if unsafe { SetClipboardData(format, h) }.is_null() {
            unsafe {
                let _ = GlobalFree(h);
            }
            return false;
        }
        true
    }

    fn registered_format(name: &str) -> u32 {
        use windows_sys::Win32::System::DataExchange::RegisterClipboardFormatW;
        let w = wide(name);
        // SAFETY: `w` is a NUL-terminated UTF-16 string.
        unsafe { RegisterClipboardFormatW(w.as_ptr()) }
    }

    /// Copy `text` marked private: clipboard monitors skip it
    /// (`ExcludeClipboardContentFromMonitorProcessing`), it stays out of
    /// Win+V history (`CanIncludeInClipboardHistory` = 0) and is never
    /// synced to other devices (`CanUploadToCloudClipboard` = 0).
    pub fn set_private_clipboard_text(text: &str) -> bool {
        use windows_sys::Win32::System::DataExchange::{
            CloseClipboard, EmptyClipboard, OpenClipboard,
        };
        use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
        let words = wide(text);
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let zero = 0u32.to_le_bytes();
        // SAFETY: Opens the system clipboard for the current task.
        if unsafe { OpenClipboard(std::ptr::null_mut()) } == FALSE {
            return false;
        }
        // SAFETY: The clipboard is open.
        let ok = unsafe { EmptyClipboard() } != FALSE
            // The markers go first so a monitor never sees the text unmarked.
            && put_clipboard_bytes(
                registered_format("ExcludeClipboardContentFromMonitorProcessing"),
                &zero,
            )
            && put_clipboard_bytes(registered_format("CanIncludeInClipboardHistory"), &zero)
            && put_clipboard_bytes(registered_format("CanUploadToCloudClipboard"), &zero)
            && put_clipboard_bytes(CF_UNICODETEXT as u32, &bytes);
        if !ok {
            // SAFETY: The clipboard is still open; drop a half-written copy.
            unsafe {
                let _ = EmptyClipboard();
            }
        }
        // SAFETY: Closes the clipboard opened above.
        unsafe {
            let _ = CloseClipboard();
        }
        ok
    }

    /// Whether the clipboard holds all three privacy markers.
    pub fn clipboard_is_private() -> bool {
        use windows_sys::Win32::System::DataExchange::IsClipboardFormatAvailable;
        [
            "ExcludeClipboardContentFromMonitorProcessing",
            "CanIncludeInClipboardHistory",
            "CanUploadToCloudClipboard",
        ]
        .iter()
        // SAFETY: Plain query; does not open the clipboard.
        .all(|n| unsafe { IsClipboardFormatAvailable(registered_format(n)) } != FALSE)
    }

    /// Empty the clipboard only if it still holds exactly `text`.
    pub fn clear_clipboard_if_text(text: &str) -> bool {
        use windows_sys::Win32::System::DataExchange::{
            CloseClipboard, EmptyClipboard, OpenClipboard,
        };
        if get_clipboard_text().as_deref() != Some(text) {
            return false;
        }
        // SAFETY: Opens the system clipboard for the current task.
        if unsafe { OpenClipboard(std::ptr::null_mut()) } == FALSE {
            return false;
        }
        // Check again with the clipboard held, so nothing slips in between.
        let same = (|| {
            use windows_sys::Win32::System::DataExchange::GetClipboardData;
            use windows_sys::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
            use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
            // SAFETY: The clipboard is open; CF_UNICODETEXT is an HGLOBAL of UTF-16LE words.
            let h = unsafe { GetClipboardData(CF_UNICODETEXT as u32) };
            if h.is_null() {
                return false;
            }
            let words = unsafe { GlobalSize(h) } / 2;
            let ptr = unsafe { GlobalLock(h) } as *const u16;
            if ptr.is_null() {
                return false;
            }
            // SAFETY: `ptr` is locked global memory of `words` u16 elements.
            let slice = unsafe { std::slice::from_raw_parts(ptr, words) };
            let len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
            let same = slice[..len].iter().copied().eq(text.encode_utf16());
            unsafe {
                let _ = GlobalUnlock(h);
            }
            same
        })();
        // SAFETY: The clipboard is open.
        let cleared = same && unsafe { EmptyClipboard() } != FALSE;
        // SAFETY: Closes the clipboard opened above.
        unsafe {
            let _ = CloseClipboard();
        }
        cleared
    }

    pub fn get_clipboard_file() -> Option<std::path::PathBuf> {
        match read_clipboard_file() {
            super::ClipboardFileRead::File(p) => Some(p),
            _ => None,
        }
    }

    /// Read the copied file (`CF_HDROP`), telling "no file" apart from "the
    /// clipboard is still held by another app" (Explorer keeps it open for a
    /// moment right after Ctrl+C).
    pub fn read_clipboard_file() -> super::ClipboardFileRead {
        use super::ClipboardFileRead;
        use windows_sys::Win32::System::DataExchange::IsClipboardFormatAvailable;
        const CF_HDROP_FORMAT: u32 = 15;
        // SAFETY: Plain query; does not open the clipboard.
        if unsafe { IsClipboardFormatAvailable(CF_HDROP_FORMAT) } == FALSE {
            return ClipboardFileRead::NoFile;
        }
        match open_and_read_hdrop() {
            None => ClipboardFileRead::Busy,
            Some(Some(p)) => ClipboardFileRead::File(p),
            Some(None) => ClipboardFileRead::NoFile,
        }
    }

    /// `None` when `OpenClipboard` failed (busy), else the parsed file.
    fn open_and_read_hdrop() -> Option<Option<std::path::PathBuf>> {
        use windows_sys::Win32::System::DataExchange::{
            CloseClipboard, GetClipboardData, OpenClipboard,
        };
        use windows_sys::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};

        const CF_HDROP_FORMAT: u32 = 15;
        // SAFETY: Opens the system clipboard for the current task.
        if unsafe { OpenClipboard(std::ptr::null_mut()) } == FALSE {
            return None;
        }
        let out = (|| {
            // SAFETY: Clipboard is open; CF_HDROP returns an HGLOBAL containing a DROPFILES header + file list.
            let h = unsafe { GetClipboardData(CF_HDROP_FORMAT) };
            if h.is_null() {
                return None;
            }
            let byte_size = unsafe { GlobalSize(h) };
            if byte_size < 22 {
                return None;
            }
            let ptr = unsafe { GlobalLock(h) } as *const u8;
            if ptr.is_null() {
                return None;
            }
            // SAFETY: `ptr` is locked global memory of `byte_size` bytes.
            let slice = unsafe { std::slice::from_raw_parts(ptr, byte_size) };
            let parsed = super::parse_cf_hdrop_bytes(slice);
            unsafe {
                let _ = GlobalUnlock(h);
            }
            parsed
        })();
        // SAFETY: Closes the clipboard opened above.
        unsafe {
            let _ = CloseClipboard();
        }
        Some(out.filter(|p| p.is_file()))
    }

    // ---- Live tray label (M3.1.2): WM_CLIPBOARDUPDATE listener ----
    mod clipwatch {

        use super::{read_clipboard_file, wide};
        use std::cell::RefCell;
        use windows_sys::Win32::Foundation::FALSE;
        use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
            HWND_MESSAGE, MSG, WNDCLASSW,
        };

        const WM_CLIPBOARDUPDATE: u32 = 0x031D;

        struct ClipWatchState {
            tracker: super::super::ClipboardFileTracker,
            on_change: super::super::ClipboardChangeCallback,
        }

        thread_local! {
            static CLIP_WATCH: RefCell<Option<ClipWatchState>> = const { RefCell::new(None) };
        }

        /// Read with a short retry while another app still holds the clipboard.
        fn read_clipboard_file_retrying() -> super::super::ClipboardFileRead {
            let mut last = super::super::ClipboardFileRead::Busy;
            for attempt in 0..super::super::CLIPBOARD_BUSY_RETRIES {
                last = read_clipboard_file();
                if !matches!(last, super::super::ClipboardFileRead::Busy) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(
                    super::super::CLIPBOARD_BUSY_RETRY_MS * (attempt as u64 + 1),
                ));
            }
            last
        }

        unsafe extern "system" fn clip_wndproc(
            hwnd: HWND,
            msg: u32,
            wparam: WPARAM,
            lparam: LPARAM,
        ) -> LRESULT {
            if msg == WM_CLIPBOARDUPDATE {
                let read = read_clipboard_file_retrying();
                let fire = CLIP_WATCH.with(|st| {
                    let mut st = st.borrow_mut();
                    let st = st.as_mut()?;
                    st.tracker.observe(&read).then(|| st.on_change.clone())
                });
                if let Some(cb) = fire {
                    cb();
                }
                return 0;
            }
            // SAFETY: default handling for every other message.
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }

        /// Start the listener thread: a message-only window registered with
        /// `AddClipboardFormatListener`. Never logs clipboard contents.
        pub fn watch_clipboard_files(on_change: super::super::ClipboardChangeCallback) -> bool {
            use windows_sys::Win32::System::DataExchange::AddClipboardFormatListener;
            use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
            let spawned = std::thread::Builder::new()
                .name("voidwire-clipwatch".into())
                .spawn(move || {
                    let initial = read_clipboard_file_retrying();
                    CLIP_WATCH.with(|st| {
                        *st.borrow_mut() = Some(ClipWatchState {
                            tracker: super::super::ClipboardFileTracker::primed(&initial),
                            on_change,
                        });
                    });
                    let class = wide("VoidwireClipboardWatch");
                    // SAFETY: NULL asks for this module's handle.
                    let hinst = unsafe { GetModuleHandleW(std::ptr::null()) };
                    let wc = WNDCLASSW {
                        style: 0,
                        lpfnWndProc: Some(clip_wndproc),
                        cbClsExtra: 0,
                        cbWndExtra: 0,
                        hInstance: hinst,
                        hIcon: std::ptr::null_mut(),
                        hCursor: std::ptr::null_mut(),
                        hbrBackground: std::ptr::null_mut(),
                        lpszMenuName: std::ptr::null(),
                        lpszClassName: class.as_ptr(),
                    };
                    // SAFETY: `wc` is fully initialised; `class` outlives the window.
                    unsafe { RegisterClassW(&wc) };
                    // SAFETY: message-only window (HWND_MESSAGE parent) of the class above.
                    let hwnd = unsafe {
                        CreateWindowExW(
                            0,
                            class.as_ptr(),
                            class.as_ptr(),
                            0,
                            0,
                            0,
                            0,
                            0,
                            HWND_MESSAGE,
                            std::ptr::null_mut(),
                            hinst,
                            std::ptr::null(),
                        )
                    };
                    if hwnd.is_null() {
                        return;
                    }
                    // SAFETY: `hwnd` is the live window created above, on this thread.
                    if unsafe { AddClipboardFormatListener(hwnd) } == FALSE {
                        return;
                    }
                    // SAFETY: zeroed MSG is a valid out-parameter.
                    let mut m: MSG = unsafe { std::mem::zeroed() };
                    // SAFETY: standard message loop for this thread's window.
                    while unsafe { GetMessageW(&mut m, std::ptr::null_mut(), 0, 0) } > 0 {
                        unsafe { DispatchMessageW(&m) };
                    }
                });
            spawned.is_ok()
        }
    }
    pub use clipwatch::watch_clipboard_files;

    #[repr(C)]
    struct HotkeyPoint {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    struct HotkeyMsg {
        hwnd: *mut core::ffi::c_void,
        message: u32,
        w_param: usize,
        l_param: isize,
        time: u32,
        pt: HotkeyPoint,
    }

    #[link(name = "user32")]
    extern "system" {
        fn RegisterHotKey(hwnd: *mut core::ffi::c_void, id: i32, fs_modifiers: u32, vk: u32)
            -> i32;
        fn UnregisterHotKey(hwnd: *mut core::ffi::c_void, id: i32) -> i32;
        fn GetMessageW(
            lp_msg: *mut HotkeyMsg,
            hwnd: *mut core::ffi::c_void,
            w_msg_filter_min: u32,
            w_msg_filter_max: u32,
        ) -> i32;
        fn PostThreadMessageW(id_thread: u32, msg: u32, w_param: usize, l_param: isize) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentThreadId() -> u32;
    }

    const HOTKEY_ID: i32 = 1;
    const WM_HOTKEY: u32 = 0x0312;
    const WM_APP_SYNC: u32 = 0x8001;

    struct HotkeyRequest {
        enabled: bool,
        mods: u32,
        vk: u32,
        accel: String,
        reply: std::sync::mpsc::SyncSender<Result<(), String>>,
    }

    static HOTKEY_ENABLED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    static HOTKEY_CALLBACK: std::sync::Mutex<Option<std::sync::Arc<dyn Fn() + Send + Sync>>> =
        std::sync::Mutex::new(None);
    static HOTKEY_WORKER: std::sync::OnceLock<(
        u32,
        std::sync::Mutex<std::sync::mpsc::Sender<HotkeyRequest>>,
    )> = std::sync::OnceLock::new();

    pub fn set_send_clipboard_hotkey_with_accel(
        enabled: bool,
        (mods, vk): (u32, u32),
        accel: &str,
        on_press: std::sync::Arc<dyn Fn() + Send + Sync>,
    ) -> Result<(), String> {
        HOTKEY_ENABLED.store(enabled, std::sync::atomic::Ordering::SeqCst);
        if let Ok(mut cb) = HOTKEY_CALLBACK.lock() {
            *cb = Some(on_press);
        }
        let (tid, req_tx) = HOTKEY_WORKER.get_or_init(|| {
            let (tid_tx, tid_rx) = std::sync::mpsc::channel();
            let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<HotkeyRequest>();
            let _ = std::thread::Builder::new()
                .name("voidwire-hotkey".into())
                .spawn(move || {
                    // SAFETY: Returns the calling Win32 thread identifier.
                    let tid = unsafe { GetCurrentThreadId() };
                    let mut msg: HotkeyMsg = unsafe { std::mem::zeroed() };
                    // Force creation of the thread message queue before publishing `tid`.
                    let _ = tid_tx.send(tid);
                    let mut registered = false;
                    // SAFETY: Blocks until a message arrives on this thread's message queue.
                    while unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) } > 0 {
                        if msg.message == WM_HOTKEY && msg.w_param == (HOTKEY_ID as usize) {
                            if HOTKEY_ENABLED.load(std::sync::atomic::Ordering::SeqCst) {
                                let cb = HOTKEY_CALLBACK.lock().ok().and_then(|g| g.clone());
                                if let Some(f) = cb {
                                    f();
                                }
                            }
                        } else if msg.message == WM_APP_SYNC {
                            while let Ok(req) = cmd_rx.try_recv() {
                                if registered {
                                    // SAFETY: Unregisters hotkey previously registered on this thread.
                                    unsafe {
                                        let _ = UnregisterHotKey(std::ptr::null_mut(), HOTKEY_ID);
                                    }
                                    registered = false;
                                }
                                if req.enabled {
                                    // SAFETY: Registers requested hotkey on this worker thread.
                                    let ok = unsafe {
                                        RegisterHotKey(
                                            std::ptr::null_mut(),
                                            HOTKEY_ID,
                                            req.mods,
                                            req.vk,
                                        )
                                    } != 0;
                                    if ok {
                                        registered = true;
                                        let _ = req.reply.send(Ok(()));
                                    } else {
                                        let _ = req.reply.send(Err(format!(
                                            "That shortcut ({}) is already in use by another app — pick a different key combination.",
                                            req.accel
                                        )));
                                    }
                                } else {
                                    let _ = req.reply.send(Ok(()));
                                }
                            }
                        }
                    }
                    if registered {
                        // SAFETY: Clean up hotkey before thread exit.
                        unsafe {
                            let _ = UnregisterHotKey(std::ptr::null_mut(), HOTKEY_ID);
                        }
                    }
                });
            let worker_tid = tid_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap_or(0);
            (worker_tid, std::sync::Mutex::new(cmd_tx))
        });

        let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
        if let Ok(tx) = req_tx.lock() {
            let _ = tx.send(HotkeyRequest {
                enabled,
                mods,
                vk,
                accel: accel.to_owned(),
                reply: reply_tx,
            });
        }
        if *tid != 0 {
            // SAFETY: Posts a thread message to wake `GetMessageW` on our hotkey worker thread.
            unsafe {
                let _ = PostThreadMessageW(*tid, WM_APP_SYNC, 0, 0);
            }
        }
        reply_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap_or(Ok(()))
    }
}

/// Windows: is the taskbar light (`SystemUsesLightTheme` = 1)? `None` off Windows.
pub fn taskbar_is_light() -> Option<bool> {
    #[cfg(windows)]
    {
        Some(taskbar_light_from_value(win::system_uses_light_theme()))
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Windows: should app windows be light (`AppsUseLightTheme` = 1)? `None`
/// off Windows (the app decides there).
pub fn apps_are_light() -> Option<bool> {
    #[cfg(windows)]
    {
        Some(apps_light_from_value(win::apps_use_light_theme()))
    }
    #[cfg(target_os = "macos")]
    {
        Some(mac::apps_are_light())
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        None
    }
}

/// Windows: the system DPI (96 = 100 %). `None` off Windows.
pub fn system_dpi() -> Option<u32> {
    #[cfg(windows)]
    {
        Some(win::system_dpi())
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Windows: block until the taskbar/app theme settings change; `false` when
/// that can't be watched (always `false` off Windows).
pub fn wait_for_theme_change() -> bool {
    #[cfg(windows)]
    {
        win::wait_for_change()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Windows: open the native Shell folder picker dialog and return the selected
/// folder path, or `None` if canceled or off Windows.
pub fn pick_folder(initial_dir: Option<&std::path::Path>) -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        win::pick_folder(initial_dir)
    }
    #[cfg(target_os = "macos")]
    {
        mac::pick_folder(initial_dir)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = initial_dir;
        None
    }
}

/// Windows: open the native file picker dialog and return the selected file path,
/// or `None` if canceled or off Windows (`M3.1`).
pub fn pick_file(initial_dir: Option<&std::path::Path>) -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        win::pick_file(initial_dir)
    }
    #[cfg(target_os = "macos")]
    {
        mac::pick_file(initial_dir)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = initial_dir;
        None
    }
}

/// Windows: read UTF-8 text from the OS clipboard, or `None` off Windows (`M3.1`).
pub fn get_clipboard_text() -> Option<String> {
    #[cfg(windows)]
    {
        win::get_clipboard_text()
    }
    #[cfg(target_os = "macos")]
    {
        mac::get_clipboard_text()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        None
    }
}

/// Windows: write UTF-8 text to the OS clipboard (`false` off Windows, `M3.1`).
pub fn set_clipboard_text(text: &str) -> bool {
    #[cfg(windows)]
    {
        win::set_clipboard_text(text)
    }
    #[cfg(target_os = "macos")]
    {
        mac::set_clipboard_text(text)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = text;
        false
    }
}

/// Windows: copy `text` so clipboard history, cloud sync and clipboard
/// monitors leave it alone (v0.7.1, pairing codes). `false` off Windows.
pub fn set_private_clipboard_text(text: &str) -> bool {
    #[cfg(windows)]
    {
        win::set_private_clipboard_text(text)
    }
    #[cfg(target_os = "macos")]
    {
        mac::set_private_clipboard_text(text)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = text;
        false
    }
}

/// Windows: whether the clipboard carries the three privacy markers.
pub fn clipboard_is_private() -> bool {
    #[cfg(windows)]
    {
        win::clipboard_is_private()
    }
    #[cfg(target_os = "macos")]
    {
        mac::clipboard_is_private()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        false
    }
}

/// Windows: empty the clipboard only if it still holds exactly `text`, so
/// something the user copied since is never wiped. `false` off Windows.
pub fn clear_clipboard_if_text(text: &str) -> bool {
    #[cfg(windows)]
    {
        win::clear_clipboard_if_text(text)
    }
    #[cfg(target_os = "macos")]
    {
        mac::clear_clipboard_if_text(text)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = text;
        false
    }
}

/// Parse a Win32 `CF_HDROP` (`DROPFILES`) memory block and return the first file path.
pub fn parse_cf_hdrop_bytes(bytes: &[u8]) -> Option<std::path::PathBuf> {
    if bytes.len() < 20 {
        return None;
    }
    let p_files = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let f_wide = i32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) != 0;
    if p_files < 20 || p_files >= bytes.len() {
        return None;
    }
    let tail = &bytes[p_files..];
    if f_wide {
        let mut units = Vec::with_capacity(tail.len() / 2);
        for &chunk in tail.as_chunks::<2>().0 {
            let ch = u16::from_le_bytes(chunk);
            if ch == 0 {
                break;
            }
            units.push(ch);
        }
        if units.is_empty() {
            return None;
        }
        let s = String::from_utf16(&units).ok()?;
        Some(std::path::PathBuf::from(s))
    } else {
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        if end == 0 {
            return None;
        }
        let s = std::str::from_utf8(&tail[..end]).ok()?;
        Some(std::path::PathBuf::from(s))
    }
}

fn percent_decode_path(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16)?;
            let lo = (bytes[i + 2] as char).to_digit(16)?;
            out.push(((hi << 4) | lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Parse a Linux `text/uri-list` or `x-special/gnome-copied-files` payload into a local `PathBuf`.
pub fn parse_clipboard_file_uri_list(raw: &str) -> Option<std::path::PathBuf> {
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.eq_ignore_ascii_case("copy")
            || trimmed.eq_ignore_ascii_case("cut")
        {
            continue;
        }
        let rest = if let Some(r) = trimmed.strip_prefix("file://localhost/") {
            format!("/{r}")
        } else if let Some(r) = trimmed.strip_prefix("file:///") {
            if r.as_bytes().get(1) == Some(&b':') {
                r.to_owned()
            } else {
                format!("/{r}")
            }
        } else {
            continue;
        };
        let decoded = percent_decode_path(&rest)?;
        if !decoded.is_empty() {
            return Some(std::path::PathBuf::from(decoded));
        }
    }
    None
}

/// One read of the clipboard's copied-file slot (`CF_HDROP`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardFileRead {
    /// No copied file (text, image, or empty clipboard).
    NoFile,
    /// A copied file.
    File(std::path::PathBuf),
    /// Another app still has the clipboard open: unknown, keep the old label.
    Busy,
}

/// Retries while another app holds the clipboard (Explorer, right after Ctrl+C).
pub const CLIPBOARD_BUSY_RETRIES: u32 = 4;
/// Back-off step between busy retries (ms; grows linearly).
pub const CLIPBOARD_BUSY_RETRY_MS: u64 = 25;

/// Called on the listener thread when the copied file's name changes.
pub type ClipboardChangeCallback = std::sync::Arc<dyn Fn() + Send + Sync>;

/// The name the tray shows for a copied file (`"Send copied file (name)"`):
/// the last path component, `None` for no file.
pub fn copied_file_label_name(path: Option<&std::path::Path>) -> Option<String> {
    let p = path?;
    let name = p.file_name()?.to_string_lossy().into_owned();
    (!name.is_empty()).then_some(name)
}

/// Change detection for the live tray label: fires only when the copied
/// file's *name* changes (copying text after text, or the same file twice,
/// doesn't rebuild the menu). A busy read never counts as a change.
#[derive(Debug, Clone, Default)]
pub struct ClipboardFileTracker {
    last: Option<String>,
}

impl ClipboardFileTracker {
    /// Start from the clipboard as it is now (the tray was built from it).
    pub fn primed(initial: &ClipboardFileRead) -> Self {
        let mut t = Self::default();
        let _ = t.observe(initial);
        t
    }

    /// Feed a new read; `true` when the tray label must change.
    pub fn observe(&mut self, read: &ClipboardFileRead) -> bool {
        let name = match read {
            ClipboardFileRead::Busy => return false,
            ClipboardFileRead::NoFile => None,
            ClipboardFileRead::File(p) => copied_file_label_name(Some(p)),
        };
        if name == self.last {
            return false;
        }
        self.last = name;
        true
    }
}

/// Windows: keep the tray's "Send copied file (name)" label live. Starts a
/// background clipboard listener (`WM_CLIPBOARDUPDATE`) that calls
/// `on_change` only when the copied file's name changes. Returns `false` off
/// Windows or if the thread couldn't start. Never logs clipboard contents.
pub fn watch_clipboard_files(on_change: ClipboardChangeCallback) -> bool {
    #[cfg(windows)]
    {
        static STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return true;
        }
        win::watch_clipboard_files(on_change)
    }
    #[cfg(not(windows))]
    {
        let _ = on_change;
        false
    }
}

/// Windows: read a copied file path (`CF_HDROP`) from the OS clipboard (`None` off Windows).
pub fn get_clipboard_file() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        win::get_clipboard_file()
    }
    #[cfg(target_os = "macos")]
    {
        mac::get_clipboard_file()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        None
    }
}

const MOD_ALT_FLAG: u32 = 0x0001;
const MOD_CONTROL_FLAG: u32 = 0x0002;
const MOD_SHIFT_FLAG: u32 = 0x0004;
const MOD_WIN_FLAG: u32 = 0x0008;
const MOD_NOREPEAT_FLAG: u32 = 0x4000;

/// Parse a human-readable shortcut accelerator (e.g. `"Ctrl+Shift+V"`, `"Ctrl+Alt+S"`,
/// `"Alt+F9"`, `"Ctrl+Shift+Space"`) into Win32 `(fsModifiers, vk)`.
/// Requires at least one modifier (`Ctrl`, `Alt`, `Shift`, or `Win`/`Super`/`Meta`)
/// and exactly one non-modifier key (`M3.1.1`).
pub fn parse_hotkey_accel(accel: &str) -> Result<(u32, u32), String> {
    let mut mods: u32 = 0;
    let mut vk: Option<u32> = None;

    for raw_part in accel.split('+') {
        let part = raw_part.trim();
        if part.is_empty() {
            continue;
        }
        let upper = part.to_ascii_uppercase();
        match upper.as_str() {
            "CTRL" | "CONTROL" => mods |= MOD_CONTROL_FLAG,
            "ALT" | "OPTION" => mods |= MOD_ALT_FLAG,
            "SHIFT" => mods |= MOD_SHIFT_FLAG,
            "WIN" | "SUPER" | "META" | "COMMAND" => mods |= MOD_WIN_FLAG,
            _ => {
                if vk.is_some() {
                    return Err(format!("Shortcut '{accel}' has multiple main keys."));
                }
                let code = match upper.as_str() {
                    s if s.len() == 1 && s.as_bytes()[0].is_ascii_uppercase() => {
                        s.as_bytes()[0] as u32
                    }
                    s if s.len() == 1 && s.as_bytes()[0].is_ascii_digit() => s.as_bytes()[0] as u32,
                    "F1" => 0x70,
                    "F2" => 0x71,
                    "F3" => 0x72,
                    "F4" => 0x73,
                    "F5" => 0x74,
                    "F6" => 0x75,
                    "F7" => 0x76,
                    "F8" => 0x77,
                    "F9" => 0x78,
                    "F10" => 0x79,
                    "F11" => 0x7A,
                    "F12" => 0x7B,
                    "SPACE" => 0x20,
                    "TAB" => 0x09,
                    "ENTER" | "RETURN" => 0x0D,
                    "BACKSPACE" => 0x08,
                    "INSERT" => 0x2D,
                    "DELETE" => 0x2E,
                    "HOME" => 0x24,
                    "END" => 0x23,
                    "PAGEUP" => 0x21,
                    "PAGEDOWN" => 0x22,
                    "UP" | "ARROWUP" => 0x26,
                    "DOWN" | "ARROWDOWN" => 0x28,
                    "LEFT" | "ARROWLEFT" => 0x25,
                    "RIGHT" | "ARROWRIGHT" => 0x27,
                    ";" | "SEMICOLON" => 0xBA,
                    "=" | "EQUAL" | "PLUS" => 0xBB,
                    "," | "COMMA" => 0xBC,
                    "-" | "MINUS" => 0xBD,
                    "." | "PERIOD" => 0xBE,
                    "/" | "SLASH" => 0xBF,
                    "`" | "BACKQUOTE" => 0xC0,
                    "[" | "BRACKETLEFT" => 0xDB,
                    "\\" | "BACKSLASH" => 0xDC,
                    "]" | "BRACKETRIGHT" => 0xDD,
                    "'" | "QUOTE" => 0xDE,
                    _ => return Err(format!("Unsupported key '{part}' in shortcut '{accel}'.")),
                };
                vk = Some(code);
            }
        }
    }

    if mods == 0 {
        return Err("Shortcut must include at least one modifier (Ctrl, Alt, or Shift).".into());
    }
    let Some(key_code) = vk else {
        return Err("Shortcut must include a non-modifier key (e.g. A–Z, 0–9, F1–F12).".into());
    };
    Ok((mods | MOD_NOREPEAT_FLAG, key_code))
}

/// macOS: the Carbon modifier mask for Win32-style `MOD_*` flags (the
/// Win/Super/Meta/Cmd key is Command).
pub fn mac_modifiers(mods: u32) -> u32 {
    const CMD: u32 = 1 << 8;
    const SHIFT: u32 = 1 << 9;
    const OPTION: u32 = 1 << 11;
    const CONTROL: u32 = 1 << 12;
    let mut out = 0;
    if mods & MOD_WIN_FLAG != 0 {
        out |= CMD;
    }
    if mods & MOD_SHIFT_FLAG != 0 {
        out |= SHIFT;
    }
    if mods & MOD_ALT_FLAG != 0 {
        out |= OPTION;
    }
    if mods & MOD_CONTROL_FLAG != 0 {
        out |= CONTROL;
    }
    out
}

/// macOS: the ANSI-layout virtual key code (`kVK_*`) for a Win32 virtual
/// key from `parse_hotkey_accel`; `None` for keys a Mac keyboard lacks
/// (Insert).
pub fn mac_key_code(vk: u32) -> Option<u32> {
    const LETTERS: [u32; 26] = [
        0x00, 0x0B, 0x08, 0x02, 0x0E, 0x03, 0x05, 0x04, 0x22, 0x26, 0x28, 0x25, 0x2E, 0x2D, 0x1F,
        0x23, 0x0C, 0x0F, 0x01, 0x11, 0x20, 0x09, 0x0D, 0x07, 0x10, 0x06,
    ];
    const DIGITS: [u32; 10] = [0x1D, 0x12, 0x13, 0x14, 0x15, 0x17, 0x16, 0x1A, 0x1C, 0x19];
    const F_KEYS: [u32; 12] = [
        0x7A, 0x78, 0x63, 0x76, 0x60, 0x61, 0x62, 0x64, 0x65, 0x6D, 0x67, 0x6F,
    ];
    Some(match vk {
        0x41..=0x5A => LETTERS[(vk - 0x41) as usize],
        0x30..=0x39 => DIGITS[(vk - 0x30) as usize],
        0x70..=0x7B => F_KEYS[(vk - 0x70) as usize],
        0x20 => 0x31,
        0x09 => 0x30,
        0x0D => 0x24,
        0x08 => 0x33,
        0x2E => 0x75,
        0x24 => 0x73,
        0x23 => 0x77,
        0x21 => 0x74,
        0x22 => 0x79,
        0x26 => 0x7E,
        0x28 => 0x7D,
        0x25 => 0x7B,
        0x27 => 0x7C,
        0xBA => 0x29,
        0xBB => 0x18,
        0xBC => 0x2B,
        0xBD => 0x1B,
        0xBE => 0x2F,
        0xBF => 0x2C,
        0xC0 => 0x32,
        0xDB => 0x21,
        0xDC => 0x2A,
        0xDD => 0x1E,
        0xDE => 0x27,
        _ => return None,
    })
}

/// Windows (`M3.1.1`) and Linux X11 (M5.1): register or unregister the global
/// send-clipboard shortcut.
/// Returns `Err` if `accel` cannot be parsed or if `RegisterHotKey` fails on Windows
/// because another app has already registered that key combination.
pub fn set_send_clipboard_hotkey_with_accel(
    enabled: bool,
    accel: &str,
    on_press: std::sync::Arc<dyn Fn() + Send + Sync>,
) -> Result<(), String> {
    let parsed = parse_hotkey_accel(accel)?;
    #[cfg(windows)]
    {
        win::set_send_clipboard_hotkey_with_accel(enabled, parsed, accel, on_press)
    }
    #[cfg(target_os = "linux")]
    {
        if portal_shortcut::wayland_session() {
            // L3: the desktop's own dialog; blocks until the user answers.
            return portal_shortcut::set(enabled, accel, on_press).map(|_| ());
        }
        x11_hotkey::set(enabled, parsed, accel, on_press)
    }
    #[cfg(target_os = "macos")]
    {
        mac::set_send_clipboard_hotkey(enabled, parsed, accel, on_press)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (enabled, parsed, on_press);
        Ok(())
    }
}

/// How the send-clipboard shortcut is set on this desktop (M5.1, L3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortcutKind {
    /// Voidwire records and grabs the keys (Windows, Linux X11).
    Keys,
    /// The desktop's GlobalShortcuts portal picks and owns the keys (Wayland).
    Portal,
    /// Wayland without the portal (e.g. GNOME 46): not available here.
    Unavailable,
}

/// The shortcut's kind here. Never blocks: before the portal check has
/// finished (it runs with the first shortcut sync at startup) this says
/// `Portal`.
pub fn send_clipboard_shortcut_kind() -> ShortcutKind {
    #[cfg(target_os = "linux")]
    {
        if portal_shortcut::wayland_session() {
            return match portal_shortcut::checked() {
                Some(false) => ShortcutKind::Unavailable,
                _ => ShortcutKind::Portal,
            };
        }
    }
    ShortcutKind::Keys
}

/// The keys the desktop bound for the portal shortcut, as it describes them,
/// while it is on (Wayland).
pub fn send_clipboard_shortcut_trigger() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        portal_shortcut::trigger().filter(|t| !t.is_empty())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// GNOME without the portal: the "Add shortcut in GNOME settings" state
/// (`gnome_shortcut`). `None`: not offered (not GNOME, or the app sets its
/// own keys and none was added); `Some(None)`: offered, not added;
/// `Some(Some(keys))`: added, with the keys GNOME has for it.
pub fn gnome_shortcut_state() -> Option<Option<String>> {
    #[cfg(target_os = "linux")]
    {
        if !gnome_shortcut::available() {
            return None;
        }
        let added = gnome_shortcut::status();
        (added.is_some() || send_clipboard_shortcut_kind() == ShortcutKind::Unavailable)
            .then_some(added)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Add (or update) the GNOME custom shortcut for `accel`, running this app
/// (`$APPIMAGE` for an AppImage) with `--send-clipboard`. Returns the keys.
pub fn gnome_shortcut_add(accel: &str) -> std::io::Result<String> {
    #[cfg(target_os = "linux")]
    {
        if !gnome_shortcut::available() {
            return Err(std::io::Error::other(
                "GNOME settings aren't available here.",
            ));
        }
        let exe = native_host_exe_path(std::env::current_exe()?, std::env::var_os("APPIMAGE"));
        gnome_shortcut::add(accel, &exe)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = accel;
        Err(std::io::Error::other("GNOME only"))
    }
}

/// Remove the GNOME custom shortcut (other custom shortcuts stay).
pub fn gnome_shortcut_remove() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        gnome_shortcut::remove()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

/// The activation token the last portal shortcut press came with (once), so
/// a window shown for it may take focus.
pub fn take_shortcut_activation_token() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        portal_shortcut::take_activation_token()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// A Wayland session (Linux); `false` elsewhere.
pub fn wayland_session() -> bool {
    #[cfg(target_os = "linux")]
    {
        portal_shortcut::wayland_session()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// macOS: call `on_change` when the system Light/Dark appearance flips
/// (event-driven). `false` elsewhere (Windows and Linux have their own).
pub fn watch_theme_changes(on_change: std::sync::Arc<dyn Fn() + Send + Sync>) -> bool {
    #[cfg(target_os = "macos")]
    {
        mac::watch_theme_changes(on_change);
        true
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = on_change;
        false
    }
}

/// macOS (M2): offer Finder's "Send with Voidwire" service; each chosen
/// file goes to `on_file`. `false` elsewhere.
pub fn register_finder_services(
    on_file: std::sync::Arc<dyn Fn(std::path::PathBuf) + Send + Sync>,
) -> bool {
    #[cfg(target_os = "macos")]
    {
        mac::register_services(on_file);
        true
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = on_file;
        false
    }
}

// ---------------------------------------------------------------------------
// M3.2: Current-user-only local IPC pipe & OS integration registration
// (`AUTH-13`: send/status-only pipe; current-user SDDL DACL +
// `PIPE_REJECT_REMOTE_CLIENTS` on Windows; `0700` dir + `0600` socket on Unix).
// ---------------------------------------------------------------------------

/// Native Messaging host identifier registered for Chromium and Firefox browsers.
pub const NATIVE_HOST_NAME: &str = "app.voidwire.native_host";
/// Deterministic Chromium extension ID derived from the public key in
/// `extension/manifest.json` (the unpacked / developer install).
pub const CHROMIUM_EXTENSION_ID: &str = "mknbkjlaloblibdffcebiegchmcbmpbm";
/// The ID Microsoft Edge Add-ons gave the published extension.
pub const EDGE_ADDONS_EXTENSION_ID: &str = "gdcjokipaeghnjfcbnjeofbealnkdgbh";
/// Every Chromium extension ID allowed to start the native host. Each
/// becomes a `chrome-extension://<id>/` entry in `allowed_origins` of the
/// one Chromium host manifest that all Chromium browsers (Chrome, Edge,
/// Brave, Chromium, Vivaldi) use on Windows, macOS and Linux.
pub const CHROMIUM_EXTENSION_IDS: &[&str] = &[
    CHROMIUM_EXTENSION_ID,
    EDGE_ADDONS_EXTENSION_ID,
    // Chrome Web Store ID: pending. Add it here as one more line.
];
/// Deterministic Firefox add-on ID in `extension/manifest.firefox.json`.
pub const FIREFOX_EXTENSION_ID: &str = "extension@voidwire.app";
/// Maximum frame payload size (`1 MiB`) for Native Messaging stdio and local IPC.
pub const MAX_IPC_FRAME_BYTES: usize = 1024 * 1024;

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Read a `u32` little-endian length-prefixed frame (`<= 1 MiB`).
/// Returns `Ok(None)` on clean EOF before the first length byte.
pub fn read_ipc_frame<R: std::io::Read>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    let mut read_len = 0usize;
    while read_len < 4 {
        match r.read(&mut len_buf[read_len..]) {
            Ok(0) if read_len == 0 => return Ok(None),
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated IPC frame length",
                ))
            }
            Ok(n) => read_len += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_IPC_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid IPC frame length: {len}"),
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some(payload))
}

/// Write a `u32` little-endian length-prefixed frame (`<= 1 MiB`) and flush.
pub fn write_ipc_frame<W: std::io::Write>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    if payload.is_empty() || payload.len() > MAX_IPC_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid IPC frame length: {}", payload.len()),
        ));
    }
    let len = (payload.len() as u32).to_le_bytes();
    w.write_all(&len)?;
    w.write_all(payload)?;
    w.flush()
}

fn json_escape_path(path: &std::path::Path) -> String {
    let mut out = String::new();
    for ch in path.to_string_lossy().chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

/// Render the Chromium Native Messaging host manifest JSON for `exe_path`.
pub fn render_chromium_native_host_manifest(exe_path: &std::path::Path) -> String {
    let escaped = json_escape_path(exe_path);
    let origins = CHROMIUM_EXTENSION_IDS
        .iter()
        .map(|id| format!("    \"chrome-extension://{id}/\""))
        .collect::<Vec<_>>()
        .join(",\n");
    format!(
        "{{\n  \"name\": \"{NATIVE_HOST_NAME}\",\n  \"description\": \"Voidwire Desktop Native Messaging Host\",\n  \"path\": \"{escaped}\",\n  \"type\": \"stdio\",\n  \"allowed_origins\": [\n{origins}\n  ]\n}}\n"
    )
}

/// Render the Firefox Native Messaging host manifest JSON for `exe_path`.
pub fn render_firefox_native_host_manifest(exe_path: &std::path::Path) -> String {
    let escaped = json_escape_path(exe_path);
    format!(
        "{{\n  \"name\": \"{NATIVE_HOST_NAME}\",\n  \"description\": \"Voidwire Desktop Native Messaging Host\",\n  \"path\": \"{escaped}\",\n  \"type\": \"stdio\",\n  \"allowed_extensions\": [\n    \"{FIREFOX_EXTENSION_ID}\"\n  ]\n}}\n"
    )
}

fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(path)?.write_all(bytes)
}

/// Write both Chromium and Firefox Native Messaging manifests into `dir`.
pub fn write_native_host_manifests_to(
    dir: &std::path::Path,
    exe_path: &std::path::Path,
) -> std::io::Result<(std::path::PathBuf, std::path::PathBuf)> {
    std::fs::create_dir_all(dir)?;
    let chromium_path = dir.join(format!("{NATIVE_HOST_NAME}.chromium.json"));
    let firefox_path = dir.join(format!("{NATIVE_HOST_NAME}.firefox.json"));
    write_private_file(
        &chromium_path,
        render_chromium_native_host_manifest(exe_path).as_bytes(),
    )?;
    write_private_file(
        &firefox_path,
        render_firefox_native_host_manifest(exe_path).as_bytes(),
    )?;
    Ok((chromium_path, firefox_path))
}

#[cfg(windows)]
mod win_ipc {
    use super::{
        fnv1a64, read_ipc_frame, write_ipc_frame, write_native_host_manifests_to, NATIVE_HOST_NAME,
    };
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY,
        ERROR_PIPE_CONNECTED, ERROR_SUCCESS, FALSE, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FlushFileBuffers, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW,
        PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
        PIPE_WAIT,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyValueW, RegDeleteTreeW, RegGetValueW,
        RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
        RRF_RT_ANY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn current_user_sid_string() -> std::io::Result<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: `GetCurrentProcess()` returns a pseudo-handle; `token` receives the process token.
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if ok == FALSE || token.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let mut needed: u32 = 0;
        // SAFETY: First call queries required buffer size for `TokenUser`.
        unsafe {
            let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        }
        if needed == 0 {
            // SAFETY: `token` was opened above.
            unsafe {
                let _ = CloseHandle(token);
            }
            return Err(std::io::Error::last_os_error());
        }
        let mut buf = vec![0u8; needed as usize];
        // SAFETY: `buf` has size `needed` bytes as requested by `GetTokenInformation`.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        // SAFETY: `token` is no longer needed once `buf` is populated.
        unsafe {
            let _ = CloseHandle(token);
        }
        if ok == FALSE {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `buf` begins with a valid `TOKEN_USER` struct whose `User.Sid` points inside `buf`.
        let user_sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
        let mut sid_str_ptr: *mut u16 = std::ptr::null_mut();
        // SAFETY: `user_sid` is a valid SID; `sid_str_ptr` receives a LocalAlloc'd wide string.
        let ok = unsafe { ConvertSidToStringSidW(user_sid, &mut sid_str_ptr) };
        if ok == FALSE || sid_str_ptr.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `sid_str_ptr` is NUL-terminated UTF-16 allocated by `ConvertSidToStringSidW`.
        let sid_string = unsafe {
            let mut len = 0usize;
            while *sid_str_ptr.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(sid_str_ptr, len);
            String::from_utf16_lossy(slice)
        };
        // SAFETY: `sid_str_ptr` must be freed via `LocalFree`.
        unsafe {
            let _ = LocalFree(sid_str_ptr as HLOCAL);
        }
        Ok(sid_string)
    }

    /// Return the SDDL string used to lock the Named Pipe DACL strictly to `sid`.
    pub fn current_user_pipe_sddl(sid: &str) -> String {
        // D:P = Protected DACL (blocks inherited ACEs);
        // (A;;GA;;;<sid>) = Allow Generic All exclusively to the current user SID.
        format!("D:P(A;;GA;;;{sid})")
    }

    pub fn ipc_pipe_name() -> std::io::Result<String> {
        let sid = current_user_sid_string()?;
        if let Some(dir) = std::env::var_os("VOIDWIRE_DATA_DIR").filter(|s| !s.is_empty()) {
            let h = fnv1a64(dir.to_string_lossy().as_bytes());
            Ok(format!(r"\\.\pipe\voidwire-ipc-{sid}-{h:016x}"))
        } else {
            Ok(format!(r"\\.\pipe\voidwire-ipc-{sid}"))
        }
    }

    fn create_pipe_instance(pipe_name: &str, sid: &str) -> std::io::Result<std::fs::File> {
        let sddl = wide(&current_user_pipe_sddl(sid));
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `sddl` is a valid NUL-terminated SDDL string; `sd` receives the allocated descriptor.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == FALSE || sd.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: FALSE,
        };
        let name_w = wide(pipe_name);
        // AUTH-13: PIPE_REJECT_REMOTE_CLIENTS rejects remote SMB connections in the kernel;
        // `sa` enforces current-user-only access via the protected DACL.
        let pipe_mode =
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        // SAFETY: `name_w` and `sa` are valid for the duration of `CreateNamedPipeW`.
        let h = unsafe {
            CreateNamedPipeW(
                name_w.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                pipe_mode,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                5000,
                &sa,
            )
        };
        // SAFETY: `sd` was allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
        unsafe {
            let _ = LocalFree(sd as HLOCAL);
        }
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `h` is a valid, newly created Named Pipe handle owned by this `File`.
        Ok(unsafe { std::fs::File::from_raw_handle(h as _) })
    }

    pub struct IpcServer {
        pipe_name: String,
        sid: String,
        next_pipe: Option<std::fs::File>,
    }

    impl IpcServer {
        pub fn bind() -> std::io::Result<Self> {
            let sid = current_user_sid_string()?;
            let pipe_name = ipc_pipe_name()?;
            let first = create_pipe_instance(&pipe_name, &sid)?;
            Ok(Self {
                pipe_name,
                sid,
                next_pipe: Some(first),
            })
        }

        pub fn accept_and_serve<F>(&mut self, mut handler: F) -> std::io::Result<()>
        where
            F: FnMut(&[u8]) -> Vec<u8>,
        {
            let mut pipe = match self.next_pipe.take() {
                Some(p) => p,
                None => create_pipe_instance(&self.pipe_name, &self.sid)?,
            };
            let raw_h = pipe.as_raw_handle() as HANDLE;
            // SAFETY: `raw_h` is a valid Named Pipe server handle.
            let connected = unsafe { ConnectNamedPipe(raw_h, std::ptr::null_mut()) };
            if connected == FALSE {
                // SAFETY: Reading thread-local Win32 error immediately after `ConnectNamedPipe`.
                let err = unsafe { GetLastError() };
                if err != ERROR_PIPE_CONNECTED {
                    self.next_pipe = create_pipe_instance(&self.pipe_name, &self.sid).ok();
                    return Err(std::io::Error::from_raw_os_error(err as i32));
                }
            }
            // Pre-create the next instance so back-to-back clients never see `ERROR_FILE_NOT_FOUND`.
            self.next_pipe = create_pipe_instance(&self.pipe_name, &self.sid).ok();

            let res = (|| -> std::io::Result<()> {
                if let Some(req) = read_ipc_frame(&mut pipe)? {
                    let resp = handler(&req);
                    write_ipc_frame(&mut pipe, &resp)?;
                    // SAFETY: Flush and disconnect the server pipe instance cleanly before closing.
                    unsafe {
                        let _ = FlushFileBuffers(raw_h);
                    }
                }
                Ok(())
            })();
            // SAFETY: `raw_h` is the connected server pipe instance; disconnect before `pipe` drops.
            unsafe {
                let _ = DisconnectNamedPipe(raw_h);
            }
            res
        }
    }

    pub fn ipc_exchange(req_payload: &[u8]) -> std::io::Result<Vec<u8>> {
        let pipe_name = ipc_pipe_name()?;
        let name_w = wide(&pipe_name);
        let mut handle: HANDLE = INVALID_HANDLE_VALUE;
        for _ in 0..20 {
            // SAFETY: `name_w` is a valid NUL-terminated wide string.
            let h = unsafe {
                CreateFileW(
                    name_w.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE && !h.is_null() {
                handle = h;
                break;
            }
            // SAFETY: Immediate `GetLastError` check after `CreateFileW`.
            let err = unsafe { GetLastError() };
            if err == ERROR_PIPE_BUSY {
                // SAFETY: `name_w` is a valid NUL-terminated wide string.
                unsafe {
                    let _ = WaitNamedPipeW(name_w.as_ptr(), 100);
                }
                continue;
            }
            return Err(std::io::Error::from_raw_os_error(err as i32));
        }
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "named pipe busy",
            ));
        }
        // SAFETY: `handle` is an open file handle to the client end of the Named Pipe.
        let mut f = unsafe { std::fs::File::from_raw_handle(handle as _) };
        write_ipc_frame(&mut f, req_payload)?;
        read_ipc_frame(&mut f)?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "empty IPC response")
        })
    }

    fn reg_set_sz(subkey: &str, value_name: Option<&str>, data: &str) -> std::io::Result<()> {
        let subkey_w = wide(subkey);
        let mut hkey: HKEY = std::ptr::null_mut();
        // SAFETY: Creates or opens `HKCU\<subkey>` with write access.
        let rc = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey_w.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                std::ptr::null(),
                &mut hkey,
                std::ptr::null_mut(),
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }
        let val_w = value_name.map(wide);
        let data_w = wide(data);
        let cb_data = (data_w.len() * std::mem::size_of::<u16>()) as u32;
        // SAFETY: `hkey` is open; `data_w` is a NUL-terminated UTF-16 buffer of `cb_data` bytes.
        let rc = unsafe {
            RegSetValueExW(
                hkey,
                val_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
                0,
                REG_SZ,
                data_w.as_ptr().cast(),
                cb_data,
            )
        };
        // SAFETY: `hkey` was opened above.
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        if rc != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }
        Ok(())
    }

    fn reg_delete_tree(subkey: &str) -> std::io::Result<()> {
        let subkey_w = wide(subkey);
        // SAFETY: Deletes `HKCU\<subkey>` recursively if present.
        let rc = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, subkey_w.as_ptr()) };
        if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }
        Ok(())
    }

    /// `HKCU\<subkey>\<value>`'s raw data, if the value exists.
    fn reg_get(subkey: &str, value_name: &str) -> Option<Vec<u8>> {
        let subkey_w = wide(subkey);
        let val_w = wide(value_name);
        let mut size: u32 = 0;
        // SAFETY: Size query only (null data pointer).
        let rc = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                subkey_w.as_ptr(),
                val_w.as_ptr(),
                RRF_RT_ANY,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: `buf` has `size` bytes, as the call above asked for.
        let rc = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                subkey_w.as_ptr(),
                val_w.as_ptr(),
                RRF_RT_ANY,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        buf.truncate(size as usize);
        Some(buf)
    }

    fn reg_delete_value(subkey: &str, value_name: &str) -> std::io::Result<()> {
        let subkey_w = wide(subkey);
        let val_w = wide(value_name);
        // SAFETY: Deletes one value under `HKCU\<subkey>` if present.
        let rc =
            unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, subkey_w.as_ptr(), val_w.as_ptr()) };
        if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }
        Ok(())
    }

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const APPROVED_KEY: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

    /// Sign-in entry (see `autostart`): the Run value is there and Task
    /// Manager hasn't turned it off.
    pub fn autostart_enabled(name: &str) -> bool {
        reg_get(RUN_KEY, name).is_some()
            && crate::autostart::windows_approved(reg_get(APPROVED_KEY, name).as_deref())
    }

    pub fn set_autostart(name: &str, exe: &std::path::Path, on: bool) -> std::io::Result<()> {
        // Clear a Task Manager "Disabled" so on means on.
        reg_delete_value(APPROVED_KEY, name)?;
        if on {
            reg_set_sz(RUN_KEY, Some(name), &crate::autostart::render_windows(exe))
        } else {
            reg_delete_value(RUN_KEY, name)
        }
    }

    pub const SHELL_MENU_KEY: &str = r"Software\Classes\*\shell\VoidwireSend";
    pub const SHELL_MENU_COMMAND_KEY: &str = r"Software\Classes\*\shell\VoidwireSend\command";

    pub fn set_file_context_menu_enabled(enabled: bool) -> std::io::Result<()> {
        if std::env::var_os("VOIDWIRE_DATA_DIR").is_some() {
            return Ok(());
        }
        if enabled {
            let exe = std::env::current_exe()?;
            let exe_s = exe.to_string_lossy();
            let icon = format!("\"{exe_s}\",0");
            let action = format!("\"{exe_s}\" --send-file \"%1\"");
            reg_set_sz(SHELL_MENU_KEY, None, "Send with Voidwire")?;
            reg_set_sz(SHELL_MENU_KEY, Some("Icon"), &icon)?;
            reg_set_sz(SHELL_MENU_COMMAND_KEY, None, &action)?;
            Ok(())
        } else {
            reg_delete_tree(SHELL_MENU_KEY)
        }
    }

    pub fn sync_native_messaging_hosts() -> std::io::Result<()> {
        if std::env::var_os("VOIDWIRE_DATA_DIR").is_some() {
            return Ok(());
        }
        let exe = std::env::current_exe()?;
        let base = std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("APPDATA"))
            .ok_or_else(|| std::io::Error::other("missing LOCALAPPDATA"))?;
        let host_dir = std::path::PathBuf::from(base)
            .join("app.voidwire.desktop")
            .join("native-messaging");
        let (chromium_manifest, firefox_manifest) =
            write_native_host_manifests_to(&host_dir, &exe)?;
        let chromium_str = chromium_manifest.to_string_lossy();
        let firefox_str = firefox_manifest.to_string_lossy();

        for prefix in [
            r"Software\Google\Chrome\NativeMessagingHosts",
            r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
            r"Software\Microsoft\Edge\NativeMessagingHosts",
            r"Software\Chromium\NativeMessagingHosts",
            r"Software\Vivaldi\NativeMessagingHosts",
        ] {
            let key = format!(r"{prefix}\{NATIVE_HOST_NAME}");
            let _ = reg_set_sz(&key, None, &chromium_str);
        }
        let ff_key = format!(r"Software\Mozilla\NativeMessagingHosts\{NATIVE_HOST_NAME}");
        let _ = reg_set_sz(&ff_key, None, &firefox_str);
        Ok(())
    }
}

#[cfg(unix)]
mod unix_ipc {
    use super::{
        fnv1a64, read_ipc_frame, render_chromium_native_host_manifest,
        render_firefox_native_host_manifest, write_ipc_frame, write_private_file, NATIVE_HOST_NAME,
    };
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    fn current_euid() -> u32 {
        // SAFETY: `geteuid` is always safe and has no preconditions.
        unsafe { libc::geteuid() }
    }

    fn ensure_private_dir(dir: &Path, uid: u32) -> std::io::Result<()> {
        if !dir.exists() {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true).mode(0o700);
            b.create(dir)?;
        }
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        let meta = std::fs::symlink_metadata(dir)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "IPC runtime directory must not be a symlink",
            ));
        }
        if meta.uid() != uid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "IPC runtime directory not owned by current user",
            ));
        }
        if (meta.permissions().mode() & 0o077) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "IPC runtime directory must have mode 0700",
            ));
        }
        Ok(())
    }

    pub fn ipc_socket_path() -> std::io::Result<PathBuf> {
        let uid = current_euid();
        if let Some(d) = std::env::var_os("VOIDWIRE_DATA_DIR").filter(|s| !s.is_empty()) {
            let dir = PathBuf::from(&d);
            let candidate = dir.join("ipc.sock");
            if candidate.as_os_str().len() < 96 {
                ensure_private_dir(&dir, uid)?;
                return Ok(candidate);
            }
            let h = fnv1a64(d.to_string_lossy().as_bytes());
            let fallback = PathBuf::from(format!("/tmp/voidwire-{uid}-{h:016x}"));
            ensure_private_dir(&fallback, uid)?;
            return Ok(fallback.join("ipc.sock"));
        }
        if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR").filter(|s| !s.is_empty()) {
            let xdg_dir = PathBuf::from(xdg);
            if let Ok(meta) = std::fs::symlink_metadata(&xdg_dir) {
                if meta.is_dir() && !meta.file_type().is_symlink() && meta.uid() == uid {
                    let sub = xdg_dir.join("voidwire");
                    if ensure_private_dir(&sub, uid).is_ok() {
                        let sock = sub.join("ipc.sock");
                        if sock.as_os_str().len() < 96 {
                            return Ok(sock);
                        }
                    }
                }
            }
        }
        // macOS: the per-user temp dir (`/var/folders/.../T/`, mode 0700),
        // asked of the system rather than read from `$TMPDIR`, so the app and
        // a native host started by a browser agree even with another env.
        #[cfg(target_os = "macos")]
        if let Some(t) = darwin_user_temp_dir() {
            let sub = t.join("voidwire");
            let sock = sub.join("ipc.sock");
            if sock.as_os_str().len() < 96 && ensure_private_dir(&sub, uid).is_ok() {
                return Ok(sock);
            }
        }
        let fallback = PathBuf::from(format!("/tmp/voidwire-{uid}"));
        ensure_private_dir(&fallback, uid)?;
        Ok(fallback.join("ipc.sock"))
    }

    #[cfg(target_os = "macos")]
    fn darwin_user_temp_dir() -> Option<PathBuf> {
        use std::os::unix::ffi::OsStrExt;
        let mut buf = [0u8; 1024];
        // SAFETY: `buf` is writable for `buf.len()` bytes; confstr writes at
        // most that many, NUL-terminated, and returns the needed size.
        let n = unsafe {
            libc::confstr(
                libc::_CS_DARWIN_USER_TEMP_DIR,
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n == 0 || n > buf.len() {
            return None;
        }
        let p = PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..n - 1]));
        p.is_absolute().then_some(p)
    }

    pub struct IpcServer {
        listener: UnixListener,
        sock_path: PathBuf,
    }

    impl IpcServer {
        pub fn bind() -> std::io::Result<Self> {
            let sock_path = ipc_socket_path()?;
            if sock_path.exists() {
                let _ = std::fs::remove_file(&sock_path);
            }
            let listener = UnixListener::bind(&sock_path)?;
            std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))?;
            Ok(Self {
                listener,
                sock_path,
            })
        }

        pub fn accept_and_serve<F>(&mut self, mut handler: F) -> std::io::Result<()>
        where
            F: FnMut(&[u8]) -> Vec<u8>,
        {
            let (mut stream, _) = self.listener.accept()?;
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
            if let Some(req) = read_ipc_frame(&mut stream)? {
                let resp = handler(&req);
                write_ipc_frame(&mut stream, &resp)?;
            }
            Ok(())
        }
    }

    impl Drop for IpcServer {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.sock_path);
        }
    }

    pub fn ipc_exchange(req_payload: &[u8]) -> std::io::Result<Vec<u8>> {
        let sock_path = ipc_socket_path()?;
        let mut stream = UnixStream::connect(sock_path)?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
        write_ipc_frame(&mut stream, req_payload)?;
        read_ipc_frame(&mut stream)?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "empty IPC response")
        })
    }

    pub fn sync_native_messaging_hosts() -> std::io::Result<()> {
        if std::env::var_os("VOIDWIRE_DATA_DIR").is_some() {
            return Ok(());
        }
        let exe =
            super::native_host_exe_path(std::env::current_exe()?, std::env::var_os("APPIMAGE"));
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return Ok(());
        };
        if cfg!(target_os = "macos") && super::native_host_location_blocked(&exe) {
            // M3: a translocated or disk-image copy moves or goes away; a
            // manifest pointing at it would break. Settings says to move it.
            super::NATIVE_HOST_BLOCKED.store(true, std::sync::atomic::Ordering::SeqCst);
            return Ok(());
        }
        let dirs = super::native_host_manifest_dirs(&home, cfg!(target_os = "macos"));
        let chromium_json = render_chromium_native_host_manifest(&exe);
        for dir in &dirs.chromium {
            let _ = write_private_file(
                &dir.join(format!("{NATIVE_HOST_NAME}.json")),
                chromium_json.as_bytes(),
            );
        }
        let _ = write_private_file(
            &dirs.firefox.join(format!("{NATIVE_HOST_NAME}.json")),
            render_firefox_native_host_manifest(&exe).as_bytes(),
        );
        Ok(())
    }
}

/// Point this process's stderr at `/dev/null` (V1: release GUI runs write
/// nothing that journald or a terminal could keep, including GTK and WebKit
/// warnings and their child processes, which inherit fd 2). Not used by the
/// CLI modes. No-op off Unix (the Windows GUI subsystem has no stderr).
pub fn silence_stderr() {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if let Ok(null) = std::fs::OpenOptions::new().write(true).open("/dev/null") {
            // SAFETY: both are valid descriptors; dup2 atomically replaces fd 2,
            // which no Rust object owns. `null` closes its own fd on drop.
            let _ = unsafe { libc::dup2(null.as_raw_fd(), libc::STDERR_FILENO) };
        }
    }
}

/// Path the browser should launch for the native host. Inside an AppImage the
/// running executable lives under a per-launch temporary mount, so the stable
/// `$APPIMAGE` path is used when it names an existing absolute file.
/// Where the browsers look for this user's Native Messaging host manifests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeHostDirs {
    /// Chrome, Brave, Chromium, Edge and Vivaldi.
    pub chromium: Vec<std::path::PathBuf>,
    pub firefox: std::path::PathBuf,
}

/// The per-user manifest folders under `home`: `~/Library/Application
/// Support/...` on macOS (M5.2), the XDG ones elsewhere on Unix.
pub fn native_host_manifest_dirs(home: &std::path::Path, macos: bool) -> NativeHostDirs {
    if macos {
        let base = home.join("Library/Application Support");
        return NativeHostDirs {
            chromium: [
                "Google/Chrome",
                "BraveSoftware/Brave-Browser",
                "Chromium",
                "Microsoft Edge",
                "Vivaldi",
            ]
            .iter()
            .map(|b| base.join(b).join("NativeMessagingHosts"))
            .collect(),
            firefox: base.join("Mozilla/NativeMessagingHosts"),
        };
    }
    NativeHostDirs {
        chromium: [
            ".config/google-chrome",
            ".config/BraveSoftware/Brave-Browser",
            ".config/chromium",
            ".config/microsoft-edge",
            ".config/vivaldi",
        ]
        .iter()
        .map(|b| home.join(b).join("NativeMessagingHosts"))
        .collect(),
        firefox: home.join(".mozilla/native-messaging-hosts"),
    }
}

/// macOS (M3): the app runs from a place that won't last, so a browser
/// manifest must not point at it: a translocated copy (Gatekeeper runs a
/// downloaded app from a random read-only path until it is moved) or the
/// mounted disk image itself.
pub fn native_host_location_blocked(exe: &std::path::Path) -> bool {
    exe.starts_with("/Volumes")
        || exe
            .components()
            .any(|c| c.as_os_str() == std::ffi::OsStr::new("AppTranslocation"))
}

static NATIVE_HOST_BLOCKED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether the last manifest sync was skipped because of where the app
/// runs (M3): Settings asks the user to move it to Applications.
pub fn native_host_blocked() -> bool {
    NATIVE_HOST_BLOCKED.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(unix)]
fn native_host_exe_path(
    current_exe: std::path::PathBuf,
    appimage: Option<std::ffi::OsString>,
) -> std::path::PathBuf {
    match appimage.map(std::path::PathBuf::from) {
        Some(p) if p.is_absolute() && p.is_file() => p,
        _ => current_exe,
    }
}

/// Current-user-only local IPC server (`AUTH-13`).
pub struct IpcServer {
    #[cfg(windows)]
    inner: win_ipc::IpcServer,
    #[cfg(unix)]
    inner: unix_ipc::IpcServer,
}

impl IpcServer {
    /// Bind the current-user-only IPC pipe/socket.
    pub fn bind() -> std::io::Result<Self> {
        #[cfg(windows)]
        {
            Ok(Self {
                inner: win_ipc::IpcServer::bind()?,
            })
        }
        #[cfg(unix)]
        {
            Ok(Self {
                inner: unix_ipc::IpcServer::bind()?,
            })
        }
    }

    /// Accept one local IPC client connection, read its request frame, invoke `handler`,
    /// and write the response frame.
    pub fn accept_and_serve<F>(&mut self, handler: F) -> std::io::Result<()>
    where
        F: FnMut(&[u8]) -> Vec<u8>,
    {
        self.inner.accept_and_serve(handler)
    }
}

/// Send one request frame to the running Voidwire instance over the current-user-only
/// local IPC pipe/socket and return the response frame (`M3.2`).
pub fn ipc_exchange(req_payload: &[u8]) -> std::io::Result<Vec<u8>> {
    #[cfg(windows)]
    {
        win_ipc::ipc_exchange(req_payload)
    }
    #[cfg(unix)]
    {
        unix_ipc::ipc_exchange(req_payload)
    }
}

/// Enable or disable the OS file manager `"Send with Voidwire"` right-click
/// context menu (`M3.2`; Linux file managers: M5.1, L2).
pub fn set_file_context_menu_enabled(enabled: bool) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        win_ipc::set_file_context_menu_enabled(enabled)
    }
    #[cfg(target_os = "linux")]
    {
        // Test runs with their own data dir leave the user's HOME alone,
        // as the native-host manifests do.
        if std::env::var_os("VOIDWIRE_DATA_DIR").is_some() {
            return Ok(());
        }
        let Some(data_home) = linux_fm::data_home() else {
            return Ok(());
        };
        let exe = native_host_exe_path(std::env::current_exe()?, std::env::var_os("APPIMAGE"));
        linux_fm::sync(&data_home, enabled.then_some(exe.as_path()))
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = enabled;
        Ok(())
    }
}

/// The program a sign-in entry starts: `$APPIMAGE` for an AppImage (not
/// the temporary mount), else this executable.
fn autostart_exe() -> std::io::Result<std::path::PathBuf> {
    let exe = std::env::current_exe()?;
    #[cfg(target_os = "linux")]
    {
        Ok(native_host_exe_path(exe, std::env::var_os("APPIMAGE")))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(exe)
    }
}

#[cfg(target_os = "macos")]
fn mac_launch_agent(id: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(|h| autostart::mac_path(std::path::Path::new(&h), id))
}

/// Whether "Start when I sign in" is on: read from the OS each time
/// (see `autostart`). `name` is the product name, `id` the bundle id.
pub fn autostart_enabled(name: &str, id: &str) -> bool {
    let _ = (name, id);
    #[cfg(windows)]
    {
        win_ipc::autostart_enabled(name)
    }
    #[cfg(target_os = "linux")]
    {
        autostart::config_home()
            .is_some_and(|c| autostart::linux_is_enabled(&autostart::linux_path(&c, name)))
    }
    #[cfg(target_os = "macos")]
    {
        mac_launch_agent(id).is_some_and(|p| p.exists())
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Add (`on`) or remove the sign-in entry.
pub fn set_autostart(name: &str, id: &str, on: bool) -> std::io::Result<()> {
    let exe = autostart_exe()?;
    let e = autostart::Entry {
        name,
        id,
        exe: &exe,
    };
    #[cfg(windows)]
    {
        win_ipc::set_autostart(e.name, e.exe, on)
    }
    #[cfg(target_os = "linux")]
    {
        let c = autostart::config_home().ok_or_else(|| std::io::Error::other("no home folder"))?;
        autostart::linux_set(&autostart::linux_path(&c, name), &e, on)
    }
    #[cfg(target_os = "macos")]
    {
        let p = mac_launch_agent(id).ok_or_else(|| std::io::Error::other("no home folder"))?;
        autostart::mac_set(&p, &e, on)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (e, on);
        Ok(())
    }
}

/// At start: an entry that is on but points at an old path (the AppImage
/// was moved) is rewritten to this one. Nothing is added.
pub fn refresh_autostart(name: &str, id: &str) {
    let _ = (name, id);
    #[cfg(target_os = "linux")]
    if let (Some(c), Ok(exe)) = (autostart::config_home(), autostart_exe()) {
        let e = autostart::Entry {
            name,
            id,
            exe: &exe,
        };
        let _ = autostart::linux_refresh(&autostart::linux_path(&c, name), &e);
    }
}

/// Register Native Messaging host manifests and sync the File Explorer context menu (`M3.2`).
pub fn sync_os_integrations(context_menu_enabled: bool) {
    let _ = set_file_context_menu_enabled(context_menu_enabled);
    #[cfg(windows)]
    {
        let _ = win_ipc::sync_native_messaging_hosts();
    }
    #[cfg(unix)]
    {
        let _ = unix_ipc::sync_native_messaging_hosts();
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn mac_shortcut_mapping() {
        let (mods, vk) = parse_hotkey_accel("Ctrl+Shift+V").unwrap();
        assert_eq!(mac_key_code(vk), Some(0x09));
        assert_eq!(mac_modifiers(mods), (1 << 12) | (1 << 9));
        let (mods, vk) = parse_hotkey_accel("Command+Option+S").unwrap();
        assert_eq!(mac_key_code(vk), Some(0x01));
        assert_eq!(mac_modifiers(mods), (1 << 8) | (1 << 11));
        assert_eq!(
            parse_hotkey_accel("Command+K").unwrap(),
            parse_hotkey_accel("Win+K").unwrap()
        );
        for (accel, code) in [
            ("Ctrl+A", 0x00),
            ("Ctrl+Z", 0x06),
            ("Ctrl+0", 0x1D),
            ("Ctrl+9", 0x19),
            ("Ctrl+F1", 0x7A),
            ("Ctrl+F12", 0x6F),
            ("Ctrl+Space", 0x31),
            ("Ctrl+Up", 0x7E),
            ("Ctrl+/", 0x2C),
        ] {
            let (_, vk) = parse_hotkey_accel(accel).unwrap();
            assert_eq!(mac_key_code(vk), Some(code), "{accel}");
        }
        let (_, ins) = parse_hotkey_accel("Ctrl+Insert").unwrap();
        assert_eq!(mac_key_code(ins), None);
    }

    #[test]
    fn native_host_dirs_follow_the_platform() {
        let home = std::path::Path::new("/home/u");
        let linux = native_host_manifest_dirs(home, false);
        assert_eq!(linux.firefox, home.join(".mozilla/native-messaging-hosts"));
        assert!(linux
            .chromium
            .contains(&home.join(".config/google-chrome/NativeMessagingHosts")));
        let mac_home = std::path::Path::new("/Users/u");
        let mac = native_host_manifest_dirs(mac_home, true);
        assert_eq!(
            mac.firefox,
            mac_home.join("Library/Application Support/Mozilla/NativeMessagingHosts")
        );
        for b in [
            "Google/Chrome",
            "BraveSoftware/Brave-Browser",
            "Chromium",
            "Microsoft Edge",
            "Vivaldi",
        ] {
            let want = mac_home
                .join("Library/Application Support")
                .join(b)
                .join("NativeMessagingHosts");
            assert!(mac.chromium.contains(&want), "{want:?}");
        }
        assert_eq!(mac.chromium.len(), 5);
        assert!(mac
            .chromium
            .iter()
            .all(|d| !d.to_string_lossy().contains(".config")));
    }

    #[test]
    fn native_host_location_blocked_for_translocated_and_dmg_copies() {
        use std::path::Path;
        assert!(native_host_location_blocked(Path::new(
            "/private/var/folders/xy/abc/T/AppTranslocation/1234-ABCD/d/Voidwire.app/Contents/MacOS/voidwire"
        )));
        assert!(native_host_location_blocked(Path::new(
            "/Volumes/Voidwire/Voidwire.app/Contents/MacOS/voidwire"
        )));
        assert!(!native_host_location_blocked(Path::new(
            "/Applications/Voidwire.app/Contents/MacOS/voidwire"
        )));
        assert!(!native_host_location_blocked(Path::new(
            "/Users/u/Applications/Voidwire.app/Contents/MacOS/voidwire"
        )));
        assert!(!native_host_location_blocked(Path::new(
            "/usr/bin/voidwire"
        )));
        assert!(!native_host_location_blocked(Path::new(
            "/VolumesX/voidwire"
        )));
    }
    use super::*;

    #[cfg(unix)]
    #[test]
    fn native_host_path_prefers_existing_appimage() {
        let tmp = std::env::temp_dir().join("vw-native-host-test.AppImage");
        std::fs::write(&tmp, b"x").unwrap();
        let mounted = std::path::PathBuf::from("/tmp/.mount_Voidwi/usr/bin/voidwire");
        assert_eq!(
            native_host_exe_path(mounted.clone(), Some(tmp.clone().into_os_string())),
            tmp
        );
        assert_eq!(native_host_exe_path(mounted.clone(), None), mounted);
        assert_eq!(
            native_host_exe_path(mounted.clone(), Some("relative/Voidwire.AppImage".into())),
            mounted
        );
        assert_eq!(
            native_host_exe_path(
                mounted.clone(),
                Some("/nonexistent/Voidwire.AppImage".into())
            ),
            mounted
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// v0.7.1: a copied pairing code carries the three privacy markers, and
    /// clearing it never wipes something copied since.
    #[cfg(windows)]
    #[test]
    fn private_copy_is_marked_and_cleared_only_if_unchanged() {
        let code = "VW-TEST-PRIV-0711";
        if !set_private_clipboard_text(code) {
            eprintln!("no clipboard on this runner; skipped");
            return;
        }
        assert!(clipboard_is_private());
        assert_eq!(get_clipboard_text().as_deref(), Some(code));
        assert!(set_clipboard_text("something the user copied"));
        assert!(!clear_clipboard_if_text(code));
        assert_eq!(
            get_clipboard_text().as_deref(),
            Some("something the user copied")
        );
        assert!(set_private_clipboard_text(code));
        assert!(clear_clipboard_if_text(code));
        assert_eq!(get_clipboard_text(), None);
    }

    #[test]
    fn copied_file_label_name_is_basename() {
        use std::path::Path;
        assert_eq!(
            copied_file_label_name(Some(Path::new("/home/u/Docs/report.pdf"))).as_deref(),
            Some("report.pdf")
        );
        assert_eq!(copied_file_label_name(None), None);
        assert_eq!(copied_file_label_name(Some(Path::new("/"))), None);
    }

    #[test]
    fn clipboard_tracker_fires_only_on_name_change() {
        let a = ClipboardFileRead::File("/x/a.txt".into());
        let a_elsewhere = ClipboardFileRead::File("/y/a.txt".into());
        let b = ClipboardFileRead::File("/x/b.txt".into());
        let mut t = ClipboardFileTracker::primed(&ClipboardFileRead::NoFile);
        assert!(!t.observe(&ClipboardFileRead::NoFile), "text after text");
        assert!(t.observe(&a), "file copied");
        assert!(!t.observe(&a), "same file again");
        assert!(!t.observe(&a_elsewhere), "same label");
        assert!(!t.observe(&ClipboardFileRead::Busy), "busy never changes");
        assert!(t.observe(&b), "different file");
        assert!(t.observe(&ClipboardFileRead::NoFile), "text copied");
    }

    #[test]
    fn clipboard_tracker_primed_with_file() {
        let a = ClipboardFileRead::File("/x/a.txt".into());
        let mut t = ClipboardFileTracker::primed(&a);
        assert!(!t.observe(&a));
        let mut busy = ClipboardFileTracker::primed(&ClipboardFileRead::Busy);
        assert!(busy.observe(&a));
    }

    #[test]
    fn dpi_maps_to_the_nearest_frame() {
        assert_eq!(tray_frame_for_dpi(96), 16); // 100 %
        assert_eq!(tray_frame_for_dpi(120), 20); // 125 %
        assert_eq!(tray_frame_for_dpi(144), 24); // 150 %
        assert_eq!(tray_frame_for_dpi(168), 32); // 175 %: 28 px, a tie between 24 and 32 → 32
        assert_eq!(tray_frame_for_dpi(192), 32); // 200 %
        assert_eq!(tray_frame_for_dpi(240), 40); // 250 %
        assert_eq!(tray_frame_for_dpi(288), 48); // 300 %
        assert_eq!(tray_frame_for_dpi(480), 48); // beyond: largest
        assert_eq!(tray_frame_for_dpi(0), 16);
    }

    #[test]
    fn taskbar_value_parsing() {
        assert!(taskbar_light_from_value(Some(1)));
        assert!(!taskbar_light_from_value(Some(0)));
        assert!(!taskbar_light_from_value(None));
    }

    #[test]
    fn apps_theme_is_dark_unless_explicitly_light() {
        assert!(apps_light_from_value(Some(1)));
        assert!(!apps_light_from_value(Some(0)));
        assert!(!apps_light_from_value(None));
        assert!(!apps_light_from_value(Some(2)));
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_everything_is_unknown() {
        // macOS reads the app theme (mac::apps_are_light); the rest is Windows-only.
        #[cfg(not(target_os = "macos"))]
        assert_eq!(apps_are_light(), None);
        #[cfg(target_os = "macos")]
        assert!(apps_are_light().is_some());
        assert_eq!(taskbar_is_light(), None);
        assert_eq!(system_dpi(), None);
        assert!(!wait_for_theme_change());
    }
    #[test]
    fn parse_cf_hdrop_and_file_uri_lists() {
        // UTF-16LE DROPFILES header (pFiles = 20, fWide = 1) + "C:\temp\report.pdf\0\0"
        let mut hdrop_wide = vec![0u8; 20];
        hdrop_wide[0..4].copy_from_slice(&20u32.to_le_bytes());
        hdrop_wide[16..20].copy_from_slice(&1i32.to_le_bytes());
        for u in "C:\temp\report.pdf".encode_utf16() {
            hdrop_wide.extend_from_slice(&u.to_le_bytes());
        }
        hdrop_wide.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            parse_cf_hdrop_bytes(&hdrop_wide),
            Some(std::path::PathBuf::from("C:\temp\report.pdf"))
        );

        // GNOME Files / Nautilus `x-special/gnome-copied-files` payload
        let gnome_payload = "copy\nfile:///home/user/My%20Documents/notes.txt\n";
        assert_eq!(
            parse_clipboard_file_uri_list(gnome_payload),
            Some(std::path::PathBuf::from(
                "/home/user/My Documents/notes.txt"
            ))
        );

        // Standard `text/uri-list` payload
        let uri_list = "# comment\r\nfile://localhost/tmp/archive.tar.gz\r\n";
        assert_eq!(
            parse_clipboard_file_uri_list(uri_list),
            Some(std::path::PathBuf::from("/tmp/archive.tar.gz"))
        );
    }

    #[test]
    fn parse_hotkey_accel_supports_custom_shortcuts_and_rejects_invalid() {
        let (mods, vk) = parse_hotkey_accel("Ctrl+Shift+V").expect("Ctrl+Shift+V");
        assert_eq!(mods, MOD_CONTROL_FLAG | MOD_SHIFT_FLAG | MOD_NOREPEAT_FLAG);
        assert_eq!(vk, b'V' as u32);

        let (mods2, vk2) = parse_hotkey_accel("Ctrl+Alt+F9").expect("Ctrl+Alt+F9");
        assert_eq!(mods2, MOD_CONTROL_FLAG | MOD_ALT_FLAG | MOD_NOREPEAT_FLAG);
        assert_eq!(vk2, 0x78);

        assert!(parse_hotkey_accel("V").is_err(), "missing modifier");
        assert!(parse_hotkey_accel("Ctrl+Shift").is_err(), "missing key");
        assert!(parse_hotkey_accel("Ctrl+A+B").is_err(), "multiple keys");
    }

    #[test]
    fn ipc_framing_roundtrip_and_bounds() {
        let mut buf = Vec::new();
        let msg = br#"{"op":"status"}"#;
        write_ipc_frame(&mut buf, msg).expect("write frame");
        assert_eq!(&buf[0..4], &(msg.len() as u32).to_le_bytes());

        let mut cursor = std::io::Cursor::new(buf);
        let decoded = read_ipc_frame(&mut cursor)
            .expect("read frame")
            .expect("some frame");
        assert_eq!(decoded, msg);
        assert!(read_ipc_frame(&mut cursor).expect("clean eof").is_none());

        // Zero-length and > 1 MiB frames must be rejected.
        let mut zero_cursor = std::io::Cursor::new(0u32.to_le_bytes());
        assert!(read_ipc_frame(&mut zero_cursor).is_err());
        let mut huge_cursor =
            std::io::Cursor::new(((MAX_IPC_FRAME_BYTES as u32) + 1).to_le_bytes());
        assert!(read_ipc_frame(&mut huge_cursor).is_err());
    }

    #[test]
    fn native_host_manifests_contain_deterministic_ids_and_escaped_paths() {
        let exe = std::path::Path::new(r"C:\Program Files\Voidwire\voidwire.exe");
        let chromium = render_chromium_native_host_manifest(exe);
        assert!(chromium.contains(NATIVE_HOST_NAME));
        assert!(chromium.contains(CHROMIUM_EXTENSION_ID));
        assert!(chromium.contains(EDGE_ADDONS_EXTENSION_ID));
        assert!(chromium.contains(r"C:\\Program Files\\Voidwire\\voidwire.exe"));
        assert!(chromium.contains(r#""type": "stdio""#));

        let firefox = render_firefox_native_host_manifest(exe);
        assert!(firefox.contains(NATIVE_HOST_NAME));
        assert!(firefox.contains(FIREFOX_EXTENSION_ID));
        assert!(firefox.contains(r#""type": "stdio""#));
    }

    #[test]
    fn chromium_manifest_allows_every_listed_extension_and_nothing_else() {
        // The dev (unpacked) build and the store builds all have to reach
        // the desktop app.
        assert!(CHROMIUM_EXTENSION_IDS.contains(&"mknbkjlaloblibdffcebiegchmcbmpbm"));
        assert!(CHROMIUM_EXTENSION_IDS.contains(&"gdcjokipaeghnjfcbnjeofbealnkdgbh"));
        for (i, id) in CHROMIUM_EXTENSION_IDS.iter().enumerate() {
            // Chromium IDs are 32 letters a-p.
            assert_eq!(id.len(), 32, "{id}");
            assert!(id.bytes().all(|b| (b'a'..=b'p').contains(&b)), "{id}");
            assert!(!CHROMIUM_EXTENSION_IDS[..i].contains(id), "duplicate {id}");
        }

        let m = render_chromium_native_host_manifest(std::path::Path::new("/usr/bin/voidwire"));
        let start = m.find("\"allowed_origins\": [").expect("allowed_origins");
        let list = &m[start..m[start..].find(']').map(|e| start + e).expect("end")];
        let origins: Vec<&str> = list
            .lines()
            .skip(1)
            .map(|l| l.trim().trim_end_matches(','))
            .filter(|l| !l.is_empty())
            .collect();
        let want: Vec<String> = CHROMIUM_EXTENSION_IDS
            .iter()
            .map(|id| format!("\"chrome-extension://{id}/\""))
            .collect();
        assert_eq!(origins, want);
        // Valid JSON list: commas between entries, none after the last.
        assert_eq!(list.matches(',').count(), CHROMIUM_EXTENSION_IDS.len() - 1);
        assert!(m.trim_end().ends_with("]\n}"));
    }

    #[test]
    fn ipc_server_and_client_roundtrip_with_current_user_acl() {
        let tmp = std::env::temp_dir().join("vw-ipc-test-os-theme");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("create temp dir");
        std::env::set_var("VOIDWIRE_DATA_DIR", &tmp);

        let mut server = IpcServer::bind().expect("bind current-user IPC server");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let sock = unix_ipc::ipc_socket_path().expect("socket path");
            let sock_mode = std::fs::symlink_metadata(&sock)
                .expect("sock meta")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(sock_mode, 0o600, "IPC socket must be mode 0600");
        }
        #[cfg(windows)]
        {
            let sid = win_ipc::current_user_sid_string().expect("current user SID");
            assert!(sid.starts_with("S-1-"), "expected Windows SID, got {sid}");
            let sddl = win_ipc::current_user_pipe_sddl(&sid);
            assert_eq!(sddl, format!("D:P(A;;GA;;;{sid})"));
        }

        let handle = std::thread::spawn(move || {
            server
                .accept_and_serve(|req| {
                    let mut out = b"ack:".to_vec();
                    out.extend_from_slice(req);
                    out
                })
                .expect("accept_and_serve");
        });

        let reply = ipc_exchange(b"ping-m32").expect("ipc_exchange");
        assert_eq!(reply, b"ack:ping-m32");
        handle.join().expect("server thread join");
        std::env::remove_var("VOIDWIRE_DATA_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
