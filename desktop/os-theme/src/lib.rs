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
    pub fn get_clipboard_file() -> Option<std::path::PathBuf> {
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
        out.filter(|p| p.is_file())
    }

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
    const MOD_CONTROL: u32 = 0x0002;
    const MOD_SHIFT: u32 = 0x0004;
    const MOD_NOREPEAT: u32 = 0x4000;
    const VK_V: u32 = 0x56;
    const WM_HOTKEY: u32 = 0x0312;
    const WM_APP_SYNC: u32 = 0x8001;

    static HOTKEY_ENABLED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    static HOTKEY_CALLBACK: std::sync::Mutex<Option<std::sync::Arc<dyn Fn() + Send + Sync>>> =
        std::sync::Mutex::new(None);
    static HOTKEY_THREAD_ID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

    pub fn set_send_clipboard_hotkey(
        enabled: bool,
        on_press: std::sync::Arc<dyn Fn() + Send + Sync>,
    ) {
        HOTKEY_ENABLED.store(enabled, std::sync::atomic::Ordering::SeqCst);
        if let Ok(mut cb) = HOTKEY_CALLBACK.lock() {
            *cb = Some(on_press);
        }
        if let Some(&tid) = HOTKEY_THREAD_ID.get() {
            // SAFETY: Posts a thread message to wake `GetMessageW` on our hotkey worker thread.
            unsafe {
                let _ = PostThreadMessageW(tid, WM_APP_SYNC, 0, 0);
            }
            return;
        }
        if !enabled {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let _ = std::thread::Builder::new()
            .name("voidwire-hotkey".into())
            .spawn(move || {
                // SAFETY: Returns the calling Win32 thread identifier.
                let tid = unsafe { GetCurrentThreadId() };
                let _ = tx.send(tid);
                let mut registered = false;
                if HOTKEY_ENABLED.load(std::sync::atomic::Ordering::SeqCst) {
                    // SAFETY: Registers Ctrl+Shift+V for the current thread's message queue.
                    registered = unsafe {
                        RegisterHotKey(
                            std::ptr::null_mut(),
                            HOTKEY_ID,
                            MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT,
                            VK_V,
                        )
                    } != 0;
                }
                let mut msg: HotkeyMsg = unsafe { std::mem::zeroed() };
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
                        let want = HOTKEY_ENABLED.load(std::sync::atomic::Ordering::SeqCst);
                        if want && !registered {
                            // SAFETY: Registers Ctrl+Shift+V on this worker thread.
                            registered = unsafe {
                                RegisterHotKey(
                                    std::ptr::null_mut(),
                                    HOTKEY_ID,
                                    MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT,
                                    VK_V,
                                )
                            } != 0;
                        } else if !want && registered {
                            // SAFETY: Unregisters hotkey previously registered on this thread.
                            unsafe {
                                let _ = UnregisterHotKey(std::ptr::null_mut(), HOTKEY_ID);
                            }
                            registered = false;
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
        if let Ok(tid) = rx.recv_timeout(std::time::Duration::from_secs(1)) {
            let _ = HOTKEY_THREAD_ID.set(tid);
        }
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
    #[cfg(not(windows))]
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
    #[cfg(not(windows))]
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
    #[cfg(not(windows))]
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
    #[cfg(not(windows))]
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
    #[cfg(not(windows))]
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
        for chunk in tail.chunks_exact(2) {
            let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
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

/// Windows: read a copied file path (`CF_HDROP`) from the OS clipboard (`None` off Windows).
pub fn get_clipboard_file() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        win::get_clipboard_file()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Windows: register or unregister the global `Ctrl+Shift+V` hotkey (`MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT`).
pub fn set_send_clipboard_hotkey(enabled: bool, on_press: std::sync::Arc<dyn Fn() + Send + Sync>) {
    #[cfg(windows)]
    {
        win::set_send_clipboard_hotkey(enabled, on_press);
    }
    #[cfg(not(windows))]
    {
        let _ = (enabled, on_press);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(apps_are_light(), None);
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
}
