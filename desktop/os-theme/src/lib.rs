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
    #[cfg(not(windows))]
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
            "WIN" | "SUPER" | "META" => mods |= MOD_WIN_FLAG,
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

/// Windows: register or unregister a customizable global send-clipboard shortcut (`M3.1.1`).
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
    #[cfg(not(windows))]
    {
        let _ = (enabled, parsed, on_press);
        Ok(())
    }
}

/// Windows: register or unregister the default `Ctrl+Shift+V` hotkey.
pub fn set_send_clipboard_hotkey(enabled: bool, on_press: std::sync::Arc<dyn Fn() + Send + Sync>) {
    let _ = set_send_clipboard_hotkey_with_accel(enabled, "Ctrl+Shift+V", on_press);
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
