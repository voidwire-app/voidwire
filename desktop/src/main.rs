//! Desktop tray app (M1): LAN listener, QR pairing window, "Open link?"
//! prompts (with "Ask before opening" on), paired devices with "Forget this device",
//! and the "Ask before opening", Theme, and Diagnostics settings.
//!
//! The only path from the network to the browser is inside `voidwire-core`
//! (`net::pc`): bytes → `Inbox::receive` → `VerifiedUrl` → `opener::deliver`
//! → (`PendingOpen::confirm` on the user's click) → `OpenApproval` → opener.
//! The webviews never see a URL: prompts show the host and are decided by an
//! opaque id. Each window is granted only its own commands
//! (`capabilities/*.json`); no shell/opener plugin is ever granted (AUTH-13).

// D7: GUI subsystem in every profile (no console window next to the tray).
#![windows_subsystem = "windows"]
#![forbid(unsafe_code)]

mod commands;
mod diag;
mod ipc;
mod node;
mod pair_clip;
mod tray_theme;
mod winmgr;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, RunEvent, UserAttentionType, WebviewUrl, WebviewWindowBuilder};
use winmgr::{Begin, MenuAction};

pub const PAIR_WINDOW: &str = "pair";
/// M4.3: pair with any device by typed code.
pub const PAIR2_WINDOW: &str = "pair2";
pub const DEVICES_WINDOW: &str = "devices";
pub const CONFIRM_WINDOW: &str = "confirm";

/// Which tab the Paired devices window shows when it is next opened from the
/// tray ("Paired devices…" vs "Settings…", SPEC 2.1). Main thread reads it.
static DEVICES_SETTINGS_TAB: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Open the Paired devices window on the Devices or the Settings tab.
pub fn request_devices(app: &AppHandle, settings: bool) {
    DEVICES_SETTINGS_TAB.store(settings, std::sync::atomic::Ordering::SeqCst);
    request_window(app, DEVICES_WINDOW);
}

fn devices_tab() -> &'static str {
    if DEVICES_SETTINGS_TAB.load(std::sync::atomic::Ordering::SeqCst) {
        "settings"
    } else {
        "devices"
    }
}

/// Show a window from a tray/menu handler: deferred until the current
/// dispatch has returned (see `winmgr`). Safe from any thread.
pub fn request_window(app: &AppHandle, label: &'static str) {
    let h = app.clone();
    let spawned = std::thread::Builder::new()
        .name("show-window".into())
        .spawn(move || {
            let h2 = h.clone();
            let _ = h.run_on_main_thread(move || show_window(&h2, label));
        });
    if spawned.is_err() {
        node::log("could not schedule a window");
    }
}

/// Show (or create, once) one of the app's windows. Main thread only.
///
/// The confirm prompt is opened by the network, not by the user, so it
/// never takes focus and is never always-on-top (QA M1): a keystroke or
/// click meant for another app can't land on it. It asks for attention
/// (taskbar flash) instead. Windows the user opened from the tray do focus.
/// Every window opens centered, and is centered again when re-shown (SPEC R2).
pub fn show_window(app: &AppHandle, label: &str) {
    let user_opened = label != CONFIRM_WINDOW;
    let existing = app.get_webview_window(label);
    // Bind first: the SLOTS guard must not live through the ShowExisting
    // arm (window calls there could re-enter show_window; std Mutex is not
    // re-entrant).
    let begin = winmgr::slots().begin(label, existing.is_some());
    match begin {
        Begin::AlreadyCreating => return,
        Begin::ShowExisting => {
            if let Some(w) = existing {
                if !w.is_visible().unwrap_or(true) && reload_on_show() {
                    // Linux: closed windows are only hidden (one WebKit
                    // context per label, see linux_incognito_context). No
                    // page state survives a hide: reload from core with the
                    // current theme and tab in the URL.
                    reload_fresh(&w, label);
                } else if label == DEVICES_WINDOW {
                    let _ = w.eval(format!("window.vwTab&&window.vwTab('{}')", devices_tab()));
                }
                let _ = w.unminimize();
                let _ = w.center();
                if label == CONFIRM_WINDOW {
                    let _ = w.set_title(&node::confirm_window_title(app));
                    let _ = w.set_always_on_top(true);
                }
                let _ = w.show();
                let _ = w.set_focus();
                if !user_opened {
                    let _ = w.request_user_attention(Some(UserAttentionType::Informational));
                }
            }
            return;
        }
        Begin::Create => {}
    }
    let name = app.package_info().name.clone();
    let spec = match label {
        PAIR_WINDOW => Some(("pair.html", format!("{name} – Pair a phone"), 440.0, 620.0)),
        PAIR2_WINDOW => Some((
            "pair2.html",
            format!("{name} – Pair with a code"),
            440.0,
            660.0,
        )),
        DEVICES_WINDOW => Some((
            "devices.html",
            format!("{name} – Paired devices"),
            500.0,
            620.0,
        )),
        CONFIRM_WINDOW => Some((
            "confirm.html",
            node::confirm_window_title(app),
            520.0,
            320.0,
        )),
        _ => None,
    };
    if let Some((page, title, w, h)) = spec {
        let light = tray_theme::app_is_light();
        let mut init = tray_theme::theme_script_url(light);
        if label == DEVICES_WINDOW {
            init.push_str(&format!(
                "window.__VW_TAB=window.__VW_TAB||'{}';",
                devices_tab()
            ));
        }
        let b = WebviewWindowBuilder::new(app, label, WebviewUrl::App(page.into()))
            .title(title)
            .inner_size(w, h)
            .resizable(false)
            .always_on_top(label == CONFIRM_WINDOW)
            .focused(true)
            // Theme setting (SPEC 2.6): Dark/Light, or System = dark unless
            // the OS explicitly says light (M1.1 design rule): title bar +
            // prefers-color-scheme, and <html data-theme> for ui/tokens.css
            // from the initialization script, before first paint. Dark background
            // first, so there is no white flash.
            // Privacy (M1.1): private/ephemeral webview session: no cookies,
            // localStorage, IndexedDB or HTTP cache kept (the pages use none).
            .incognito(true);
        let b = linux_incognito_context(app, b, label)
            .theme(Some(tray_theme::tauri_theme(light)))
            .initialization_script(init)
            // tokens.json background: #070B14 dark, #F4F6F9 light.
            .background_color(tray_theme::window_bg(light))
            .center();
        match b.build() {
            Ok(w) => {
                if label == CONFIRM_WINDOW {
                    let _ = w.set_always_on_top(true);
                }
                let _ = w.set_focus();
                if !user_opened {
                    let _ = w.request_user_attention(Some(UserAttentionType::Informational));
                }
            }
            Err(e) => node::log(&format!("could not open the {label} window: {e}")),
        }
    }
    winmgr::slots().end(label);
}

/// Linux WebKit contexts (QA 10-13, three rounds):
/// - tauri-runtime-wry keeps one WebKit context per `data_directory` key
///   and hands the `tauri://` scheme only to the first webview on that key;
///   with `.incognito(true)` wry builds an ephemeral context for it.
/// - Those keyed contexts live for the whole app run (tauri-runtime-wry
///   2.12.1 lib.rs:2404-2414, tauri#14626) and each keeps a WebKitWebProcess
///   and a WebKitNetworkProcess alive. 8e17fc7 used a fresh key per window
///   instance so reopen rendered, but leaked two processes (~107 MB) per
///   open (QA d446e01, High).
/// - Fix (d446): one fixed key per label (`webview/<label>`), and on Linux a
///   window is never destroyed while the app runs: close is intercepted and
///   the window is hidden (see `on_window_event`); showing it again reloads
///   the page (`reload_fresh`), so no page state is kept across a hide. So
///   each label has at most one context and one set of WebKit processes for
///   the whole run.
///
/// Nothing is stored: the webview is ephemeral (incognito); the keyed dir
/// only holds an empty skeleton, removed at start and exit.
/// Windows (WebView2) registers schemes per webview and is unaffected; a
/// data_directory there would mean a separate WebView2 profile, so this is
/// Linux-only.
#[cfg(target_os = "linux")]
fn linux_incognito_context<'a>(
    app: &'a AppHandle,
    b: WebviewWindowBuilder<'a, tauri::Wry, AppHandle>,
    label: &str,
) -> WebviewWindowBuilder<'a, tauri::Wry, AppHandle> {
    match app.path().app_cache_dir() {
        Ok(dir) => b.data_directory(dir.join("webview").join(label)),
        Err(_) => b,
    }
}

/// Run in a window as it is hidden: clear every timer (no poll re-renders)
/// and empty the document.
const BLANK_PAGE_JS: &str = "(()=>{const t=setTimeout(()=>{},0);for(let i=0;i<=t;i++){clearTimeout(i);clearInterval(i);}if(typeof devs!=='undefined')devs=[];if(typeof shownKey!=='undefined')shownKey=null;if(window.vwClear)window.vwClear();document.documentElement.replaceChildren();})();";

/// Linux hides windows on close instead of destroying them.
const fn reload_on_show() -> bool {
    cfg!(target_os = "linux")
}

/// Reload a hidden window's page from scratch: theme and Devices tab go in
/// the query (the initialization script from creation time may be stale).
fn reload_fresh(w: &tauri::WebviewWindow, label: &str) {
    let Ok(mut url) = w.url() else {
        let _ = w.reload();
        return;
    };
    let theme = if tray_theme::app_is_light() {
        "light"
    } else {
        "dark"
    };
    url.set_query(None);
    url.query_pairs_mut().append_pair("vwtheme", theme);
    if label == DEVICES_WINDOW {
        url.query_pairs_mut().append_pair("vwtab", devices_tab());
    }
    if w.navigate(url).is_err() {
        let _ = w.reload();
    }
}

/// Linux: closing a window hides it (see `linux_incognito_context`), with
/// the same side effects a destroy had (the pair QR is burnt).
fn hide_instead_of_close(window: &tauri::Window, api: &tauri::CloseRequestApi) {
    if !reload_on_show() {
        return;
    }
    api.prevent_close();
    let _ = window.hide();
    // Privacy (QA 8ee9a16): a hidden window keeps no phone names in its DOM.
    // Stop its timers and empty the document; the URL stays, so showing it
    // again reloads the page from core (`reload_fresh`).
    if let Some(w) = window.app_handle().get_webview_window(window.label()) {
        let _ = w.eval(BLANK_PAGE_JS);
    }
    if window.label() == PAIR_WINDOW {
        if let Some(n) = node::get(window.app_handle()) {
            n.pair_cancel();
        }
    }
}

/// The keyed (unused) WebKit contexts leave an empty skeleton under
/// `<cache>/webview` (salt files, an empty HSTS db; no page data: the pages
/// run in ephemeral contexts). Removed at start-up and on exit.
fn clear_webview_scratch(app: &AppHandle) {
    #[cfg(target_os = "linux")]
    if let Ok(dir) = app.path().app_cache_dir() {
        let _ = std::fs::remove_dir_all(dir.join("webview"));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = app;
}

#[cfg(not(target_os = "linux"))]
fn linux_incognito_context<'a>(
    _app: &'a AppHandle,
    b: WebviewWindowBuilder<'a, tauri::Wry, AppHandle>,
    _label: &str,
) -> WebviewWindowBuilder<'a, tauri::Wry, AppHandle> {
    b
}

/// Keeps the tray icon alive for the whole run (never dropped or rebuilt;
/// the theme swap only changes its image).
struct Tray {
    icon: TrayIcon,
}

fn build_tray_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let name = app.package_info().name.clone();
    let header = MenuItem::with_id(
        app,
        "header",
        node::menu_header(app, &name),
        false,
        None::<&str>,
    )?;
    let pair = MenuItem::with_id(app, "pair", "Pair a phone…", true, None::<&str>)?;
    let pair2 = MenuItem::with_id(app, "pair2", "Pair with a code…", true, None::<&str>)?;
    let devices = MenuItem::with_id(app, "devices", "Paired devices…", true, None::<&str>)?;
    let settings = MenuItem::with_id(app, "settings", "Settings…", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", format!("Quit {name}"), true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep_send = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let devs = node::get(app).map(|n| n.devices()).unwrap_or_default();
    if devs.len() <= 1 {
        let (clip_label, file_label) = node::menu_send_labels(app);
        let (clip_id, file_id) = if let Some(d) = devs.first() {
            let hex = d.id.to_hex();
            (format!("send_clipboard:{hex}"), format!("send_file:{hex}"))
        } else {
            ("send_clipboard".to_owned(), "send_file".to_owned())
        };
        let send_clip = MenuItem::with_id(app, clip_id, clip_label, true, None::<&str>)?;
        let send_file = MenuItem::with_id(app, file_id, file_label, true, None::<&str>)?;
        Menu::with_items(
            app,
            &[
                &header, &sep1, &send_clip, &send_file, &sep_send, &pair, &pair2, &devices,
                &settings, &sep2, &quit,
            ],
        )
    } else {
        let copied_fname = node::get_os_clipboard_file(app)
            .and_then(|p| p.file_name().and_then(|s| s.to_str()).map(|s| s.to_owned()));
        let clip_sub_label = match copied_fname.as_deref() {
            Some(fname) => format!("Send copied file ({fname})"),
            None => "Send clipboard".to_owned(),
        };
        let mut submenus = Vec::with_capacity(devs.len());
        for d in &devs {
            let hex = d.id.to_hex();
            let sub_clip = MenuItem::with_id(
                app,
                format!("send_clipboard:{hex}"),
                &clip_sub_label,
                true,
                None::<&str>,
            )?;
            let sub_file = MenuItem::with_id(
                app,
                format!("send_file:{hex}"),
                "Choose file to send…",
                true,
                None::<&str>,
            )?;
            let sub =
                tauri::menu::Submenu::with_items(app, &d.name, true, &[&sub_clip, &sub_file])?;
            submenus.push(sub);
        }
        let menu = Menu::new(app)?;
        menu.append(&header)?;
        menu.append(&sep1)?;
        for sub in &submenus {
            menu.append(sub)?;
        }
        menu.append(&sep_send)?;
        menu.append(&pair)?;
        menu.append(&pair2)?;
        menu.append(&devices)?;
        menu.append(&settings)?;
        menu.append(&sep2)?;
        menu.append(&quit)?;
        Ok(menu)
    }
}

/// Re-read the tray status header, per-phone menu items, and tooltip.
/// Called on pairing/device changes; marshalled onto the main thread.
pub fn refresh_tray(app: &AppHandle) {
    let h = app.clone();
    let _ = app.run_on_main_thread(move || {
        let Some(t) = h.try_state::<Tray>() else {
            return;
        };
        let name = h.package_info().name.clone();
        if let Ok(menu) = build_tray_menu(&h) {
            let _ = t.icon.set_menu(Some(menu));
        }
        let _ = t.icon.set_tooltip(Some(node::tooltip(&h, &name)));
    });
}

/// A second launch (QA 10-13): bring the running copy to the front. The
/// window the user last had open is shown and focused; with none open, the
/// Paired devices window opens. The confirm prompt never takes focus.
fn on_second_launch(app: &AppHandle) {
    for label in [PAIR_WINDOW, DEVICES_WINDOW, CONFIRM_WINDOW] {
        if let Some(w) = app.get_webview_window(label) {
            if w.is_visible().unwrap_or(false) {
                if label == DEVICES_WINDOW {
                    // Keep the tab the user is on.
                    let _ = w.unminimize();
                    let _ = w.show();
                    let _ = w.set_focus();
                } else {
                    request_window(app, label);
                }
                return;
            }
        }
    }
    request_devices(app, false);
}

fn main() {
    // M3.2 single-binary early CLI intercept: Browser Native Messaging host,
    // `--send-file <path>`, and AUTH-13 CLI URL refusal exit here in < 5 ms
    // before Tauri, WebView2/GTK, or single-instance initializes.
    if ipc::try_handle_cli_early() {
        return;
    }
    // Crash capture (local file only with Diagnostics on; never uploaded).
    diag::install_panic_hook();
    let app = tauri::Builder::default()
        // Must be the first plugin: a second launch hands over to the
        // running copy (Windows: per-session named mutex + window message;
        // Linux: a D-Bus name on the session bus) and exits right here,
        // before any setup. The instance.lock in node.rs stays as the
        // backstop (e.g. no session bus).
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            // Runs inside the plugin's IPC handler (Linux: a D-Bus method
            // call the second process waits on): answer at once and do the
            // window work on the main thread afterwards.
            let mode = ipc::classify_cli_args(&argv);
            let h = app.clone();
            let _ = std::thread::Builder::new()
                .name("second-launch".into())
                .spawn(move || match mode {
                    ipc::CliMode::SendFile(path) => {
                        let _ = ipc::handle_send_file_in_app(&h, path, None);
                    }
                    ipc::CliMode::NativeMessagingHost | ipc::CliMode::RejectExit => {}
                    ipc::CliMode::NormalGui => {
                        let h2 = h.clone();
                        let _ = h.run_on_main_thread(move || on_second_launch(&h2));
                    }
                });
        }))
        .invoke_handler(tauri::generate_handler![
            commands::pair_start,
            commands::pair_status,
            commands::pair_submit_code,
            commands::pair_cancel,
            commands::devices_list,
            commands::device_forget,
            commands::settings_get,
            commands::settings_set_no_prompt,
            commands::settings_set_diagnostics,
            commands::settings_set_theme,
            commands::open_pair_window,
            commands::pair2_relays,
            commands::relays_list,
            commands::relays_add,
            commands::relays_remove,
            commands::relays_rename,
            commands::relays_retry,
            commands::relays_set_home,
            commands::pairing_relays,
            commands::relay_change_propose,
            commands::relay_changes,
            commands::relay_change_answer,
            commands::pair2_show,
            commands::pair2_status,
            commands::pair2_submit_code,
            commands::pair2_open_code,
            commands::pair2_add_relay,
            commands::pair2_join,
            commands::pair2_join_wait,
            commands::pair2_cancel,
            commands::pair2_copy_code,
            commands::open_pair2_window,
            commands::pending_list,
            commands::pending_decide,
            commands::settings_set_connection_stats,
            commands::connection_stats_list,
            commands::settings_set_relay_cap,
            commands::settings_set_never_relay_files,
            commands::settings_set_file_history,
            commands::completed_files_clear,
            commands::settings_set_relay_config,
            commands::settings_set_pc_name,
            commands::settings_set_download_dir,
            commands::pick_download_dir,
            commands::incoming_files_list,
            commands::completed_files_list,
            commands::incoming_file_decide,
            commands::accept_file,
            commands::cancel_file,
            commands::settings_set_auto_copy_clipboard,
            commands::settings_set_send_clipboard_shortcut,
            commands::settings_set_send_clipboard_shortcut_accel,
            commands::set_drop_target_phone,
            commands::pending_clipboards_list,
            commands::pending_clipboard_decide,
            commands::send_clipboard_to_phone,
            commands::send_text_to_phone,
            commands::send_file_to_phone_pick,
            commands::outgoing_files_list,
            commands::cancel_outgoing_file,
            commands::settings_set_context_menu,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            node::start(&handle);
            if node::start_error().as_deref() == Some(node::ALREADY_RUNNING) {
                // A second launch the single-instance plugin did not catch
                // (no session bus): the running copy keeps the tray.
                handle.exit(0);
                return Ok(());
            }
            clear_webview_scratch(&handle);
            let name = app.package_info().name.clone();
            let menu = build_tray_menu(&handle)?;
            // C2 Relay tray glyph for the taskbar/panel theme (not the app icon).
            let (icon, template) = tray_theme::initial()?;
            let tray = TrayIconBuilder::with_id(tray_theme::TRAY_ID)
                .icon(icon)
                .icon_as_template(template)
                .tooltip(node::tooltip(&handle, &name))
                .menu(&menu)
                .show_menu_on_left_click(false)
                // Tray handlers only queue work (winmgr): no window is built
                // inside a tray/menu dispatch, nothing here can panic.
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::DoubleClick {
                        button: MouseButton::Left,
                        ..
                    } = event
                    {
                        request_devices(tray.app_handle(), false);
                    }
                })
                .on_menu_event(|app, event| match winmgr::menu_action(event.id.as_ref()) {
                    Some(MenuAction::ShowPair) => request_window(app, PAIR_WINDOW),
                    Some(MenuAction::ShowPair2) => request_window(app, PAIR2_WINDOW),
                    Some(MenuAction::ShowDevices) => request_devices(app, false),
                    Some(MenuAction::ShowSettings) => request_devices(app, true),
                    Some(MenuAction::SendClipboardToPhone(target_id)) => {
                        let h = app.clone();
                        let id = target_id.unwrap_or_default();
                        tauri::async_runtime::spawn(async move {
                            let clip_file = node::get_os_clipboard_file(&h)
                                .map(|p| p.display().to_string());
                            if let Err(e) =
                                commands::send_clipboard_to_phone(h.clone(), id.clone(), None).await
                            {
                                node::log(&format!("tray send clipboard: {}", crate::commands::send_err_log_kind(&e)));
                                node::set_pending_ui_send_error(node::PendingUiSendError {
                                    error: e,
                                    device_id: id,
                                    file_path: clip_file,
                                    retry_text: None,
                                });
                                request_devices(&h, false);
                                if let Some(w) = h.get_webview_window(DEVICES_WINDOW) {
                                    let _ = w.eval("if(typeof window.vwCheckPendingSendError==='function')window.vwCheckPendingSendError();");
                                }
                            }
                        });
                    }
                    Some(MenuAction::SendFileToPhone(target_id)) => {
                        let h = app.clone();
                        let id = target_id.unwrap_or_default();
                        tauri::async_runtime::spawn(async move {
                            if let Err(e) =
                                commands::send_file_to_phone_pick(h.clone(), id.clone(), None, None)
                                    .await
                            {
                                node::log(&format!("tray send file: {}", crate::commands::send_err_log_kind(&e)));
                                node::set_pending_ui_send_error(node::PendingUiSendError {
                                    error: e,
                                    device_id: id,
                                    file_path: None,
                                    retry_text: None,
                                });
                                request_devices(&h, false);
                                if let Some(w) = h.get_webview_window(DEVICES_WINDOW) {
                                    let _ = w.eval("if(typeof window.vwCheckPendingSendError==='function')window.vwCheckPendingSendError();");
                                }
                            }
                        });
                    }
                    Some(MenuAction::Quit) => {
                        node::shutdown(app);
                        app.exit(0)
                    }
                    None => {}
                })
                .build(app)?;
            app.manage(Tray { icon: tray });
            tray_theme::follow_theme(&handle);
            // Windows: keep "Send copied file (name)" live while the menu is
            // closed (WM_CLIPBOARDUPDATE; fires only when the file name changes).
            let clip_handle = handle.clone();
            voidwire_os_theme::watch_clipboard_files(std::sync::Arc::new(move || {
                refresh_tray(&clip_handle)
            }));
            // QA/support: `VOIDWIRE_SHOW=pair|devices` opens a window at start.
            if let Ok(w) = std::env::var(concat!(env!("VOIDWIRE_BRAND_ENV_PREFIX"), "_SHOW")) {
                match w.as_str() {
                    PAIR_WINDOW => request_window(&handle, PAIR_WINDOW),
                    DEVICES_WINDOW => request_devices(&handle, false),
                    "settings" => request_devices(&handle, true),
                    CONFIRM_WINDOW => request_window(&handle, CONFIRM_WINDOW),
                    _ => {}
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                hide_instead_of_close(window, api);
            }
            if window.label() == DEVICES_WINDOW {
                // M4.2: the window coming to the front is an event to pull
                // the pairing inboxes (rate-limited in core; no timers).
                if let tauri::WindowEvent::Focused(true) = event {
                    if let Some(n) = node::get(window.app_handle()) {
                        std::thread::spawn(move || {
                            let _ = n.pull_pairing_inboxes_on_focus();
                        });
                    }
                }
                if let tauri::WindowEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) =
                    event
                {
                    let files: Vec<std::path::PathBuf> =
                        paths.iter().filter(|p| p.is_file()).cloned().collect();
                    if !files.is_empty() {
                        let app_handle = window.app_handle().clone();
                        let target_id = node::get_drop_target_phone().unwrap_or_default();
                        tauri::async_runtime::spawn(async move {
                            let Some(n) = node::get(&app_handle) else {
                                return;
                            };
                            let Ok(phone_id) = commands::resolve_target_phone(&n, &target_id)
                            else {
                                return;
                            };
                            let phone_id_hex = phone_id.to_hex();
                            for path in files {
                                let p_str = path.display().to_string();
                                if let Err(e) = commands::send_file_to_phone_pick(
                                    app_handle.clone(),
                                    phone_id_hex.clone(),
                                    Some(p_str.clone()),
                                    None,
                                )
                                .await
                                {
                                    node::set_pending_ui_send_error(node::PendingUiSendError {
                                        error: e,
                                        device_id: phone_id_hex.clone(),
                                        file_path: Some(p_str),
                                        retry_text: None,
                                    });
                                    break;
                                }
                            }
                            if let Some(w) = app_handle.get_webview_window(DEVICES_WINDOW) {
                                let _ = w.eval(
                                    "if(typeof shownTransfersKey!=='undefined')shownTransfersKey=null;if(typeof refresh==='function')refresh();if(typeof window.vwCheckPendingSendError==='function')window.vwCheckPendingSendError();",
                                );
                            }
                        });
                    }
                }
                return;
            }
            if window.label() == PAIR2_WINDOW {
                // Closing the code window cancels it (the code and its
                // relay card stop working).
                if let (tauri::WindowEvent::Destroyed, Some(n)) =
                    (event, node::get(window.app_handle()))
                {
                    n.pair2_cancel();
                }
                if let tauri::WindowEvent::Destroyed = event {
                    pair_clip::finish(window.app_handle());
                }
                return;
            }
            if window.label() != PAIR_WINDOW {
                return;
            }
            let Some(n) = node::get(window.app_handle()) else {
                return;
            };
            // Closing the pair window burns its QR (single use). Minimized or
            // hidden: nothing; the live QR lives out its own short expiry.
            if let tauri::WindowEvent::Destroyed = event {
                n.pair_cancel();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building the tray app");

    app.run(|app, event| match event {
        // Closing a window must not quit the tray app.
        RunEvent::ExitRequested { api, code, .. } if code.is_none() => api.prevent_exit(),
        RunEvent::Exit => {
            clear_webview_scratch(app);
        }
        _ => {}
    });
}
