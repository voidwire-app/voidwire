//! M3.2 single-binary local IPC and Browser Native Messaging bridge.
//!
//! Security invariant (`AUTH-13` in `docs/TEST-PLAN.md`):
//! - The local IPC pipe/socket and Native Messaging stdio bridge are strictly
//!   **send/status-only** (`status`, `send_url`, `send_text`, `send_clipboard`,
//!   `send_file`).
//! - No IPC variant or CLI argument can ever reach the desktop link-opening pipeline or open a URL on
//!   this PC.
//! - The underlying OS pipe/socket ACL is restricted to the current OS user
//!   (`D:P(A;;GA;;;<sid>)` + `PIPE_REJECT_REMOTE_CLIENTS` on Windows; `0700`
//!   dir + `0600` socket on Unix).

use std::sync::Mutex;
use tauri::AppHandle;
use voidwire_os_theme::{
    ipc_exchange, read_ipc_frame, write_ipc_frame, IpcServer, FIREFOX_EXTENSION_ID,
    NATIVE_HOST_NAME,
};

/// File path queued when `voidwire --send-file <path>` was launched while no
/// tray instance was running yet; dispatched as soon as `node::start` completes.
static STARTUP_SEND_FILE: Mutex<Option<String>> = Mutex::new(None);

pub fn take_startup_send_file() -> Option<String> {
    STARTUP_SEND_FILE.lock().ok().and_then(|mut g| g.take())
}

fn set_startup_send_file(path: String) {
    if let Ok(mut g) = STARTUP_SEND_FILE.lock() {
        *g = Some(path);
    }
}

/// How `main()` should treat its command-line arguments before initializing GUI/Tauri.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliMode {
    /// Normal desktop tray application startup.
    NormalGui,
    /// Browser Native Messaging stdio host (`stdin` -> local IPC pipe -> `stdout`).
    NativeMessagingHost,
    /// OS file manager context menu action (`voidwire --send-file <path>`).
    SendFile(String),
    /// `AUTH-13`: Refused CLI invocation (e.g. URL/URI/open flags passed on argv).
    RejectExit,
}

/// Inspect `argv` (including `argv[0]`) and classify the invocation mode.
pub fn classify_cli_args(args: &[String]) -> CliMode {
    if is_native_messaging_args(args) {
        return CliMode::NativeMessagingHost;
    }
    if let Some(path) = parse_send_file_arg(args) {
        return CliMode::SendFile(path);
    }
    if is_rejected_cli_url_arg(args) {
        return CliMode::RejectExit;
    }
    CliMode::NormalGui
}

/// True when `args` comes from Chrome/Brave/Edge/Chromium/Firefox Native Messaging
/// or explicit `--native-messaging-host`.
pub fn is_native_messaging_args(args: &[String]) -> bool {
    args.iter().skip(1).any(|a| {
        let trimmed = a.trim();
        trimmed == "--native-messaging-host"
            || trimmed.starts_with("chrome-extension://")
            || trimmed.starts_with("moz-extension://")
            || trimmed == FIREFOX_EXTENSION_ID
            || trimmed.ends_with(&format!("{NATIVE_HOST_NAME}.json"))
            || trimmed.ends_with(&format!("{NATIVE_HOST_NAME}.chromium.json"))
            || trimmed.ends_with(&format!("{NATIVE_HOST_NAME}.firefox.json"))
    })
}

/// Extract `<path>` from `--send-file <path>` or `--send-file=<path>`.
pub fn parse_send_file_arg(args: &[String]) -> Option<String> {
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == "--send-file" {
            let val = iter.next()?.trim();
            if !val.is_empty() {
                return Some(val.to_owned());
            }
            return None;
        }
        if let Some(rest) = arg.strip_prefix("--send-file=") {
            let val = rest.trim();
            if !val.is_empty() {
                return Some(val.to_owned());
            }
            return None;
        }
    }
    None
}

/// `AUTH-13`: Reject any attempt to pass a URL, custom URI scheme, or `--open`
/// flag on the command line so `voidwire` can never be used as a local URL opener.
pub fn is_rejected_cli_url_arg(args: &[String]) -> bool {
    args.iter().skip(1).any(|a| {
        let lower = a.trim().to_ascii_lowercase();
        lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("voidwire:")
            || lower.starts_with("urlshare:")
            || lower.starts_with("file://")
            || lower == "--open"
            || lower.starts_with("--open=")
            || lower == "--url"
            || lower.starts_with("--url=")
    })
}

/// Send/status-only request schema accepted over Native Messaging and the local IPC pipe (`AUTH-13`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcRequest {
    Status,
    SendUrl {
        url: String,
        #[serde(default)]
        phone_id: Option<String>,
        #[serde(default)]
        pop_ui_on_error: bool,
    },
    SendText {
        text: String,
        #[serde(default)]
        phone_id: Option<String>,
        #[serde(default)]
        allow_relay: bool,
        #[serde(default)]
        pop_ui_on_error: bool,
    },
    SendClipboard {
        #[serde(default)]
        phone_id: Option<String>,
        #[serde(default)]
        allow_relay: bool,
        #[serde(default)]
        pop_ui_on_error: bool,
    },
    SendFile {
        path: String,
        #[serde(default)]
        phone_id: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IpcPhoneDto {
    pub id: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct IpcResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub running: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phones: Option<Vec<IpcPhoneDto>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_prompt: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exceeds_relay_cap: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl IpcResponse {
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            ..Self::default()
        }
    }

    pub fn not_running() -> Self {
        Self {
            ok: false,
            running: Some(false),
            error: Some(
                "Voidwire desktop app is not running. Launch Voidwire from the system tray or Start menu."
                    .to_owned(),
            ),
            ..Self::default()
        }
    }
}

/// Parse and validate an `IpcRequest` from raw JSON bytes (`AUTH-13`).
pub fn parse_ipc_request_bytes(bytes: &[u8]) -> Result<IpcRequest, String> {
    let req: IpcRequest = serde_json::from_slice(bytes)
        .map_err(|_| "unsupported or invalid IPC request (send/status only)".to_owned())?;
    match &req {
        IpcRequest::Status => Ok(req),
        IpcRequest::SendUrl { url, .. } => {
            let trimmed = url.trim();
            let lower = trimmed.to_ascii_lowercase();
            if !(lower.starts_with("https://") || lower.starts_with("http://")) {
                return Err("SendUrl requires an http:// or https:// URL.".to_owned());
            }
            Ok(req)
        }
        IpcRequest::SendText { text, .. } => {
            if text.trim().is_empty() {
                return Err("Text is empty.".to_owned());
            }
            Ok(req)
        }
        IpcRequest::SendClipboard { .. } => Ok(req),
        IpcRequest::SendFile { path, .. } => {
            if path.trim().is_empty() {
                return Err("File path is empty.".to_owned());
            }
            Ok(req)
        }
    }
}

/// Dispatch raw request bytes through a caller-supplied handler after `AUTH-13` validation.
pub fn dispatch_ipc_bytes_with<F>(raw: &[u8], handler: F) -> Vec<u8>
where
    F: FnOnce(IpcRequest) -> IpcResponse,
{
    let resp = match parse_ipc_request_bytes(raw) {
        Ok(req) => handler(req),
        Err(e) => IpcResponse::err(e),
    };
    serde_json::to_vec(&resp).unwrap_or_else(|_| br#"{"ok":false,"error":"serialize"}"#.to_vec())
}

/// Run the Native Messaging stdio loop (`u32 LE` frames on `stdin` -> local IPC pipe -> `stdout`).
pub fn run_native_messaging_host_io<R: std::io::Read, W: std::io::Write>(
    mut reader: R,
    mut writer: W,
) -> std::io::Result<()> {
    while let Some(frame) = read_ipc_frame(&mut reader)? {
        let resp_bytes = match parse_ipc_request_bytes(&frame) {
            Ok(_) => match ipc_exchange(&frame) {
                Ok(reply) => reply,
                Err(_) => serde_json::to_vec(&IpcResponse::not_running())
                    .unwrap_or_else(|_| br#"{"ok":false,"running":false}"#.to_vec()),
            },
            Err(e) => serde_json::to_vec(&IpcResponse::err(e))
                .unwrap_or_else(|_| br#"{"ok":false}"#.to_vec()),
        };
        write_ipc_frame(&mut writer, &resp_bytes)?;
    }
    Ok(())
}

/// Intercept `--native-messaging-host`, `--send-file <path>`, or rejected CLI URL args
/// at the very top of `fn main()` before Tauri or single-instance initializes.
/// Returns `true` when the process has completed its CLI/host duty and `main()` should return.
pub fn try_handle_cli_early() -> bool {
    let args: Vec<String> = std::env::args().collect();
    match classify_cli_args(&args) {
        CliMode::NormalGui => false,
        CliMode::RejectExit => true,
        CliMode::NativeMessagingHost => {
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let _ = run_native_messaging_host_io(stdin.lock(), stdout.lock());
            true
        }
        CliMode::SendFile(path) => {
            let req = IpcRequest::SendFile {
                path: path.clone(),
                phone_id: None,
            };
            if let Ok(payload) = serde_json::to_vec(&req) {
                if ipc_exchange(&payload).is_ok() {
                    return true;
                }
            }
            // No tray instance is listening yet: boot the tray app and queue this file send.
            set_startup_send_file(path);
            false
        }
    }
}

fn notify_devices_window_error(app: &AppHandle) {
    crate::request_devices(app, false);
    if let Some(w) = tauri::Manager::get_webview_window(app, crate::DEVICES_WINDOW) {
        let _ = w.eval(
            "if(typeof window.vwCheckPendingSendError==='function')window.vwCheckPendingSendError();",
        );
    }
}

fn map_formatted_send_err(
    app: &AppHandle,
    formatted: String,
    phone_id: String,
    file_path: Option<String>,
    retry_text: Option<String>,
    pop_ui: bool,
) -> IpcResponse {
    let kind = crate::commands::send_err_log_kind(&formatted);
    let relay_prompt = (kind == "relay_prompt").then_some(true);
    let exceeds_relay_cap = (kind == "relay_cap" || kind == "relay_never").then_some(true);
    let first_line = formatted
        .lines()
        .next()
        .unwrap_or("Send failed.")
        .to_owned();
    let human_err = if relay_prompt == Some(true) {
        "Phone is only reachable via the encrypted relay. Confirm relay transfer to send items over 256 KB.".to_owned()
    } else if exceeds_relay_cap == Some(true) {
        "Item exceeds the relay limit while the phone is not on the same Wi-Fi / LAN.".to_owned()
    } else {
        first_line
    };
    if pop_ui {
        crate::node::set_pending_ui_send_error(crate::node::PendingUiSendError {
            error: formatted,
            phone_id,
            file_path,
            retry_text,
        });
        notify_devices_window_error(app);
    }
    IpcResponse {
        ok: false,
        relay_prompt,
        exceeds_relay_cap,
        error: Some(human_err),
        ..IpcResponse::default()
    }
}

/// Error for an IPC send with no `phone_id` while 2+ phones are paired (`M3.2.1`).
/// The extension popup and context-menu submenus always send an explicit id, so this
/// only fires for a caller that skipped the picker; never silently pick a phone.
pub const CHOOSE_PHONE_ERR: &str = "Choose a phone: more than one phone is paired with this PC.";
/// Error for an IPC send whose `phone_id` is not (or no longer) paired. The extension
/// matches this exact text to refresh its right-click menus.
pub const PHONE_NOT_PAIRED_ERR: &str = "Selected phone is no longer paired.";
/// Error for an IPC send when nothing is paired.
pub const NO_PHONE_ERR: &str = "No paired phone found. Pair a phone first.";

/// Pick the target phone for an IPC `send_url` / `send_text` / `send_clipboard` (`M3.2.1`).
/// `paired` is the paired phones' hex ids in Devices order. Returns the index into `paired`.
/// - explicit id: must be one of `paired` (case-insensitive), else [`PHONE_NOT_PAIRED_ERR`];
/// - no id, exactly one phone: that phone;
/// - no id, 2+ phones: [`CHOOSE_PHONE_ERR`] (no silent `devices[0]` fallback);
/// - nothing paired: [`NO_PHONE_ERR`].
pub fn pick_ipc_send_target(
    paired: &[String],
    phone_id: Option<&str>,
) -> Result<usize, &'static str> {
    if paired.is_empty() {
        return Err(NO_PHONE_ERR);
    }
    let wanted = phone_id.map(str::trim).unwrap_or("");
    if wanted.is_empty() {
        return if paired.len() == 1 {
            Ok(0)
        } else {
            Err(CHOOSE_PHONE_ERR)
        };
    }
    paired
        .iter()
        .position(|id| id.eq_ignore_ascii_case(wanted))
        .ok_or(PHONE_NOT_PAIRED_ERR)
}

fn resolve_ipc_send_target(
    app: &AppHandle,
    n: &voidwire_core::net::pc::PcNode,
    phone_id: Option<String>,
    pop_ui_on_error: bool,
) -> Result<voidwire_core::ids::DeviceId, &'static str> {
    let devices = n.devices();
    let paired: Vec<String> = devices.iter().map(|d| d.id.to_hex()).collect();
    match pick_ipc_send_target(&paired, phone_id.as_deref()) {
        Ok(i) => Ok(devices[i].id),
        Err(e) => {
            if pop_ui_on_error {
                crate::node::set_pending_ui_send_error(crate::node::PendingUiSendError {
                    error: e.to_owned(),
                    phone_id: String::new(),
                    file_path: None,
                    retry_text: None,
                });
                notify_devices_window_error(app);
            }
            Err(e)
        }
    }
}

/// Dispatch a `--send-file <path>` request inside the running Voidwire tray app.
pub fn handle_send_file_in_app(
    app: &AppHandle,
    path: String,
    phone_id: Option<String>,
) -> IpcResponse {
    let n = match crate::commands::node(app) {
        Ok(n) => n,
        Err(e) => return IpcResponse::err(e),
    };
    let devices = n.devices();
    if devices.is_empty() {
        crate::node::set_pending_ui_send_error(crate::node::PendingUiSendError {
            error: "No phone is paired with this PC yet. Pair your phone first, then right-click the file and choose Send with Voidwire.".to_owned(),
            phone_id: String::new(),
            file_path: Some(path),
            retry_text: None,
        });
        notify_devices_window_error(app);
        return IpcResponse::err("No paired phone found.");
    }
    let explicit_id = phone_id.unwrap_or_default();
    if explicit_id.trim().is_empty() && devices.len() > 1 {
        crate::node::set_pending_ui_send_error(crate::node::PendingUiSendError {
            error: "__pick_phone__".to_owned(),
            phone_id: String::new(),
            file_path: Some(path),
            retry_text: None,
        });
        notify_devices_window_error(app);
        return IpcResponse {
            ok: true,
            running: Some(true),
            ..IpcResponse::default()
        };
    }

    let target_dev = if explicit_id.trim().is_empty() {
        devices[0].clone()
    } else {
        match devices
            .into_iter()
            .find(|d| d.id.to_hex() == explicit_id.trim())
        {
            Some(d) => d,
            None => return IpcResponse::err(PHONE_NOT_PAIRED_ERR),
        }
    };
    let target_hex = target_dev.id.to_hex();
    let target_name = target_dev.name;
    let fname = std::path::Path::new(&path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file")
        .to_owned();

    // Open/focus the Devices window so the user sees the transfer progress or relay prompt.
    crate::request_devices(app, false);
    let h = app.clone();
    let path_for_task = path;
    let id_for_task = target_hex;
    tauri::async_runtime::spawn(async move {
        match crate::commands::send_file_to_phone_pick(
            h.clone(),
            id_for_task.clone(),
            Some(path_for_task.clone()),
            None,
        )
        .await
        {
            Ok(_) => {
                if let Some(w) = tauri::Manager::get_webview_window(&h, crate::DEVICES_WINDOW) {
                    let _ = w.eval(
                        "if(typeof window.vwCheckPendingSendError==='function')window.vwCheckPendingSendError();",
                    );
                }
            }
            Err(e) => {
                crate::node::log(&format!(
                    "context-menu send file: {}",
                    crate::commands::send_err_log_kind(&e)
                ));
                crate::node::set_pending_ui_send_error(crate::node::PendingUiSendError {
                    error: e,
                    phone_id: id_for_task,
                    file_path: Some(path_for_task),
                    retry_text: None,
                });
                notify_devices_window_error(&h);
            }
        }
    });

    IpcResponse {
        ok: true,
        running: Some(true),
        sent_to: Some(target_name),
        filename: Some(fname),
        ..IpcResponse::default()
    }
}

/// Handle a validated `IpcRequest` inside the running Voidwire tray application.
pub fn handle_request_in_app(app: &AppHandle, req: IpcRequest) -> IpcResponse {
    match req {
        IpcRequest::Status => match crate::commands::node(app) {
            Ok(n) => {
                let phones = n
                    .devices()
                    .into_iter()
                    .map(|d| IpcPhoneDto {
                        id: d.id.to_hex(),
                        label: d.name,
                    })
                    .collect();
                IpcResponse {
                    ok: true,
                    running: Some(true),
                    version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                    phones: Some(phones),
                    ..IpcResponse::default()
                }
            }
            Err(e) => IpcResponse::err(e),
        },
        IpcRequest::SendUrl {
            url,
            phone_id,
            pop_ui_on_error,
        } => {
            let n = match crate::commands::node(app) {
                Ok(n) => n,
                Err(e) => return IpcResponse::err(e),
            };
            let dev_id = match resolve_ipc_send_target(app, &n, phone_id, pop_ui_on_error) {
                Ok(id) => id,
                Err(e) => return IpcResponse::err(e),
            };
            let to_name = crate::commands::phone_display_name(&n, &dev_id);
            let hex_id = dev_id.to_hex();
            match tauri::async_runtime::block_on(crate::commands::send_text_to_phone(
                app.clone(),
                hex_id.clone(),
                url.clone(),
                None,
            )) {
                Ok(out) => IpcResponse {
                    ok: true,
                    running: Some(true),
                    sent_to: Some(to_name),
                    path: Some(out.delivery_path.to_owned()),
                    ..IpcResponse::default()
                },
                Err(formatted) => {
                    map_formatted_send_err(app, formatted, hex_id, None, Some(url), pop_ui_on_error)
                }
            }
        }
        IpcRequest::SendText {
            text,
            phone_id,
            allow_relay,
            pop_ui_on_error,
        } => {
            let n = match crate::commands::node(app) {
                Ok(n) => n,
                Err(e) => return IpcResponse::err(e),
            };
            let dev_id = match resolve_ipc_send_target(app, &n, phone_id, pop_ui_on_error) {
                Ok(id) => id,
                Err(e) => return IpcResponse::err(e),
            };
            let to_name = crate::commands::phone_display_name(&n, &dev_id);
            let hex_id = dev_id.to_hex();
            let decision = allow_relay.then(|| "send_via_relay".to_owned());
            match tauri::async_runtime::block_on(crate::commands::send_text_to_phone(
                app.clone(),
                hex_id.clone(),
                text.clone(),
                decision,
            )) {
                Ok(out) => IpcResponse {
                    ok: true,
                    running: Some(true),
                    sent_to: Some(to_name),
                    path: Some(out.delivery_path.to_owned()),
                    ..IpcResponse::default()
                },
                Err(formatted) => map_formatted_send_err(
                    app,
                    formatted,
                    hex_id,
                    None,
                    Some(text),
                    pop_ui_on_error,
                ),
            }
        }
        IpcRequest::SendClipboard {
            phone_id,
            allow_relay,
            pop_ui_on_error,
        } => {
            let n = match crate::commands::node(app) {
                Ok(n) => n,
                Err(e) => return IpcResponse::err(e),
            };
            let dev_id = match resolve_ipc_send_target(app, &n, phone_id, pop_ui_on_error) {
                Ok(id) => id,
                Err(e) => return IpcResponse::err(e),
            };
            let to_name = crate::commands::phone_display_name(&n, &dev_id);
            let hex_id = dev_id.to_hex();
            let clip_file =
                crate::node::get_os_clipboard_file(app).map(|p| p.display().to_string());
            let decision = allow_relay.then(|| "send_via_relay".to_owned());
            match tauri::async_runtime::block_on(crate::commands::send_clipboard_to_phone(
                app.clone(),
                hex_id.clone(),
                decision,
            )) {
                Ok(out) => IpcResponse {
                    ok: true,
                    running: Some(true),
                    sent_to: Some(to_name),
                    path: Some(out.delivery_path.to_owned()),
                    ..IpcResponse::default()
                },
                Err(formatted) => {
                    map_formatted_send_err(app, formatted, hex_id, clip_file, None, pop_ui_on_error)
                }
            }
        }
        IpcRequest::SendFile { path, phone_id } => handle_send_file_in_app(app, path, phone_id),
    }
}

/// Spawn the background current-user-only local IPC listener thread for the running tray app.
pub fn spawn_ipc_server(app: AppHandle) {
    std::thread::spawn(move || {
        let mut server = match IpcServer::bind() {
            Ok(s) => s,
            Err(e) => {
                crate::node::log(&format!("ipc bind failed: {e}"));
                return;
            }
        };
        loop {
            let h = app.clone();
            if let Err(e) = server.accept_and_serve(|raw| {
                dispatch_ipc_bytes_with(raw, |req| handle_request_in_app(&h, req))
            }) {
                crate::node::log(&format!("ipc accept: {e}"));
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("{:064x}", i + 0xa0)).collect()
    }

    #[test]
    fn m321_ipc_send_without_phone_id_requires_choice_when_two_or_more_paired() {
        for n in [2usize, 3, 5] {
            let p = ids(n);
            assert_eq!(pick_ipc_send_target(&p, None), Err(CHOOSE_PHONE_ERR));
            assert_eq!(pick_ipc_send_target(&p, Some("")), Err(CHOOSE_PHONE_ERR));
            assert_eq!(pick_ipc_send_target(&p, Some("   ")), Err(CHOOSE_PHONE_ERR));
        }
    }

    #[test]
    fn m321_ipc_send_without_phone_id_uses_the_only_phone() {
        let p = ids(1);
        assert_eq!(pick_ipc_send_target(&p, None), Ok(0));
        assert_eq!(pick_ipc_send_target(&p, Some("")), Ok(0));
    }

    #[test]
    fn m321_ipc_send_explicit_phone_id_targets_that_phone() {
        let p = ids(3);
        assert_eq!(pick_ipc_send_target(&p, Some(&p[2])), Ok(2));
        assert_eq!(pick_ipc_send_target(&p, Some(&p[1].to_uppercase())), Ok(1));
        assert_eq!(
            pick_ipc_send_target(&p, Some(&format!(" {} ", p[0]))),
            Ok(0)
        );
    }

    #[test]
    fn m321_ipc_send_unpaired_or_empty_list_errors() {
        let p = ids(2);
        let gone = format!("{:064x}", 0xffu32);
        assert_eq!(
            pick_ipc_send_target(&p, Some(&gone)),
            Err(PHONE_NOT_PAIRED_ERR)
        );
        assert_eq!(
            pick_ipc_send_target(&ids(1), Some(&gone)),
            Err(PHONE_NOT_PAIRED_ERR)
        );
        assert_eq!(pick_ipc_send_target(&[], None), Err(NO_PHONE_ERR));
        assert_eq!(pick_ipc_send_target(&[], Some(&p[0])), Err(NO_PHONE_ERR));
    }

    #[test]
    fn m321_phone_not_paired_text_matches_extension() {
        let bg = include_str!("../../extension/background.js");
        assert!(
            bg.contains(PHONE_NOT_PAIRED_ERR),
            "background.js must match the IPC error text"
        );
    }

    #[test]
    fn auth_13_rejects_every_open_shaped_ipc_payload() {
        // AUTH-13 (docs/TEST-PLAN.md line 66): send "open"-shaped payloads to the
        // local IPC parser and dispatcher; none is accepted or reaches the desktop link-opening pipeline.
        let forbidden_payloads: &[&[u8]] = &[
            br#"{"op":"open","url":"https://evil.example"}"#,
            br#"{"op":"open_url","url":"https://evil.example"}"#,
            br#"{"op":"deliver","url":"https://evil.example"}"#,
            br#"{"op":"decide","id":1,"open":true}"#,
            br#"{"op":"launch","target":"https://evil.example"}"#,
            br#"{"url":"https://evil.example"}"#,
            br#"{"action":"open","url":"https://evil.example"}"#,
            br#"{"op":"send_url","url":"file:///etc/passwd"}"#,
            br#"{"op":"send_url","url":"javascript:alert(1)"}"#,
            br#"{"op":"send_url","url":"voidwire:pair?x=1"}"#,
        ];

        for &payload in forbidden_payloads {
            assert!(
                parse_ipc_request_bytes(payload).is_err(),
                "AUTH-13 violation: payload should be rejected: {}",
                String::from_utf8_lossy(payload)
            );
            let mut called = false;
            let reply_bytes = dispatch_ipc_bytes_with(payload, |_| {
                called = true;
                IpcResponse::default()
            });
            assert!(
                !called,
                "handler must never be invoked for forbidden payload"
            );
            let reply: IpcResponse =
                serde_json::from_slice(&reply_bytes).expect("valid error JSON");
            assert!(!reply.ok);
        }
    }

    #[test]
    fn auth_13_rejects_cli_urls_and_deep_links() {
        for bad_arg in [
            "https://evil.example/path",
            "http://evil.example",
            "voidwire:pair?ip=1.2.3.4",
            "urlshare:open?url=https://evil.example",
            "file:///C:/Windows/System32/calc.exe",
            "--open",
            "--open=https://evil.example",
            "--url=https://evil.example",
        ] {
            let args = vec!["voidwire".to_owned(), bad_arg.to_owned()];
            assert_eq!(
                classify_cli_args(&args),
                CliMode::RejectExit,
                "CLI arg {bad_arg} must be rejected by AUTH-13"
            );
        }
    }

    #[test]
    fn cli_mode_detects_native_messaging_and_send_file() {
        let chrome_args = vec![
            "voidwire.exe".to_owned(),
            "chrome-extension://mknbkjlaloblibdffcebiegchmcbmpbm/".to_owned(),
            "--parent-window=0".to_owned(),
        ];
        assert_eq!(
            classify_cli_args(&chrome_args),
            CliMode::NativeMessagingHost
        );

        let ff_args = vec![
            "voidwire".to_owned(),
            "/home/u/.mozilla/native-messaging-hosts/app.voidwire.native_host.json".to_owned(),
            "extension@voidwire.app".to_owned(),
        ];
        assert_eq!(classify_cli_args(&ff_args), CliMode::NativeMessagingHost);

        let flag_args = vec!["voidwire".to_owned(), "--native-messaging-host".to_owned()];
        assert_eq!(classify_cli_args(&flag_args), CliMode::NativeMessagingHost);

        let send_args = vec![
            "voidwire.exe".to_owned(),
            "--send-file".to_owned(),
            r"C:\Users\demo\Documents\report.pdf".to_owned(),
        ];
        assert_eq!(
            classify_cli_args(&send_args),
            CliMode::SendFile(r"C:\Users\demo\Documents\report.pdf".to_owned())
        );

        let normal_args = vec!["voidwire".to_owned()];
        assert_eq!(classify_cli_args(&normal_args), CliMode::NormalGui);
    }

    #[test]
    fn native_messaging_stdio_bridge_roundtrips_and_blocks_open_payloads() {
        let tmp = std::env::temp_dir().join("vw-nm-stdio-test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("create temp dir");
        std::env::set_var("VOIDWIRE_DATA_DIR", &tmp);

        let mut server = IpcServer::bind().expect("bind IPC server");
        let server_thread = std::thread::spawn(move || {
            server
                .accept_and_serve(|raw| {
                    dispatch_ipc_bytes_with(raw, |req| match req {
                        IpcRequest::Status => IpcResponse {
                            ok: true,
                            running: Some(true),
                            version: Some("0.4.0".to_owned()),
                            phones: Some(vec![IpcPhoneDto {
                                id: "aa".repeat(32),
                                label: "Pixel 9".to_owned(),
                            }]),
                            ..IpcResponse::default()
                        },
                        _ => IpcResponse::err("unexpected"),
                    })
                })
                .expect("serve status");
        });

        let mut input = Vec::new();
        // Frame 1: valid status request -> forwarded to IPC server
        write_ipc_frame(&mut input, br#"{"op":"status"}"#).expect("write status frame");
        // Frame 2: forbidden open request -> rejected locally without hitting IPC server
        write_ipc_frame(&mut input, br#"{"op":"open","url":"https://evil.example"}"#)
            .expect("write open frame");

        let mut output = Vec::new();
        run_native_messaging_host_io(std::io::Cursor::new(input), &mut output)
            .expect("run native messaging stdio loop");

        server_thread.join().expect("server thread");

        let mut out_cursor = std::io::Cursor::new(output);
        let frame1 = read_ipc_frame(&mut out_cursor)
            .expect("read frame 1")
            .expect("some frame 1");
        let resp1: IpcResponse = serde_json::from_slice(&frame1).expect("decode resp1");
        assert!(resp1.ok);
        assert_eq!(resp1.running, Some(true));
        assert_eq!(resp1.phones.as_ref().map(Vec::len), Some(1));

        let frame2 = read_ipc_frame(&mut out_cursor)
            .expect("read frame 2")
            .expect("some frame 2");
        let resp2: IpcResponse = serde_json::from_slice(&frame2).expect("decode resp2");
        assert!(!resp2.ok);
        assert!(resp2.error.is_some());

        std::env::remove_var("VOIDWIRE_DATA_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
