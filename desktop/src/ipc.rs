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
/// The target is `device_id` (M4.2: a PC or a phone); `phone_id`, the name
/// before M4.2, is still accepted so older extensions keep working.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcRequest {
    Status,
    SendUrl {
        url: String,
        #[serde(default, alias = "phone_id")]
        device_id: Option<String>,
        #[serde(default)]
        pop_ui_on_error: bool,
    },
    SendText {
        text: String,
        #[serde(default, alias = "phone_id")]
        device_id: Option<String>,
        #[serde(default)]
        allow_relay: bool,
        #[serde(default)]
        pop_ui_on_error: bool,
    },
    SendClipboard {
        #[serde(default, alias = "phone_id")]
        device_id: Option<String>,
        #[serde(default)]
        allow_relay: bool,
        #[serde(default)]
        pop_ui_on_error: bool,
    },
    SendFile {
        path: String,
        #[serde(default, alias = "phone_id")]
        device_id: Option<String>,
    },
}

/// One paired device in a `status` answer (a PC or a phone).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IpcDeviceDto {
    pub id: String,
    pub label: String,
    /// A phone or tablet: counted for the "All phones" target.
    #[serde(default)]
    pub mobile: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct IpcResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub running: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Every paired device, PCs and phones, in Devices order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<IpcDeviceDto>>,
    /// The same list under its pre-M4.5 name (for extensions built before it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phones: Option<Vec<IpcDeviceDto>>,
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
                device_id: None,
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
        "The device is only reachable via the encrypted relay. Confirm relay transfer to send items over 256 KB.".to_owned()
    } else if exceeds_relay_cap == Some(true) {
        "Item exceeds the relay limit while the device is not on the same Wi-Fi / LAN.".to_owned()
    } else {
        first_line
    };
    if pop_ui {
        crate::node::set_pending_ui_send_error(crate::node::PendingUiSendError {
            error: formatted,
            device_id: phone_id,
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

/// Error for an IPC send with no `device_id` while 2+ devices are paired (`M3.2.1`).
/// The extension popup and context-menu submenus always send an explicit id, so this
/// only fires for a caller that skipped the picker; never silently pick a device.
pub const CHOOSE_PHONE_ERR: &str = "Choose a device: more than one device is paired with this PC.";
/// Error for an IPC send whose `device_id` is not (or no longer) paired. The extension
/// matches this exact text to refresh its right-click menus.
pub const PHONE_NOT_PAIRED_ERR: &str = "Selected device is no longer paired.";
/// Error for an IPC send when nothing is paired.
pub const NO_PHONE_ERR: &str = "No paired device found. Pair one with Pair a device…";
/// Error for an "All phones" send when no phone is paired.
pub const NO_PHONES_FOR_ALL_ERR: &str = "No paired phone found. Pair one with Pair a device…";
/// The `device_id` that means "every phone paired with this PC" (M4.5; the
/// extension and the tray only). PCs are never included.
pub const ALL_PHONES: &str = "all_phones";

/// Pick the target device for an IPC `send_url` / `send_text` / `send_clipboard` (`M3.2.1`).
/// `paired` is the paired devices' hex ids in Devices order. Returns the index into `paired`.
/// - explicit id: must be one of `paired` (case-insensitive), else [`PHONE_NOT_PAIRED_ERR`];
/// - no id, exactly one device: that device;
/// - no id, 2+ devices: [`CHOOSE_PHONE_ERR`] (no silent `devices[0]` fallback);
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

/// [`pick_ipc_send_target`] plus [`ALL_PHONES`]: `paired` is (hex id, is a
/// phone) in Devices order; the answer is the indexes to send to, one send each.
pub fn pick_ipc_send_targets(
    paired: &[(String, bool)],
    wanted: Option<&str>,
) -> Result<Vec<usize>, &'static str> {
    if wanted.is_some_and(|w| w.trim().eq_ignore_ascii_case(ALL_PHONES)) {
        let phones: Vec<usize> = (0..paired.len()).filter(|&i| paired[i].1).collect();
        return if phones.is_empty() {
            Err(NO_PHONES_FOR_ALL_ERR)
        } else {
            Ok(phones)
        };
    }
    let ids: Vec<String> = paired.iter().map(|(id, _)| id.clone()).collect();
    pick_ipc_send_target(&ids, wanted).map(|i| vec![i])
}

/// The phones of `devices`, for [`pick_ipc_send_targets`].
pub(crate) fn target_list(devices: &[voidwire_core::net::pc::DeviceInfo]) -> Vec<(String, bool)> {
    devices
        .iter()
        .map(|d| (d.id.to_hex(), d.platform.is_some_and(|p| p.is_mobile())))
        .collect()
}

fn resolve_ipc_send_targets(
    app: &AppHandle,
    n: &voidwire_core::net::pc::PcNode,
    device_id: Option<String>,
    pop_ui_on_error: bool,
) -> Result<Vec<voidwire_core::ids::DeviceId>, &'static str> {
    let devices = n.devices();
    match pick_ipc_send_targets(&target_list(&devices), device_id.as_deref()) {
        Ok(v) => Ok(v.into_iter().map(|i| devices[i].id).collect()),
        Err(e) => {
            if pop_ui_on_error {
                crate::node::set_pending_ui_send_error(crate::node::PendingUiSendError {
                    error: e.to_owned(),
                    device_id: String::new(),
                    file_path: None,
                    retry_text: None,
                });
                notify_devices_window_error(app);
            }
            Err(e)
        }
    }
}

/// What a text, link or clipboard send is.
enum IpcItem {
    Text(String),
    Clipboard,
}

/// One send per target (a fan-out for "All phones"). All succeed: `sent_to`
/// lists them. Otherwise the first failure is reported (and shown in the
/// Devices window when `pop_ui`), naming the ones that did get it.
///
/// "All phones" sends text and links only: a copied file goes to one device
/// at a time, so a relay prompt is never asked once per phone.
fn send_to_targets(
    app: &AppHandle,
    n: &voidwire_core::net::pc::PcNode,
    targets: Vec<voidwire_core::ids::DeviceId>,
    item: IpcItem,
    allow_relay: bool,
    pop_ui: bool,
) -> IpcResponse {
    let fan_out = targets.len() > 1;
    let clip_file = match item {
        IpcItem::Clipboard => {
            crate::node::get_os_clipboard_file(app).map(|p| p.display().to_string())
        }
        IpcItem::Text(_) => None,
    };
    if fan_out && clip_file.is_some() {
        return fan_out_refused(app, ALL_PHONES_FILE_ERR, pop_ui);
    }
    let text = match item {
        IpcItem::Text(t) => Some(t),
        // Read once, so every phone gets the same text.
        IpcItem::Clipboard if fan_out => match crate::node::get_os_clipboard(app) {
            Some(t) => Some(t),
            None => {
                return IpcResponse::err("Clipboard is empty or does not contain text or a file.")
            }
        },
        IpcItem::Clipboard => None,
    };
    // One relay question for the whole fan-out: there is none, because only
    // items that never ask (up to the small-item cap) go to all phones.
    if fan_out
        && text.as_ref().is_some_and(|t| {
            t.len() as u64 > voidwire_core::file_transfer::DEFAULT_SMALL_ITEM_CAP_BYTES
        })
    {
        return fan_out_refused(app, ALL_PHONES_SIZE_ERR, pop_ui);
    }
    let decision = allow_relay.then(|| "send_via_relay".to_owned());
    let mut sent: Vec<String> = Vec::new();
    let mut path: Option<String> = None;
    for id in targets {
        let hex = id.to_hex();
        let res = match &text {
            Some(t) => tauri::async_runtime::block_on(crate::commands::send_text_to_phone(
                app.clone(),
                hex.clone(),
                t.clone(),
                decision.clone(),
            )),
            None => tauri::async_runtime::block_on(crate::commands::send_clipboard_to_phone(
                app.clone(),
                hex.clone(),
                decision.clone(),
            )),
        };
        match res {
            Ok(out) => {
                sent.push(crate::commands::phone_display_name(n, &id));
                path.get_or_insert_with(|| out.delivery_path.to_owned());
            }
            Err(formatted) => {
                let mut r =
                    map_formatted_send_err(app, formatted, hex, clip_file, text.clone(), pop_ui);
                if !sent.is_empty() {
                    let before = r.error.take().unwrap_or_default();
                    r.error = Some(format!("Sent to {}. {before}", sent.join(", ")));
                }
                return r;
            }
        }
    }
    IpcResponse {
        ok: true,
        running: Some(true),
        sent_to: Some(sent.join(", ")),
        path,
        ..IpcResponse::default()
    }
}

fn fan_out_refused(app: &AppHandle, why: &'static str, pop_ui: bool) -> IpcResponse {
    if pop_ui {
        crate::node::set_pending_ui_send_error(crate::node::PendingUiSendError {
            error: why.to_owned(),
            device_id: String::new(),
            file_path: None,
            retry_text: None,
        });
        notify_devices_window_error(app);
    }
    IpcResponse::err(why)
}

/// "All phones" with text over the small-item cap.
pub const ALL_PHONES_SIZE_ERR: &str =
    "All phones sends items up to 256 KB. For a larger one, choose one device.";
/// "All phones" with a copied file on the clipboard.
pub const ALL_PHONES_FILE_ERR: &str =
    "All phones sends text and links. To send a file, choose one device.";

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
            error: "No device is paired with this PC yet. Pair one first, then right-click the file and choose Send with Voidwire.".to_owned(),
            device_id: String::new(),
            file_path: Some(path),
            retry_text: None,
        });
        notify_devices_window_error(app);
        return IpcResponse::err(NO_PHONE_ERR);
    }
    let explicit_id = phone_id.unwrap_or_default();
    if explicit_id.trim().is_empty() && devices.len() > 1 {
        crate::node::set_pending_ui_send_error(crate::node::PendingUiSendError {
            error: "__pick_phone__".to_owned(),
            device_id: String::new(),
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
                    device_id: id_for_task,
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
                let devices: Vec<IpcDeviceDto> = n
                    .devices()
                    .into_iter()
                    .map(|d| IpcDeviceDto {
                        id: d.id.to_hex(),
                        label: d.name,
                        mobile: d.platform.is_some_and(|p| p.is_mobile()),
                    })
                    .collect();
                IpcResponse {
                    ok: true,
                    running: Some(true),
                    version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                    phones: Some(devices.clone()),
                    devices: Some(devices),
                    ..IpcResponse::default()
                }
            }
            Err(e) => IpcResponse::err(e),
        },
        IpcRequest::SendUrl {
            url,
            device_id,
            pop_ui_on_error,
        } => ipc_send(app, device_id, IpcItem::Text(url), false, pop_ui_on_error),
        IpcRequest::SendText {
            text,
            device_id,
            allow_relay,
            pop_ui_on_error,
        } => ipc_send(
            app,
            device_id,
            IpcItem::Text(text),
            allow_relay,
            pop_ui_on_error,
        ),
        IpcRequest::SendClipboard {
            device_id,
            allow_relay,
            pop_ui_on_error,
        } => ipc_send(
            app,
            device_id,
            IpcItem::Clipboard,
            allow_relay,
            pop_ui_on_error,
        ),
        IpcRequest::SendFile { path, device_id } => handle_send_file_in_app(app, path, device_id),
    }
}

/// Where the send-clipboard hotkey goes (M4.5): its fixed device while that
/// is still paired, else the only device, else ask (never a guess). With
/// nothing paired it "sends" to no one, which shows the pair-first error.
#[derive(Debug, PartialEq, Eq)]
pub enum HotkeyTarget {
    Send(String),
    Ask,
}

pub fn hotkey_target(paired: &[String], fixed: Option<&str>) -> HotkeyTarget {
    if let Some(f) = fixed.filter(|f| paired.iter().any(|id| id.eq_ignore_ascii_case(f))) {
        return HotkeyTarget::Send(f.to_owned());
    }
    match paired {
        [] => HotkeyTarget::Send(String::new()),
        [only] => HotkeyTarget::Send(only.clone()),
        _ => HotkeyTarget::Ask,
    }
}

/// The marker a Devices window reads as "show the device picker for the
/// clipboard" (the hotkey with 2+ devices and no fixed device).
pub const PICK_DEVICE_FOR_CLIPBOARD: &str = "__pick_device_clipboard__";

/// The send-clipboard hotkey. Blocks; call it off the main thread.
pub fn hotkey_send_clipboard(app: &AppHandle) {
    let Ok(n) = crate::commands::node(app) else {
        return;
    };
    let paired: Vec<String> = n.devices().iter().map(|d| d.id.to_hex()).collect();
    match hotkey_target(&paired, crate::diag::hotkey_device().as_deref()) {
        HotkeyTarget::Send(id) => send_clipboard_from_ui(app, id, "hotkey send clipboard: failed"),
        HotkeyTarget::Ask => {
            crate::node::set_pending_ui_send_error(crate::node::PendingUiSendError {
                error: PICK_DEVICE_FOR_CLIPBOARD.to_owned(),
                device_id: String::new(),
                file_path: crate::node::get_os_clipboard_file(app).map(|p| p.display().to_string()),
                retry_text: None,
            });
            notify_devices_window_error(app);
        }
    }
}

/// The tray's or hotkey's "Send clipboard" for one device or [`ALL_PHONES`]:
/// the same path as an extension send, with failures shown in the Devices
/// window. Blocks; call it off the main thread.
/// `fail_log` is a fixed line ("tray send clipboard: failed"), never a name.
pub fn send_clipboard_from_ui(app: &AppHandle, device_id: String, fail_log: &'static str) {
    let r = ipc_send(app, Some(device_id), IpcItem::Clipboard, false, true);
    if !r.ok {
        crate::node::log(fail_log);
    }
}

fn ipc_send(
    app: &AppHandle,
    device_id: Option<String>,
    item: IpcItem,
    allow_relay: bool,
    pop_ui_on_error: bool,
) -> IpcResponse {
    let n = match crate::commands::node(app) {
        Ok(n) => n,
        Err(e) => return IpcResponse::err(e),
    };
    match resolve_ipc_send_targets(app, &n, device_id, pop_ui_on_error) {
        Ok(targets) => send_to_targets(app, &n, targets, item, allow_relay, pop_ui_on_error),
        Err(e) => IpcResponse::err(e),
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
    fn m42_ipc_target_is_device_id_and_phone_id_still_works() {
        let id = format!("{:064x}", 7);
        for key in ["device_id", "phone_id"] {
            let raw = format!(r#"{{"op":"send_url","url":"https://example.com/","{key}":"{id}"}}"#);
            let req: IpcRequest = serde_json::from_str(&raw).unwrap();
            assert_eq!(
                req,
                IpcRequest::SendUrl {
                    url: "https://example.com/".into(),
                    device_id: Some(id.clone()),
                    pop_ui_on_error: false,
                }
            );
            let raw = format!(r#"{{"op":"send_file","path":"a","{key}":"{id}"}}"#);
            let req: IpcRequest = serde_json::from_str(&raw).unwrap();
            assert!(matches!(req, IpcRequest::SendFile { device_id: Some(ref d), .. } if *d == id));
        }
        let out = serde_json::to_string(&IpcRequest::SendClipboard {
            device_id: Some(id.clone()),
            allow_relay: false,
            pop_ui_on_error: false,
        })
        .unwrap();
        assert!(out.contains("\"device_id\""));
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
    fn m45_hotkey_asks_unless_one_device_or_a_paired_fixed_device() {
        let p = ids(3);
        assert_eq!(hotkey_target(&p, None), HotkeyTarget::Ask);
        assert_eq!(
            hotkey_target(&p, Some(&p[1])),
            HotkeyTarget::Send(p[1].clone())
        );
        let gone = format!("{:064x}", 0xffu32);
        assert_eq!(
            hotkey_target(&p, Some(&gone)),
            HotkeyTarget::Ask,
            "an unpaired fixed device is ignored"
        );
        assert_eq!(
            hotkey_target(&p[..1], None),
            HotkeyTarget::Send(p[0].clone())
        );
        assert_eq!(
            hotkey_target(&p[..1], Some(&gone)),
            HotkeyTarget::Send(p[0].clone())
        );
        assert_eq!(
            hotkey_target(&[], Some(&gone)),
            HotkeyTarget::Send(String::new())
        );
    }

    #[test]
    fn m45_all_phones_is_every_phone_and_never_a_pc() {
        let p = ids(4);
        let list: Vec<(String, bool)> = p
            .iter()
            .zip([true, false, true, false])
            .map(|(id, m)| (id.clone(), m))
            .collect();
        for w in [ALL_PHONES, " ALL_PHONES "] {
            assert_eq!(pick_ipc_send_targets(&list, Some(w)), Ok(vec![0, 2]));
        }
        // A PC is still a target on its own.
        assert_eq!(pick_ipc_send_targets(&list, Some(&p[1])), Ok(vec![1]));
        assert_eq!(pick_ipc_send_targets(&list, None), Err(CHOOSE_PHONE_ERR));
        let pcs: Vec<(String, bool)> = ids(2).into_iter().map(|id| (id, false)).collect();
        assert_eq!(
            pick_ipc_send_targets(&pcs, Some(ALL_PHONES)),
            Err(NO_PHONES_FOR_ALL_ERR)
        );
        assert_eq!(
            pick_ipc_send_targets(&[], Some(ALL_PHONES)),
            Err(NO_PHONES_FOR_ALL_ERR)
        );
    }

    #[test]
    fn m45_all_phones_id_matches_extension_and_tray() {
        let bg = include_str!("../../extension/background.js");
        let popup = include_str!("../../extension/popup.js");
        let quoted = format!("\"{ALL_PHONES}\"");
        assert!(bg.contains(&quoted) && popup.contains(&quoted));
        assert_eq!(crate::winmgr::ALL_PHONES_ID, ALL_PHONES);
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
                            phones: Some(vec![IpcDeviceDto {
                                id: "aa".repeat(32),
                                label: "Pixel 9".to_owned(),
                                mobile: true,
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
