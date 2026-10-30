//! Tauri commands. Each window's capability file grants only its own
//! commands. Nothing here takes or returns a URL: prompts carry the host
//! for display and are decided by id.

use serde::Serialize;
use tauri::{AppHandle, Manager};
use voidwire_core::ids::DeviceId;
use voidwire_core::net::pc::{PairInvitation, PairStatus, PcNode};
use voidwire_core::net::NetError;

use crate::{node, CONFIRM_WINDOW};

pub(crate) fn node(app: &AppHandle) -> Result<std::sync::Arc<PcNode>, String> {
    node::get(app).ok_or_else(|| {
        format!(
            "The network service isn't running: {}",
            node::start_error().unwrap_or_default()
        )
    })
}

fn msg(e: NetError) -> String {
    match e {
        NetError::Rejected(r) => human(r),
        other => other.to_string(),
    }
}

fn human(r: voidwire_core::reject::RejectReason) -> String {
    use voidwire_core::reject::RejectReason::*;
    match r {
        SasRejected => "That code didn't match. Start again with a new QR code.".into(),
        SasTimeout => "The code wasn't entered in time. Start again.".into(),
        PairingSecretExpired => "The QR code expired. Show a new one.".into(),
        PairingSecretUsed => "That QR code was already used. Show a new one.".into(),
        PairingSecretUnknown => "No pairing in progress. Show a new QR code.".into(),
        PairingCancelled => "Pairing was cancelled.".into(),
        NoSuchPrompt => "That link was already handled.".into(),
        PromptExpired => "That link waited too long and was not opened.".into(),
        PairingHmacBad => "The phone's proof didn't check out. Show a new QR code.".into(),
        other => format!("Refused ({}).", other.label()),
    }
}

#[derive(Serialize)]
pub struct QrOut {
    /// SVG markup of the QR (shown as a data: image).
    svg: String,
    expires_at_ms: u64,
    /// Changes whenever the QR is replaced (auto-refresh).
    qr_seq: u64,
}

fn qr_out(inv: &PairInvitation) -> Result<QrOut, String> {
    let code =
        qrcode::QrCode::with_error_correction_level(inv.qr_uri.as_bytes(), qrcode::EcLevel::M)
            .map_err(|e| e.to_string())?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(280, 280)
        .quiet_zone(true)
        .build();
    Ok(QrOut {
        svg,
        expires_at_ms: inv.expires_at.0,
        qr_seq: inv.qr_seq,
    })
}

/// Show a QR and (re)start auto-refresh; also "Show a new code" (paused state).
#[tauri::command]
pub fn pair_start(app: AppHandle) -> Result<QrOut, String> {
    let n = node(&app)?;
    let inv = n.pair_start().map_err(msg)?;
    qr_out(&inv)
}

/// SPEC 2.3 paused state (round 3, screens/16).
pub const PAUSED_TEXT: &str =
    "Codes stop after 10 minutes, or while this window is hidden. No code is valid right now.";

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum StatusOut {
    Idle,
    /// `qr` is set only when the live QR differs from the one the window
    /// says it shows (`have_seq`), so the SVG isn't resent every poll.
    WaitingForScan {
        expires_at_ms: u64,
        qr_seq: u64,
        qr: Option<QrOut>,
    },
    Paused {
        message: String,
    },
    AwaitingCode {
        device_name: String,
    },
    /// Done state (SPEC 2.3, screens/17): the success card names the phone,
    /// its platform and date; the NEXT steps name this PC.
    Paired {
        device_name: String,
        platform: String,
        paired_at_ms: Option<u64>,
        pc_name: String,
    },
    Failed {
        message: String,
    },
}

#[tauri::command]
pub fn pair_status(app: AppHandle, have_seq: Option<u64>) -> Result<StatusOut, String> {
    let n = node(&app)?;
    Ok(match n.pair_status() {
        PairStatus::Idle => StatusOut::Idle,
        PairStatus::WaitingForScan { expires_at, qr_seq } => StatusOut::WaitingForScan {
            expires_at_ms: expires_at.0,
            qr_seq,
            qr: match (have_seq == Some(qr_seq), n.pair_qr()) {
                (false, Some(inv)) => Some(qr_out(&inv)?),
                _ => None,
            },
        },
        PairStatus::Paused { .. } => StatusOut::Paused {
            message: PAUSED_TEXT.into(),
        },
        PairStatus::AwaitingCode { device_name } => StatusOut::AwaitingCode { device_name },
        PairStatus::Paired { device_name } => {
            // The newest device with that name is the one just paired.
            let dev = n
                .devices()
                .into_iter()
                .filter(|d| d.name == device_name)
                .max_by_key(|d| d.paired_at.map(|t| t.0));
            StatusOut::Paired {
                platform: dev
                    .as_ref()
                    .and_then(|d| d.platform.map(|p| format!("{p:?}")))
                    .unwrap_or_else(|| "Unknown".into()),
                paired_at_ms: dev.and_then(|d| d.paired_at.map(|t| t.0)),
                pc_name: n.device_name(),
                device_name,
            }
        }
        PairStatus::Failed { reason } => StatusOut::Failed {
            message: human(reason),
        },
    })
}

#[tauri::command]
pub fn pair_submit_code(app: AppHandle, code: String) -> Result<String, String> {
    let n = node(&app)?;
    n.pair_submit_code(&code).map(|d| d.name).map_err(msg)
}

#[tauri::command]
pub fn pair_cancel(app: AppHandle) -> Result<(), String> {
    node(&app)?.pair_cancel();
    // The Cancel button (SPEC 2.3) cancels and closes; the webview gets no
    // core:window permission for that (AUTH-13).
    if let Some(w) = app.get_webview_window(crate::PAIR_WINDOW) {
        let _ = w.close();
    }
    Ok(())
}

// ---- M4.3: pair with any device by typed code (and a `v=2` QR) ----

/// Messages for the code-pairing window ("the other device", not "the phone").
fn human2(e: NetError) -> String {
    use voidwire_core::reject::RejectReason::*;
    let r = match e {
        NetError::Rejected(r) => r,
        NetError::Unreachable(_) => {
            return "Couldn't reach the other device or the relay. Check both are online and try again.".into()
        }
        NetError::Cancelled => return "Pairing was cancelled.".into(),
        other => return other.to_string(),
    };
    match r {
        PairingCodeInvalid => "That code has a typo. Check it and type it again.".into(),
        PairingSecretExpired => "That code expired. Show a new one on the other device.".into(),
        PairingSecretUsed => "That code was already used. Show a new one.".into(),
        PairingSecretUnknown => {
            "That code isn't active. Check it, or show a new one on the other device.".into()
        }
        PairingCancelled => "Pairing was cancelled on the other device.".into(),
        SasRejected => "The 6-digit code didn't match. Start again.".into(),
        SasTimeout => "The 6-digit code wasn't typed in time. Start again.".into(),
        SenderMismatch => {
            "This code doesn't match the device that answered. Show a new one.".into()
        }
        PairingHmacBad => "Pairing stopped: the connection didn't check out. Start again.".into(),
        FromSelf => "That's this PC's own code. Type it on the other device.".into(),
        UnsupportedVersion => {
            "This code needs a newer Voidwire. Update Voidwire on the other device.".into()
        }
        PairingLimitReached => {
            "This PC already has 16 paired devices. Forget one before pairing another.".into()
        }
        RelayLimitReached => {
            "This PC already uses 4 relays (or has 8 saved). Remove one before pairing over another.".into()
        }
        RelayNotAdded => "This pairing uses a relay you didn't add, so it stopped.".into(),
        AlreadyPaired => "You're already paired with this device.".into(),
        other => human(other),
    }
}

#[derive(Serialize)]
pub struct RelayOut {
    nickname: String,
    url: String,
    home: bool,
}

#[tauri::command]
pub fn pair2_relays(app: AppHandle) -> Result<Vec<RelayOut>, String> {
    Ok(node(&app)?
        .saved_relays()
        .into_iter()
        .map(|r| RelayOut {
            nickname: r.nickname,
            url: r.url,
            home: r.home,
        })
        .collect())
}

#[derive(Serialize)]
pub struct ShowOut {
    /// `VW-…`, or `None` when the relay couldn't be reached (QR only).
    code: Option<String>,
    /// The `v=2` QR (for phones), as SVG markup.
    svg: String,
    expires_at_ms: u64,
    /// The code's full lifetime (for the countdown bar).
    ttl_ms: u64,
}

/// Show a code (and its QR) over `relay_url` (a saved relay; `None`: home).
#[tauri::command]
pub async fn pair2_show(app: AppHandle, relay_url: Option<String>) -> Result<ShowOut, String> {
    let n = node(&app)?;
    let info = tauri::async_runtime::spawn_blocking(move || n.pair2_show(relay_url.as_deref()))
        .await
        .map_err(|e| e.to_string())?
        .map_err(human2)?;
    crate::pair_clip::shown(&app, info.code.clone());
    Ok(ShowOut {
        code: info.code.clone(),
        svg: pair2_qr_svg(&info.qr)?,
        expires_at_ms: info.expires_at.0,
        ttl_ms: voidwire_core::net::pair2::CODE_TTL_MS,
    })
}

/// A finished pairing: who, and whether it replaced an older one with them.
#[derive(Serialize)]
pub struct Paired2Out {
    name: String,
    refreshed: bool,
}

impl From<voidwire_core::net::pair2::Paired2> for Paired2Out {
    fn from(p: voidwire_core::net::pair2::Paired2) -> Self {
        Paired2Out {
            name: p.name,
            refreshed: p.refreshed,
        }
    }
}

/// The v=2 pairing QR for a phone camera (0.8.1 field test: neither phone
/// could read it). It carries ~400 bytes, so the modules must be big: low
/// error correction (a screen isn't dirty or torn; L is one QR version
/// smaller than M), no quiet zone inside the image (the light plate around
/// it is the quiet zone), and a bigger plate in pair2.css.
/// The pairing QR's symbol. Low error correction keeps the modules large;
/// the screen is a clean source, so size matters more than redundancy.
fn pair2_qr(uri: &str) -> Result<qrcode::QrCode, String> {
    qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::L)
        .map_err(|e| e.to_string())
}

pub(crate) fn pair2_qr_svg(uri: &str) -> Result<String, String> {
    Ok(pair2_qr(uri)?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(244, 244)
        .quiet_zone(false)
        .build())
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Status2Out {
    Idle,
    Showing {
        expires_at_ms: u64,
    },
    /// This PC's own code ran out (the window shows a fresh one).
    Expired,
    AwaitingCode {
        device_name: String,
    },
    Paired {
        device_name: String,
    },
    Failed {
        message: String,
    },
}

#[tauri::command]
pub fn pair2_status(app: AppHandle) -> Result<Status2Out, String> {
    use voidwire_core::net::pair2::HostStatus as H;
    let st = node(&app)?.pair2_status();
    if matches!(st, H::Idle | H::Paired { .. } | H::Failed { .. }) {
        // Paired, expired or failed: the copied code is no use any more.
        crate::pair_clip::finish(&app);
    }
    Ok(match st {
        H::Idle => Status2Out::Idle,
        H::Showing { expires_at } => Status2Out::Showing {
            expires_at_ms: expires_at.0,
        },
        H::AwaitingCode { device_name } => Status2Out::AwaitingCode { device_name },
        H::Paired { device_name } => Status2Out::Paired { device_name },
        H::Failed {
            reason: voidwire_core::reject::RejectReason::PairingSecretExpired,
        } => Status2Out::Expired,
        H::Failed { reason } => Status2Out::Failed {
            message: human2(NetError::Rejected(reason)),
        },
    })
}

#[tauri::command]
pub async fn pair2_submit_code(app: AppHandle, code: String) -> Result<Paired2Out, String> {
    let n = node(&app)?;
    let r = tauri::async_runtime::spawn_blocking(move || n.pair2_submit_code(&code))
        .await
        .map_err(|e| e.to_string())?
        .map(Paired2Out::from)
        .map_err(human2);
    crate::pair_clip::finish(&app);
    r
}

/// "Copy" next to the shown code (v0.7.1): only the code the core handed
/// out, marked private, and cleared when the pairing is over.
#[tauri::command]
pub fn pair2_copy_code(app: AppHandle) -> Result<(), String> {
    crate::pair_clip::copy(&app)
}

#[derive(Serialize)]
pub struct OpenedOut {
    inviter_name: Option<String>,
    /// `saved`, `ask` ("This pairing uses <relay_host>. Add it?") or `full`.
    relay_state: &'static str,
    relay_host: Option<String>,
}

/// Typed code: a typo is refused locally, before any network.
#[tauri::command]
pub async fn pair2_open_code(
    app: AppHandle,
    code: String,
    relay_url: Option<String>,
) -> Result<OpenedOut, String> {
    use voidwire_core::net::pair2::RelayCheck as R;
    let n = node(&app)?;
    let o = tauri::async_runtime::spawn_blocking(move || {
        n.pair2_open_code(&code, relay_url.as_deref())
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(human2)?;
    let (relay_state, relay_host) = match o.relay {
        R::Saved => ("saved", None),
        R::Ask { host } => ("ask", Some(host)),
        R::Full { host } => ("full", Some(host)),
    };
    Ok(OpenedOut {
        inviter_name: o.inviter_name,
        relay_state,
        relay_host,
    })
}

/// [Add and pair] on the add-relay prompt.
#[tauri::command]
pub fn pair2_add_relay(app: AppHandle) -> Result<(), String> {
    node(&app)?.pair2_add_relay().map_err(human2)
}

/// Connect to the inviter; returns the 6-digit code to show.
#[tauri::command]
pub async fn pair2_join(app: AppHandle) -> Result<String, String> {
    let n = node(&app)?;
    tauri::async_runtime::spawn_blocking(move || n.pair2_join())
        .await
        .map_err(|e| e.to_string())?
        .map_err(human2)
}

/// Wait until the other device's user typed our code.
#[tauri::command]
pub async fn pair2_join_wait(app: AppHandle) -> Result<Paired2Out, String> {
    let n = node(&app)?;
    tauri::async_runtime::spawn_blocking(move || n.pair2_join_wait())
        .await
        .map_err(|e| e.to_string())?
        .map(Paired2Out::from)
        .map_err(human2)
}

/// Cancel (the code stops working) and close the window. No error screen.
#[tauri::command]
pub fn pair2_cancel(app: AppHandle) -> Result<(), String> {
    crate::pair_clip::finish(&app);
    node(&app)?.pair2_cancel();
    if let Some(w) = app.get_webview_window(crate::PAIR2_WINDOW) {
        let _ = w.close();
    }
    Ok(())
}

/// "Pair with a code…" in Paired devices.
#[tauri::command]
pub fn open_pair2_window(app: AppHandle) {
    crate::request_window(&app, crate::PAIR2_WINDOW);
}

#[derive(Serialize)]
pub struct DeviceOut {
    id: String,
    name: String,
    platform: String,
    paired_at_ms: Option<u64>,
}

#[tauri::command]
pub fn devices_list(app: AppHandle) -> Result<Vec<DeviceOut>, String> {
    Ok(node(&app)?
        .devices()
        .into_iter()
        .map(|d| DeviceOut {
            id: d.id.to_hex(),
            name: d.name,
            platform: d
                .platform
                .map(|p| format!("{p:?}"))
                .unwrap_or_else(|| "Unknown".into()),
            paired_at_ms: d.paired_at.map(|t| t.0),
        })
        .collect())
}

/// Forget a device. Async so the window stays responsive while the state
/// file is rewritten; the reply carries the confirmation text.
#[tauri::command]
pub async fn device_forget(app: AppHandle, id: String) -> Result<ForgetOut, String> {
    let id = DeviceId::from_hex(&id).ok_or("bad device id")?;
    let n = node(&app)?;
    let name = n.devices().into_iter().find(|d| d.id == id).map(|d| d.name);
    match (n.forget_device(&id).map_err(msg)?, name) {
        (true, Some(name)) => {
            node::log("forgot a device"); // never its name
            Ok(ForgetOut {
                message: forgot_text(&name),
            })
        }
        // Already gone (e.g. a second click).
        _ => Ok(ForgetOut {
            message: "Already forgotten".into(),
        }),
    }
}

#[derive(Serialize)]
pub struct SettingsOut {
    no_prompt: bool,
    /// Local log + crash files (off by default; nothing written when off).
    diagnostics: bool,
    pc_name: String,
    pc_id: String,
    listening: Vec<String>,
    /// Theme setting: "system" (default) | "dark" | "light" (SPEC 2.6).
    theme: &'static str,
    /// Footer "VOIDWIRE 0.2.0 · CORE 0.2.0" (SPEC 2.4).
    app_version: &'static str,
    core_version: &'static str,
    /// Fail-open warning (`"Couldn't check for removals since <time>"`) when a
    /// blind mailbox sync/check failed (`docs/PROTOCOL.md` §7.1(e)).
    removal_check_warning: Option<String>,
    /// Optional on-device connection stats (`false` by default, `M2.6` §6a.3).
    connection_stats_enabled: bool,
    /// Effective relay file-transfer cap in bytes (`M2.6` §6a.1 & §6b).
    relay_file_cap_bytes: u64,
    /// Whether "Never send files over relay" is enabled (`false` by default, `M2.8`).
    never_send_files_over_relay: bool,
    /// Whether completed file transfers are kept in the Devices tab list (`false` by default, `M2.8`).
    keep_file_history: bool,
    /// Configured relay server URL (`https://relay.voidwire.app` by default, `M2.8`).
    relay_url: String,
    default_relay_url: &'static str,
    /// Configured blind mailbox endpoint ID (64-hex, `DEFAULT_MAILBOX_ID` by default, `M2.8`).
    mailbox_id: String,
    default_mailbox_id: &'static str,
    /// Configured target download directory (`~/Downloads/Voidwire` by default, `M2.8`).
    download_dir: String,
    default_download_dir: String,
    /// Whether incoming clipboard text from paired phones is auto-copied (`false` by default, `M3.1`).
    auto_copy_clipboard: bool,
    /// Whether the opt-in send-clipboard shortcut is enabled (`false` by default, `M3.1`).
    send_clipboard_shortcut: bool,
    /// Configured accelerator string for the send-clipboard shortcut (`"Ctrl+Shift+V"` by default, `M3.1.1`).
    send_clipboard_shortcut_accel: String,
    /// Whether the OS file manager right-click `"Send with Voidwire"` item is enabled (`true` by default, `M3.2`).
    context_menu_enabled: bool,
    /// Pending background tray/shortcut send error (consumed once by the Devices window).
    pending_ui_send_error: Option<node::PendingUiSendError>,
}

#[tauri::command]
pub fn settings_get(app: AppHandle) -> Result<SettingsOut, String> {
    let n = node(&app)?;
    Ok(SettingsOut {
        no_prompt: n.no_prompt(),
        diagnostics: crate::diag::enabled(),
        pc_name: n.device_name(),
        pc_id: n.device_id().short(),
        listening: n.bound_sockets().iter().map(|s| s.to_string()).collect(),
        theme: match crate::diag::theme() {
            None => "system",
            Some(true) => "light",
            Some(false) => "dark",
        },
        app_version: env!("CARGO_PKG_VERSION"),
        core_version: voidwire_core::CORE_VERSION,
        removal_check_warning: n.removal_check_warning(),
        connection_stats_enabled: n.connection_stats_enabled(),
        relay_file_cap_bytes: n.relay_policy().effective_cap_bytes(),
        never_send_files_over_relay: n.never_send_files_over_relay(),
        keep_file_history: n.keep_file_history(),
        relay_url: n
            .relay_url()
            .unwrap_or_else(|| voidwire_core::net::DEFAULT_RELAY_URL.to_owned()),
        default_relay_url: voidwire_core::net::DEFAULT_RELAY_URL,
        mailbox_id: n
            .mailbox_id()
            .map(|id| id.to_hex())
            .unwrap_or_else(|| voidwire_core::net::mailbox_client::DEFAULT_MAILBOX_ID.to_owned()),
        default_mailbox_id: voidwire_core::net::mailbox_client::DEFAULT_MAILBOX_ID,
        download_dir: n.download_dir().display().to_string(),
        default_download_dir: n.default_download_dir().display().to_string(),
        auto_copy_clipboard: n.auto_copy_clipboard(),
        send_clipboard_shortcut: n.send_clipboard_shortcut(),
        send_clipboard_shortcut_accel: n.send_clipboard_shortcut_accel(),
        context_menu_enabled: crate::diag::context_menu_enabled(),
        pending_ui_send_error: node::take_pending_ui_send_error(),
    })
}

#[tauri::command]
pub fn settings_set_no_prompt(app: AppHandle, on: bool) -> Result<(), String> {
    node(&app)?.set_no_prompt(on).map_err(msg)
}

#[tauri::command]
pub fn settings_set_context_menu(on: bool) -> Result<bool, String> {
    crate::diag::set_context_menu_enabled(on).map_err(|e| e.to_string())?;
    Ok(crate::diag::context_menu_enabled())
}

/// "Pair a phone…" in Paired devices (SPEC 2.4, approved round 2): opens
/// the existing Pair window, centered (same path as the tray item).
#[tauri::command]
pub fn open_pair_window(app: AppHandle) {
    crate::request_window(&app, crate::PAIR_WINDOW);
}

/// Theme setting (SPEC 2.6): "system" | "dark" | "light". System stores nothing.
#[tauri::command]
pub fn settings_set_theme(app: AppHandle, theme: String) -> Result<(), String> {
    crate::diag::set_theme(&theme).map_err(|e| e.to_string())?;
    // Live update: every open window's caption and <html data-theme>.
    crate::tray_theme::apply_windows(&app);
    Ok(())
}

/// Diagnostics on: local log + crash files. Off: deletes them all.
#[tauri::command]
pub fn settings_set_diagnostics(on: bool) -> Result<(), String> {
    crate::diag::set(on).map_err(|e| e.to_string())?;
    if on {
        node::log("diagnostics turned on");
    }
    Ok(())
}

#[derive(Serialize)]
pub struct ForgetOut {
    /// "Forgot <device>" (shown in the window).
    message: String,
}

#[derive(Serialize)]
pub struct PendingOut {
    id: u64,
    host: String,
    from: String,
}

#[tauri::command]
pub fn pending_list(app: AppHandle) -> Result<Vec<PendingOut>, String> {
    let n = node(&app)?;
    if let Some(w) = app.get_webview_window(CONFIRM_WINDOW) {
        let _ = w.set_title(&node::confirm_window_title(&app));
    }
    Ok(n.pending()
        .into_iter()
        .map(|p| PendingOut {
            id: p.id,
            host: p.host,
            from: p.from,
        })
        .collect())
}

fn hide_confirm_if_empty(app: &AppHandle, n: &PcNode) {
    if n.pending().is_empty() && n.incoming_files().is_empty() && n.pending_clipboards().is_empty()
    {
        if let Some(w) = app.get_webview_window(CONFIRM_WINDOW) {
            let _ = w.hide();
        }
    }
}

/// Open (or dismiss) prompt `id`. Hides the prompt window when none remain.
#[tauri::command]
pub fn pending_decide(app: AppHandle, id: u64, open: bool) -> Result<(), String> {
    let n = node(&app)?;
    let r = n.decide(id, open).map_err(msg);
    hide_confirm_if_empty(&app, &n);
    r
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionStatOut {
    pub peer_id: String,
    pub day_utc: u64,
    pub direct_count: u32,
    pub relay_count: u32,
    pub direct_bytes: u64,
    pub relay_bytes: u64,
    pub prompts_shown: u32,
    pub prompts_accepted: u32,
}

#[tauri::command]
pub fn settings_set_connection_stats(app: AppHandle, on: bool) -> Result<(), String> {
    node(&app)?.set_connection_stats_enabled(on).map_err(msg)
}

#[tauri::command]
pub fn connection_stats_list(app: AppHandle) -> Result<Vec<ConnectionStatOut>, String> {
    Ok(node(&app)?
        .connection_stats()
        .into_iter()
        .map(|(peer, s)| ConnectionStatOut {
            peer_id: peer.to_hex(),
            day_utc: s.day as u64,
            direct_count: s.direct_count as u32,
            relay_count: s.relay_count as u32,
            direct_bytes: s.direct_bytes,
            relay_bytes: s.relay_bytes,
            prompts_shown: s.prompts_shown as u32,
            prompts_accepted: s.prompts_accepted as u32,
        })
        .collect())
}

#[tauri::command]
pub fn settings_set_relay_cap(app: AppHandle, cap_bytes: u64) -> Result<(), String> {
    node(&app)?.set_user_relay_cap_bytes(cap_bytes).map_err(msg)
}

#[tauri::command]
pub fn settings_set_never_relay_files(app: AppHandle, never: bool) -> Result<(), String> {
    node(&app)?
        .set_never_send_files_over_relay(never)
        .map_err(msg)
}

#[tauri::command]
pub fn settings_set_file_history(app: AppHandle, on: bool) -> Result<(), String> {
    node(&app)?.set_keep_file_history(on).map_err(msg)
}

#[tauri::command]
pub fn completed_files_clear(app: AppHandle) -> Result<(), String> {
    node(&app)?.clear_completed_files();
    Ok(())
}

#[tauri::command]
pub fn settings_set_relay_config(
    app: AppHandle,
    relay_url: String,
    mailbox_id: String,
) -> Result<(), String> {
    let n = node(&app)?;
    let r_trimmed = relay_url.trim();
    let target_relay = if r_trimmed.is_empty() {
        Some(voidwire_core::net::DEFAULT_RELAY_URL.to_owned())
    } else {
        Some(r_trimmed.to_owned())
    };
    let m_trimmed = mailbox_id.trim();
    let parsed_mb = if m_trimmed.is_empty() {
        Some(voidwire_core::net::mailbox_client::default_mailbox_device_id())
    } else {
        voidwire_core::net::mailbox_client::parse_mailbox_peer_opt(Some(m_trimmed))
            .map_err(human)?
    };
    n.set_relay_url(target_relay).map_err(msg)?;
    n.set_mailbox_id(parsed_mb).map_err(msg)?;
    Ok(())
}

#[tauri::command]
pub fn settings_set_pc_name(app: AppHandle, name: String) -> Result<String, String> {
    let n = node(&app)?;
    n.rename_device(&name).map_err(msg)?;
    crate::refresh_tray(&app);
    Ok(n.device_name())
}

#[tauri::command]
pub fn settings_set_download_dir(app: AppHandle, path: String) -> Result<String, String> {
    let n = node(&app)?;
    let trimmed = path.trim();
    if trimmed.is_empty() {
        n.reset_download_dir().map_err(msg)?;
    } else {
        n.set_download_dir(std::path::PathBuf::from(trimmed))
            .map_err(msg)?;
    }
    Ok(n.download_dir().display().to_string())
}

pub type Snapshot = SettingsOut;

#[cfg(target_os = "linux")]
fn pick_folder_native(app: &AppHandle, initial: std::path::PathBuf) -> Option<std::path::PathBuf> {
    use gtk::prelude::*;
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = app.run_on_main_thread(move || {
        let dialog = gtk::FileChooserNative::new(
            Some("Choose download folder"),
            gtk::Window::NONE,
            gtk::FileChooserAction::SelectFolder,
            Some("Select"),
            Some("Cancel"),
        );
        if initial.exists() {
            let _ = dialog.set_current_folder(&initial);
        }
        let res = dialog.run();
        let chosen = if res == gtk::ResponseType::Accept {
            dialog.filename()
        } else {
            None
        };
        let _ = tx.send(chosen);
    });
    rx.recv().ok().flatten()
}

#[cfg(not(target_os = "linux"))]
fn pick_folder_native(_app: &AppHandle, initial: std::path::PathBuf) -> Option<std::path::PathBuf> {
    voidwire_os_theme::pick_folder(Some(&initial))
}

/// Open the native OS folder picker dialog (taking no path arguments from JS)
/// and, if the user picks a folder, validate and save it via `set_download_dir`.
#[tauri::command]
pub async fn pick_download_dir(app: AppHandle) -> Result<Snapshot, String> {
    let initial = node(&app)?.download_dir();
    let app_for_dialog = app.clone();
    let chosen =
        tauri::async_runtime::spawn_blocking(move || pick_folder_native(&app_for_dialog, initial))
            .await
            .map_err(|e| e.to_string())?;
    if let Some(dir) = chosen {
        let n = node(&app)?;
        n.set_download_dir(dir).map_err(msg)?;
    }
    settings_get(app)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IncomingFileOut {
    pub transfer_id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub from: String,
    pub filename: String,
    pub mime: String,
    pub size: u64,
    pub bytes_received: u64,
    pub chunks_done: u64,
    pub total_chunks: u64,
    pub chunk_count: u64,
    pub next_chunk: u64,
    pub is_executable: bool,
    pub accepted: bool,
    pub canceled: bool,
    pub allow_open: bool,
    pub download_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompletedFileOut {
    pub transfer_id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub from: String,
    pub filename: String,
    pub size: u64,
    pub bytes_received: u64,
    pub chunks_done: u64,
    pub total_chunks: u64,
    pub is_executable: bool,
    pub accepted: bool,
    pub canceled: bool,
    pub allow_open: bool,
}

pub fn incoming_file_dto(
    f: voidwire_core::net::pc::IncomingFileInfo,
    download_dir: &str,
) -> IncomingFileOut {
    let is_executable =
        !f.allow_open || voidwire_core::file_transfer::is_executable_filename(&f.filename);
    let bytes_received = f
        .next_chunk
        .saturating_mul(voidwire_core::file_transfer::FILE_CHUNK_SIZE as u64)
        .min(f.size);
    IncomingFileOut {
        transfer_id: f.transfer_id.to_hex(),
        sender_id: f.sender.to_hex(),
        sender_name: f.from.clone(),
        from: f.from,
        filename: f.filename,
        mime: f.mime,
        size: f.size,
        bytes_received,
        chunks_done: f.next_chunk,
        total_chunks: f.chunk_count,
        chunk_count: f.chunk_count,
        next_chunk: f.next_chunk,
        is_executable,
        accepted: f.accepted,
        canceled: false,
        allow_open: !is_executable,
        download_dir: download_dir.to_owned(),
    }
}

pub fn completed_file_dto(f: voidwire_core::net::pc::CompletedFileInfo) -> CompletedFileOut {
    let is_executable =
        !f.allow_open || voidwire_core::file_transfer::is_executable_filename(&f.filename);
    let total_chunks = voidwire_core::file_transfer::chunk_count_for_size(f.size);
    CompletedFileOut {
        transfer_id: f.transfer_id.to_hex(),
        sender_id: f.sender.to_hex(),
        sender_name: f.from.clone(),
        from: f.from,
        filename: f.filename,
        size: f.size,
        bytes_received: f.size,
        chunks_done: total_chunks,
        total_chunks,
        is_executable,
        accepted: true,
        canceled: false,
        allow_open: !is_executable,
    }
}

#[tauri::command]
pub fn incoming_files_list(app: AppHandle) -> Result<Vec<IncomingFileOut>, String> {
    let n = node(&app)?;
    let dir = n.download_dir().display().to_string();
    Ok(n.incoming_files()
        .into_iter()
        .map(|f| incoming_file_dto(f, &dir))
        .collect())
}

#[tauri::command]
pub fn completed_files_list(app: AppHandle) -> Result<Vec<CompletedFileOut>, String> {
    let n = node(&app)?;
    if !n.keep_file_history() {
        return Ok(Vec::new());
    }
    Ok(n.completed_files()
        .into_iter()
        .map(completed_file_dto)
        .collect())
}

#[tauri::command]
pub fn incoming_file_decide(
    app: AppHandle,
    transfer_id: String,
    accept: bool,
) -> Result<(), String> {
    let tid = voidwire_core::file_transfer::TransferId::from_hex(&transfer_id)
        .ok_or("bad transfer id")?;
    let n = node(&app)?;
    if accept {
        n.accept_file(&tid).map(|_| ()).map_err(msg)
    } else {
        n.cancel_file(&tid);
        hide_confirm_if_empty(&app, &n);
        Ok(())
    }
}

#[tauri::command]
pub fn accept_file(app: AppHandle, transfer_id: String) -> Result<(), String> {
    incoming_file_decide(app, transfer_id, true)
}

#[tauri::command]
pub fn cancel_file(app: AppHandle, transfer_id: String) -> Result<(), String> {
    incoming_file_decide(app, transfer_id, false)
}

#[cfg(target_os = "linux")]
fn pick_file_native(app: &AppHandle, initial: std::path::PathBuf) -> Option<std::path::PathBuf> {
    use gtk::prelude::*;
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = app.run_on_main_thread(move || {
        let dialog = gtk::FileChooserNative::new(
            Some("Choose file to send"),
            gtk::Window::NONE,
            gtk::FileChooserAction::Open,
            Some("Send"),
            Some("Cancel"),
        );
        if initial.exists() {
            let _ = dialog.set_current_folder(&initial);
        }
        let res = dialog.run();
        let chosen = if res == gtk::ResponseType::Accept {
            dialog.filename()
        } else {
            None
        };
        let _ = tx.send(chosen);
    });
    rx.recv().ok().flatten()
}

#[cfg(not(target_os = "linux"))]
fn pick_file_native(_app: &AppHandle, initial: std::path::PathBuf) -> Option<std::path::PathBuf> {
    voidwire_os_theme::pick_file(Some(&initial))
}

#[tauri::command]
pub fn settings_set_auto_copy_clipboard(app: AppHandle, on: bool) -> Result<(), String> {
    node(&app)?.set_auto_copy_clipboard(on).map_err(msg)
}

#[tauri::command]
pub fn settings_set_send_clipboard_shortcut(app: AppHandle, on: bool) -> Result<(), String> {
    let n = node(&app)?;
    let prev = n.send_clipboard_shortcut();
    let accel = n.send_clipboard_shortcut_accel();
    if let Err(e) = node::sync_clipboard_hotkey(&app, on, &accel) {
        let _ = node::sync_clipboard_hotkey(&app, prev, &accel);
        return Err(e);
    }
    n.set_send_clipboard_shortcut(on).map_err(msg)?;
    Ok(())
}

#[tauri::command]
pub fn settings_set_send_clipboard_shortcut_accel(
    app: AppHandle,
    accel: String,
) -> Result<String, String> {
    let clean = accel.trim();
    voidwire_os_theme::parse_hotkey_accel(clean)?;
    let n = node(&app)?;
    let prev_accel = n.send_clipboard_shortcut_accel();
    let enabled = n.send_clipboard_shortcut();
    if enabled {
        if let Err(e) = node::sync_clipboard_hotkey(&app, true, clean) {
            let _ = node::sync_clipboard_hotkey(&app, true, &prev_accel);
            return Err(e);
        }
    }
    n.set_send_clipboard_shortcut_accel(clean).map_err(msg)?;
    Ok(n.send_clipboard_shortcut_accel())
}

#[tauri::command]
pub fn set_drop_target_phone(id: String) -> Result<(), String> {
    node::set_drop_target_phone(Some(id));
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingClipboardOut {
    pub id: u64,
    pub from: String,
    pub sender_id: String,
    pub text: String,
    pub byte_len: usize,
    pub sensitive: bool,
}

pub fn pending_clipboard_dto(
    c: voidwire_core::net::pc::PendingClipboardInfo,
) -> PendingClipboardOut {
    PendingClipboardOut {
        id: c.id,
        from: c.from,
        sender_id: c.sender.to_hex(),
        text: c.text,
        byte_len: c.byte_len,
        sensitive: c.sensitive,
    }
}

#[tauri::command]
pub fn pending_clipboards_list(app: AppHandle) -> Result<Vec<PendingClipboardOut>, String> {
    Ok(node(&app)?
        .pending_clipboards()
        .into_iter()
        .map(pending_clipboard_dto)
        .collect())
}

#[tauri::command]
pub fn pending_clipboard_decide(
    app: AppHandle,
    id: u64,
    action: String,
) -> Result<Option<String>, String> {
    let n = node(&app)?;
    let out = match action.as_str() {
        "copy" => {
            if let Some(info) = n.decide_clipboard(id, true).map_err(msg)? {
                node::set_os_clipboard(&app, &info.text);
            }
            Ok(None)
        }
        "save_txt" => {
            let saved_path = n.save_pending_clipboard_as_txt(id).map_err(msg)?;
            let fname = saved_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("clipboard.txt")
                .to_owned();
            Ok(Some(fname))
        }
        _ => {
            let _ = n.decide_clipboard(id, false).map_err(msg)?;
            Ok(None)
        }
    };
    hide_confirm_if_empty(&app, &n);
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PcSendOut {
    pub outcome: &'static str,
    pub delivery_path: &'static str,
    pub latency_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutgoingFileOut {
    pub transfer_id: String,
    pub recipient_id: String,
    pub to: String,
    pub filename: String,
    pub mime: String,
    pub size: u64,
    pub chunk_count: u64,
    pub chunks_sent: u64,
    pub delivery_path: &'static str,
    pub waiting_for_accept: bool,
}

fn delivery_path_label(p: voidwire_core::net::DeliveryPath) -> &'static str {
    match p {
        voidwire_core::net::DeliveryPath::Direct => "direct",
        voidwire_core::net::DeliveryPath::Relayed => "relay",
        voidwire_core::net::DeliveryPath::QueuedInDeviceInbox => "device_inbox",
    }
}

pub fn outgoing_file_dto(o: voidwire_core::net::pc::OutgoingFileInfo) -> OutgoingFileOut {
    let waiting_for_accept = o.delivery_path
        == voidwire_core::net::DeliveryPath::QueuedInDeviceInbox
        && o.chunks_sent == 0;
    OutgoingFileOut {
        transfer_id: o.transfer_id.to_hex(),
        recipient_id: o.recipient.to_hex(),
        to: o.to,
        filename: o.filename,
        mime: o.mime,
        size: o.size,
        chunk_count: o.chunk_count,
        chunks_sent: o.chunks_sent,
        delivery_path: delivery_path_label(o.delivery_path),
        waiting_for_accept,
    }
}

pub(crate) fn resolve_target_phone(n: &PcNode, id: &str) -> Result<DeviceId, String> {
    let trimmed = id.trim();
    if !trimmed.is_empty() {
        return DeviceId::from_hex(trimmed).ok_or_else(|| "bad device id".to_owned());
    }
    n.devices()
        .into_iter()
        .next()
        .map(|d| d.id)
        .ok_or_else(|| "No paired phone found. Pair a phone first.".to_owned())
}

fn parse_relay_decision(
    raw: Option<&str>,
) -> Option<voidwire_core::file_transfer::RelayPromptDecision> {
    use voidwire_core::file_transfer::RelayPromptDecision;
    match raw.map(str::trim) {
        Some("send_via_relay") | Some("send_once") | Some("always_allow") => {
            Some(RelayPromptDecision::SendViaRelay)
        }
        Some("wait_for_direct") => Some(RelayPromptDecision::WaitForDirect),
        Some("cancel") => Some(RelayPromptDecision::Cancel),
        _ => None,
    }
}

/// How a PC -> phone send failed, as the Devices window needs to know it (`M3.1.2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendErrKind {
    /// Relayed path, size between the small-item cap (256 KiB) and the relay cap: ask the sender.
    RelayPrompt,
    /// Relayed path, size over the relay cap (25 MB by default): blocked, direct only.
    RelayCap,
    /// "Never send files over relay" is on (this PC, or the phone's own setting when `phone_side`).
    RelayNever,
    /// Anything else: shown as a friendly sentence in an OK dialog.
    Error,
}

impl SendErrKind {
    fn label(self) -> &'static str {
        match self {
            SendErrKind::RelayPrompt => "relay_prompt",
            SendErrKind::RelayCap => "relay_cap",
            SendErrKind::RelayNever => "relay_never",
            SendErrKind::Error => "error",
        }
    }
}

/// Wrappers that can sit in front of a relay-policy tag: the `NetError`
/// Display prefix (the M3.1.1 bug: `msg()` turned `Protocol(..)` into
/// `"protocol error: relay_prompt_required: .."`, so no prefix check ever
/// matched) and the PC's wrapper for a phone-side offer rejection.
const SEND_ERR_WRAPPERS: [&str; 2] = ["protocol error: ", "file_offer_rejected: "];

/// Strip [`SEND_ERR_WRAPPERS`] (repeatedly, in any order) from a raw error string.
pub(crate) fn strip_send_err_wrappers(raw: &str) -> (&str, bool) {
    let mut s = raw.trim();
    let mut phone_side = false;
    loop {
        let mut stripped = false;
        for w in SEND_ERR_WRAPPERS {
            if let Some(rest) = s.strip_prefix(w) {
                if w.starts_with("file_offer_rejected") {
                    phone_side = true;
                }
                s = rest.trim_start();
                stripped = true;
            }
        }
        if !stripped {
            return (s, phone_side);
        }
    }
}

/// Classify a send error by its variant (never by its Display text). Returns the
/// kind, the bare policy tag line (e.g. `relay_prompt_required: size=.. cap=..`)
/// when it is a relay-policy error, and whether the phone (not this PC) refused.
pub(crate) fn classify_send_err(err: &NetError) -> (SendErrKind, Option<String>, bool) {
    let NetError::Protocol(raw) = err else {
        return (SendErrKind::Error, None, false);
    };
    let (tag, phone_side) = strip_send_err_wrappers(raw);
    if tag.starts_with("relay_prompt_required:") {
        return (SendErrKind::RelayPrompt, Some(tag.to_owned()), phone_side);
    }
    if tag.starts_with("exceeds_relay_cap") {
        let cap_zero = tag
            .split_whitespace()
            .any(|t| t.trim_end_matches(',') == "cap=0");
        let kind = if tag.contains("never_send_files_over_relay") || (phone_side && cap_zero) {
            SendErrKind::RelayNever
        } else {
            SendErrKind::RelayCap
        };
        return (kind, Some(tag.to_owned()), phone_side);
    }
    (SendErrKind::Error, None, phone_side)
}

/// Plain-language text for a failed PC -> phone send. Never echoes raw iroh /
/// QUIC errors, and never says "the PC" (the core's `Unreachable` Display is
/// written from the phone's point of view).
pub(crate) fn friendly_send_error(err: &NetError, phone_name: &str) -> String {
    use voidwire_core::reject::RejectReason;
    match err {
        NetError::Unreachable(_) | NetError::Timeout => format!(
            "Couldn't reach {phone_name}, and the item couldn't be queued in the relay inbox either. \
             Check that this PC is online and that Voidwire is open on the phone (or Receive in \
             background is on), then try again."
        ),
        NetError::Cancelled => "The send was cancelled.".to_owned(),
        NetError::UnknownDevice => format!(
            "{phone_name} isn't paired with this PC anymore. Pair it again with Pair a phone…"
        ),
        NetError::Storage(detail) => format!("Couldn't read the file on this PC ({detail})."),
        NetError::Rejected(RejectReason::Removed) => format!(
            "{phone_name} was removed from this PC's devices. Pair it again with Pair a phone…"
        ),
        NetError::Rejected(RejectReason::UrlTooLong) => {
            "That's too long to send (clipboard text is limited to 10 MB).".to_owned()
        }
        NetError::Rejected(r) => human(*r),
        NetError::Protocol(raw) => {
            let (tag, _) = strip_send_err_wrappers(raw);
            if tag.starts_with("canceled_by_recipient") {
                format!("{phone_name} declined the file.")
            } else if tag.starts_with("clipboard_too_large") {
                format!("That clipboard text is too large for {phone_name} to accept.")
            } else if tag.starts_with("waiting_for_direct_path") {
                format!(
                    "Waiting for a direct connection to {phone_name}. Connect both devices to the \
                     same Wi-Fi / LAN and try again."
                )
            } else if tag.starts_with("file exceeds") {
                "That file is larger than the 2 GiB limit.".to_owned()
            } else {
                format!(
                    "Something went wrong while sending to {phone_name}. Try again in a moment."
                )
            }
        }
    }
}

/// Format a failed PC -> phone send (file, copied file, or clipboard text) for
/// the Devices window (`M3.1.2`). Line 1 is the bare relay-policy tag
/// (`relay_prompt_required: ..` / `exceeds_relay_cap: ..`) or a friendly
/// sentence; then `key=value` lines: `kind`, `phone_id`, `phone_name`, and for
/// files `path` + `filename`, and `side=phone` when the phone refused.
/// `devices.js` turns `kind` into the matching modal and retries a confirmed
/// relay send with `path` + `phone_id`.
pub(crate) fn format_file_send_err(
    err: NetError,
    path: Option<&std::path::Path>,
    phone_id: &DeviceId,
    phone_name: &str,
) -> String {
    let (kind, tag, phone_side) = classify_send_err(&err);
    let first = tag.unwrap_or_else(|| friendly_send_error(&err, phone_name));
    let mut out = format!("{first}\nkind={}", kind.label());
    if let Some(p) = path {
        let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("file");
        out.push_str(&format!("\npath={}\nfilename={fname}", p.display()));
    }
    // `device_id` since M4.2; `phone_id` stays for windows built before it.
    out.push_str(&format!(
        "\ndevice_id={id}\nphone_id={id}\nphone_name={phone_name}",
        id = phone_id.to_hex()
    ));
    if phone_side {
        out.push_str("\nside=phone");
    }
    out
}

/// What a send error may put in the log: only its `kind` (never the path,
/// filename, clipboard text, or phone name carried in the metadata lines).
pub(crate) fn send_err_log_kind(formatted: &str) -> &str {
    formatted
        .lines()
        .find_map(|l| l.strip_prefix("kind="))
        .unwrap_or("error")
}

pub(crate) fn phone_display_name(n: &PcNode, phone_id: &DeviceId) -> String {
    n.devices()
        .into_iter()
        .find(|d| d.id == *phone_id)
        .map(|d| d.name)
        .unwrap_or_else(|| "Phone".to_owned())
}

#[tauri::command]
pub async fn send_clipboard_to_phone(
    app: AppHandle,
    id: String,
    relay_decision: Option<String>,
) -> Result<PcSendOut, String> {
    if let Some(path) = node::get_os_clipboard_file(&app) {
        let n = node(&app)?;
        let phone_id = resolve_target_phone(&n, &id)?;
        let to_name = phone_display_name(&n, &phone_id);
        let decision = parse_relay_decision(relay_decision.as_deref());
        let path_for_err = path.clone();
        let report = tauri::async_runtime::spawn_blocking(move || {
            n.send_file_to_phone(&phone_id, &path, "application/octet-stream", decision)
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format_file_send_err(e, Some(&path_for_err), &phone_id, &to_name))?;
        let outcome = if report.awaiting_accept {
            "pending_prompt"
        } else {
            "opened"
        };
        return Ok(PcSendOut {
            outcome,
            delivery_path: delivery_path_label(report.delivery_path),
            latency_us: report.latency_us,
        });
    }
    let text = node::get_os_clipboard(&app)
        .ok_or_else(|| "Clipboard is empty or does not contain text or a file.".to_owned())?;
    send_text_to_phone(app, id, text, relay_decision).await
}

#[tauri::command]
pub async fn send_text_to_phone(
    app: AppHandle,
    id: String,
    text: String,
    relay_decision: Option<String>,
) -> Result<PcSendOut, String> {
    let n = node(&app)?;
    let phone_id = resolve_target_phone(&n, &id)?;
    let to_name = phone_display_name(&n, &phone_id);
    let decision = parse_relay_decision(relay_decision.as_deref());
    let report = tauri::async_runtime::spawn_blocking(move || {
        n.send_text_or_url_to_phone_with_decision(&phone_id, &text, decision)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format_file_send_err(e, None, &phone_id, &to_name))?;
    let outcome = match report.outcome {
        voidwire_core::net::SendOutcome::Opened => "opened",
        voidwire_core::net::SendOutcome::Prompted => "pending_prompt",
    };
    Ok(PcSendOut {
        outcome,
        delivery_path: delivery_path_label(report.delivery_path),
        latency_us: report.latency_us,
    })
}

#[tauri::command]
pub async fn send_file_to_phone_pick(
    app: AppHandle,
    id: String,
    path: Option<String>,
    relay_decision: Option<String>,
) -> Result<Option<OutgoingFileOut>, String> {
    let n = node(&app)?;
    let phone_id = resolve_target_phone(&n, &id)?;
    let to_name = phone_display_name(&n, &phone_id);
    let chosen = if let Some(explicit_path) = path.filter(|s| !s.trim().is_empty()) {
        Some(std::path::PathBuf::from(explicit_path))
    } else {
        let initial = n.download_dir();
        let app_for_dialog = app.clone();
        tauri::async_runtime::spawn_blocking(move || pick_file_native(&app_for_dialog, initial))
            .await
            .map_err(|e| e.to_string())?
    };
    let Some(path) = chosen else {
        return Ok(None);
    };
    let decision = parse_relay_decision(relay_decision.as_deref());
    let path_for_err = path.clone();
    let to_name_for_err = to_name.clone();
    let report = tauri::async_runtime::spawn_blocking(move || {
        n.send_file_to_phone(&phone_id, &path, "application/octet-stream", decision)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format_file_send_err(e, Some(&path_for_err), &phone_id, &to_name_for_err))?;
    let chunk_count = voidwire_core::file_transfer::chunk_count_for_size(report.size);
    Ok(Some(OutgoingFileOut {
        transfer_id: report.transfer_id.to_hex(),
        recipient_id: phone_id.to_hex(),
        to: to_name,
        filename: report.filename,
        mime: "application/octet-stream".to_owned(),
        size: report.size,
        chunk_count,
        chunks_sent: report.chunks_sent,
        delivery_path: delivery_path_label(report.delivery_path),
        waiting_for_accept: report.awaiting_accept,
    }))
}

#[tauri::command]
pub fn outgoing_files_list(app: AppHandle) -> Result<Vec<OutgoingFileOut>, String> {
    Ok(node(&app)?
        .outgoing_files()
        .into_iter()
        .map(outgoing_file_dto)
        .collect())
}

#[tauri::command]
pub fn cancel_outgoing_file(app: AppHandle, transfer_id: String) -> Result<(), String> {
    let tid = voidwire_core::file_transfer::TransferId::from_hex(&transfer_id)
        .ok_or("bad transfer id")?;
    let _ = node(&app)?.cancel_outgoing_file(&tid);
    Ok(())
}

/// Confirmation toast after forgetting a device in Paired devices (SPEC 2.4).
pub fn forgot_text(device_name: &str) -> String {
    format!("Forgot {device_name}. Its links are refused until you pair it again.")
}

#[cfg(test)]
mod pair2_qr_tests {
    /// The phone's scanner test decodes testdata/qr/pair2-worst.matrix; this
    /// keeps that matrix the one this renderer draws for the fixture URI.
    #[test]
    fn renderer_draws_the_scanner_fixture() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/qr/");
        let uri = std::fs::read_to_string(format!("{dir}pair2-worst.uri")).unwrap();
        let qr = super::pair2_qr(uri.trim_end()).unwrap();
        let w = qr.width();
        let drawn: Vec<String> = qr
            .to_colors()
            .chunks(w)
            .map(|r| {
                r.iter()
                    .map(|c| if *c == qrcode::Color::Dark { '1' } else { '0' })
                    .collect()
            })
            .collect();
        let fixture = std::fs::read_to_string(format!("{dir}pair2-worst.matrix")).unwrap();
        assert_eq!(drawn, fixture.lines().collect::<Vec<_>>());
        let svg = super::pair2_qr_svg(uri.trim_end()).unwrap();
        assert!(svg.contains("<svg"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use voidwire_core::file_transfer::TransferId;
    use voidwire_core::net::pc::{CompletedFileInfo, IncomingFileInfo};

    #[test]
    fn forgot_text_names_the_device() {
        assert_eq!(
            forgot_text("Pixel 8"),
            "Forgot Pixel 8. Its links are refused until you pair it again."
        );
    }

    #[test]
    fn incoming_and_completed_file_dtos_serialize_with_executable_flags_and_no_path() {
        let tid = TransferId::from_bytes([0x42; 16]);
        let sender = DeviceId::from_bytes([0x11; 32]).unwrap();
        let inc = IncomingFileInfo {
            transfer_id: tid,
            sender,
            from: "Pixel 9".into(),
            filename: "installer.exe".into(),
            mime: "application/octet-stream".into(),
            size: 600_000,
            chunk_count: 3,
            next_chunk: 1,
            accepted: true,
            allow_open: false,
        };
        let dto = incoming_file_dto(inc, "D:\\Voidwire\\Downloads");
        assert_eq!(dto.transfer_id.len(), 32);
        assert_eq!(dto.download_dir, "D:\\Voidwire\\Downloads");
        assert_eq!(dto.sender_id.len(), 64);
        assert_eq!(dto.sender_name, "Pixel 9");
        assert!(dto.is_executable);
        assert!(!dto.allow_open);
        assert_eq!(dto.bytes_received, 256 * 1024);
        assert_eq!(dto.chunks_done, 1);
        assert_eq!(dto.total_chunks, 3);
        assert!(dto.accepted);
        assert!(!dto.canceled);

        let comp = CompletedFileInfo {
            transfer_id: tid,
            sender,
            from: "Pixel 9".into(),
            filename: "notes.pdf".into(),
            path: PathBuf::from("/tmp/secret/notes.pdf"),
            size: 12_345,
            blake3_root: [0xaa; 32],
            allow_open: true,
        };
        let comp_dto = completed_file_dto(comp);
        assert_eq!(comp_dto.sender_name, "Pixel 9");
        assert!(!comp_dto.is_executable);
        assert!(comp_dto.allow_open);
        assert_eq!(comp_dto.bytes_received, 12_345);
        assert_eq!(comp_dto.chunks_done, 1);
        assert_eq!(comp_dto.total_chunks, 1);
        let dbg = format!("{comp_dto:?}");
        assert!(!dbg.contains("/tmp/secret"));
    }

    #[test]
    fn pending_clipboard_and_outgoing_file_dtos_serialize_cleanly() {
        use voidwire_core::net::pc::{OutgoingFileInfo, PendingClipboardInfo};
        use voidwire_core::net::DeliveryPath;
        use voidwire_core::time::UnixMillis;

        let sender = DeviceId::from_bytes([0x22; 32]).unwrap();
        let clip = PendingClipboardInfo {
            id: 7,
            from: "Pixel 9".into(),
            sender,
            text: "ghp_1234567890abcdefghijklmnopqrstuv".into(),
            byte_len: 36,
            sensitive: true,
            received_at: UnixMillis(1_700_000_000_000),
        };
        let clip_dto = pending_clipboard_dto(clip);
        assert_eq!(clip_dto.id, 7);
        assert_eq!(clip_dto.from, "Pixel 9");
        assert_eq!(clip_dto.sender_id.len(), 64);
        assert!(clip_dto.sensitive);
        assert_eq!(clip_dto.byte_len, 36);

        let tid = TransferId::from_bytes([0x55; 16]);
        let out = OutgoingFileInfo {
            transfer_id: tid,
            recipient: sender,
            to: "Pixel 9".into(),
            filename: "report.pdf".into(),
            mime: "application/pdf".into(),
            size: 512_000,
            chunk_count: 2,
            chunks_sent: 0,
            delivery_path: DeliveryPath::QueuedInDeviceInbox,
            created_at: UnixMillis(1_700_000_000_000),
            expires_at: UnixMillis(1_700_086_400_000),
        };
        let out_dto = outgoing_file_dto(out);
        assert_eq!(out_dto.transfer_id.len(), 32);
        assert_eq!(out_dto.to, "Pixel 9");
        assert_eq!(out_dto.delivery_path, "device_inbox");
        assert!(out_dto.waiting_for_accept);
    }

    // M3.1.2: the relay popup never showed because `msg()` prefixed every
    // `NetError::Protocol` with "protocol error: ". These use real variants.
    fn meta(out: &str, key: &str) -> Option<String> {
        out.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")).map(str::to_owned))
    }

    fn phone() -> DeviceId {
        DeviceId::from_bytes([0x33; 32]).unwrap()
    }

    #[test]
    fn send_err_relay_prompt_from_protocol_error() {
        let p = PathBuf::from("/tmp/report 5mb.pdf");
        let e = NetError::Protocol("relay_prompt_required: size=5242880 cap=26214400".into());
        let out = format_file_send_err(e, Some(&p), &phone(), "Pixel 6 Pro");
        let first = out.lines().next().unwrap();
        assert_eq!(first, "relay_prompt_required: size=5242880 cap=26214400");
        assert!(!out.contains("protocol error"));
        assert_eq!(meta(&out, "kind").as_deref(), Some("relay_prompt"));
        assert_eq!(meta(&out, "path").as_deref(), Some("/tmp/report 5mb.pdf"));
        assert_eq!(meta(&out, "filename").as_deref(), Some("report 5mb.pdf"));
        assert_eq!(meta(&out, "phone_id"), Some(phone().to_hex()));
        assert_eq!(meta(&out, "phone_name").as_deref(), Some("Pixel 6 Pro"));
        assert_eq!(meta(&out, "side"), None);
    }

    #[test]
    fn send_err_relay_cap_from_protocol_error() {
        let p = PathBuf::from("/tmp/video.mp4");
        let e = NetError::Protocol("exceeds_relay_cap: size=83886080 cap=26214400".into());
        let out = format_file_send_err(e, Some(&p), &phone(), "Pixel");
        assert!(out.starts_with("exceeds_relay_cap: size=83886080 cap=26214400\n"));
        assert_eq!(meta(&out, "kind").as_deref(), Some("relay_cap"));
    }

    #[test]
    fn send_err_never_relay_on_this_pc() {
        let e = NetError::Protocol(
            "exceeds_relay_cap: never_send_files_over_relay: size=1000000 cap=0".into(),
        );
        let out = format_file_send_err(e, Some(&PathBuf::from("/a/b.bin")), &phone(), "P");
        assert_eq!(meta(&out, "kind").as_deref(), Some("relay_never"));
        assert_eq!(meta(&out, "side"), None);
    }

    #[test]
    fn send_err_phone_rejected_offer_over_cap() {
        let e = NetError::Protocol("file_offer_rejected: exceeds_relay_cap: cap=26214400".into());
        let out = format_file_send_err(e, Some(&PathBuf::from("/a/big.iso")), &phone(), "P");
        assert!(out.starts_with("exceeds_relay_cap: cap=26214400\n"));
        assert_eq!(meta(&out, "kind").as_deref(), Some("relay_cap"));
        assert_eq!(meta(&out, "side").as_deref(), Some("phone"));
    }

    #[test]
    fn send_err_phone_never_relay_is_cap_zero_from_phone() {
        let e = NetError::Protocol("file_offer_rejected: exceeds_relay_cap: cap=0".into());
        let out = format_file_send_err(e, Some(&PathBuf::from("/a/x")), &phone(), "P");
        assert_eq!(meta(&out, "kind").as_deref(), Some("relay_never"));
        assert_eq!(meta(&out, "side").as_deref(), Some("phone"));
    }

    #[test]
    fn send_err_wrappers_stripped_even_if_doubled() {
        let (tag, phone_side) = strip_send_err_wrappers(
            "protocol error: file_offer_rejected: relay_prompt_required: size=1 cap=2",
        );
        assert_eq!(tag, "relay_prompt_required: size=1 cap=2");
        assert!(phone_side);
    }

    #[test]
    fn send_err_unreachable_is_friendly_and_hides_iroh() {
        for e in [
            NetError::Unreachable("connection lost: timed out (iroh-quinn magicsock)".into()),
            NetError::Timeout,
        ] {
            let out = format_file_send_err(e, None, &phone(), "Pixel 6 Pro");
            let first = out.lines().next().unwrap();
            assert!(first.starts_with("Couldn't reach Pixel 6 Pro"), "{first}");
            assert!(!out.contains("iroh"));
            assert!(!out.contains("couldn't reach the PC"));
            assert_eq!(meta(&out, "kind").as_deref(), Some("error"));
            assert_eq!(meta(&out, "path"), None);
        }
    }

    #[test]
    fn send_err_other_variants_are_friendly() {
        let pid = phone();
        let f = |e| {
            format_file_send_err(e, None, &pid, "Pixel")
                .lines()
                .next()
                .unwrap()
                .to_owned()
        };
        assert_eq!(f(NetError::Cancelled), "The send was cancelled.");
        assert!(f(NetError::UnknownDevice).contains("isn't paired"));
        assert!(f(NetError::Storage("permission denied".into())).starts_with("Couldn't read"));
        assert_eq!(
            f(NetError::Protocol(
                "file_offer_rejected: canceled_by_recipient".into()
            )),
            "Pixel declined the file."
        );
        assert!(f(NetError::Protocol("waiting_for_direct_path".into())).contains("direct"));
        let generic = f(NetError::Protocol("bad frame 0x7".into()));
        assert!(generic.starts_with("Something went wrong"));
        assert!(!generic.contains("0x7"));
        assert!(!f(NetError::Rejected(
            voidwire_core::reject::RejectReason::Removed
        ))
        .is_empty());
    }

    #[test]
    fn send_err_log_kind_never_leaks_metadata() {
        let p = PathBuf::from("/home/u/secret-plans.txt");
        let e = NetError::Protocol("relay_prompt_required: size=1 cap=2".into());
        let out = format_file_send_err(e, Some(&p), &phone(), "Pixel");
        assert_eq!(send_err_log_kind(&out), "relay_prompt");
        assert_eq!(send_err_log_kind("No paired phone found."), "error");
    }

    #[test]
    fn relay_decision_parses() {
        use voidwire_core::file_transfer::RelayPromptDecision;
        assert_eq!(
            parse_relay_decision(Some("send_via_relay")),
            Some(RelayPromptDecision::SendViaRelay)
        );
        assert_eq!(parse_relay_decision(None), None);
    }
}

/// Static checks on the Devices window (`M3.1.2`): the parts of the relay
/// popup / error dialog fix that live in plain JS and HTML.
#[cfg(test)]
mod ui_static_tests {
    const DEVICES_JS: &str = include_str!("../ui/devices.js");
    const DEVICES_HTML: &str = include_str!("../ui/devices.html");
    const PAIR_CSS: &str = include_str!("../ui/pair.css");
    const MAIN_RS: &str = include_str!("main.rs");

    #[test]
    fn pair_window_fits_without_scrolling_and_tray_double_click_opens_devices() {
        assert!(
            MAIN_RS.contains(r#"PAIR_WINDOW => Some(("pair.html", format!("{name} – Pair a phone"), 440.0, 620.0))"#),
            "PAIR_WINDOW height must be 620.0 so QR and footer fit without vertical scrolling"
        );
        assert!(
            PAIR_CSS.contains(".actions:not(:has(:not(.hidden))) { display: none; }"),
            "pair.css must collapse .actions when all action buttons are hidden"
        );
        assert!(
            MAIN_RS.contains(".show_menu_on_left_click(false)")
                && MAIN_RS.contains("TrayIconEvent::DoubleClick")
                && MAIN_RS.contains("request_devices(tray.app_handle(), false)"),
            "TrayIconBuilder must open Devices window on left double-click without left-click menu stealing the second click"
        );
    }

    #[test]
    fn js_strips_both_error_wrappers() {
        assert!(DEVICES_JS.contains(
            r#"const SEND_ERR_WRAPPERS = ["protocol error: ", "file_offer_rejected: "];"#
        ));
        for kind in ["relay_prompt", "relay_cap", "relay_never"] {
            assert!(DEVICES_JS.contains(&format!("\"{kind}\"")), "{kind}");
        }
    }

    #[test]
    fn js_send_errors_use_a_modal_not_red_text() {
        assert!(!DEVICES_JS.contains("err.textContent = String(e);\n    } finally"));
        assert!(!DEVICES_JS.contains("errEl.textContent = meta.raw"));
        assert!(DEVICES_JS.contains("function showSendErrorModal("));
        assert!(DEVICES_JS.contains("handleFileSendError(e, d.id, d.name, err, null, val);"));
        assert!(DEVICES_JS.contains("handleFileSendError(e, d.id, d.name, err, null, raw);"));
    }

    #[test]
    fn refresh_only_clears_its_own_banner_text() {
        let start = DEVICES_JS.find("async function refresh()").unwrap();
        let body = &DEVICES_JS[start..start + 3000];
        assert!(!body.contains(r#"$("msg").textContent = "";"#));
        assert!(body.contains("setRefreshMsg("));
    }

    #[test]
    fn pair_button_is_a_chamfered_primary() {
        let line = DEVICES_HTML
            .lines()
            .find(|l| l.contains(r#"id="pairbtn""#))
            .unwrap();
        assert!(line.contains("btn btn-primary vw-cut vw-cut-md vw-cut-frame"));
    }

    #[test]
    fn every_primary_button_is_chamfered() {
        for (name, src) in [("devices.html", DEVICES_HTML), ("devices.js", DEVICES_JS)] {
            for l in src.lines().filter(|l| l.contains("btn-primary")) {
                assert!(l.contains("vw-cut"), "{name}: {l}");
            }
        }
    }
}

// ---- M4.4 relays ----

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayRowOut {
    nickname: String,
    url: String,
    host: String,
    mailbox_id: String,
    home: bool,
    builtin: bool,
    used_by: u32,
    /// `connected`, `unreachable` or `idle`.
    status: &'static str,
    down_since_ms: u64,
    link: String,
}

#[tauri::command]
pub fn relays_list(app: AppHandle) -> Result<Vec<RelayRowOut>, String> {
    use voidwire_core::net::relays::RelayStatus as S;
    Ok(node(&app)?
        .relays()
        .into_iter()
        .map(|r| {
            let (status, down_since_ms) = match r.status {
                S::Connected => ("connected", 0),
                S::Unreachable { since_ms } => ("unreachable", since_ms),
                S::Idle => ("idle", 0),
            };
            RelayRowOut {
                nickname: r.nickname,
                url: r.url,
                host: r.host,
                mailbox_id: r.mailbox_id,
                home: r.home,
                builtin: r.builtin,
                used_by: r.used_by,
                status,
                down_since_ms,
                link: r.link,
            }
        })
        .collect())
}

#[tauri::command]
pub fn relays_add(
    app: AppHandle,
    link_or_url: String,
    mailbox_id: String,
    nickname: String,
) -> Result<(), String> {
    let n = node(&app)?;
    let t = link_or_url.trim();
    if t.starts_with("voidwire:") {
        n.add_relay_link(t)
    } else {
        n.add_relay(t, &mailbox_id, &nickname)
    }
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn relays_remove(app: AppHandle, url: String) -> Result<(), String> {
    node(&app)?.remove_relay(&url).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn relays_rename(app: AppHandle, url: String, nickname: String) -> Result<(), String> {
    node(&app)?
        .rename_relay(&url, &nickname)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn relays_retry(app: AppHandle, url: String) -> Result<(), String> {
    node(&app)?.retry_relay(&url);
    Ok(())
}

/// Make a saved relay this PC's home relay (its own mailbox id kept).
#[tauri::command]
pub fn relays_set_home(app: AppHandle, url: String) -> Result<(), String> {
    let n = node(&app)?;
    let row = n
        .relays()
        .into_iter()
        .find(|r| r.url == url)
        .ok_or_else(|| "That relay isn't saved.".to_string())?;
    settings_set_relay_config(app, row.url, row.mailbox_id)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRelayOut {
    peer_id: String,
    url: Option<String>,
    host: String,
}

/// The relay each pairing uses ("via <host>").
#[tauri::command]
pub fn pairing_relays(app: AppHandle) -> Result<Vec<PairingRelayOut>, String> {
    let n = node(&app)?;
    let home = n.relay_url();
    Ok(n.pairings()
        .into_iter()
        .map(|p| {
            let host = p
                .relay_url
                .as_deref()
                .or(home.as_deref())
                .map(voidwire_core::net::pair2::relay_host)
                .unwrap_or_default();
            PairingRelayOut {
                peer_id: p.peer.to_hex(),
                url: p.relay_url,
                host,
            }
        })
        .collect())
}

fn peer_of(hex: &str) -> Result<DeviceId, String> {
    DeviceId::from_hex(hex).ok_or_else(|| "Unknown device.".to_string())
}

#[tauri::command]
pub async fn relay_change_propose(
    app: AppHandle,
    peer_id: String,
    url: String,
) -> Result<(), String> {
    let n = node(&app)?;
    let peer = peer_of(&peer_id)?;
    tauri::async_runtime::spawn_blocking(move || n.change_pairing_relay(&peer, &url))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayChangeOut {
    peer_id: String,
    peer_name: String,
    host: String,
    new_relay: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayChangeStatusOut {
    peer_id: String,
    host: String,
    state: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayChangesOut {
    requests: Vec<RelayChangeOut>,
    mine: Vec<RelayChangeStatusOut>,
}

#[tauri::command]
pub fn relay_changes(app: AppHandle) -> Result<RelayChangesOut, String> {
    use voidwire_core::net::relay_change::RelayChangeState as S;
    let n = node(&app)?;
    Ok(RelayChangesOut {
        requests: n
            .relay_change_requests()
            .into_iter()
            .map(|r| RelayChangeOut {
                peer_id: r.peer.to_hex(),
                peer_name: r.peer_name,
                host: r.host,
                new_relay: r.new_relay,
            })
            .collect(),
        mine: n
            .relay_change_statuses()
            .into_iter()
            .map(|s| RelayChangeStatusOut {
                peer_id: s.peer.to_hex(),
                host: s.host,
                state: match s.state {
                    S::Waiting => "waiting",
                    S::Declined => "declined",
                    S::Done => "done",
                    S::NoRoom => "no_room",
                },
            })
            .collect(),
    })
}

#[tauri::command]
pub async fn relay_change_answer(
    app: AppHandle,
    peer_id: String,
    allow: bool,
) -> Result<(), String> {
    let n = node(&app)?;
    let peer = peer_of(&peer_id)?;
    tauri::async_runtime::spawn_blocking(move || n.answer_relay_change(&peer, allow))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}
