//! Tauri commands. Each window's capability file grants only its own
//! commands. Nothing here takes or returns a URL: prompts carry the host
//! for display and are decided by id.

use serde::Serialize;
use tauri::{AppHandle, Manager};
use voidwire_core::ids::DeviceId;
use voidwire_core::net::pc::{PairInvitation, PairStatus, PcNode};
use voidwire_core::net::NetError;

use crate::{node, CONFIRM_WINDOW};

fn node(app: &AppHandle) -> Result<std::sync::Arc<PcNode>, String> {
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

/// The window was hidden/minimized: stop refreshing, revoke the live QR.
#[tauri::command]
pub fn pair_pause(app: AppHandle) -> Result<(), String> {
    node(&app)?.pair_pause();
    Ok(())
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
            node::log(&format!("forgot {name}"));
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
    })
}

#[tauri::command]
pub fn settings_set_no_prompt(app: AppHandle, on: bool) -> Result<(), String> {
    node(&app)?.set_no_prompt(on).map_err(msg)
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
    Ok(node(&app)?
        .pending()
        .into_iter()
        .map(|p| PendingOut {
            id: p.id,
            host: p.host,
            from: p.from,
        })
        .collect())
}

fn hide_confirm_if_empty(app: &AppHandle, n: &PcNode) {
    if n.pending().is_empty() && n.incoming_files().is_empty() {
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

/// Confirmation toast after forgetting a device in Paired devices (SPEC 2.4).
pub fn forgot_text(device_name: &str) -> String {
    format!("Forgot {device_name}. Its links are refused until you pair it again.")
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
}
