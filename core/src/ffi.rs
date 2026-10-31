//! UniFFI surface for Android/iOS. Deliberately small (plan §2).
//!
//! `VerifiedUrl`, `Inbox` and the opener are **not** exported: nothing across
//! the FFI can mint a `VerifiedUrl`, and mobile apps never open network URLs on
//! their own (they show a "tap to open" notification).

use crate::limits::{MAX_PUSH_URL_BYTES, MAX_URL_BYTES};
use crate::reject::RejectReason;
use crate::url_policy::check_url;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ShareUrlError {
    #[error("no link found in the shared text")]
    NoUrl,
    #[error("link is longer than the size limit")]
    TooLong,
    #[error("only http and https links can be sent")]
    DisallowedScheme,
    #[error("links with a username or password can't be sent")]
    HasUserinfo,
    #[error("links to this device's own, link-local or unspecified addresses can't be sent")]
    LocalOnlyAddress,
}

/// Version of the Rust core, for the about screen.
#[uniffi::export]
pub fn core_version() -> String {
    crate::CORE_VERSION.to_owned()
}

#[uniffi::export]
pub fn max_url_bytes() -> u32 {
    MAX_URL_BYTES as u32
}

#[uniffi::export]
pub fn max_push_url_bytes() -> u32 {
    MAX_PUSH_URL_BYTES as u32
}

/// Pick the URL out of share-sheet text (apps often send "Title https://…")
/// and apply the receiver's allow-list. Sender-side only: returns the
/// canonical `String`, never a `VerifiedUrl`.
#[uniffi::export]
pub fn extract_shareable_url(shared_text: String) -> Result<String, ShareUrlError> {
    let trimmed = shared_text.trim();
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(ShareUrlError::NoUrl);
    }
    let mut first_err: Option<ShareUrlError> = None;
    for token in trimmed.split_whitespace() {
        let token = token.trim_matches(|c: char| {
            matches!(c, '<' | '>' | '"' | '\'' | '(' | ')' | ',' | '[' | ']')
        });
        let Some((scheme, rest)) = token.split_once(':') else {
            continue;
        };
        let valid_scheme = !scheme.is_empty()
            && scheme.as_bytes()[0].is_ascii_alphabetic()
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
        let looks_like_uri = rest.starts_with("//")
            || matches!(
                scheme.to_ascii_lowercase().as_str(),
                "javascript"
                    | "data"
                    | "file"
                    | "mailto"
                    | "intent"
                    | "tel"
                    | "sms"
                    | "blob"
                    | "vbscript"
                    | "about"
                    | "chrome"
                    | "content"
            );
        if !valid_scheme || rest.is_empty() || !looks_like_uri {
            continue;
        }
        match check_url(token) {
            Ok(u) => return Ok(u.as_str().to_owned()),
            Err(e) => {
                let mapped = match e {
                    RejectReason::UrlTooLong => Some(ShareUrlError::TooLong),
                    RejectReason::SchemeNotAllowed => Some(ShareUrlError::DisallowedScheme),
                    RejectReason::UrlHasUserinfo => Some(ShareUrlError::HasUserinfo),
                    RejectReason::HostLoopback
                    | RejectReason::HostLinkLocal
                    | RejectReason::HostUnspecified
                    | RejectReason::HostMulticast
                    | RejectReason::HostBroadcast
                    | RejectReason::HostSiteLocal => Some(ShareUrlError::LocalOnlyAddress),
                    _ => None,
                };
                if first_err.is_none() {
                    first_err = mapped;
                }
            }
        }
    }
    Err(first_err.unwrap_or(ShareUrlError::NoUrl))
}

/// Classified result of inspecting user-pasted or OS-shared text (`M3.1`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SharedContent {
    Url { url: String },
    ClipboardText { text: String, sensitive: bool },
}

/// Classify raw text as either a single valid `http`/`https` link (`SharedContent::Url`)
/// or UTF-8 clipboard text (`SharedContent::ClipboardText`, `M3.1`).
#[uniffi::export]
pub fn classify_shared_text(raw: String) -> Result<SharedContent, ShareUrlError> {
    match crate::clipboard::classify_shared_text(&raw) {
        Ok(crate::clipboard::SharedContentKind::Url { url }) => Ok(SharedContent::Url { url }),
        Ok(
            crate::clipboard::SharedContentKind::InlineClipboard {
                text,
                sensitive_hint: sensitive,
            }
            | crate::clipboard::SharedContentKind::StreamedClipboard {
                text,
                sensitive_hint: sensitive,
            },
        ) => Ok(SharedContent::ClipboardText { text, sensitive }),
        Err(RejectReason::UrlTooLong) => Err(ShareUrlError::TooLong),
        Err(RejectReason::SchemeNotAllowed) => Err(ShareUrlError::DisallowedScheme),
        Err(RejectReason::UrlHasUserinfo) => Err(ShareUrlError::HasUserinfo),
        Err(
            RejectReason::HostLoopback
            | RejectReason::HostLinkLocal
            | RejectReason::HostUnspecified
            | RejectReason::HostMulticast
            | RejectReason::HostBroadcast
            | RejectReason::HostSiteLocal,
        ) => Err(ShareUrlError::LocalOnlyAddress),
        Err(_) => Err(ShareUrlError::NoUrl),
    }
}

/// Heuristic check for single-line secrets (tokens, keys, passwords) to default-mask
/// clipboard previews in UI (`M3.1`).
#[uniffi::export]
pub fn looks_sensitive_clipboard(text: String) -> bool {
    crate::clipboard::looks_sensitive_clipboard(&text)
}

// ---- M1: the phone client --------------------------------------------------

use crate::net::phone::{PairedPc, PhoneClient, PhoneConfig};
use crate::net::{NetError, SendOutcome};
use std::sync::Arc;
use std::time::Duration;

/// Where the app keeps the phone's state blob. The Android app wraps it with
/// an AndroidKeyStore AES-GCM key before writing (StateStore.kt).
#[uniffi::export(with_foreign)]
pub trait StateStorage: Send + Sync {
    /// The saved blob, or `None` on first run.
    fn load(&self) -> Option<Vec<u8>>;
    /// Persist atomically; `false` if it couldn't.
    fn save(&self, data: Vec<u8>) -> bool;
}

struct ForeignStore(Arc<dyn StateStorage>);

impl crate::net::state::StateStore for ForeignStore {
    fn load(&self) -> Result<Option<Vec<u8>>, String> {
        Ok(self.0.load())
    }
    fn save(&self, data: &[u8]) -> Result<(), String> {
        // Crosses into the app's keystore wrapper; our copy is ours to wipe
        // only up to the FFI boundary.
        if self.0.save(data.to_vec()) {
            Ok(())
        } else {
            Err("couldn't save the app state".into())
        }
    }
}

/// Errors with a message fit for the UI (never contains the link).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PhoneError {
    /// The PC wasn't found or didn't answer (different Wi-Fi, PC asleep,
    /// firewall).
    #[error("{detail}")]
    Unreachable { detail: String },
    /// The PC (or this phone) refused; `code` is a stable label for reports.
    #[error("{detail}")]
    Refused { code: String, detail: String },
    /// The PC removed this phone ("Forget this device").
    #[error("This PC removed this phone. Pair again to send to it.")]
    Removed,
    #[error("Timed out.")]
    Timeout,
    #[error("Cancelled.")]
    Cancelled,
    #[error("{detail}")]
    Other { detail: String },
    /// `NativeInit.init(context)` wasn't called (or failed) before `Phone()`.
    /// An app bug, reported instead of the native abort (QA M1 re-check C1).
    #[error("Voidwire didn't start up properly (network layer not initialized). Close the app and open it again; if it keeps happening, please report it.")]
    NotInitialized,
}

fn refused(r: RejectReason) -> PhoneError {
    use RejectReason::*;
    let detail = match r {
        Removed => return PhoneError::Removed,
        NotInRoster => "This PC doesn't know this phone. Pair again.",
        PairingSecretExpired => "That QR code expired or was replaced. Show a new one on the PC.",
        PairingSecretUsed => "That QR code was already used. Show a new one on the PC.",
        PairingSecretUnknown => "That QR code isn't active on the PC. Show a new one.",
        PairingCancelled => "Pairing was cancelled on the PC.",
        SasRejected => "The code typed on the PC didn't match. Start again.",
        SasTimeout => "The code wasn't typed on the PC in time. Start again.",
        MalformedFrame => "This doesn't look like a Voidwire pairing QR code.",
        UnsupportedVersion => {
            "This pairing code needs a newer Voidwire. Update Voidwire on this phone to use it."
        }
        SchemeNotAllowed => "Only http and https links can be sent.",
        UrlTooLong => "This link is longer than the size limit.",
        UrlHasUserinfo => "Links with a username or password can't be sent.",
        HostLoopback | HostLinkLocal | HostUnspecified | HostMulticast | HostBroadcast
        | HostSiteLocal => "Links to local-only addresses can't be sent.",
        RateLimitedDevice | RateLimitedGlobal | RateLimitedPeer => {
            "Too many links in a short time. Wait a few seconds and try again."
        }
        StaleTimestamp | FutureTimestamp => {
            "The phone's and PC's clocks differ by more than 10 minutes. Fix the time and retry."
        }
        BadDeviceName => "Device names must be 1-64 characters, no control characters.",
        // L4: the PC's replay cache was missing or damaged at startup, so for
        // a while it only accepts links sent after it started.
        ReplayStartupGuard => {
            "The PC just restarted its replay protection, so it's refusing links sent before it started. Share the link again now; if it keeps happening, check the PC's clock or restart Voidwire on the PC."
        }
        Replay => "The PC already received this exact message. Share the link again.",
        GroupChangeNotConfirmed => {
            "Pairing stopped: the warning about this PC (different device group or duplicate name) wasn't confirmed."
        }
        SenderMismatch => {
            "This QR code doesn't match the PC that answered. Show a new one on the PC."
        }
        PairingLimitReached => {
            "This device already has 16 paired devices. Remove one before pairing another."
        }
        PairingCodeInvalid => "That code has a typo. Check it and type it again.",
        RelayLimitReached => {
            "This device already uses 4 relays (or has 8 saved). Remove one before pairing over another."
        }
        RelayNotAdded => "This pairing uses a relay you didn't add, so it stopped.",
        AlreadyPaired => "You're already paired with this device.",
        _ => "The PC refused this.",
    };
    PhoneError::Refused {
        code: r.label().to_owned(),
        detail: detail.to_owned(),
    }
}

/// M4.3: the v2 pairing screens talk about "the other device", not "the PC".
fn refused2(e: NetError) -> PhoneError {
    use RejectReason::*;
    let r = match e {
        NetError::Rejected(r) => r,
        other => return other.into(),
    };
    let detail = match r {
        PairingSecretExpired => {
            "That code expired or was replaced. Show a new one on the other device."
        }
        PairingSecretUsed => "That code was already used. Show a new one on the other device.",
        PairingSecretUnknown => {
            "That code isn't active. Check it, or show a new one on the other device."
        }
        PairingCancelled => "Pairing was cancelled on the other device.",
        SasRejected => "The 6-digit code didn't match. Start again.",
        SasTimeout => "The 6-digit code wasn't typed in time. Start again.",
        SenderMismatch => "This code doesn't match the device that answered. Show a new one.",
        PairingHmacBad => "Pairing stopped: the connection didn't check out. Start again.",
        FromSelf => "That's this device's own code. Use it on the other device.",
        _ => return refused(r),
    };
    PhoneError::Refused {
        code: r.label().to_owned(),
        detail: detail.to_owned(),
    }
}

/// M4.3: which pairing format a scanned QR uses (`"1"`, `"2"`, …), or
/// `None` when it isn't a Voidwire pairing QR. The app calls
/// `pair2_open_qr` for `"2"` and shows an update message for any other
/// version (v=1 QRs came from pre-0.8 PCs, which are not supported).
#[uniffi::export]
pub fn pairing_qr_version(qr: String) -> Option<String> {
    crate::net::pair2::qr_version(qr.trim())
}

/// M4.4: one row in Settings → Relays.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RelayRow {
    pub nickname: String,
    pub url: String,
    pub host: String,
    pub mailbox_id: String,
    pub home: bool,
    pub builtin: bool,
    pub used_by: u32,
    /// `connected`, `unreachable` or `idle`.
    pub status: String,
    /// Wall-clock ms the relay went down (0 when it isn't down).
    pub down_since_ms: u64,
    /// A `voidwire:relay?…` link to share this relay.
    pub link: String,
}

impl From<crate::net::relays::RelayInfo> for RelayRow {
    fn from(r: crate::net::relays::RelayInfo) -> Self {
        use crate::net::relays::RelayStatus as S;
        let (status, down_since_ms) = match r.status {
            S::Connected => ("connected", 0),
            S::Unreachable { since_ms } => ("unreachable", since_ms),
            S::Idle => ("idle", 0),
        };
        RelayRow {
            nickname: r.nickname,
            url: r.url,
            host: r.host,
            mailbox_id: r.mailbox_id,
            home: r.home,
            builtin: r.builtin,
            used_by: r.used_by,
            status: status.into(),
            down_since_ms,
            link: r.link,
        }
    }
}

/// M4.4: "<peer> wants to move your pairing to <host>. Allow?"
#[derive(Debug, Clone, uniffi::Record)]
pub struct RelayChangeAsk {
    pub peer_id: String,
    pub peer_name: String,
    pub host: String,
    pub url: String,
    pub new_relay: bool,
}

/// M4.4: where this device's own relay-change proposal stands.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RelayChangeInfo {
    pub peer_id: String,
    pub host: String,
    /// `waiting`, `declined`, `done` or `no_room`.
    pub state: String,
}

/// M4.4: the relay one pairing uses ("via <host>").
#[derive(Debug, Clone, uniffi::Record)]
pub struct PairingRelay {
    pub peer_id: String,
    /// `None`: this phone's home relay.
    pub url: Option<String>,
    pub host: String,
}

fn relay_err(e: crate::net::relays::RelayError) -> PhoneError {
    PhoneError::Other {
        detail: e.to_string(),
    }
}

pub(crate) fn relay_change_state(s: &crate::net::relay_change::RelayChangeState) -> &'static str {
    use crate::net::relay_change::RelayChangeState as S;
    match s {
        S::Waiting => "waiting",
        S::Declined => "declined",
        S::Done => "done",
        S::NoRoom => "no_room",
    }
}

/// A relay the user saved (for the relay picker).
#[derive(Debug, Clone, uniffi::Record)]
pub struct RelayChoice {
    pub nickname: String,
    pub url: String,
    pub home: bool,
    pub in_use: bool,
    pub builtin: bool,
}

impl From<crate::net::pair2::SavedRelay> for RelayChoice {
    fn from(r: crate::net::pair2::SavedRelay) -> Self {
        RelayChoice {
            nickname: r.nickname,
            url: r.url,
            home: r.home,
            in_use: r.in_use,
            builtin: r.builtin,
        }
    }
}

/// What to show while inviting: the `v=2` QR and the typed code.
#[derive(Clone, uniffi::Record)]
pub struct Pair2Show {
    pub qr: String,
    /// `None`: the relay couldn't be reached, so only the QR works.
    pub code: Option<String>,
    pub expires_at_ms: u64,
    pub relay_url: String,
    /// The code's full lifetime (for the countdown bar).
    pub ttl_ms: u64,
}

impl std::fmt::Debug for Pair2Show {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pair2Show(..)")
    }
}

impl From<crate::net::pair2::ShowInfo> for Pair2Show {
    fn from(s: crate::net::pair2::ShowInfo) -> Self {
        Pair2Show {
            qr: s.qr,
            code: s.code,
            expires_at_ms: s.expires_at.0,
            relay_url: s.relay_url,
            ttl_ms: crate::net::pair2::CODE_TTL_MS,
        }
    }
}

/// The inviting screen's state: `showing`, `awaiting_code` (type the code
/// `device_name` shows), `paired`, `failed` (`detail` says why) or `idle`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Pair2Status {
    pub state: String,
    pub expires_at_ms: Option<u64>,
    pub device_name: Option<String>,
    pub code: Option<String>,
    pub detail: Option<String>,
}

impl From<crate::net::pair2::HostStatus> for Pair2Status {
    fn from(h: crate::net::pair2::HostStatus) -> Self {
        use crate::net::pair2::HostStatus as H;
        let mut out = Pair2Status {
            state: String::new(),
            expires_at_ms: None,
            device_name: None,
            code: None,
            detail: None,
        };
        match h {
            H::Idle => out.state = "idle".into(),
            H::Showing { expires_at } => {
                out.state = "showing".into();
                out.expires_at_ms = Some(expires_at.0);
            }
            H::AwaitingCode { device_name } => {
                out.state = "awaiting_code".into();
                out.device_name = Some(device_name);
            }
            H::Paired { device_name } => {
                out.state = "paired".into();
                out.device_name = Some(device_name);
            }
            H::Failed { reason } => {
                out.state = "failed".into();
                if let PhoneError::Refused { code, detail } = refused2(NetError::Rejected(reason)) {
                    out.code = Some(code);
                    out.detail = Some(detail);
                }
            }
        }
        out
    }
}

/// An opened invite (QR or typed code), before connecting.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Pair2Opened {
    pub inviter_name: Option<String>,
    pub relay_url: String,
    /// `saved`, `ask` ("This pairing uses <relay_host>. Add it?" with
    /// [Add and pair] [Cancel]) or `full` ([Cancel] only).
    pub relay_state: String,
    pub relay_host: Option<String>,
}

impl From<crate::net::pair2::Opened> for Pair2Opened {
    fn from(o: crate::net::pair2::Opened) -> Self {
        use crate::net::pair2::RelayCheck as R;
        let (relay_state, relay_host) = match o.relay {
            R::Saved => ("saved", None),
            R::Ask { host } => ("ask", Some(host)),
            R::Full { host } => ("full", Some(host)),
        };
        Pair2Opened {
            inviter_name: o.inviter_name,
            relay_url: o.relay_url,
            relay_state: relay_state.into(),
            relay_host,
        }
    }
}

/// A finished v2 pairing.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Pair2Done {
    pub device_id: String,
    pub name: String,
    /// It was already paired: the old pairing was replaced (one entry).
    pub refreshed: bool,
}

/// Errors from a file transfer. Never the pairing texts: an "unknown
/// frame" answer used to read "This doesn't look like a Voidwire pairing
/// QR code" after Accept (v0.7.1).
fn file_error(e: NetError) -> PhoneError {
    match e {
        NetError::Rejected(r @ (RejectReason::MalformedFrame | RejectReason::UnsupportedVersion)) => {
            PhoneError::Refused {
                code: r.label().to_owned(),
                detail: "The other device can't send this file this way. Update Voidwire on both devices and send it again.".into(),
            }
        }
        NetError::Unreachable(_) => PhoneError::Unreachable {
            detail: "Couldn't reach the other device. Check that Voidwire is open on it and both devices have a connection.".into(),
        },
        NetError::Timeout => PhoneError::Other {
            detail: "The transfer stopped: nothing arrived for a while. Ask the sender to send it again.".into(),
        },
        other => other.into(),
    }
}

impl From<NetError> for PhoneError {
    fn from(e: NetError) -> Self {
        match e {
            NetError::Rejected(r) => refused(r),
            NetError::Unreachable(_) => PhoneError::Unreachable {
                detail: "Couldn't reach the PC. Check that the PC app is running and both devices have a connection.".into(),
            },
            NetError::Timeout => PhoneError::Timeout,
            NetError::Cancelled => PhoneError::Cancelled,
            NetError::UnknownDevice => PhoneError::Other {
                detail: "That PC isn't paired with this phone.".into(),
            },
            NetError::Storage(m) | NetError::Protocol(m) => PhoneError::Other { detail: m },
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PcInfo {
    /// Hex device id (stable handle for `send_url` / `forget_pc`).
    pub id: String,
    pub name: String,
    /// The PC removed this phone.
    pub removed: bool,
}

impl From<PairedPc> for PcInfo {
    fn from(p: PairedPc) -> Self {
        PcInfo {
            id: p.id.to_hex(),
            name: p.name,
            removed: p.removed,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SendResult {
    /// Opened right away (no-prompt, the PC's default).
    pub opened: bool,
    /// Waiting for a click on the PC ("Ask before opening" is on).
    pub prompted: bool,
    pub latency_us: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FileSendResult {
    pub transfer_id_hex: String,
    pub filename: String,
    pub size: u64,
    pub chunks_sent: u64,
    pub resumed_from_chunk: u64,
    pub relayed: bool,
    pub latency_us: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ConnectionStatRecord {
    pub peer_id_hex: String,
    pub day_utc: u64,
    pub direct_count: u32,
    pub relay_count: u32,
    pub direct_bytes: u64,
    pub relay_bytes: u64,
    pub prompts_shown: u32,
    pub prompts_accepted: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IncomingLinkItem {
    pub id: u64,
    pub pc_id: String,
    pub pc_name: String,
    pub url: String,
    pub host: String,
    pub received_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IncomingClipboardItem {
    pub id: u64,
    pub pc_id: String,
    pub pc_name: String,
    pub text: String,
    pub sensitive: bool,
    pub received_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IncomingFileOfferItem {
    pub transfer_id: String,
    pub pc_id: String,
    pub pc_name: String,
    pub filename: String,
    pub size_bytes: u64,
    pub bytes_received: u64,
    pub is_executable: bool,
    pub relayed: bool,
    pub accepted: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct IncomingSnapshot {
    pub links: Vec<IncomingLinkItem>,
    pub clipboards: Vec<IncomingClipboardItem>,
    pub files: Vec<IncomingFileOfferItem>,
}

fn pc_id(hex: &str) -> Result<crate::ids::DeviceId, PhoneError> {
    crate::ids::DeviceId::from_hex(hex).ok_or(PhoneError::Other {
        detail: "bad PC id".into(),
    })
}

/// The phone: pairing, paired PCs, sending. Blocking calls; call them off
/// the main thread.
type PendingTransferMap = std::sync::Mutex<
    std::collections::HashMap<(crate::ids::DeviceId, String), crate::file_transfer::TransferId>,
>;

#[derive(uniffi::Object)]
pub struct Phone {
    client: PhoneClient,
    pending_transfers: PendingTransferMap,
}

#[uniffi::export]
impl Phone {
    #[uniffi::constructor]
    pub fn new(
        storage: Arc<dyn StateStorage>,
        default_name: String,
    ) -> Result<Arc<Phone>, PhoneError> {
        // C1: on Android the endpoint needs the JNI context (iroh's DNS
        // resolver). Refuse with an error instead of reaching the abort.
        if !crate::platform_init::is_ready() {
            return Err(PhoneError::NotInitialized);
        }
        Phone::build(storage, default_name, true)
    }

    #[uniffi::constructor]
    pub fn open(
        storage: Arc<dyn StateStorage>,
        default_name: String,
        data_dir: String,
    ) -> Result<Arc<Phone>, PhoneError> {
        if !crate::platform_init::is_ready() {
            return Err(PhoneError::NotInitialized);
        }
        let phone = Phone::build(storage, default_name, true)?;
        phone.set_data_dir(data_dir);
        Ok(phone)
    }

    pub fn set_data_dir(&self, data_dir: String) {
        if !data_dir.trim().is_empty() {
            self.client
                .set_data_dir(std::path::PathBuf::from(data_dir.trim()));
        }
    }

    pub fn device_name(&self) -> String {
        self.client.device_name()
    }

    /// Name shown on PCs paired from now on.
    pub fn set_device_name(&self, name: String) -> Result<(), PhoneError> {
        Ok(self.client.set_device_name(&name)?)
    }

    pub fn paired_pcs(&self) -> Vec<PcInfo> {
        self.client
            .paired_pcs()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// M4.4: Settings → Relays.
    pub fn relays(&self) -> Vec<RelayRow> {
        self.client.relays().into_iter().map(Into::into).collect()
    }

    pub fn add_relay_link(&self, link: String) -> Result<(), PhoneError> {
        self.client.add_relay_link(&link).map_err(relay_err)
    }

    pub fn add_relay(
        &self,
        url: String,
        mailbox_id: String,
        nickname: String,
    ) -> Result<(), PhoneError> {
        self.client
            .add_relay(&url, &mailbox_id, &nickname)
            .map_err(relay_err)
    }

    pub fn remove_relay(&self, url: String) -> Result<(), PhoneError> {
        self.client.remove_relay(&url).map_err(relay_err)
    }

    pub fn rename_relay(&self, url: String, nickname: String) -> Result<(), PhoneError> {
        self.client.rename_relay(&url, &nickname).map_err(relay_err)
    }

    pub fn retry_relay(&self, url: String) {
        self.client.retry_relay(&url)
    }

    /// The relay each pairing uses.
    pub fn pairing_relays(&self) -> Vec<PairingRelay> {
        let home = self.client.relay_url();
        self.client
            .pairings()
            .into_iter()
            .map(|p| {
                let host = p
                    .relay_url
                    .as_deref()
                    .or(home.as_deref())
                    .map(crate::net::pair2::relay_host)
                    .unwrap_or_default();
                PairingRelay {
                    peer_id: p.peer.to_hex(),
                    url: p.relay_url,
                    host,
                }
            })
            .collect()
    }

    /// Ask the other device to move this pairing to the saved relay `url`.
    /// Blocking (a live exchange; both devices must be online).
    pub fn change_pairing_relay(&self, peer_id: String, url: String) -> Result<(), PhoneError> {
        self.client
            .change_pairing_relay(&pc_id(&peer_id)?, &url)
            .map_err(relay_err)
    }

    pub fn relay_change_requests(&self) -> Vec<RelayChangeAsk> {
        self.client
            .relay_change_requests()
            .into_iter()
            .map(|r| RelayChangeAsk {
                peer_id: r.peer.to_hex(),
                peer_name: r.peer_name,
                host: r.host,
                url: r.url,
                new_relay: r.new_relay,
            })
            .collect()
    }

    pub fn relay_change_statuses(&self) -> Vec<RelayChangeInfo> {
        self.client
            .relay_change_statuses()
            .into_iter()
            .map(|s| RelayChangeInfo {
                peer_id: s.peer.to_hex(),
                host: s.host,
                state: relay_change_state(&s.state).into(),
            })
            .collect()
    }

    /// Allow or decline a request. Blocking.
    pub fn answer_relay_change(&self, peer_id: String, allow: bool) -> Result<(), PhoneError> {
        self.client
            .answer_relay_change(&pc_id(&peer_id)?, allow)
            .map_err(relay_err)
    }

    /// M4.3: saved relays for the relay picker.
    pub fn saved_relays(&self) -> Vec<RelayChoice> {
        self.client
            .saved_relays()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// M4.3: show a `v=2` QR and code (the app asks for the screen lock
    /// first). `relay_url`: a saved relay, or `None` for this phone's.
    pub fn pair2_show(&self, relay_url: Option<String>) -> Result<Pair2Show, PhoneError> {
        self.client
            .pair2_show(relay_url.as_deref())
            .map(Into::into)
            .map_err(refused2)
    }

    pub fn pair2_status(&self) -> Pair2Status {
        self.client.pair2_status().into()
    }

    /// The user typed the 6-digit code the joining device shows.
    pub fn pair2_submit_code(&self, sas: String) -> Result<Pair2Done, PhoneError> {
        self.client
            .pair2_submit_code(&sas)
            .map(|d| Pair2Done {
                device_id: d.peer.to_hex(),
                name: d.name,
                refreshed: d.refreshed,
            })
            .map_err(refused2)
    }

    /// Leave the pairing screen: a showing code stops working.
    pub fn pair2_cancel(&self) {
        self.client.pair2_cancel()
    }

    /// Open a typed `VW-…` code (a typo is refused here, before any network).
    pub fn pair2_open_code(
        &self,
        code: String,
        relay_url: Option<String>,
    ) -> Result<Pair2Opened, PhoneError> {
        self.client
            .pair2_open_code(&code, relay_url.as_deref())
            .map(Into::into)
            .map_err(refused2)
    }

    /// Open a scanned `v=2` QR (see `pairing_qr_version`).
    pub fn pair2_open_qr(&self, qr: String) -> Result<Pair2Opened, PhoneError> {
        self.client
            .pair2_open_qr(qr.trim())
            .map(Into::into)
            .map_err(refused2)
    }

    /// The user chose [Add and pair] for the opened invite's relay.
    pub fn pair2_add_relay(&self) -> Result<(), PhoneError> {
        self.client.pair2_add_relay().map_err(refused2)
    }

    /// Connect to the inviter; returns the 6-digit code to show.
    pub fn pair2_join(&self) -> Result<String, PhoneError> {
        self.client.pair2_join().map_err(refused2)
    }

    /// Wait until the inviter's user typed our code (blocking; run off the
    /// main thread).
    pub fn pair2_join_wait(&self) -> Result<Pair2Done, PhoneError> {
        self.client
            .pair2_join_wait()
            .map(|d| Pair2Done {
                device_id: d.peer.to_hex(),
                name: d.name,
                refreshed: d.refreshed,
            })
            .map_err(refused2)
    }

    /// Send a link (already extracted with `extract_shareable_url`).
    pub fn send_url(&self, pc_id_hex: String, url: String) -> Result<SendResult, PhoneError> {
        let r = self.client.send_url(&pc_id(&pc_id_hex)?, &url)?;
        Ok(SendResult {
            opened: r.outcome == SendOutcome::Opened,
            prompted: r.outcome == SendOutcome::Prompted,
            latency_us: r.latency_us,
        })
    }

    /// Check with the PC (learns if it removed us). Returns `true` if still paired.
    pub fn refresh(&self, pc_id_hex: String) -> Result<bool, PhoneError> {
        Ok(self.client.sync(&pc_id(&pc_id_hex)?)? == crate::grouplog::Membership::Member)
    }

    /// Remove a PC from this phone (local).
    pub fn forget_pc(&self, pc_id_hex: String) -> Result<(), PhoneError> {
        self.client.forget_pc(&pc_id(&pc_id_hex)?)?;
        Ok(())
    }

    /// Configure the blind mailbox service `DeviceId` (64-char hex),
    /// `Some("off")` / `Some("none")` to disable, or `None` to use the
    /// default (`DEFAULT_MAILBOX_ID`, `M2-H1`).
    pub fn set_mailbox_peer(&self, peer_hex: Option<String>) -> Result<(), PhoneError> {
        let parsed = crate::net::mailbox_client::parse_mailbox_peer_opt(peer_hex.as_deref())
            .map_err(refused)?;
        self.client.set_mailbox_peer(parsed);
        Ok(())
    }

    /// Send a file from a local path to a paired PC (`M2.6`).
    /// `relay_decision`: `None` (default), `Some("send")` / `Some("send_via_relay")`,
    /// `Some("wait")`, or `Some("cancel")`.
    pub fn send_file(
        &self,
        pc_id_hex: String,
        file_path: String,
        mime: String,
        relay_decision: Option<String>,
    ) -> Result<FileSendResult, PhoneError> {
        let decision = match relay_decision.as_deref() {
            Some("send") | Some("send_via_relay") => {
                Some(crate::file_transfer::RelayPromptDecision::SendViaRelay)
            }
            Some("wait") => Some(crate::file_transfer::RelayPromptDecision::WaitForDirect),
            Some("cancel") => Some(crate::file_transfer::RelayPromptDecision::Cancel),
            None | Some("") => None,
            Some(other) => {
                return Err(PhoneError::Other {
                    detail: format!("unknown relay_decision: {other}"),
                })
            }
        };
        let pc = pc_id(&pc_id_hex)?;
        let key = (pc, file_path.clone());
        if matches!(
            decision,
            Some(crate::file_transfer::RelayPromptDecision::Cancel)
        ) {
            if let Some(tid) = self
                .pending_transfers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key)
            {
                let _ = self.client.cancel_file_transfer(&pc, &tid);
            }
            return Err(PhoneError::Cancelled);
        }
        let tid = {
            let mut map = self
                .pending_transfers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *map.entry(key.clone())
                .or_insert_with(crate::file_transfer::TransferId::random)
        };
        let path = std::path::Path::new(&file_path);
        match self.client.send_file_awaiting_accept(
            &pc,
            tid,
            path,
            &mime,
            decision,
            150,
            Duration::from_millis(400),
        ) {
            Ok(r) => {
                self.pending_transfers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&key);
                Ok(FileSendResult {
                    transfer_id_hex: r.transfer_id.to_hex(),
                    filename: r.filename,
                    size: r.size,
                    chunks_sent: r.chunks_sent,
                    resumed_from_chunk: r.resumed_from_chunk,
                    relayed: r.path_kind == crate::file_transfer::TransportPathKind::Relayed,
                    latency_us: r.latency_us,
                })
            }
            Err(NetError::Protocol(ref msg)) if msg.starts_with("relay_prompt_required") => {
                Err(NetError::Protocol(msg.clone()).into())
            }
            Err(e) => {
                self.pending_transfers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&key);
                Err(file_error(e))
            }
        }
    }

    /// Cancel an in-progress file transfer (`M2.6`).
    pub fn cancel_file_transfer(
        &self,
        pc_id_hex: String,
        transfer_id_hex: String,
    ) -> Result<(), PhoneError> {
        let tid =
            crate::file_transfer::TransferId::from_hex(&transfer_id_hex).ok_or_else(|| {
                PhoneError::Other {
                    detail: "bad transfer id".into(),
                }
            })?;
        self.client
            .cancel_file_transfer(&pc_id(&pc_id_hex)?, &tid)?;
        Ok(())
    }

    /// Effective relay file-transfer cap in bytes (`min(server_cap, user_cap)`, `M2.6` §6a.1 & §6b).
    pub fn relay_file_cap_bytes(&self) -> u64 {
        self.client.relay_policy().user_cap_bytes()
    }

    /// Set the user's local relay file size cap (`0..=MAX_FILE_SIZE`, `M2.6` §6a.1).
    pub fn set_user_relay_cap_bytes(&self, cap_bytes: u64) -> Result<(), PhoneError> {
        self.client.set_user_relay_cap_bytes(cap_bytes)?;
        Ok(())
    }

    /// Whether "Never send files over relay" is enabled (`false` by default, `M2.8`).
    pub fn never_send_files_over_relay(&self) -> bool {
        self.client.never_send_files_over_relay()
    }

    /// Enable or disable "Never send files over relay" (`M2.8`).
    pub fn set_never_send_files_over_relay(&self, never: bool) -> Result<(), PhoneError> {
        self.client.set_never_send_files_over_relay(never)?;
        Ok(())
    }

    /// Currently configured relay server URL (`None` if disabled, defaults to `DEFAULT_RELAY_URL`, `M2.8`).
    pub fn relay_url(&self) -> Option<String> {
        self.client.relay_url()
    }

    /// Set or reset the relay server URL (`None` or empty string resets to `DEFAULT_RELAY_URL`; `"off"` disables, `M2.8`).
    pub fn set_relay_url(&self, relay_url: Option<String>) -> Result<(), PhoneError> {
        self.client.set_relay_url(relay_url)?;
        Ok(())
    }

    /// Currently configured blind mailbox endpoint ID (64-char hex, `M2.8`).
    pub fn mailbox_id(&self) -> Option<String> {
        self.client.mailbox_id().map(|id| id.to_hex())
    }

    /// Set or reset the blind mailbox endpoint ID (`None` or empty string resets to `DEFAULT_MAILBOX_ID`; `"off"` disables, `M2.8`).
    pub fn set_mailbox_id(&self, peer_hex: Option<String>) -> Result<(), PhoneError> {
        let parsed = crate::net::mailbox_client::parse_mailbox_peer_opt(peer_hex.as_deref())
            .map_err(refused)?;
        self.client.set_mailbox_id(parsed)?;
        Ok(())
    }

    /// Whether optional on-device connection stats are enabled (`false` by default, `M2.6` §6a.3).
    pub fn connection_stats_enabled(&self) -> bool {
        self.client.connection_stats_enabled()
    }

    /// Enable or disable on-device connection stats. Disabling immediately deletes
    /// all saved stats (`M2.6` §6a.3).
    pub fn set_connection_stats_enabled(&self, enabled: bool) -> Result<(), PhoneError> {
        self.client.set_connection_stats_enabled(enabled)?;
        Ok(())
    }

    /// Read on-device day-granularity connection stats (`M2.6` §6a.3).
    pub fn connection_stats(&self) -> Vec<ConnectionStatRecord> {
        self.client
            .connection_stats()
            .into_iter()
            .map(|(peer, e)| ConnectionStatRecord {
                peer_id_hex: peer.to_hex(),
                day_utc: e.day as u64,
                direct_count: e.direct_count as u32,
                relay_count: e.relay_count as u32,
                direct_bytes: e.direct_bytes,
                relay_bytes: e.relay_bytes,
                prompts_shown: e.prompts_shown as u32,
                prompts_accepted: e.prompts_accepted as u32,
            })
            .collect()
    }

    /// Send UTF-8 clipboard text to a paired PC (`M3.1`).
    pub fn send_clipboard_text(
        &self,
        pc_id_hex: String,
        text: String,
    ) -> Result<SendResult, PhoneError> {
        let r = self
            .client
            .send_clipboard_text(&pc_id(&pc_id_hex)?, &text)?;
        Ok(SendResult {
            opened: r.outcome == SendOutcome::Opened,
            prompted: r.outcome == SendOutcome::Prompted,
            latency_us: r.latency_us,
        })
    }

    /// Auto-detect link vs. clipboard text and send to a paired PC (`M3.1`).
    pub fn send_text_or_url(
        &self,
        pc_id_hex: String,
        raw_text: String,
    ) -> Result<SendResult, PhoneError> {
        let r = self
            .client
            .send_text_or_url(&pc_id(&pc_id_hex)?, &raw_text)?;
        Ok(SendResult {
            opened: r.outcome == SendOutcome::Opened,
            prompted: r.outcome == SendOutcome::Prompted,
            latency_us: r.latency_us,
        })
    }

    /// Snapshot of waiting incoming links, clipboards, and file offers from paired PCs (`M3.1`).
    pub fn poll_incoming(&self) -> Result<IncomingSnapshot, PhoneError> {
        let batch = self.client.poll_incoming();
        let mut links = Vec::new();
        let mut clipboards = Vec::new();
        for item in batch.items {
            match item.kind {
                crate::net::phone::IncomingItemKind::Url => {
                    links.push(IncomingLinkItem {
                        id: item.item_id,
                        pc_id: item.sender_id.to_hex(),
                        pc_name: item.sender_name,
                        host: item.host_display.unwrap_or_default(),
                        url: item.payload_text,
                        received_at_ms: item.received_at.0,
                    });
                }
                crate::net::phone::IncomingItemKind::ClipboardText => {
                    clipboards.push(IncomingClipboardItem {
                        id: item.item_id,
                        pc_id: item.sender_id.to_hex(),
                        pc_name: item.sender_name,
                        text: item.payload_text,
                        sensitive: item.sensitive_hint,
                        received_at_ms: item.received_at.0,
                    });
                }
            }
        }
        let files = batch
            .files
            .into_iter()
            .filter(|f| f.completed_path.is_none())
            .map(|f| {
                let bytes_received =
                    (f.chunks_received * crate::file_transfer::FILE_CHUNK_SIZE as u64).min(f.size);
                IncomingFileOfferItem {
                    transfer_id: f.transfer_id.to_hex(),
                    pc_id: f.sender_id.to_hex(),
                    pc_name: f.sender_name,
                    filename: f.filename,
                    size_bytes: f.size,
                    bytes_received,
                    is_executable: f.is_executable,
                    relayed: f.relayed,
                    accepted: f.accepted,
                }
            })
            .collect();
        Ok(IncomingSnapshot {
            links,
            clipboards,
            files,
        })
    }

    /// Explicitly pull the RAM-only blind device inbox across all paired PCs (`M3.1`).
    pub fn pull_device_inbox_now(&self) -> Result<u32, PhoneError> {
        let n = self.client.pull_device_inbox_now()?;
        Ok(n as u32)
    }

    /// Dismiss a received link or clipboard item by `id` (`M3.1`).
    pub fn dismiss_incoming_item(&self, id: u64) -> Result<(), PhoneError> {
        let _ = self.client.dismiss_incoming_item(id);
        Ok(())
    }

    /// Accept an incoming file offer and stream/save it into `dest_dir`, returning
    /// the finalized file path (`M3.1`).
    pub fn accept_incoming_file(
        &self,
        transfer_id: String,
        dest_dir: String,
    ) -> Result<String, PhoneError> {
        let tid = crate::file_transfer::TransferId::from_hex(&transfer_id).ok_or_else(|| {
            PhoneError::Other {
                detail: "bad transfer id".into(),
            }
        })?;
        let dir = std::path::Path::new(&dest_dir);
        let path = self
            .client
            .accept_incoming_file(
                &tid,
                Some(dir),
                Some(crate::file_transfer::RelayPromptDecision::SendViaRelay),
            )
            .map_err(file_error)?;
        Ok(path.to_string_lossy().into_owned())
    }

    /// Decline or cancel an incoming file offer (`M3.1`).
    pub fn cancel_incoming_file(&self, transfer_id: String) -> Result<(), PhoneError> {
        let tid = crate::file_transfer::TransferId::from_hex(&transfer_id).ok_or_else(|| {
            PhoneError::Other {
                detail: "bad transfer id".into(),
            }
        })?;
        let _ = self.client.cancel_incoming_file(&tid);
        Ok(())
    }

    /// Enable or disable background receive mode (`M3.1`).
    pub fn set_background_listening(&self, enabled: bool) -> Result<(), PhoneError> {
        self.client.set_background_listening(enabled)?;
        Ok(())
    }

    /// The app UI opened or closed (`M4.1` relay supervisor). Non-blocking.
    pub fn set_app_foreground(&self, foreground: bool) {
        self.client.set_app_foreground(foreground);
    }

    /// The OS reported a network change (`M4.1`). Non-blocking.
    pub fn network_changed(&self) {
        self.client.network_changed();
    }

    /// Event-driven inbox pull, at most every 5 minutes per relay unless
    /// `force` (app open) (`M4.1`).
    pub fn pull_device_inbox_on_event(&self, force: bool) -> Result<u32, PhoneError> {
        let n = self.client.pull_device_inbox_on_event(force)?;
        Ok(n as u32)
    }
}

impl Phone {
    fn build(
        storage: Arc<dyn StateStorage>,
        default_name: String,
        mdns: bool,
    ) -> Result<Arc<Phone>, PhoneError> {
        let client = PhoneClient::new(PhoneConfig {
            state: Arc::new(ForeignStore(storage)),
            default_name,
            platform: crate::keys::Platform::current(),
            mdns,
        })?;
        Ok(Arc::new(Phone {
            client,
            pending_transfers: std::sync::Mutex::new(std::collections::HashMap::new()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v0.7.1: a file that fails with an unknown-frame reply must not say
    /// "This doesn't look like a Voidwire pairing QR code".
    #[test]
    fn file_errors_never_talk_about_pairing_qr_codes() {
        let detail = |e: PhoneError| match e {
            PhoneError::Refused { detail, .. }
            | PhoneError::Unreachable { detail }
            | PhoneError::Other { detail } => detail,
            other => format!("{other:?}"),
        };
        for e in [
            NetError::Rejected(RejectReason::MalformedFrame),
            NetError::Rejected(RejectReason::UnsupportedVersion),
            NetError::Unreachable("x".into()),
            NetError::Timeout,
        ] {
            let d = detail(file_error(e));
            assert!(!d.to_lowercase().contains("qr"), "{d}");
            assert!(!d.to_lowercase().contains("pair"), "{d}");
        }
        // Pairing keeps its own wording.
        let d = detail(NetError::Rejected(RejectReason::MalformedFrame).into());
        assert!(d.contains("pairing QR"), "{d}");
    }

    #[test]
    fn qr_version_dispatch_and_update_message() {
        assert_eq!(
            pairing_qr_version("voidwire:pair?v=1&x=y".into()).as_deref(),
            Some("1")
        );
        assert_eq!(
            pairing_qr_version(" voidwire:pair?v=2&id=a ".into()).as_deref(),
            Some("2")
        );
        assert_eq!(pairing_qr_version("https://example.com".into()), None);
        match refused(RejectReason::UnsupportedVersion) {
            PhoneError::Refused { detail, .. } => {
                assert!(detail.contains("Update Voidwire on this phone"))
            }
            other => panic!("{other:?}"),
        }
        match refused2(NetError::Rejected(RejectReason::PairingCodeInvalid)) {
            PhoneError::Refused { code, .. } => assert_eq!(code, "pairing_code_invalid"),
            other => panic!("{other:?}"),
        }
    }
    #[test]
    fn extracts_from_share_text() {
        assert_eq!(
            extract_shareable_url("Look at this https://example.com/a?b=1 cool".into()).unwrap(),
            "https://example.com/a?b=1"
        );
        assert_eq!(
            extract_shareable_url("(https://example.com)".into()).unwrap(),
            "https://example.com/"
        );
        assert!(matches!(
            extract_shareable_url("hello".into()),
            Err(ShareUrlError::NoUrl)
        ));
        assert!(matches!(
            extract_shareable_url("javascript:alert(1)".into()),
            Err(ShareUrlError::DisallowedScheme)
        ));
        assert!(matches!(
            extract_shareable_url("see http://localhost:3000/".into()),
            Err(ShareUrlError::LocalOnlyAddress)
        ));
        let long = format!("https://x.example/{}", "a".repeat(MAX_URL_BYTES));
        assert!(matches!(
            extract_shareable_url(long),
            Err(ShareUrlError::TooLong)
        ));
    }

    /// L4: the replay-guard refusal has its own message for the phone.
    #[test]
    fn replay_guard_refusal_has_a_specific_message() {
        match refused(RejectReason::ReplayStartupGuard) {
            PhoneError::Refused { code, detail } => {
                assert_eq!(code, "replay_startup_guard");
                assert!(
                    detail.contains("restarted its replay protection"),
                    "{detail}"
                );
            }
            e => panic!("{e:?}"),
        }
        match refused(RejectReason::Replay) {
            PhoneError::Refused { detail, .. } => assert_ne!(detail, "The PC refused this."),
            e => panic!("{e:?}"),
        }
    }

    /// C1: `Phone()` before `NativeInit.init` is an error, never an abort.
    /// (No test in this binary calls the JNI init, so the flag stays unset.)
    #[test]
    fn phone_without_platform_init_is_an_error() {
        struct Nothing;
        impl StateStorage for Nothing {
            fn load(&self) -> Option<Vec<u8>> {
                None
            }
            fn save(&self, _: Vec<u8>) -> bool {
                true
            }
        }
        assert!(!crate::platform_init::is_ready());
        match Phone::new(Arc::new(Nothing), "No init".into()) {
            Err(PhoneError::NotInitialized) => {}
            Err(e) => panic!("wrong error: {e:?}"),
            Ok(_) => panic!("Phone built without platform init"),
        }
    }

    /// The exported phone object keeps its state through the foreign-storage
    /// callback. (Pairing over the FFI is covered by android-qa against a
    /// real PC peer, and in core by the mailbox crate's v2 tests.)
    #[test]
    fn phone_object_reloads_from_foreign_storage() {
        use std::sync::Mutex;

        #[derive(Default)]
        struct Mem(Mutex<Option<Vec<u8>>>);
        impl StateStorage for Mem {
            fn load(&self) -> Option<Vec<u8>> {
                self.0.lock().unwrap().clone()
            }
            fn save(&self, data: Vec<u8>) -> bool {
                *self.0.lock().unwrap() = Some(data);
                true
            }
        }

        let store = Arc::new(Mem::default());
        let phone = Phone::build(store.clone(), "FFI Phone".into(), false).unwrap();
        assert!(phone.paired_pcs().is_empty());
        let id = phone.client.device_id();
        phone.set_device_name("Renamed Phone".into()).unwrap();
        drop(phone);

        let phone = Phone::build(store, "ignored".into(), false).unwrap();
        assert_eq!(phone.device_name(), "Renamed Phone");
        assert_eq!(phone.client.device_id(), id);
        assert!(phone.paired_pcs().is_empty());
    }
}
