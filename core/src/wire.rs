#![forbid(unsafe_code)]
//! Canonical, signed message body (the plaintext inside the envelope).
//! Spec: docs/PROTOCOL.md §4 and M3.1 §2.2. All integers big-endian.
//!
//! ```text
//! magic      4   'V' 'W' version(=1) kind(0=Url, 1=ClipboardText, 2=FileWake, 3=PairNotice)
//! group      32
//! sender     32  Ed25519 public key (DeviceId)
//! recipient  32
//! log_head   32  sender's group-log head
//! msg_id     16
//! timestamp  8   unix millis (wall clock)
//! payload    var kind-specific payload (Url / ClipboardText / FileWake)
//! signature  64  Ed25519 over DOMAIN_TAG_MESSAGE || all preceding bytes
//! ```
//!
//! Decoding is strict: exact lengths, no trailing bytes, UTF-8 required,
//! unknown kind or reserved flag bits rejected, no panics on any input.

use crate::clipboard::FLAG_SENSITIVE_HINT;
use crate::file_transfer::{
    is_executable_filename, sanitize_filename, MAX_FILENAME_BYTES, MAX_FILE_SIZE,
};
use crate::ids::{DeviceId, GroupId, LogHead, MsgId};
use crate::keys::DeviceKeypair;
use crate::limits::{MAX_INLINE_CLIPBOARD_BYTES, MAX_URL_BYTES};
use crate::reject::RejectReason;
use crate::time::UnixMillis;
use ed25519_dalek::Signature;
use std::fmt;

pub const VERSION: u8 = crate::protocol::PROTOCOL_VERSION;
pub const KIND_URL: u8 = 0x00;
pub const KIND_CLIPBOARD: u8 = 0x01;
pub const KIND_FILE_WAKE: u8 = 0x02;
/// M4.2: a signed pairing-log op for the recipient (an Unpair notice). Only
/// sent on v2 pairings; a v0.4.x receiver refuses the unknown kind.
pub const KIND_PAIR_NOTICE: u8 = 0x03;
/// Largest pairing-log op a notice may carry.
pub const MAX_PAIR_NOTICE_BYTES: usize = 1024;

pub const MAGIC: [u8; 4] = [b'V', b'W', VERSION, KIND_URL];
pub const MAGIC_CLIPBOARD: [u8; 4] = [b'V', b'W', VERSION, KIND_CLIPBOARD];
pub const MAGIC_FILE_WAKE: [u8; 4] = [b'V', b'W', VERSION, KIND_FILE_WAKE];
pub const MAGIC_PAIR_NOTICE: [u8; 4] = [b'V', b'W', VERSION, KIND_PAIR_NOTICE];

/// Domain separation for message signatures.
pub const DOMAIN_TAG_MESSAGE: &[u8] = b"voidwire/v1/message\0";

/// Common fixed header before the kind-specific payload (`4 + 32*4 + 16 + 8 = 156` bytes).
pub const COMMON_HEADER_LEN: usize = 4 + 32 + 32 + 32 + 32 + 16 + 8;
/// URL message header length including the 2-byte `url_len` (`158` bytes).
pub const HEADER_LEN: usize = COMMON_HEADER_LEN + 2;
pub const SIG_LEN: usize = 64;
/// Largest body we will even try to parse.
pub const MAX_BODY_LEN: usize = HEADER_LEN + MAX_URL_BYTES + SIG_LEN;

/// Flag bit 0 (`0x01`) on `MessageKind::FileWake`: marks an executable/installable file.
pub const FLAG_FILE_EXECUTABLE: u8 = 0x01;

/// Payload of a `MessageKind::FileWake` envelope deposited in a phone's blind RAM inbox
/// when the PC offers a file while the phone is offline (`M3-PLAN.md` §1.5 & §2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileWakePayload {
    pub transfer_id: [u8; 16],
    pub size_bytes: u64,
    pub expires_at: UnixMillis,
    pub filename: String,
    pub is_executable: bool,
}

/// Discriminated inner payload of a signed Voidwire wire message (`M3-PLAN.md` §2.2).
#[derive(Clone, PartialEq, Eq)]
pub enum MessageKind {
    /// `0x00`: URL payload (`u16 BE url_len || url_utf8`).
    Url(String),
    /// `0x01`: Inline clipboard text (`u8 flags || u16 BE text_len || text_utf8`).
    ClipboardText { text: String, sensitive: bool },
    /// `0x02`: Offline file-offer wake pointer (`transfer_id || size || expires || flags || name`).
    FileWake(FileWakePayload),
    /// `0x03`: an encoded pairing-log op (`u16 BE len || op`), M4.2.
    PairNotice(Vec<u8>),
}

impl fmt::Debug for MessageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageKind::Url(u) => f
                .debug_struct("MessageKind::Url")
                .field("len", &u.len())
                .field("url", &"<redacted>")
                .finish(),
            MessageKind::ClipboardText { text, sensitive } => f
                .debug_struct("MessageKind::ClipboardText")
                .field("len", &text.len())
                .field("sensitive", sensitive)
                .field("text", &"<redacted>")
                .finish(),
            MessageKind::FileWake(w) => f
                .debug_struct("MessageKind::FileWake")
                .field("transfer_id", &w.transfer_id)
                .field("size_bytes", &w.size_bytes)
                .field("expires_at", &w.expires_at)
                .field("is_executable", &w.is_executable)
                .field("filename", &"<redacted>")
                .finish(),
            MessageKind::PairNotice(op) => f
                .debug_struct("MessageKind::PairNotice")
                .field("len", &op.len())
                .finish(),
        }
    }
}

/// Every field of a URL body, unvalidated. Used by `encode_signed` and by the
/// fake malicious peer to forge arbitrary frames. Building one grants nothing:
/// the receiver checks everything.
#[derive(Clone)]
pub struct RawBody {
    pub magic: [u8; 4],
    pub group: [u8; 32],
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub log_head: [u8; 32],
    pub msg_id: [u8; 16],
    pub timestamp: u64,
    pub url: Vec<u8>,
}

impl fmt::Debug for RawBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawBody")
            .field("url_len", &self.url.len())
            .field("url", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl RawBody {
    /// Bytes covered by the signature (without the domain tag), i.e. the body
    /// minus the signature. `url_len` is the real length, truncated to u16.
    pub fn signed_part(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.url.len());
        out.extend_from_slice(&self.magic);
        out.extend_from_slice(&self.group);
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.recipient);
        out.extend_from_slice(&self.log_head);
        out.extend_from_slice(&self.msg_id);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&(self.url.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.url);
        out
    }

    /// Signed with `key`, regardless of what `sender` says.
    pub fn sign_with(&self, key: &DeviceKeypair) -> Vec<u8> {
        let mut out = self.signed_part();
        let sig = key.sign(&signing_input(&out));
        out.extend_from_slice(&sig.to_bytes());
        out
    }

    /// Attached arbitrary signature bytes.
    pub fn with_signature(&self, sig: &[u8; 64]) -> Vec<u8> {
        let mut out = self.signed_part();
        out.extend_from_slice(sig);
        out
    }
}

/// Decoded but **unverified** message. Fields are crate-private so nothing
/// outside core can pull the URL/text out of an unverified message. Debug redacts
/// the payload (`LOG-04`).
pub struct SignedMessage {
    pub(crate) group: GroupId,
    pub(crate) sender: DeviceId,
    pub(crate) recipient: [u8; 32],
    pub(crate) log_head: LogHead,
    pub(crate) msg_id: MsgId,
    pub(crate) timestamp: UnixMillis,
    pub(crate) url: String,
    pub(crate) kind: MessageKind,
    pub(crate) signature: [u8; SIG_LEN],
    pub(crate) signed_part: Vec<u8>,
}

impl fmt::Debug for SignedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedMessage")
            .field("group", &self.group)
            .field("sender", &self.sender)
            .field("msg_id", &self.msg_id)
            .field("timestamp", &self.timestamp)
            .field("url", &"<redacted>")
            .field("url_len", &self.url.len())
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Fields for an outgoing URL message.
pub struct Outgoing<'a> {
    pub group: GroupId,
    pub recipient: DeviceId,
    pub log_head: LogHead,
    pub msg_id: MsgId,
    pub timestamp: UnixMillis,
    pub url: &'a str,
}

/// Fields for an outgoing inline clipboard text message (`M3-PLAN.md` §2.2).
pub struct OutgoingClipboard<'a> {
    pub group: GroupId,
    pub recipient: DeviceId,
    pub log_head: LogHead,
    pub msg_id: MsgId,
    pub timestamp: UnixMillis,
    pub text: &'a str,
    pub sensitive: bool,
}

/// Fields for an outgoing `FileWake` message (`M3-PLAN.md` §1.5 & §2.2).
pub struct OutgoingFileWake<'a> {
    pub group: GroupId,
    pub recipient: DeviceId,
    pub log_head: LogHead,
    pub msg_id: MsgId,
    pub timestamp: UnixMillis,
    pub wake: &'a FileWakePayload,
}

/// Build and sign an outgoing URL message body (`KIND_URL = 0x00`).
pub fn encode_signed(sender: &DeviceKeypair, m: &Outgoing<'_>) -> Result<Vec<u8>, RejectReason> {
    if m.url.len() > MAX_URL_BYTES {
        return Err(RejectReason::UrlTooLong);
    }
    Ok(RawBody {
        magic: MAGIC,
        group: m.group.0,
        sender: *sender.device_id().as_bytes(),
        recipient: *m.recipient.as_bytes(),
        log_head: m.log_head.0,
        msg_id: m.msg_id.0,
        timestamp: m.timestamp.0,
        url: m.url.as_bytes().to_vec(),
    }
    .sign_with(sender))
}

/// Build and sign an outgoing inline clipboard message body (`KIND_CLIPBOARD = 0x01`).
pub fn encode_signed_clipboard(
    sender: &DeviceKeypair,
    m: &OutgoingClipboard<'_>,
) -> Result<Vec<u8>, RejectReason> {
    if m.text.is_empty() {
        return Err(RejectReason::MalformedFrame);
    }
    if m.text.contains(' ') {
        return Err(RejectReason::MalformedFrame);
    }
    if m.text.len() > MAX_INLINE_CLIPBOARD_BYTES {
        return Err(RejectReason::UrlTooLong);
    }
    let flags = if m.sensitive || crate::clipboard::looks_sensitive_clipboard(m.text) {
        FLAG_SENSITIVE_HINT
    } else {
        0u8
    };
    let text_bytes = m.text.as_bytes();
    let mut out = Vec::with_capacity(COMMON_HEADER_LEN + 1 + 2 + text_bytes.len() + SIG_LEN);
    out.extend_from_slice(&MAGIC_CLIPBOARD);
    out.extend_from_slice(&m.group.0);
    out.extend_from_slice(sender.device_id().as_bytes());
    out.extend_from_slice(m.recipient.as_bytes());
    out.extend_from_slice(&m.log_head.0);
    out.extend_from_slice(&m.msg_id.0);
    out.extend_from_slice(&m.timestamp.0.to_be_bytes());
    out.push(flags);
    out.extend_from_slice(&(text_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(text_bytes);
    let sig = sender.sign(&signing_input(&out));
    out.extend_from_slice(&sig.to_bytes());
    Ok(out)
}

/// Build and sign an outgoing `FileWake` message body (`KIND_FILE_WAKE = 0x02`).
pub fn encode_signed_file_wake(
    sender: &DeviceKeypair,
    m: &OutgoingFileWake<'_>,
) -> Result<Vec<u8>, RejectReason> {
    if m.wake.size_bytes == 0 || m.wake.size_bytes > MAX_FILE_SIZE {
        return Err(RejectReason::UrlTooLong);
    }
    let clean_name = sanitize_filename(&m.wake.filename);
    let name_bytes = clean_name.as_bytes();
    if name_bytes.is_empty() || name_bytes.len() > MAX_FILENAME_BYTES {
        return Err(RejectReason::MalformedFrame);
    }
    let is_exec = m.wake.is_executable || is_executable_filename(&clean_name);
    let flags = if is_exec { FLAG_FILE_EXECUTABLE } else { 0u8 };
    let mut out =
        Vec::with_capacity(COMMON_HEADER_LEN + 16 + 8 + 8 + 1 + 2 + name_bytes.len() + SIG_LEN);
    out.extend_from_slice(&MAGIC_FILE_WAKE);
    out.extend_from_slice(&m.group.0);
    out.extend_from_slice(sender.device_id().as_bytes());
    out.extend_from_slice(m.recipient.as_bytes());
    out.extend_from_slice(&m.log_head.0);
    out.extend_from_slice(&m.msg_id.0);
    out.extend_from_slice(&m.timestamp.0.to_be_bytes());
    out.extend_from_slice(&m.wake.transfer_id);
    out.extend_from_slice(&m.wake.size_bytes.to_be_bytes());
    out.extend_from_slice(&m.wake.expires_at.0.to_be_bytes());
    out.push(flags);
    out.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(name_bytes);
    let sig = sender.sign(&signing_input(&out));
    out.extend_from_slice(&sig.to_bytes());
    Ok(out)
}

/// Fields for an outgoing pairing notice (M4.2).
pub struct OutgoingPairNotice<'a> {
    pub group: GroupId,
    pub recipient: DeviceId,
    pub log_head: LogHead,
    pub msg_id: MsgId,
    pub timestamp: UnixMillis,
    pub op: &'a [u8],
}

/// Build and sign an outgoing pairing notice (`KIND_PAIR_NOTICE = 0x03`).
pub fn encode_signed_pair_notice(
    sender: &DeviceKeypair,
    m: &OutgoingPairNotice<'_>,
) -> Result<Vec<u8>, RejectReason> {
    if m.op.is_empty() || m.op.len() > MAX_PAIR_NOTICE_BYTES {
        return Err(RejectReason::MalformedFrame);
    }
    let mut out = Vec::with_capacity(COMMON_HEADER_LEN + 2 + m.op.len() + SIG_LEN);
    out.extend_from_slice(&MAGIC_PAIR_NOTICE);
    out.extend_from_slice(&m.group.0);
    out.extend_from_slice(sender.device_id().as_bytes());
    out.extend_from_slice(m.recipient.as_bytes());
    out.extend_from_slice(&m.log_head.0);
    out.extend_from_slice(&m.msg_id.0);
    out.extend_from_slice(&m.timestamp.0.to_be_bytes());
    out.extend_from_slice(&(m.op.len() as u16).to_be_bytes());
    out.extend_from_slice(m.op);
    let sig = sender.sign(&signing_input(&out));
    out.extend_from_slice(&sig.to_bytes());
    Ok(out)
}

pub fn signing_input(signed_part: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(DOMAIN_TAG_MESSAGE.len() + signed_part.len());
    v.extend_from_slice(DOMAIN_TAG_MESSAGE);
    v.extend_from_slice(signed_part);
    v
}

fn arr<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&b[at..at + N]);
    out
}

pub(crate) fn decode(bytes: &[u8]) -> Result<SignedMessage, RejectReason> {
    // Upper bound is enforced by the envelope cap; an over-cap URL inside a
    // well-formed frame is reported by the URL policy as `UrlTooLong`.
    if bytes.len() > crate::envelope::MAX_PADDED_LEN || bytes.len() < HEADER_LEN + SIG_LEN {
        return Err(RejectReason::MalformedFrame);
    }
    if bytes[0] != MAGIC[0] || bytes[1] != MAGIC[1] {
        return Err(RejectReason::MalformedFrame);
    }
    if bytes[2] != VERSION {
        return Err(RejectReason::UnsupportedVersion);
    }

    let kind_byte = bytes[3];
    let (url, kind, signed_end) = match kind_byte {
        KIND_URL => {
            let url_len = u16::from_be_bytes(arr::<2>(bytes, COMMON_HEADER_LEN)) as usize;
            if bytes.len() != HEADER_LEN + url_len + SIG_LEN {
                return Err(RejectReason::MalformedFrame);
            }
            let url_end = HEADER_LEN + url_len;
            let u = std::str::from_utf8(&bytes[HEADER_LEN..url_end])
                .map_err(|_| RejectReason::MalformedFrame)?
                .to_owned();
            (u.clone(), MessageKind::Url(u), url_end)
        }
        KIND_CLIPBOARD => {
            const CLIP_HEADER_LEN: usize = COMMON_HEADER_LEN + 1 + 2;
            if bytes.len() < CLIP_HEADER_LEN + SIG_LEN {
                return Err(RejectReason::MalformedFrame);
            }
            let flags = bytes[COMMON_HEADER_LEN];
            if (flags & !FLAG_SENSITIVE_HINT) != 0 {
                return Err(RejectReason::MalformedFrame);
            }
            let text_len = u16::from_be_bytes(arr::<2>(bytes, COMMON_HEADER_LEN + 1)) as usize;
            if text_len == 0 || bytes.len() != CLIP_HEADER_LEN + text_len + SIG_LEN {
                return Err(RejectReason::MalformedFrame);
            }
            if text_len > MAX_INLINE_CLIPBOARD_BYTES {
                return Err(RejectReason::UrlTooLong);
            }
            let text_end = CLIP_HEADER_LEN + text_len;
            let text = std::str::from_utf8(&bytes[CLIP_HEADER_LEN..text_end])
                .map_err(|_| RejectReason::MalformedFrame)?;
            if text.contains(' ') {
                return Err(RejectReason::MalformedFrame);
            }
            let sensitive = (flags & FLAG_SENSITIVE_HINT) != 0
                || crate::clipboard::looks_sensitive_clipboard(text);
            (
                String::new(),
                MessageKind::ClipboardText {
                    text: text.to_owned(),
                    sensitive,
                },
                text_end,
            )
        }
        KIND_FILE_WAKE => {
            const WAKE_FIXED_LEN: usize = COMMON_HEADER_LEN + 16 + 8 + 8 + 1 + 2;
            if bytes.len() < WAKE_FIXED_LEN + 1 + SIG_LEN {
                return Err(RejectReason::MalformedFrame);
            }
            let transfer_id = arr::<16>(bytes, COMMON_HEADER_LEN);
            let size_bytes = u64::from_be_bytes(arr::<8>(bytes, COMMON_HEADER_LEN + 16));
            let expires_at =
                UnixMillis(u64::from_be_bytes(arr::<8>(bytes, COMMON_HEADER_LEN + 24)));
            let flags = bytes[COMMON_HEADER_LEN + 32];
            if (flags & !FLAG_FILE_EXECUTABLE) != 0 {
                return Err(RejectReason::MalformedFrame);
            }
            let name_len = u16::from_be_bytes(arr::<2>(bytes, COMMON_HEADER_LEN + 33)) as usize;
            if name_len == 0
                || name_len > MAX_FILENAME_BYTES
                || bytes.len() != WAKE_FIXED_LEN + name_len + SIG_LEN
            {
                return Err(RejectReason::MalformedFrame);
            }
            if size_bytes == 0 || size_bytes > MAX_FILE_SIZE {
                return Err(RejectReason::UrlTooLong);
            }
            let name_end = WAKE_FIXED_LEN + name_len;
            let raw_name = std::str::from_utf8(&bytes[WAKE_FIXED_LEN..name_end])
                .map_err(|_| RejectReason::MalformedFrame)?;
            if raw_name.contains(' ') {
                return Err(RejectReason::MalformedFrame);
            }
            let filename = sanitize_filename(raw_name);
            let is_executable =
                (flags & FLAG_FILE_EXECUTABLE) != 0 || is_executable_filename(&filename);
            (
                String::new(),
                MessageKind::FileWake(FileWakePayload {
                    transfer_id,
                    size_bytes,
                    expires_at,
                    filename,
                    is_executable,
                }),
                name_end,
            )
        }
        KIND_PAIR_NOTICE => {
            let op_len = u16::from_be_bytes(arr::<2>(bytes, COMMON_HEADER_LEN)) as usize;
            if op_len == 0
                || op_len > MAX_PAIR_NOTICE_BYTES
                || bytes.len() != HEADER_LEN + op_len + SIG_LEN
            {
                return Err(RejectReason::MalformedFrame);
            }
            let op_end = HEADER_LEN + op_len;
            (
                String::new(),
                MessageKind::PairNotice(bytes[HEADER_LEN..op_end].to_vec()),
                op_end,
            )
        }
        _ => return Err(RejectReason::MalformedFrame),
    };

    // A weak or invalid sender key can never verify: reject as BadSignature.
    let sender = DeviceId::from_bytes(arr::<32>(bytes, 36))?;
    Ok(SignedMessage {
        group: GroupId(arr::<32>(bytes, 4)),
        sender,
        recipient: arr::<32>(bytes, 68),
        log_head: LogHead(arr::<32>(bytes, 100)),
        msg_id: MsgId(arr::<16>(bytes, 132)),
        timestamp: UnixMillis(u64::from_be_bytes(arr::<8>(bytes, 148))),
        url,
        kind,
        signature: arr::<64>(bytes, signed_end),
        signed_part: bytes[..signed_end].to_vec(),
    })
}

impl SignedMessage {
    pub(crate) fn signature(&self) -> Signature {
        Signature::from_bytes(&self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (DeviceKeypair, Vec<u8>, DeviceId) {
        let k = DeviceKeypair::generate();
        let r = DeviceKeypair::generate().device_id();
        let bytes = encode_signed(
            &k,
            &Outgoing {
                group: GroupId([7; 32]),
                recipient: r,
                log_head: LogHead([3; 32]),
                msg_id: MsgId([9; 16]),
                timestamp: UnixMillis(1234),
                url: "https://secret-marker.example/",
            },
        )
        .unwrap();
        (k, bytes, r)
    }

    #[test]
    fn roundtrip() {
        let (k, bytes, r) = sample();
        let d = decode(&bytes).unwrap();
        assert_eq!(d.group, GroupId([7; 32]));
        assert_eq!(d.sender, k.device_id());
        assert_eq!(&d.recipient, r.as_bytes());
        assert_eq!(d.log_head, LogHead([3; 32]));
        assert_eq!(d.msg_id, MsgId([9; 16]));
        assert_eq!(d.timestamp, UnixMillis(1234));
        assert_eq!(d.url, "https://secret-marker.example/");
        assert_eq!(
            d.kind,
            MessageKind::Url("https://secret-marker.example/".to_string())
        );
    }

    #[test]
    fn roundtrip_clipboard_and_file_wake() {
        let k = DeviceKeypair::generate();
        let r = DeviceKeypair::generate().device_id();
        let clip = encode_signed_clipboard(
            &k,
            &OutgoingClipboard {
                group: GroupId([7; 32]),
                recipient: r,
                log_head: LogHead([3; 32]),
                msg_id: MsgId([5; 16]),
                timestamp: UnixMillis(5678),
                text: "sk-live-secret-123456",
                sensitive: false,
            },
        )
        .unwrap();
        let d = decode(&clip).unwrap();
        assert_eq!(
            d.kind,
            MessageKind::ClipboardText {
                text: "sk-live-secret-123456".to_string(),
                sensitive: true,
            }
        );

        let wake = FileWakePayload {
            transfer_id: [0xAB; 16],
            size_bytes: 1_048_576,
            expires_at: UnixMillis(999_999),
            filename: "installer.apk".to_string(),
            is_executable: false,
        };
        let wake_bytes = encode_signed_file_wake(
            &k,
            &OutgoingFileWake {
                group: GroupId([7; 32]),
                recipient: r,
                log_head: LogHead([3; 32]),
                msg_id: MsgId([6; 16]),
                timestamp: UnixMillis(5678),
                wake: &wake,
            },
        )
        .unwrap();
        let dw = decode(&wake_bytes).unwrap();
        assert_eq!(
            dw.kind,
            MessageKind::FileWake(FileWakePayload {
                transfer_id: [0xAB; 16],
                size_bytes: 1_048_576,
                expires_at: UnixMillis(999_999),
                filename: "installer.apk".to_string(),
                is_executable: true,
            })
        );
    }

    #[test]
    fn strictness() {
        let (_, bytes, _) = sample();
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(decode(&trailing).unwrap_err(), RejectReason::MalformedFrame);
        assert_eq!(
            decode(&bytes[..10]).unwrap_err(),
            RejectReason::MalformedFrame
        );
        for v in [0u8, 2, 255] {
            let mut b = bytes.clone();
            b[2] = v;
            assert_eq!(decode(&b).unwrap_err(), RejectReason::UnsupportedVersion);
        }
        let mut reserved = bytes.clone();
        reserved[3] = 1;
        assert_eq!(decode(&reserved).unwrap_err(), RejectReason::MalformedFrame);
        let mut unknown_kind = bytes.clone();
        unknown_kind[3] = 4;
        assert_eq!(
            decode(&unknown_kind).unwrap_err(),
            RejectReason::MalformedFrame
        );
        // Truncation at every offset never panics and never succeeds.
        for i in 0..bytes.len() {
            assert!(decode(&bytes[..i]).is_err());
        }
    }

    #[test]
    fn pair_notice_round_trips_and_is_strict() {
        let k = DeviceKeypair::generate();
        let r = DeviceKeypair::generate().device_id();
        let m = OutgoingPairNotice {
            group: GroupId([7; 32]),
            recipient: r,
            log_head: LogHead([3; 32]),
            msg_id: MsgId([9; 16]),
            timestamp: UnixMillis(1234),
            op: &[5u8; 300],
        };
        let bytes = encode_signed_pair_notice(&k, &m).unwrap();
        let d = decode(&bytes).unwrap();
        assert_eq!(d.kind, MessageKind::PairNotice(vec![5u8; 300]));
        assert_eq!(d.sender, k.device_id());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        let big = [0u8; MAX_PAIR_NOTICE_BYTES + 1];
        assert!(encode_signed_pair_notice(&k, &OutgoingPairNotice { op: &big, ..m }).is_err());
        assert!(format!("{:?}", d.kind).contains("len"));
    }

    #[test]
    fn debug_redacts_url() {
        let (_, bytes, _) = sample();
        let d = decode(&bytes).unwrap();
        let s = format!(
            "{d:?} {:?}",
            RawBody {
                magic: MAGIC,
                group: [0; 32],
                sender: [0; 32],
                recipient: [0; 32],
                log_head: [0; 32],
                msg_id: [0; 16],
                timestamp: 0,
                url: b"https://secret-marker.example/".to_vec(),
            }
        );
        assert!(!s.contains("secret-marker"), "{s}");
        assert!(s.contains("<redacted>"));
    }
}
