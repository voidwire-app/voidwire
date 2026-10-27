#![forbid(unsafe_code)]
//! Canonical, signed message body (the plaintext inside the envelope).
//! Spec: docs/PROTOCOL.md §4. All integers big-endian.
//!
//! ```text
//! magic      4   'V' 'W' version(=1) reserved(=0)
//! group      32
//! sender     32  Ed25519 public key (DeviceId)
//! recipient  32
//! log_head   32  sender's group-log head
//! msg_id     16
//! timestamp  8   unix millis (wall clock)
//! url_len    2
//! url        url_len bytes, UTF-8
//! signature  64  Ed25519 over DOMAIN_TAG_MESSAGE || all preceding bytes
//! ```
//!
//! Decoding is strict: exact lengths, no trailing bytes, UTF-8 required,
//! reserved byte zero, no panics on any input.

use crate::ids::{DeviceId, GroupId, LogHead, MsgId};
use crate::keys::DeviceKeypair;
use crate::reject::RejectReason;
use crate::time::UnixMillis;
use ed25519_dalek::Signature;
use std::fmt;

pub const VERSION: u8 = crate::protocol::PROTOCOL_VERSION;
pub const MAGIC: [u8; 4] = [b'V', b'W', VERSION, 0];
/// Domain separation for message signatures.
pub const DOMAIN_TAG_MESSAGE: &[u8] = b"voidwire/v1/message\0";

pub const HEADER_LEN: usize = 4 + 32 + 32 + 32 + 32 + 16 + 8 + 2;
pub const SIG_LEN: usize = 64;
/// Largest body we will even try to parse.
pub const MAX_BODY_LEN: usize = HEADER_LEN + crate::limits::MAX_URL_BYTES + SIG_LEN;

/// Every field of a body, unvalidated. Used by `encode_signed` and by the
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
/// outside core can pull the URL out of an unverified message. Debug redacts
/// the URL (LOG-04).
pub struct SignedMessage {
    pub(crate) group: GroupId,
    pub(crate) sender: DeviceId,
    pub(crate) recipient: [u8; 32],
    pub(crate) log_head: LogHead,
    pub(crate) msg_id: MsgId,
    pub(crate) timestamp: UnixMillis,
    pub(crate) url: String,
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
            .finish_non_exhaustive()
    }
}

/// Fields for an outgoing message.
pub struct Outgoing<'a> {
    pub group: GroupId,
    pub recipient: DeviceId,
    pub log_head: LogHead,
    pub msg_id: MsgId,
    pub timestamp: UnixMillis,
    pub url: &'a str,
}

/// Build and sign an outgoing message body.
pub fn encode_signed(sender: &DeviceKeypair, m: &Outgoing<'_>) -> Result<Vec<u8>, RejectReason> {
    if m.url.len() > crate::limits::MAX_URL_BYTES {
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
    if bytes[3] != 0 {
        return Err(RejectReason::MalformedFrame);
    }
    let url_len = u16::from_be_bytes(arr::<2>(bytes, HEADER_LEN - 2)) as usize;
    if bytes.len() != HEADER_LEN + url_len + SIG_LEN {
        return Err(RejectReason::MalformedFrame);
    }
    let url_end = HEADER_LEN + url_len;
    let url = std::str::from_utf8(&bytes[HEADER_LEN..url_end])
        .map_err(|_| RejectReason::MalformedFrame)?
        .to_owned();
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
        signature: arr::<64>(bytes, url_end),
        signed_part: bytes[..url_end].to_vec(),
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
        // Truncation at every offset never panics and never succeeds.
        for i in 0..bytes.len() {
            assert!(decode(&bytes[..i]).is_err());
        }
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
