//! M1 transport: QUIC (iroh) on the home LAN, mDNS/DNS-SD discovery, no relay.
//!
//! * The iroh endpoint key **is** the device identity key, so the TLS-
//!   authenticated `EndpointId` of a connection is the sender's `DeviceId`
//!   (step 1 of `Inbox::receive` uses it before anything is parsed).
//! * Two ALPNs: [`ALPN_PAIR`] (QR pairing) and [`ALPN_APP`] (sync + sends).
//! * One request per bidirectional stream; frames are `type u8 | len u32 BE |
//!   payload`, with a per-type cap checked **before** the payload is read.
//!
//! See docs/PROTOCOL.md §6 (pairing) and §8 (transport).

use std::time::Duration;

use iroh::endpoint::{Connection, ConnectionError, RecvStream, SendStream, VarInt};

use crate::envelope::MAX_ENVELOPE_LEN;
use crate::ids::DeviceId;
use crate::reject::RejectReason;

pub use crate::protocol::{ALPN_APP, ALPN_MAILBOX, ALPN_PAIR, EXPORTER_PAIR};

pub(crate) mod links;
pub mod mailbox_client;
pub(crate) mod outbox;
pub mod pairings_state;
pub mod pc;
pub mod phone;
pub mod relay_watch;
pub(crate) mod split;
pub mod state;
pub mod test_relay;

/// Default Voidwire M2 relay URL (TLS-ALPN-01 on TCP 443 + QAD on UDP 7842).
pub const DEFAULT_RELAY_URL: &str = "https://relay.voidwire.app";
/// Environment override for local/dev testing (`"off"` or `"none"` disables relay).
pub const ENV_RELAY_URL: &str = "VOIDWIRE_RELAY_URL";

/// Resolve the active relay URL from an explicit override, `VOIDWIRE_RELAY_URL`,
/// or [`DEFAULT_RELAY_URL`]. Passing `"off"`, `"none"`, or `"disabled"` disables
/// the relay (`RelayMode::Disabled`).
pub fn resolve_relay_url(configured: Option<&str>) -> Option<String> {
    if let Some(c) = configured {
        let t = c.trim();
        if t.is_empty()
            || t.eq_ignore_ascii_case("off")
            || t.eq_ignore_ascii_case("none")
            || t.eq_ignore_ascii_case("disabled")
        {
            return None;
        }
        return Some(t.to_string());
    }
    if let Ok(env_val) = std::env::var(ENV_RELAY_URL) {
        let t = env_val.trim();
        if !t.is_empty() {
            if t.eq_ignore_ascii_case("off")
                || t.eq_ignore_ascii_case("none")
                || t.eq_ignore_ascii_case("disabled")
            {
                return None;
            }
            return Some(t.to_string());
        }
    }
    Some(DEFAULT_RELAY_URL.to_string())
}

/// Build an [`iroh::RelayMode`] (`RelayMode::Custom` for a valid URL, or
/// `RelayMode::Disabled` when `None` / `"off"`). Plain `http://` test relays
/// omit QUIC address discovery (`quic: None`) since QAD requires TLS.
pub use crate::pairing::validate_relay_url;

pub fn build_relay_mode(
    relay_url: Option<&str>,
) -> Result<(iroh::RelayMode, Option<iroh::RelayUrl>), NetError> {
    let Some(raw) = resolve_relay_url(relay_url) else {
        return Ok((iroh::RelayMode::Disabled, None));
    };
    let Some(validated) = validate_relay_url(&raw).map_err(NetError::Rejected)? else {
        return Ok((iroh::RelayMode::Disabled, None));
    };
    let parsed: iroh::RelayUrl = validated
        .parse()
        .map_err(|e| NetError::Protocol(format!("invalid relay url {validated:?}: {e}")))?;
    let map = iroh::RelayMap::from(relay_config_for(&parsed));
    Ok((iroh::RelayMode::Custom(map), Some(parsed)))
}

/// The relay config Voidwire uses for `url`: plain-http (dev/test) relays
/// have no QUIC address discovery; https relays use iroh's default.
pub fn relay_config_for(url: &iroh::RelayUrl) -> iroh::RelayConfig {
    if url.scheme() == "http" {
        iroh::RelayConfig::new(url.clone(), None)
    } else {
        iroh::RelayConfig::from(url.clone())
    }
}

/// Client `NetReportConfig` with plaintext port-80 captive-portal probe disabled
/// (`docs/M2-PLAN.md` §1.1 & §3.2: port 80 is not open on `relay.voidwire.app`).
pub fn default_net_report_config() -> iroh::NetReportConfig {
    let mut cfg = iroh::NetReportConfig::default();
    cfg.captive_portal_check = false;
    cfg
}

/// Preferred UDP port for the PC listener (falls back to a random port).
pub const PREFERRED_PORT: u16 = 48484;
/// DNS-SD service label: `<endpoint id>._voidwire._udp.local`.
pub const MDNS_SERVICE: &str = "voidwire";

/// Per-read timeout on a stream (the SAS wait has its own, longer one).
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) mod frame {
    pub const HELLO: u8 = 0x01;
    pub const INVITER_CERT: u8 = 0x02;
    pub const PROOF: u8 = 0x03;
    pub const PROOF_OK: u8 = 0x04;
    pub const WELCOME: u8 = 0x05;
    pub const SYNC: u8 = 0x10;
    pub const OPS: u8 = 0x11;
    pub const SEND: u8 = 0x12;
    pub const RESULT: u8 = 0x13;
    pub const FILE_OFFER: u8 = 0x20;
    pub const FILE_OFFER_ACK: u8 = 0x21;
    pub const FILE_CHUNK: u8 = 0x22;
    pub const FILE_CHUNK_ACK: u8 = 0x23;
    pub const FILE_CANCEL: u8 = 0x24;
    pub const FILE_PULL: u8 = 0x25;
    // M4.2 legacy split (see `split`).
    pub const SPLIT_REQ: u8 = 0x30;
    pub const SPLIT_READY: u8 = 0x31;
    pub const SPLIT_JOIN: u8 = 0x32;
    pub const SPLIT_OFFER: u8 = 0x33;
    pub const SPLIT_ACCEPT: u8 = 0x34;
    pub const SPLIT_CAPS: u8 = 0x35;
    pub const SPLIT_DONE: u8 = 0x36;
    pub const ERROR: u8 = 0x7F;
}

/// Largest ops list on the wire: count u16 + (len u16 + op) per op.
pub(crate) const MAX_OPS_FRAME: usize =
    2 + crate::grouplog::MAX_LOG_OPS * (2 + crate::grouplog::MAX_OP_LEN);

/// Payload cap per frame type. Unknown types get 0 (rejected unread).
pub(crate) const MAX_FILE_CHUNK_FRAME: usize =
    16 + 8 + 1 + crate::file_transfer::MAX_CHUNK_CIPHERTEXT_LEN;

pub(crate) fn frame_cap(t: u8) -> usize {
    match t {
        frame::HELLO => 8,
        frame::INVITER_CERT => 512,
        frame::PROOF => 32 + 512,
        frame::PROOF_OK => 0,
        frame::WELCOME | frame::OPS => MAX_OPS_FRAME,
        frame::SYNC => 32,
        frame::SEND => MAX_ENVELOPE_LEN,
        frame::FILE_OFFER => crate::file_transfer::MAX_OFFER_ENVELOPE_LEN,
        frame::RESULT => 3,
        frame::FILE_OFFER_ACK | frame::FILE_CHUNK_ACK | frame::FILE_CANCEL => 256,
        frame::FILE_PULL => 16,
        frame::FILE_CHUNK => MAX_FILE_CHUNK_FRAME,
        frame::ERROR => 2,
        frame::SPLIT_REQ | frame::SPLIT_READY => 0,
        frame::SPLIT_JOIN => 2 + split::MAX_SPLIT_OP + 32,
        frame::SPLIT_OFFER | frame::SPLIT_CAPS => {
            2 + split::MAX_SPLIT_OP + crate::mailbox::WRAPPED_EPOCH_SECRET_LEN
        }
        frame::SPLIT_ACCEPT => 2 * (2 + split::MAX_SPLIT_OP),
        frame::SPLIT_DONE => 32,
        _ => 0,
    }
}

/// Close code for "refused by policy": `0x100 + RejectReason::code()`.
pub(crate) fn close_code(r: RejectReason) -> VarInt {
    VarInt::from_u32(0x100 + r.code() as u32)
}

/// Errors surfaced to apps (UI strings come from the reason, never a URL).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    /// The other side refused (or we refused locally) for a protocol reason.
    #[error("refused: {0}")]
    Rejected(RejectReason),
    #[error("couldn't reach the PC on this network: {0}")]
    Unreachable(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("timed out")]
    Timeout,
    #[error("cancelled")]
    Cancelled,
    #[error("unknown device")]
    UnknownDevice,
}

impl From<RejectReason> for NetError {
    fn from(r: RejectReason) -> Self {
        NetError::Rejected(r)
    }
}

/// Map a connection-level failure to the most specific error: a policy close
/// from the peer becomes `Rejected(reason)`.
pub(crate) fn conn_error(conn: &Connection, fallback: impl std::fmt::Display) -> NetError {
    match conn.close_reason() {
        Some(ConnectionError::ApplicationClosed(c)) => {
            let code = c.error_code.into_inner();
            if code >= 0x100 {
                if let Ok(c) = u16::try_from(code - 0x100) {
                    return NetError::Rejected(RejectReason::from_code(c));
                }
            }
            NetError::Protocol(format!("closed by peer ({code})"))
        }
        Some(ConnectionError::TimedOut) => NetError::Timeout,
        _ => NetError::Protocol(fallback.to_string()),
    }
}

pub(crate) async fn write_frame(
    send: &mut SendStream,
    t: u8,
    payload: &[u8],
) -> Result<(), NetError> {
    debug_assert!(payload.len() <= frame_cap(t));
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(t);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    send.write_all(&buf)
        .await
        .map_err(|e| NetError::Protocol(format!("write: {e}")))
}

/// Read one frame, refusing an unknown type or an over-cap length before
/// reading the payload.
pub(crate) async fn read_frame(
    recv: &mut RecvStream,
    timeout: Duration,
) -> Result<(u8, Vec<u8>), NetError> {
    let fut = async {
        let mut hdr = [0u8; 5];
        recv.read_exact(&mut hdr)
            .await
            .map_err(|e| NetError::Protocol(format!("read: {e}")))?;
        let t = hdr[0];
        let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        if len > frame_cap(t) {
            return Err(NetError::Rejected(RejectReason::MalformedFrame));
        }
        let mut payload = vec![0u8; len];
        recv.read_exact(&mut payload)
            .await
            .map_err(|e| NetError::Protocol(format!("read: {e}")))?;
        Ok((t, payload))
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| NetError::Timeout)?
}

pub(crate) fn error_payload(r: RejectReason) -> [u8; 2] {
    r.code().to_be_bytes()
}

pub(crate) fn parse_error(payload: &[u8]) -> NetError {
    match payload {
        [a, b] => NetError::Rejected(RejectReason::from_code(u16::from_be_bytes([*a, *b]))),
        _ => NetError::Protocol("bad error frame".into()),
    }
}

pub(crate) fn encode_ops<'a>(ops: impl ExactSizeIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(ops.len() as u16).to_be_bytes());
    for op in ops {
        b.extend_from_slice(&(op.len() as u16).to_be_bytes());
        b.extend_from_slice(op);
    }
    b
}

pub(crate) fn decode_ops(b: &[u8]) -> Result<Vec<crate::grouplog::SignedOp>, RejectReason> {
    let mut r = state::Reader::new(b);
    let n = r.u16().ok_or(RejectReason::MalformedFrame)? as usize;
    if n > crate::grouplog::MAX_LOG_OPS {
        return Err(RejectReason::BadLogOp);
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let op = r.bytes16().ok_or(RejectReason::MalformedFrame)?;
        out.push(crate::grouplog::SignedOp::parse_verified(op)?);
    }
    if !r.is_empty() {
        return Err(RejectReason::MalformedFrame);
    }
    Ok(out)
}

const WELCOME_M2_TAG: u8 = 1;
const WELCOME_MAILBOX_PEER_TAG: u8 = 2;

pub(crate) fn encode_welcome<'a>(
    ops: impl ExactSizeIterator<Item = &'a [u8]>,
    epoch: u64,
    sealed_gs: &[u8; crate::mailbox::WRAPPED_EPOCH_SECRET_LEN],
    mailbox_peer: Option<DeviceId>,
) -> Vec<u8> {
    let mut b = encode_ops(ops);
    b.push(WELCOME_M2_TAG);
    b.extend_from_slice(&epoch.to_be_bytes());
    b.extend_from_slice(sealed_gs);
    if let Some(mp) = mailbox_peer {
        b.push(WELCOME_MAILBOX_PEER_TAG);
        b.extend_from_slice(mp.as_bytes());
    }
    b
}

#[allow(clippy::type_complexity)]
pub(crate) fn decode_welcome(
    b: &[u8],
) -> Result<
    (
        Vec<crate::grouplog::SignedOp>,
        Option<(u64, [u8; crate::mailbox::WRAPPED_EPOCH_SECRET_LEN])>,
        Option<DeviceId>,
    ),
    RejectReason,
> {
    let mut r = state::Reader::new(b);
    let n = r.u16().ok_or(RejectReason::MalformedFrame)? as usize;
    if n > crate::grouplog::MAX_LOG_OPS {
        return Err(RejectReason::BadLogOp);
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let op = r.bytes16().ok_or(RejectReason::MalformedFrame)?;
        out.push(crate::grouplog::SignedOp::parse_verified(op)?);
    }
    if r.is_empty() {
        return Ok((out, None, None));
    }
    let tag = r.u8().ok_or(RejectReason::MalformedFrame)?;
    if tag != WELCOME_M2_TAG {
        return Err(RejectReason::MalformedFrame);
    }
    let ep_bytes = r.take(8).ok_or(RejectReason::MalformedFrame)?;
    let epoch = u64::from_be_bytes(ep_bytes.try_into().expect("8"));
    let sealed_bytes = r
        .take(crate::mailbox::WRAPPED_EPOCH_SECRET_LEN)
        .ok_or(RejectReason::MalformedFrame)?;
    let sealed: [u8; crate::mailbox::WRAPPED_EPOCH_SECRET_LEN] =
        sealed_bytes.try_into().expect("80");
    let mailbox_peer = if !r.is_empty() {
        let mtag = r.u8().ok_or(RejectReason::MalformedFrame)?;
        if mtag != WELCOME_MAILBOX_PEER_TAG {
            return Err(RejectReason::MalformedFrame);
        }
        let mp_bytes = r.take(32).ok_or(RejectReason::MalformedFrame)?;
        if !r.is_empty() {
            return Err(RejectReason::MalformedFrame);
        }
        let arr: [u8; 32] = mp_bytes.try_into().expect("32");
        Some(DeviceId::from_bytes(arr)?)
    } else {
        None
    };
    Ok((out, Some((epoch, sealed)), mailbox_peer))
}

pub(crate) fn device_id_of(id: &iroh::EndpointId) -> Result<DeviceId, RejectReason> {
    DeviceId::from_bytes(*id.as_bytes())
}

pub(crate) fn endpoint_id_of(id: &DeviceId) -> Result<iroh::EndpointId, NetError> {
    iroh::EndpointId::from_bytes(id.as_bytes())
        .map_err(|_| NetError::Rejected(RejectReason::MalformedFrame))
}

/// The pairing transcript's TLS binding: both ends export the same 32 bytes
/// from this QUIC connection (context = the QR secret id).
pub(crate) fn pairing_exporter(conn: &Connection, secret_id: &[u8]) -> Result<[u8; 32], NetError> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, EXPORTER_PAIR, secret_id)
        .map_err(|_| NetError::Protocol("exporter".into()))?;
    Ok(out)
}

pub(crate) fn pairing_handshake(
    exporter: &[u8; 32],
    inviter_cert: &[u8],
    joiner_cert: &[u8],
) -> Vec<u8> {
    let mut h = Vec::with_capacity(32 + inviter_cert.len() + joiner_cert.len() + 4);
    h.extend_from_slice(exporter);
    h.extend_from_slice(&(inviter_cert.len() as u16).to_be_bytes());
    h.extend_from_slice(inviter_cert);
    h.extend_from_slice(&(joiner_cert.len() as u16).to_be_bytes());
    h.extend_from_slice(joiner_cert);
    h
}

/// Outcome of one delivered link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// Opened right away (no-prompt mode, the default).
    Opened = 1,
    /// Waiting for the user's click on the PC ("Ask before opening" is on).
    Prompted = 2,
}

impl SendOutcome {
    pub(crate) fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(SendOutcome::Opened),
            2 => Some(SendOutcome::Prompted),
            _ => None,
        }
    }
}

/// How an outbound item was delivered to a peer device (`M3.1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryPath {
    /// Delivered live over a direct LAN QUIC connection.
    Direct = 1,
    /// Delivered live over an `iroh-relay` connection.
    Relayed = 2,
    /// Peer was offline/unreachable; sealed envelope queued in its RAM-only blind device inbox.
    QueuedInDeviceInbox = 3,
}

/// Test harness (M4.2): one end of a v2 pairing.
#[cfg(feature = "test-util")]
pub enum V2Node<'a> {
    Pc(&'a pc::PcNode),
    Phone(&'a phone::PhoneClient),
}

/// Test harness (M4.2): pair two devices the v2 way, with no pairing flow
/// (the flows arrive in M4.3). `a` invites, `b` joins; `relay` is where the
/// pairing's inboxes live (`None`: each side's home relay). `a_addrs` /
/// `b_addrs`: direct addresses each side should dial the other on.
#[cfg(feature = "test-util")]
pub fn pair_v2_for_tests(
    a: V2Node<'_>,
    a_addrs: Vec<std::net::SocketAddr>,
    b: V2Node<'_>,
    b_addrs: Vec<std::net::SocketAddr>,
    relay: Option<crate::pairwise::RelayRef>,
) -> Result<crate::ids::GroupId, NetError> {
    let ident = |n: &V2Node<'_>| match n {
        V2Node::Pc(p) => p.v2_identity_for_tests(),
        V2Node::Phone(p) => p.v2_identity_for_tests(),
    };
    let (ak, ac) = ident(&a);
    let (bk, bc) = ident(&b);
    let (pa, pb) = crate::pairwise::v2::pair_for_tests(&ak, ac, &bk, bc, relay);
    let id = pa.pairing_id;
    let adopt = |n: &V2Node<'_>, p, addrs| match n {
        V2Node::Pc(x) => x.adopt_v2_pairing_for_tests(p, addrs),
        V2Node::Phone(x) => x.adopt_v2_pairing_for_tests(p, addrs),
    };
    // Each side dials the other on the other's addresses.
    adopt(&a, pa, b_addrs)?;
    adopt(&b, pb, a_addrs)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_mode_defaults_to_custom_production_relay() {
        let (mode, url) = build_relay_mode(Some(DEFAULT_RELAY_URL)).unwrap();
        assert!(matches!(mode, iroh::RelayMode::Custom(_)));
        assert_eq!(url.unwrap().as_str(), "https://relay.voidwire.app/");
    }

    #[test]
    fn relay_mode_can_be_disabled_explicitly() {
        let (mode, url) = build_relay_mode(Some("off")).unwrap();
        assert!(matches!(mode, iroh::RelayMode::Disabled));
        assert!(url.is_none());
    }

    #[test]
    fn net_report_config_disables_captive_portal_port_80_probe() {
        let cfg = default_net_report_config();
        assert!(!cfg.captive_portal_check);
        assert!(cfg.https_probes);
    }
}

/// Test harness (M4.3): the inputs of a v2 pairing's inbox key derivation.
#[cfg(feature = "test-util")]
#[derive(Clone)]
pub struct PairingInboxInputs {
    pub pairing_id: crate::ids::GroupId,
    pub epoch: u64,
    pub my_rx: crate::keys::ReceivePublicKey,
    pub peer_rx: crate::keys::ReceivePublicKey,
    pub gs_e: crate::mailbox::EpochSecret,
}
