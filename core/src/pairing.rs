#![forbid(unsafe_code)]
//! QR + SAS pairing (plan §3; decisions in docs/PROTOCOL.md §6).
//!
//! ```text
//! inviter: PairingRegistry::issue ─► PairingInvite ─► QR (voidwire:pair?...)
//! joiner : ScannedInvite::parse(QR) ─► PairingRequest::create (HMAC proof + name)
//! inviter: PairingRegistry::redeem(req) ─► PairingGrant (shows joiner name)
//! user   : types the 6-digit code shown on the phone
//!          ─► PairingGrant::confirm_typed_code ─► ConfirmedPairing
//! inviter: Roster::add_paired_device(ConfirmedPairing, ..)
//! ```
//!
//! * The secret is consumed by the **first attempt of any kind** (success,
//!   bad proof, expired): single use, no grinding, no races.
//! * Hard expiry of 120 s on the inviter's monotonic clock; expired at `>= 120 s`.
//! * The SAS must be **typed** (not a bare tap) within 120 s of the proof.
//! * `PairingGrant`/`ConfirmedPairing` have private fields and no public
//!   constructors, so the roster only grows through this flow.

use crate::ids::{DeviceId, GroupId};
use crate::keys::DeviceCert;
use crate::limits::{
    MAX_DEVICE_NAME_BYTES, PAIRING_SECRET_TTL_MS, QR_REFRESH_CAP_MS, QR_REFRESH_LEAD_MS,
    SAS_CONFIRM_TTL_MS,
};
use crate::protocol::{PAIRING_URI_SCHEME, PROTOCOL_VERSION};
use crate::reject::RejectReason;
use crate::time::{MonoMillis, Now, UnixMillis};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(crate) const TAG_SECRET_ID: &[u8] = b"voidwire/v1/pair-id\0";
pub(crate) const TAG_PROOF: &[u8] = b"voidwire/v1/pair-proof\0";
pub(crate) const TAG_SAS: &[u8] = b"voidwire/v1/sas\0";
pub(crate) const TAG_TRANSCRIPT: &[u8] = b"voidwire/v1/pair-transcript\0";

/// 128-bit one-time pairing secret. Zeroized on drop, never logged.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairingSecret([u8; 16]);

pub type SecretId = [u8; 8];

impl PairingSecret {
    /// Public, non-secret handle (lets the inviter find the secret without
    /// trial-HMACing every pending invite).
    pub fn id(&self) -> SecretId {
        let mut h = Sha256::new();
        h.update(TAG_SECRET_ID);
        h.update(self.0);
        let d = h.finalize();
        let mut id = [0u8; 8];
        id.copy_from_slice(&d[..8]);
        id
    }
}

impl fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingSecret(<redacted>)")
    }
}

/// What the inviter shows as a QR code.
pub struct PairingInvite {
    pub inviter: DeviceId,
    pub group: GroupId,
    /// Informational for the scanner; the inviter enforces expiry on its own
    /// monotonic clock.
    pub expires_at: UnixMillis,
    secret: PairingSecret,
}

impl fmt::Debug for PairingInvite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingInvite")
            .field("inviter", &self.inviter)
            .finish_non_exhaustive()
    }
}

impl PairingInvite {
    /// The secret's bytes (M4.3: the typed code and the rendezvous inbox
    /// are derived from it). Never logged.
    pub(crate) fn secret_bytes(&self) -> zeroize::Zeroizing<[u8; 16]> {
        zeroize::Zeroizing::new(self.secret.0)
    }

    /// `voidwire:pair?v=1&id=<hex>&r=<relay>&g=<hex>&s=<hex>&exp=<unix ms>`
    pub fn qr_uri(&self, relay_url: &str) -> String {
        self.qr_uri_with_addrs(relay_url, &[])
    }

    /// Same, plus `&a=<ip:port>,<ip:port>` direct-address hints (M1 LAN): the
    /// joiner dials the QR `id` at these addresses first, then via mDNS. The
    /// addresses are hints only; the TLS identity must still be `id`.
    pub fn qr_uri_with_addrs(&self, relay_url: &str, addrs: &[std::net::SocketAddr]) -> String {
        self.qr_uri_full(relay_url, addrs, None)
    }

    /// Same, plus `&n=<inviter name>` (OQ-9): lets the joiner warn "this will
    /// join a different device group (named X)" **before** any network
    /// traffic. Unauthenticated in the QR; the joiner checks it against the
    /// inviter's signed certificate and aborts on a mismatch.
    pub fn qr_uri_full(
        &self,
        relay_url: &str,
        addrs: &[std::net::SocketAddr],
        inviter_name: Option<&str>,
    ) -> String {
        self.qr_uri_full_with_mailbox(relay_url, addrs, inviter_name, None)
    }

    /// Same as [`Self::qr_uri_full`], plus optional `&m=<64-hex>` mailbox peer id (`M2-H1`).
    pub fn qr_uri_full_with_mailbox(
        &self,
        relay_url: &str,
        addrs: &[std::net::SocketAddr],
        inviter_name: Option<&str>,
        mailbox_peer: Option<&DeviceId>,
    ) -> String {
        let r: String = url::form_urlencoded::byte_serialize(relay_url.as_bytes()).collect();
        let mut uri = format!(
            "{PAIRING_URI_SCHEME}:pair?v={PROTOCOL_VERSION}&id={}&r={r}&g={}&s={}&exp={}",
            self.inviter.to_hex(),
            self.group.to_hex(),
            crate::hex::encode(&self.secret.0),
            self.expires_at.0
        );
        if let Some(n) = inviter_name.filter(|n| crate::keys::valid_device_name(n)) {
            let n: String = url::form_urlencoded::byte_serialize(n.as_bytes()).collect();
            uri.push_str("&n=");
            uri.push_str(&n);
        }
        if !addrs.is_empty() {
            let a: Vec<String> = addrs
                .iter()
                .take(MAX_QR_ADDRS)
                .map(|a| a.to_string())
                .collect();
            let a: String = url::form_urlencoded::byte_serialize(a.join(",").as_bytes()).collect();
            uri.push_str("&a=");
            uri.push_str(&a);
        }
        if let Some(mp) = mailbox_peer {
            uri.push_str("&m=");
            uri.push_str(&mp.to_hex());
        }
        uri
    }
}

#[cfg(any(test, feature = "test-util"))]
fn live_test_relay_ports() -> &'static std::sync::Mutex<std::collections::HashSet<u16>> {
    static PORTS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<u16>>> =
        std::sync::OnceLock::new();
    PORTS.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

#[cfg(any(test, feature = "test-util"))]
pub(crate) fn register_test_relay_port(port: u16) {
    live_test_relay_ports()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(port);
}

#[cfg(any(test, feature = "test-util"))]
pub(crate) fn unregister_test_relay_port(port: u16) {
    live_test_relay_ports()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&port);
}

#[cfg(any(test, feature = "test-util"))]
fn is_registered_test_relay(u: &url::Url) -> bool {
    if std::env::var("VOIDWIRE_ALLOW_INSECURE_TEST_RELAY").is_ok() {
        return true;
    }
    if u.scheme() == "http" && u.host_str() == Some("127.0.0.1") {
        if let Some(port) = u.port() {
            return live_test_relay_ports()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&port);
        }
    }
    false
}

/// Validate a relay URL from a QR code (`r=`) or user configuration (`M2-M2`).
///
/// Allows `""`, `"off"`, `"none"`, or `"disabled"` (`Ok(None)`).
/// Otherwise requires `https://` with a valid public hostname or public IP
/// (rejecting `http://`, `localhost`, loopback `127.0.0.0/8` / `::1`,
/// RFC1918 `10.0.0.0/8` / `172.16.0.0/12` / `192.168.0.0/16`, link-local
/// `169.254.0.0/16` / `fe80::/10`, credentials `@`, and query/fragment).
pub fn validate_relay_url(raw: &str) -> Result<Option<String>, RejectReason> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("off")
        || trimmed.eq_ignore_ascii_case("none")
        || trimmed.eq_ignore_ascii_case("disabled")
    {
        return Ok(None);
    }
    if trimmed.len() > 256 || trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(RejectReason::MalformedFrame);
    }
    let u = url::Url::parse(trimmed).map_err(|_| RejectReason::MalformedFrame)?;
    if !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(RejectReason::MalformedFrame);
    }
    #[cfg(any(test, feature = "test-util"))]
    if is_registered_test_relay(&u) {
        return Ok(Some(trimmed.to_owned()));
    }
    if u.scheme() != "https" {
        return Err(RejectReason::MalformedFrame);
    }
    match u.host().ok_or(RejectReason::MalformedFrame)? {
        url::Host::Domain(d) => {
            let lower = d.to_ascii_lowercase();
            if lower.is_empty()
                || lower == "localhost"
                || lower.ends_with(".localhost")
                || lower.ends_with(".local")
                || lower.ends_with(".internal")
                || !lower.contains('.')
                || lower.starts_with('.')
                || lower.ends_with('.')
            {
                return Err(RejectReason::MalformedFrame);
            }
        }
        url::Host::Ipv4(ip) => {
            let oct = ip.octets();
            let is_cgnat = oct[0] == 100 && (oct[1] & 0b1100_0000) == 64;
            if ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_documentation()
                || is_cgnat
            {
                return Err(RejectReason::MalformedFrame);
            }
        }
        url::Host::Ipv6(ip) => {
            let seg0 = ip.segments()[0];
            let is_ula = (seg0 & 0xfe00) == 0xfc00;
            let is_ll = (seg0 & 0xffc0) == 0xfe80;
            if ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || is_ula
                || is_ll
                || ip.to_ipv4_mapped().is_some()
            {
                return Err(RejectReason::MalformedFrame);
            }
        }
    }
    Ok(Some(trimmed.to_owned()))
}

/// At most this many direct-address hints in a QR code.
pub const MAX_QR_ADDRS: usize = 6;

/// The joiner's parsed view of a QR code. Debug is hand-written (carries a URL
/// and the secret).
pub struct ScannedInvite {
    pub inviter: DeviceId,
    pub group: GroupId,
    pub relay_url: String,
    /// Direct-address hints (`a=`), possibly empty.
    pub addrs: Vec<std::net::SocketAddr>,
    /// Inviter's device name from the QR (`n=`), if present. Unauthenticated
    /// until checked against the inviter's certificate.
    pub inviter_name: Option<String>,
    /// Optional mailbox service peer id (`m=<64-hex>`, `M2-H1`).
    pub mailbox_peer: Option<DeviceId>,
    pub expires_at: UnixMillis,
    secret: PairingSecret,
}

impl fmt::Debug for ScannedInvite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScannedInvite")
            .field("inviter", &self.inviter)
            .field("group", &self.group)
            .field("relay_url", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ScannedInvite {
    /// Strict parser: required fields, no duplicates, known version.
    pub fn parse(uri: &str, now: Now) -> Result<Self, RejectReason> {
        let prefix = format!("{PAIRING_URI_SCHEME}:pair?");
        let query = uri
            .strip_prefix(&prefix)
            .ok_or(RejectReason::MalformedFrame)?;
        if uri.len() > 1024 {
            return Err(RejectReason::MalformedFrame);
        }
        let mut fields: HashMap<String, String> = HashMap::new();
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            if fields.insert(k.into_owned(), v.into_owned()).is_some() {
                return Err(RejectReason::MalformedFrame); // duplicate param
            }
        }
        let get = |k: &str| fields.get(k).ok_or(RejectReason::MalformedFrame);
        if get("v")? != &PROTOCOL_VERSION.to_string() {
            return Err(RejectReason::UnsupportedVersion);
        }
        let inviter = DeviceId::from_hex(get("id")?).ok_or(RejectReason::MalformedFrame)?;
        let group = GroupId::from_hex(get("g")?).ok_or(RejectReason::MalformedFrame)?;
        let secret = crate::hex::decode_array::<16>(get("s")?)
            .map(PairingSecret)
            .ok_or(RejectReason::MalformedFrame)?;
        let expires_at = UnixMillis(
            get("exp")?
                .parse::<u64>()
                .map_err(|_| RejectReason::MalformedFrame)?,
        );
        let raw_relay = fields.get("r").map(String::as_str).unwrap_or("");
        let relay_url = if raw_relay.is_empty() {
            String::new()
        } else {
            validate_relay_url(raw_relay)?.unwrap_or_default()
        };
        let mut addrs = Vec::new();
        if let Some(a) = fields.get("a") {
            for part in a.split(',').filter(|p| !p.is_empty()) {
                if addrs.len() == MAX_QR_ADDRS {
                    return Err(RejectReason::MalformedFrame);
                }
                addrs.push(part.parse().map_err(|_| RejectReason::MalformedFrame)?);
            }
        }
        let inviter_name = match fields.get("n") {
            Some(n) if crate::keys::valid_device_name(n) => Some(n.clone()),
            Some(_) => return Err(RejectReason::BadDeviceName),
            None => None,
        };
        let mailbox_peer = match fields.get("m").map(String::as_str) {
            None | Some("") => None,
            Some(m_hex) => Some(DeviceId::from_hex(m_hex).ok_or(RejectReason::MalformedFrame)?),
        };
        if now.wall >= expires_at {
            return Err(RejectReason::PairingSecretExpired);
        }
        Ok(ScannedInvite {
            inviter,
            group,
            relay_url,
            addrs,
            inviter_name,
            mailbox_peer,
            expires_at,
            secret,
        })
    }

    /// M4.3: a v2 invite (QR `v=2` or a fetched invite card) in the
    /// joiner's shape. `relay_url` is where the inviter answers.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        inviter: DeviceId,
        group: GroupId,
        relay_url: String,
        addrs: Vec<std::net::SocketAddr>,
        inviter_name: Option<String>,
        mailbox_peer: Option<DeviceId>,
        expires_at: UnixMillis,
        secret: [u8; 16],
    ) -> Self {
        ScannedInvite {
            inviter,
            group,
            relay_url,
            addrs,
            inviter_name,
            mailbox_peer,
            expires_at,
            secret: PairingSecret(secret),
        }
    }

    /// The secret's bytes (M4.3: compared with a typed code). Never logged.
    pub(crate) fn secret_bytes(&self) -> zeroize::Zeroizing<[u8; 16]> {
        zeroize::Zeroizing::new(self.secret.0)
    }

    /// Public handle of the secret (sent in the pairing hello).
    pub fn secret_id(&self) -> SecretId {
        self.secret.id()
    }

    /// The SAS the joiner displays (the inviter's user types it).
    pub fn sas_code(&self, joiner: &DeviceId, joiner_name: &str, handshake: &[u8]) -> String {
        let t = transcript(&self.group, &self.inviter, joiner, joiner_name, handshake);
        format_sas(derive_sas(&self.secret, &t))
    }
}

/// Everything both sides agree on. `handshake` = transport-level bytes
/// (M1: TLS exporter of the iroh connection + exchanged device certificates).
fn transcript(
    group: &GroupId,
    inviter: &DeviceId,
    joiner: &DeviceId,
    joiner_name: &str,
    handshake: &[u8],
) -> Vec<u8> {
    let mut t =
        Vec::with_capacity(TAG_TRANSCRIPT.len() + 96 + 16 + joiner_name.len() + handshake.len());
    t.extend_from_slice(TAG_TRANSCRIPT);
    t.extend_from_slice(&group.0);
    t.extend_from_slice(inviter.as_bytes());
    t.extend_from_slice(joiner.as_bytes());
    t.extend_from_slice(&(joiner_name.len() as u64).to_be_bytes());
    t.extend_from_slice(joiner_name.as_bytes());
    t.extend_from_slice(&(handshake.len() as u64).to_be_bytes());
    t.extend_from_slice(handshake);
    t
}

fn proof_mac(secret: &PairingSecret, transcript: &[u8]) -> Hmac<Sha256> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&secret.0).expect("hmac accepts any key length");
    mac.update(TAG_PROOF);
    mac.update(transcript);
    mac
}

fn derive_sas(secret: &PairingSecret, transcript: &[u8]) -> u32 {
    let hk = Hkdf::<Sha256>::new(Some(TAG_SAS), &secret.0);
    // 8 bytes so the modulo bias is negligible (< 2^-40).
    let mut okm = [0u8; 8];
    hk.expand(transcript, &mut okm)
        .expect("8 bytes is a valid HKDF length");
    (u64::from_be_bytes(okm) % 1_000_000) as u32
}

fn format_sas(n: u32) -> String {
    format!("{n:06}")
}

/// Sent by the joiner to prove knowledge of the QR secret.
#[derive(Clone)]
pub struct PairingRequest {
    pub secret_id: SecretId,
    pub joiner: DeviceId,
    pub joiner_name: String,
    pub proof: [u8; 32],
    /// M1: the joiner's signed device certificate (receive key, platform).
    /// Its device id and name must match `joiner` / `joiner_name`.
    pub joiner_cert: Option<DeviceCert>,
}

impl fmt::Debug for PairingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingRequest")
            .field("joiner", &self.joiner)
            .finish_non_exhaustive()
    }
}

impl PairingRequest {
    pub fn create(
        invite: &ScannedInvite,
        joiner: DeviceId,
        joiner_name: &str,
        handshake: &[u8],
    ) -> Self {
        let t = transcript(
            &invite.group,
            &invite.inviter,
            &joiner,
            joiner_name,
            handshake,
        );
        let proof = proof_mac(&invite.secret, &t).finalize().into_bytes().into();
        PairingRequest {
            secret_id: invite.secret.id(),
            joiner,
            joiner_name: joiner_name.to_owned(),
            proof,
            joiner_cert: None,
        }
    }

    /// M1: request carrying the joiner's certificate (name and id from it).
    /// `handshake` must already include the certificate bytes (the network
    /// layer builds it as TLS exporter || inviter cert || joiner cert).
    pub fn create_with_cert(invite: &ScannedInvite, cert: &DeviceCert, handshake: &[u8]) -> Self {
        let mut r = Self::create(invite, cert.device(), cert.name(), handshake);
        r.joiner_cert = Some(cert.clone());
        r
    }
}

struct Pending {
    secret: PairingSecret,
    expires_mono: MonoMillis,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpentReason {
    /// A proof was checked against it (single use).
    Used,
    Expired,
    /// Cancelled before anyone used it (window closed, Cancel, New code).
    /// Answers as expired: telling the phone "already used" would be wrong.
    Revoked,
}

/// Inviter-side state: outstanding secrets and tombstones of spent ones.
pub struct PairingRegistry {
    inviter: DeviceId,
    group: GroupId,
    pending: HashMap<SecretId, Pending>,
    /// Only ids are kept; secrets are dropped (zeroized) as soon as spent.
    spent: HashMap<SecretId, (SpentReason, MonoMillis)>,
}

/// Read-only view for tests and diagnostics (TEST-PLAN H-7). No secret bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSnapshot {
    pub pending: Vec<(SecretId, MonoMillis)>,
    pub spent: Vec<(SecretId, SpentReason)>,
}

impl PairingRegistry {
    pub fn new(inviter: DeviceId, group: GroupId) -> Self {
        PairingRegistry {
            inviter,
            group,
            pending: HashMap::new(),
            spent: HashMap::new(),
        }
    }

    fn sweep(&mut self, now: Now) {
        let expired: Vec<SecretId> = self
            .pending
            .iter()
            .filter(|(_, p)| now.mono >= p.expires_mono)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.pending.remove(&id);
            self.spent.insert(
                id,
                (
                    SpentReason::Expired,
                    now.mono.saturating_add(10 * PAIRING_SECRET_TTL_MS),
                ),
            );
        }
        self.spent.retain(|_, (_, forget)| *forget > now.mono);
    }

    /// Create a fresh single-use secret. Refuses (Internal) if the RNG looks
    /// stuck (all-zero output or a repeat of a live secret).
    pub fn issue(
        &mut self,
        now: Now,
        rng: &mut impl CryptoRngCore,
    ) -> Result<PairingInvite, RejectReason> {
        self.issue_with_ttl(now, rng, PAIRING_SECRET_TTL_MS)
    }

    /// [`Self::issue`] with its own lifetime (M4.3 typed codes live
    /// `PAIRING_CODE_TTL_MS`). Capped at `PAIRING_CODE_TTL_MS` so a spent
    /// secret is always remembered longer than it could have lived.
    pub fn issue_with_ttl(
        &mut self,
        now: Now,
        rng: &mut impl CryptoRngCore,
        ttl_ms: u64,
    ) -> Result<PairingInvite, RejectReason> {
        let ttl_ms = ttl_ms.min(crate::limits::PAIRING_CODE_TTL_MS);
        self.sweep(now);
        let mut s = [0u8; 16];
        rng.fill_bytes(&mut s);
        let secret = PairingSecret(s);
        s.zeroize();
        let id = secret.id();
        if secret.0 == [0u8; 16] || self.pending.contains_key(&id) || self.spent.contains_key(&id) {
            return Err(RejectReason::Internal);
        }
        let expires_mono = now.mono.saturating_add(ttl_ms);
        self.pending.insert(
            id,
            Pending {
                secret: PairingSecret(secret.0),
                expires_mono,
            },
        );
        Ok(PairingInvite {
            inviter: self.inviter,
            group: self.group,
            expires_at: now.wall.saturating_add(ttl_ms),
            secret,
        })
    }

    /// A newer QR replaced the live ones: each keeps working for at most
    /// `grace_ms` more (never past its own expiry), then expires as usual.
    pub fn replace_all(&mut self, now: Now, grace_ms: u64) {
        self.sweep(now);
        let until = now.mono.saturating_add(grace_ms);
        for p in self.pending.values_mut() {
            p.expires_mono = p.expires_mono.min(until);
        }
    }

    /// Cancel every outstanding invite (user closed the pairing window).
    pub fn cancel_all(&mut self, now: Now) {
        let ids: Vec<SecretId> = self.pending.keys().copied().collect();
        for id in ids {
            self.pending.remove(&id);
            self.spent.insert(
                id,
                (
                    SpentReason::Revoked,
                    now.mono.saturating_add(10 * PAIRING_SECRET_TTL_MS),
                ),
            );
        }
    }

    pub fn snapshot(&self) -> StoreSnapshot {
        let mut pending: Vec<_> = self
            .pending
            .iter()
            .map(|(id, p)| (*id, p.expires_mono))
            .collect();
        let mut spent: Vec<_> = self.spent.iter().map(|(id, (r, _))| (*id, *r)).collect();
        pending.sort();
        spent.sort_by_key(|(id, _)| *id);
        StoreSnapshot { pending, spent }
    }

    /// Is `id` a live, unspent secret? Does **not** consume it (the proof
    /// does); lets the inviter answer a hello with its certificate only for
    /// holders of a valid QR.
    pub fn check_pending(&mut self, id: &SecretId, now: Now) -> Result<(), RejectReason> {
        self.sweep(now);
        if let Some((why, _)) = self.spent.get(id) {
            return Err(match why {
                SpentReason::Used => RejectReason::PairingSecretUsed,
                SpentReason::Expired | SpentReason::Revoked => RejectReason::PairingSecretExpired,
            });
        }
        match self.pending.get(id) {
            Some(p) if now.mono < p.expires_mono => Ok(()),
            Some(_) => Err(RejectReason::PairingSecretExpired),
            None => Err(RejectReason::PairingSecretUnknown),
        }
    }

    /// Check a joiner's proof. Any attempt burns the secret.
    pub fn redeem(
        &mut self,
        req: &PairingRequest,
        handshake: &[u8],
        now: Now,
    ) -> Result<PairingGrant, RejectReason> {
        self.sweep(now);
        if let Some((why, _)) = self.spent.get(&req.secret_id) {
            return Err(match why {
                SpentReason::Used => RejectReason::PairingSecretUsed,
                SpentReason::Expired | SpentReason::Revoked => RejectReason::PairingSecretExpired,
            });
        }
        let pending = self
            .pending
            .remove(&req.secret_id)
            .ok_or(RejectReason::PairingSecretUnknown)?;
        let forget = now.mono.saturating_add(10 * PAIRING_SECRET_TTL_MS);
        // Consume first, then judge.
        self.spent
            .insert(req.secret_id, (SpentReason::Used, forget));
        if now.mono >= pending.expires_mono {
            self.spent
                .insert(req.secret_id, (SpentReason::Expired, forget));
            return Err(RejectReason::PairingSecretExpired);
        }
        let name_ok = !req.joiner_name.is_empty()
            && req.joiner_name.len() <= MAX_DEVICE_NAME_BYTES
            && !req.joiner_name.chars().any(|c| c.is_control())
            && req
                .joiner_cert
                .as_ref()
                .is_none_or(|c| c.device() == req.joiner && c.name() == req.joiner_name);
        let t = transcript(
            &self.group,
            &self.inviter,
            &req.joiner,
            &req.joiner_name,
            handshake,
        );
        // Constant-time comparison via `Mac::verify_slice`.
        proof_mac(&pending.secret, &t)
            .verify_slice(&req.proof)
            .map_err(|_| RejectReason::PairingHmacBad)?;
        if !name_ok {
            return Err(RejectReason::MalformedFrame);
        }
        Ok(PairingGrant {
            joiner: req.joiner,
            joiner_name: req.joiner_name.clone(),
            joiner_cert: req.joiner_cert.clone(),
            sas: derive_sas(&pending.secret, &t),
            confirm_by: now.mono.saturating_add(SAS_CONFIRM_TTL_MS),
        })
    }
}

/// Why the pair window stopped showing QR codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QrPause {
    /// `QR_REFRESH_CAP_MS` after the window started.
    TimeLimit,
    /// The window was hidden or minimized (or stopped asking for a while).
    NotVisible,
}

/// What the pair window's QR should do right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QrTick {
    /// The live QR is fine.
    Keep,
    /// Mint a fresh secret + QR and revoke the live one.
    Refresh,
    /// Stop: revoke the live QR and show "Pairing paused" (Show a new code).
    Pause(QrPause),
}

/// Auto-refresh schedule for the pair window (M1.1). Pure: every decision
/// takes an injected [`Now`] and only the monotonic clock is used.
///
/// * a fresh QR `QR_REFRESH_LEAD_MS` before the live one expires;
/// * nothing after `QR_REFRESH_CAP_MS` from [`QrSchedule::start`];
/// * a live QR that already expired (nobody asked in time, e.g. the window
///   was hidden and stopped polling) pauses instead of refreshing late.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QrSchedule {
    started: MonoMillis,
    expires: MonoMillis,
}

impl QrSchedule {
    /// The window showed its first QR (issued at `now`).
    pub fn start(now: Now) -> Self {
        QrSchedule {
            started: now.mono,
            expires: now.mono.saturating_add(PAIRING_SECRET_TTL_MS),
        }
    }

    /// A fresh QR was issued at `now`.
    pub fn refreshed(&mut self, now: Now) {
        self.expires = now.mono.saturating_add(PAIRING_SECRET_TTL_MS);
    }

    /// When the next refresh is due (monotonic).
    pub fn refresh_at(&self) -> MonoMillis {
        MonoMillis(self.expires.0.saturating_sub(QR_REFRESH_LEAD_MS))
    }

    /// When auto-refresh stops (monotonic).
    pub fn cap_at(&self) -> MonoMillis {
        self.started.saturating_add(QR_REFRESH_CAP_MS)
    }

    pub fn tick(&self, now: Now) -> QrTick {
        if now.mono >= self.cap_at() {
            QrTick::Pause(QrPause::TimeLimit)
        } else if now.mono >= self.expires {
            QrTick::Pause(QrPause::NotVisible)
        } else if now.mono >= self.refresh_at() {
            QrTick::Refresh
        } else {
            QrTick::Keep
        }
    }
}

/// A verified proof awaiting the user's typed SAS. Not `Clone`.
pub struct PairingGrant {
    joiner: DeviceId,
    joiner_name: String,
    joiner_cert: Option<DeviceCert>,
    sas: u32,
    confirm_by: MonoMillis,
}

impl fmt::Debug for PairingGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingGrant")
            .field("joiner", &self.joiner)
            .finish_non_exhaustive()
    }
}

impl PairingGrant {
    pub fn joiner(&self) -> DeviceId {
        self.joiner
    }

    /// Shown on the confirm screen ("Add <name>?"). Display with bidi isolation.
    pub fn joiner_name(&self) -> &str {
        &self.joiner_name
    }

    /// The user typed the 6-digit code shown on the new device. This is the
    /// authorization gate. One try: a wrong code consumes the grant.
    pub fn confirm_typed_code(
        self,
        typed: &str,
        now: Now,
    ) -> Result<ConfirmedPairing, RejectReason> {
        if now.mono > self.confirm_by {
            return Err(RejectReason::SasTimeout);
        }
        let typed: String = typed.chars().filter(|c| !c.is_whitespace()).collect();
        let expected = format_sas(self.sas);
        if typed.len() != 6 || !bool::from(typed.as_bytes().ct_eq(expected.as_bytes())) {
            return Err(RejectReason::SasRejected);
        }
        Ok(ConfirmedPairing {
            joiner: self.joiner,
            name: self.joiner_name,
            cert: self.joiner_cert,
        })
    }

    /// Test-only peek at the SAS the inviter expects.
    #[cfg(any(test, feature = "test-util"))]
    pub fn expected_sas_for_tests(&self) -> String {
        format_sas(self.sas)
    }
}

/// Proof that a device completed pairing. Only `confirm_typed_code` makes one;
/// only `Roster::add_paired_device` consumes one.
#[derive(Debug)]
pub struct ConfirmedPairing {
    joiner: DeviceId,
    name: String,
    cert: Option<DeviceCert>,
}

impl ConfirmedPairing {
    pub(crate) fn into_parts(self) -> (DeviceId, String, Option<DeviceCert>) {
        (self.joiner, self.name, self.cert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceKeypair;
    use rand_core::OsRng;

    fn t0() -> Now {
        Now {
            wall: UnixMillis(1_700_000_000_000),
            mono: MonoMillis(5_000),
        }
    }

    fn setup() -> (PairingRegistry, DeviceId) {
        let inviter = DeviceKeypair::generate().device_id();
        (
            PairingRegistry::new(inviter, GroupId([1; 32])),
            DeviceKeypair::generate().device_id(),
        )
    }

    fn scan(reg: &mut PairingRegistry, now: Now) -> ScannedInvite {
        let qr = reg
            .issue(now, &mut OsRng)
            .unwrap()
            .qr_uri("https://relay.example/");
        ScannedInvite::parse(&qr, now).unwrap()
    }

    #[test]
    fn qr_schedule_refreshes_10s_before_expiry_and_stops_at_10_minutes() {
        let n = t0();
        let mut s = QrSchedule::start(n);
        assert_eq!(s.tick(n), QrTick::Keep);
        assert_eq!(
            s.tick(n.plus(PAIRING_SECRET_TTL_MS - QR_REFRESH_LEAD_MS - 1)),
            QrTick::Keep
        );
        assert_eq!(
            s.tick(n.plus(PAIRING_SECRET_TTL_MS - QR_REFRESH_LEAD_MS)),
            QrTick::Refresh
        );
        // Refresh at 110 s; the next one is due at 220 s.
        let mut t = n.plus(110_000);
        let mut refreshes = 1;
        s.refreshed(t);
        loop {
            t = t.plus(500); // the window polls every 500 ms
            match s.tick(t) {
                QrTick::Keep => {}
                QrTick::Refresh => {
                    assert_eq!(t.mono.saturating_sub(n.mono) % 110_000, 0);
                    refreshes += 1;
                    s.refreshed(t);
                }
                QrTick::Pause(why) => {
                    assert_eq!(why, QrPause::TimeLimit);
                    break;
                }
            }
        }
        assert_eq!(t.mono.saturating_sub(n.mono), QR_REFRESH_CAP_MS);
        assert_eq!(refreshes, 5, "110, 220, 330, 440, 550 s");
        // Wall-clock jumps don't matter (monotonic only).
        let jumped = Now {
            wall: UnixMillis(0),
            mono: n.mono,
        };
        assert_eq!(QrSchedule::start(n).tick(jumped), QrTick::Keep);
    }

    #[test]
    fn qr_schedule_pauses_instead_of_refreshing_an_expired_qr() {
        let n = t0();
        let s = QrSchedule::start(n);
        assert_eq!(
            s.tick(n.plus(PAIRING_SECRET_TTL_MS)),
            QrTick::Pause(QrPause::NotVisible)
        );
    }

    #[test]
    fn refresh_keeps_the_replaced_secret_for_a_short_grace() {
        use crate::limits::QR_REPLACED_GRACE_MS;
        let (mut reg, joiner) = setup();
        let n = t0();
        let old = reg.issue(n, &mut OsRng).unwrap().qr_uri("");
        let old_scan = ScannedInvite::parse(&old, n).unwrap();
        // Refresh (QA 41018162417): the old QR keeps a short grace, so a
        // phone that scanned it just before the refresh still pairs.
        let t = n.plus(100_000);
        reg.replace_all(t, QR_REPLACED_GRACE_MS);
        let new = reg.issue(t, &mut OsRng).unwrap().qr_uri("");
        let new_scan = ScannedInvite::parse(&new, t).unwrap();
        assert_eq!(
            reg.check_pending(&old_scan.secret_id(), t.plus(QR_REPLACED_GRACE_MS - 1)),
            Ok(())
        );
        assert_eq!(
            reg.check_pending(&old_scan.secret_id(), t.plus(QR_REPLACED_GRACE_MS)),
            Err(RejectReason::PairingSecretExpired),
            "after the grace: expired, not 'already used'"
        );
        let req = PairingRequest::create(&new_scan, joiner, "Pixel 8", b"hs");
        assert!(reg.redeem(&req, b"hs", t.plus(1)).is_ok());

        // Within the grace the replaced QR redeems.
        let (mut reg, joiner) = setup();
        let old = reg.issue(n, &mut OsRng).unwrap().qr_uri("");
        let old_scan = ScannedInvite::parse(&old, n).unwrap();
        reg.replace_all(t, QR_REPLACED_GRACE_MS);
        reg.issue(t, &mut OsRng).unwrap();
        let req = PairingRequest::create(&old_scan, joiner, "Pixel 8", b"hs");
        assert!(reg.redeem(&req, b"hs", t.plus(5_000)).is_ok());

        // The grace never extends a secret past its own expiry.
        let (mut reg, _) = setup();
        let old = reg.issue(n, &mut OsRng).unwrap().qr_uri("");
        let old_scan = ScannedInvite::parse(&old, n).unwrap();
        reg.replace_all(n.plus(PAIRING_SECRET_TTL_MS - 1_000), QR_REPLACED_GRACE_MS);
        assert_eq!(
            reg.check_pending(&old_scan.secret_id(), n.plus(PAIRING_SECRET_TTL_MS)),
            Err(RejectReason::PairingSecretExpired)
        );
    }

    #[test]
    fn a_cancelled_secret_answers_expired_not_used() {
        let (mut reg, joiner) = setup();
        let n = t0();
        let scanned = scan(&mut reg, n);
        reg.cancel_all(n.plus(1));
        assert_eq!(
            reg.check_pending(&scanned.secret_id(), n.plus(2)),
            Err(RejectReason::PairingSecretExpired)
        );
        let req = PairingRequest::create(&scanned, joiner, "Pixel 8", b"hs");
        assert_eq!(
            reg.redeem(&req, b"hs", n.plus(2)).err(),
            Some(RejectReason::PairingSecretExpired)
        );
        assert!(
            reg.snapshot().pending.is_empty(),
            "nothing live after a cancel"
        );
    }

    #[test]
    fn happy_path_typed_sas() {
        let (mut reg, joiner) = setup();
        let now = t0();
        let scanned = scan(&mut reg, now);
        assert_eq!(scanned.relay_url, "https://relay.example/");
        let req = PairingRequest::create(&scanned, joiner, "Pixel 8", b"hs");
        let grant = reg.redeem(&req, b"hs", now.plus(5_000)).unwrap();
        assert_eq!(grant.joiner_name(), "Pixel 8");
        let phone_shows = scanned.sas_code(&joiner, "Pixel 8", b"hs");
        assert_eq!(grant.expected_sas_for_tests(), phone_shows);
        let confirmed = grant
            .confirm_typed_code(&phone_shows, now.plus(10_000))
            .unwrap();
        assert_eq!(confirmed.into_parts().0, joiner);
        assert!(
            reg.snapshot().pending.is_empty(),
            "secret store empty after success"
        );
    }

    #[test]
    fn mistyped_sas_rejected() {
        let (mut reg, joiner) = setup();
        let now = t0();
        let scanned = scan(&mut reg, now);
        let grant = reg
            .redeem(
                &PairingRequest::create(&scanned, joiner, "P", b""),
                b"",
                now,
            )
            .unwrap();
        let good = grant.expected_sas_for_tests();
        let bad = if good == "000000" { "000001" } else { "000000" };
        assert_eq!(
            grant.confirm_typed_code(bad, now).unwrap_err(),
            RejectReason::SasRejected
        );
        let (mut reg, joiner) = setup();
        let scanned = scan(&mut reg, now);
        let grant = reg
            .redeem(
                &PairingRequest::create(&scanned, joiner, "P", b""),
                b"",
                now,
            )
            .unwrap();
        assert_eq!(
            grant.confirm_typed_code("", now).unwrap_err(),
            RejectReason::SasRejected
        );
    }

    #[test]
    fn secret_is_single_use() {
        let (mut reg, joiner) = setup();
        let now = t0();
        let scanned = scan(&mut reg, now);
        let req = PairingRequest::create(&scanned, joiner, "P", b"hs");
        assert!(reg.redeem(&req, b"hs", now).is_ok());
        assert_eq!(
            reg.redeem(&req, b"hs", now).unwrap_err(),
            RejectReason::PairingSecretUsed
        );
        let other = DeviceKeypair::generate().device_id();
        let req2 = PairingRequest::create(&scanned, other, "Q", b"hs");
        assert_eq!(
            reg.redeem(&req2, b"hs", now).unwrap_err(),
            RejectReason::PairingSecretUsed
        );
    }

    #[test]
    fn expiry_boundaries_pair_04_05_06() {
        for (offset, ok) in [
            (PAIRING_SECRET_TTL_MS - 1000, true),
            (PAIRING_SECRET_TTL_MS - 1, true),
            (PAIRING_SECRET_TTL_MS, false),
            (PAIRING_SECRET_TTL_MS + 1000, false),
        ] {
            let (mut reg, joiner) = setup();
            let now = t0();
            let scanned = scan(&mut reg, now);
            let req = PairingRequest::create(&scanned, joiner, "P", b"hs");
            let r = reg.redeem(&req, b"hs", now.plus(offset));
            if ok {
                assert!(r.is_ok(), "offset {offset}");
            } else {
                assert_eq!(
                    r.unwrap_err(),
                    RejectReason::PairingSecretExpired,
                    "offset {offset}"
                );
                assert_eq!(
                    reg.redeem(&req, b"hs", now.plus(offset)).unwrap_err(),
                    RejectReason::PairingSecretExpired
                );
            }
        }
    }

    #[test]
    fn expiry_uses_monotonic_not_wall() {
        let (mut reg, joiner) = setup();
        let now = t0();
        let scanned = scan(&mut reg, now);
        let req = PairingRequest::create(&scanned, joiner, "P", b"hs");
        // Wall clock jumps back an hour, monotonic moves past TTL: still expired.
        let later = Now {
            wall: UnixMillis(now.wall.0 - 3_600_000),
            mono: now.mono.saturating_add(PAIRING_SECRET_TTL_MS),
        };
        assert_eq!(
            reg.redeem(&req, b"hs", later).unwrap_err(),
            RejectReason::PairingSecretExpired
        );
    }

    #[test]
    fn scanner_refuses_stale_qr() {
        let (mut reg, _) = setup();
        let now = t0();
        let qr = reg.issue(now, &mut OsRng).unwrap().qr_uri("");
        assert_eq!(
            ScannedInvite::parse(&qr, now.plus(PAIRING_SECRET_TTL_MS)).unwrap_err(),
            RejectReason::PairingSecretExpired
        );
    }

    #[test]
    fn wrong_proof_rejected_and_burns_secret() {
        let (mut reg, joiner) = setup();
        let now = t0();
        let scanned = scan(&mut reg, now);
        let mut req = PairingRequest::create(&scanned, joiner, "P", b"hs");
        req.proof[0] ^= 1;
        assert_eq!(
            reg.redeem(&req, b"hs", now).unwrap_err(),
            RejectReason::PairingHmacBad
        );
        let good = PairingRequest::create(&scanned, joiner, "P", b"hs");
        assert_eq!(
            reg.redeem(&good, b"hs", now).unwrap_err(),
            RejectReason::PairingSecretUsed
        );
    }

    #[test]
    fn transcript_and_name_are_bound() {
        let (mut reg, joiner) = setup();
        let now = t0();
        let scanned = scan(&mut reg, now);
        let req = PairingRequest::create(&scanned, joiner, "P", b"handshake-A");
        assert_eq!(
            reg.redeem(&req, b"handshake-B", now).unwrap_err(),
            RejectReason::PairingHmacBad
        );
        let (mut reg, joiner) = setup();
        let scanned = scan(&mut reg, now);
        let mut req = PairingRequest::create(&scanned, joiner, "Pixel", b"");
        req.joiner_name = "Desktop-PC".into();
        assert_eq!(
            reg.redeem(&req, b"", now).unwrap_err(),
            RejectReason::PairingHmacBad
        );
    }

    #[test]
    fn sas_changes_with_every_input() {
        let (mut reg, joiner) = setup();
        let now = t0();
        let s = scan(&mut reg, now);
        let other = DeviceKeypair::generate().device_id();
        let base = s.sas_code(&joiner, "A", b"x");
        // Collisions are possible at 1e-6 each; these inputs are fixed per run.
        let variants = [
            s.sas_code(&other, "A", b"x"),
            s.sas_code(&joiner, "B", b"x"),
            s.sas_code(&joiner, "A", b"y"),
        ];
        assert!(variants.iter().filter(|v| **v == base).count() <= 1);
    }

    #[test]
    fn unknown_secret_and_unsolicited_rejected() {
        let (mut reg, joiner) = setup();
        let req = PairingRequest {
            secret_id: [0; 8],
            joiner,
            joiner_name: "x".into(),
            proof: [0; 32],
            joiner_cert: None,
        };
        assert_eq!(
            reg.redeem(&req, b"", t0()).unwrap_err(),
            RejectReason::PairingSecretUnknown
        );
    }

    #[test]
    fn qr_inviter_name_round_trips_and_is_validated() {
        let (mut reg, _) = setup();
        let now = t0();
        let invite = reg.issue(now, &mut OsRng).unwrap();
        let qr = invite.qr_uri_full("", &[], Some("Desktop-PC & Co"));
        let scanned = ScannedInvite::parse(&qr, now).unwrap();
        assert_eq!(scanned.inviter_name.as_deref(), Some("Desktop-PC & Co"));
        assert_eq!(
            ScannedInvite::parse(&invite.qr_uri(""), now)
                .unwrap()
                .inviter_name,
            None
        );
        // A control character in the name: the QR is refused.
        let bad = format!("{}&n=a%07b", invite.qr_uri(""));
        assert_eq!(
            ScannedInvite::parse(&bad, now).unwrap_err(),
            RejectReason::BadDeviceName
        );
        // An invalid name is simply left out when building the QR.
        assert!(!invite.qr_uri_full("", &[], Some("")).contains("&n="));
    }

    #[test]
    fn qr_addr_hints_round_trip_and_are_bounded() {
        let (mut reg, _) = setup();
        let now = t0();
        let invite = reg.issue(now, &mut OsRng).unwrap();
        let addrs: Vec<std::net::SocketAddr> = vec![
            "192.168.1.20:48484".parse().unwrap(),
            "[fe80::1]:48484".parse().unwrap(),
        ];
        let qr = invite.qr_uri_with_addrs("", &addrs);
        let scanned = ScannedInvite::parse(&qr, now).unwrap();
        assert_eq!(scanned.addrs, addrs);
        assert!(reg.check_pending(&scanned.secret_id(), now).is_ok());
        let bad = format!("{}&a=not-an-addr", invite.qr_uri(""));
        assert_eq!(
            ScannedInvite::parse(&bad, now).unwrap_err(),
            RejectReason::MalformedFrame
        );
    }

    #[test]
    fn cert_must_match_joiner_and_name() {
        use crate::keys::{DeviceKeypair, Platform};
        let (mut reg, _) = setup();
        let now = t0();
        let invite = reg.issue(now, &mut OsRng).unwrap();
        let scanned = ScannedInvite::parse(&invite.qr_uri(""), now).unwrap();
        let kp = DeviceKeypair::generate();
        let cert = DeviceCert::issue(&kp, "Pixel", Platform::Android, now.wall).unwrap();
        let mut req = PairingRequest::create_with_cert(&scanned, &cert, b"hs");
        req.joiner_name = "Other".into();
        req.proof = PairingRequest::create(&scanned, kp.device_id(), "Other", b"hs").proof;
        assert_eq!(
            reg.redeem(&req, b"hs", now).unwrap_err(),
            RejectReason::MalformedFrame
        );
    }

    #[test]
    fn sas_confirmation_times_out() {
        let (mut reg, joiner) = setup();
        let now = t0();
        let scanned = scan(&mut reg, now);
        let grant = reg
            .redeem(
                &PairingRequest::create(&scanned, joiner, "P", b""),
                b"",
                now,
            )
            .unwrap();
        let code = grant.expected_sas_for_tests();
        assert_eq!(
            grant
                .confirm_typed_code(&code, now.plus(SAS_CONFIRM_TTL_MS + 1))
                .unwrap_err(),
            RejectReason::SasTimeout
        );
    }

    #[test]
    fn stuck_rng_refused() {
        struct Zero;
        impl rand_core::RngCore for Zero {
            fn next_u32(&mut self) -> u32 {
                0
            }
            fn next_u64(&mut self) -> u64 {
                0
            }
            fn fill_bytes(&mut self, d: &mut [u8]) {
                d.fill(0)
            }
            fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> {
                d.fill(0);
                Ok(())
            }
        }
        impl rand_core::CryptoRng for Zero {}
        let (mut reg, _) = setup();
        assert_eq!(
            reg.issue(t0(), &mut Zero).unwrap_err(),
            RejectReason::Internal
        );
    }

    #[test]
    fn malformed_qr_rejected() {
        let now = Now {
            wall: UnixMillis(0),
            mono: MonoMillis(0),
        };
        let k = DeviceKeypair::generate().device_id().to_hex();
        let g = "00".repeat(32);
        let s = "11".repeat(16);
        let ok = format!("voidwire:pair?v=1&id={k}&g={g}&s={s}&exp=10");
        assert!(ScannedInvite::parse(&ok, now).is_ok());
        assert_eq!(
            ScannedInvite::parse(&format!("{ok}&s={s}"), now).unwrap_err(),
            RejectReason::MalformedFrame
        );
        assert_eq!(
            ScannedInvite::parse(&ok.replace("v=1", "v=2"), now).unwrap_err(),
            RejectReason::UnsupportedVersion
        );
        for qr in [
            "",
            "https://x",
            "voidwire:pair?v=1",
            &ok.replace("&exp=10", ""),
            &ok.replace(&k, "zz"),
        ] {
            assert!(ScannedInvite::parse(qr, now).is_err(), "{qr}");
        }
        assert!(!format!("{:?}", ScannedInvite::parse(&ok, now).unwrap()).contains(&s));
    }

    #[test]
    fn relay_url_validation_and_mailbox_qr_param() {
        let now = Now {
            wall: UnixMillis(0),
            mono: MonoMillis(0),
        };
        assert_eq!(validate_relay_url("").unwrap(), None);
        assert_eq!(validate_relay_url("off").unwrap(), None);
        assert_eq!(
            validate_relay_url("https://relay.voidwire.app").unwrap(),
            Some("https://relay.voidwire.app".to_string())
        );
        for bad in [
            "http://relay.voidwire.app",
            "https://localhost:443",
            "https://127.0.0.1:443",
            "https://10.0.0.1:443",
            "https://192.168.1.1:443",
            "https://172.16.0.1:443",
            "https://169.254.169.254:443",
            "https://[::1]:443",
            "https://user:pass@relay.voidwire.app",
            "https://relay.voidwire.app?x=1",
            "https://relay.voidwire.app#frag",
        ] {
            assert!(
                validate_relay_url(bad).is_err(),
                "expected {bad} to be rejected"
            );
        }

        let k = DeviceKeypair::generate().device_id().to_hex();
        let m_id = DeviceKeypair::generate().device_id();
        let g = "00".repeat(32);
        let s = "11".repeat(16);
        let qr = format!(
            "voidwire:pair?v=1&id={k}&g={g}&s={s}&exp=10&r=https%3A%2F%2Frelay.voidwire.app&m={}",
            m_id.to_hex()
        );
        let parsed = ScannedInvite::parse(&qr, now).unwrap();
        assert_eq!(parsed.relay_url, "https://relay.voidwire.app");
        assert_eq!(parsed.mailbox_peer, Some(m_id));

        let bad_qr =
            format!("voidwire:pair?v=1&id={k}&g={g}&s={s}&exp=10&r=http%3A%2F%2Fevil.example.com");
        assert_eq!(
            ScannedInvite::parse(&bad_qr, now).unwrap_err(),
            RejectReason::MalformedFrame
        );
    }
}
