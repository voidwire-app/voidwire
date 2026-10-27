#![forbid(unsafe_code)]
//! Device identity keys.
//!
//! M0: Ed25519 identity key only. M1 adds the X25519 receive key (signed by the
//! identity key, rotated monthly) and OS-keystore storage.

use crate::ids::DeviceId;
use ed25519_dalek::{Signature, Signer, SigningKey};
use rand_core::CryptoRngCore;

/// A device's long-term Ed25519 identity. The secret half never leaves core.
pub struct DeviceKeypair {
    signing: SigningKey,
    id: DeviceId,
}

impl DeviceKeypair {
    pub fn generate() -> Self {
        Self::generate_with(&mut rand_core::OsRng)
    }

    /// Injectable RNG (TEST-PLAN H-3). Production passes `OsRng`.
    pub fn generate_with(rng: &mut impl CryptoRngCore) -> Self {
        loop {
            let signing = SigningKey::generate(rng);
            if let Some(kp) = Self::from_signing(signing) {
                return kp;
            }
        }
    }

    /// Restore from stored secret bytes (M1: bytes come from the OS keystore).
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self::from_signing(SigningKey::from_bytes(secret))
            .expect("an Ed25519 public key derived from a secret scalar is never weak")
    }

    fn from_signing(signing: SigningKey) -> Option<Self> {
        let id = DeviceId::from_bytes(signing.verifying_key().to_bytes()).ok()?;
        Some(DeviceKeypair { signing, id })
    }

    pub fn device_id(&self) -> DeviceId {
        self.id
    }

    /// Sign arbitrary bytes. Callers outside core should use the typed
    /// encoders (`wire::encode_signed`); this exists so the test peer can
    /// forge frames with a real key.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }
}

impl std::fmt::Debug for DeviceKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeviceKeypair({:?}, secret redacted)", self.id)
    }
}

// ---------------------------------------------------------------------------
// Receive key (X25519, HPKE KEM key) and signed device certificates. M1.
// ---------------------------------------------------------------------------

use crate::reject::RejectReason;
use crate::time::UnixMillis;
use hpke::{Deserializable, Kem as _, Serializable};
use zeroize::Zeroizing;

/// Adapts our CSPRNG (rand_core 0.6) to the rand_core version `hpke` uses.
pub(crate) struct HpkeRng<'a, R: CryptoRngCore>(pub &'a mut R);

impl<R: CryptoRngCore> hpke::rand_core::RngCore for HpkeRng<'_, R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.fill_bytes(dst)
    }
}

impl<R: CryptoRngCore> hpke::rand_core::CryptoRng for HpkeRng<'_, R> {}

/// The one HPKE KEM we use (PROTOCOL §3): DHKEM(X25519, HKDF-SHA256).
pub(crate) type HpkeKem = hpke::kem::X25519HkdfSha256;

/// Public half of a receive key. Anyone holding it can seal *to* the device;
/// it proves nothing about the sender (HPKE base mode is not authentication).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceivePublicKey(pub [u8; 32]);

impl std::fmt::Debug for ReceivePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReceivePublicKey({})", crate::hex::encode(&self.0[..4]))
    }
}

impl ReceivePublicKey {
    pub(crate) fn to_hpke(self) -> Result<<HpkeKem as hpke::Kem>::PublicKey, RejectReason> {
        <HpkeKem as hpke::Kem>::PublicKey::from_bytes(&self.0)
            .map_err(|_| RejectReason::MalformedFrame)
    }
}

/// A device's X25519 receive key pair (envelopes are sealed to it). The secret
/// half never leaves core except as zeroizing bytes for the OS keystore.
pub struct ReceiveKeypair {
    sk: <HpkeKem as hpke::Kem>::PrivateKey,
    pk: ReceivePublicKey,
}

impl ReceiveKeypair {
    pub fn generate() -> Self {
        Self::generate_with(&mut rand_core::OsRng)
    }

    pub fn generate_with(rng: &mut impl CryptoRngCore) -> Self {
        // RFC 9180 DeriveKeyPair from 32 fresh bytes of our CSPRNG.
        let mut ikm = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut ikm[..]);
        let (sk, pk) = HpkeKem::derive_keypair(&ikm[..]);
        let mut b = [0u8; 32];
        b.copy_from_slice(&pk.to_bytes());
        ReceiveKeypair {
            sk,
            pk: ReceivePublicKey(b),
        }
    }

    /// Restore from stored secret bytes. `None` if the bytes are not a valid
    /// X25519 secret (never happens for bytes we wrote).
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Option<Self> {
        let sk = <HpkeKem as hpke::Kem>::PrivateKey::from_bytes(secret).ok()?;
        let pk = HpkeKem::sk_to_pk(&sk);
        let mut b = [0u8; 32];
        b.copy_from_slice(&pk.to_bytes());
        Some(ReceiveKeypair {
            sk,
            pk: ReceivePublicKey(b),
        })
    }

    /// Secret bytes for the OS keystore. Zeroized when dropped.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&self.sk.to_bytes());
        out
    }

    pub fn public(&self) -> ReceivePublicKey {
        self.pk
    }

    pub(crate) fn hpke_secret(&self) -> &<HpkeKem as hpke::Kem>::PrivateKey {
        &self.sk
    }
}

impl std::fmt::Debug for ReceiveKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReceiveKeypair({:?}, secret redacted)", self.pk)
    }
}

impl DeviceKeypair {
    /// Secret bytes for the OS keystore. Zeroized when dropped.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }
}

/// Domain tag for device-certificate signatures.
pub(crate) const TAG_DEVICE_CERT: &[u8] = b"voidwire/v1/device-cert\0";

const CERT_MAGIC: [u8; 4] = [b'V', b'W', crate::protocol::PROTOCOL_VERSION, b'C'];
const CERT_FIXED_LEN: usize = 4 + 32 + 32 + 1 + 8 + 1;

/// What kind of device a certificate describes (shown in device lists).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Unknown = 0,
    Android = 1,
    Windows = 2,
    Linux = 3,
    MacOs = 4,
    Ios = 5,
}

impl Platform {
    fn from_u8(b: u8) -> Platform {
        match b {
            1 => Platform::Android,
            2 => Platform::Windows,
            3 => Platform::Linux,
            4 => Platform::MacOs,
            5 => Platform::Ios,
            _ => Platform::Unknown,
        }
    }

    /// The platform this binary was built for.
    pub fn current() -> Platform {
        if cfg!(target_os = "android") {
            Platform::Android
        } else if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::MacOs
        } else if cfg!(target_os = "ios") {
            Platform::Ios
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else {
            Platform::Unknown
        }
    }
}

/// Device names: 1–64 bytes of UTF-8, no control characters (incl. bidi
/// controls, which UIs would otherwise have to isolate).
pub fn valid_device_name(name: &str) -> bool {
    !name.trim().is_empty()
        && name.len() <= crate::limits::MAX_DEVICE_NAME_BYTES
        && !name.chars().any(|c| {
            c.is_control()
                || matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{2028}' | '\u{2029}' | '\u{FEFF}')
        })
}

/// A device certificate: the identity key vouching for the device's receive
/// key, name and platform (PROTOCOL §1). Only produced by [`DeviceCert::issue`]
/// (our own) or [`DeviceCert::parse_verified`] (someone else's, signature
/// checked with `verify_strict`).
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceCert {
    device: DeviceId,
    receive: ReceivePublicKey,
    platform: Platform,
    issued_at: UnixMillis,
    name: String,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for DeviceCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCert")
            .field("device", &self.device)
            .field("platform", &self.platform)
            .finish_non_exhaustive()
    }
}

impl DeviceCert {
    /// Sign a certificate for our own device.
    pub fn issue(
        identity: &DeviceKeypair,
        receive: ReceivePublicKey,
        name: &str,
        platform: Platform,
        now: UnixMillis,
    ) -> Result<DeviceCert, RejectReason> {
        if !valid_device_name(name) {
            return Err(RejectReason::BadDeviceName);
        }
        let mut b = Vec::with_capacity(CERT_FIXED_LEN + name.len() + 64);
        b.extend_from_slice(&CERT_MAGIC);
        b.extend_from_slice(identity.device_id().as_bytes());
        b.extend_from_slice(&receive.0);
        b.push(platform as u8);
        b.extend_from_slice(&now.0.to_be_bytes());
        b.push(name.len() as u8);
        b.extend_from_slice(name.as_bytes());
        let mut input = TAG_DEVICE_CERT.to_vec();
        input.extend_from_slice(&b);
        b.extend_from_slice(&identity.sign(&input).to_bytes());
        Ok(DeviceCert {
            device: identity.device_id(),
            receive,
            platform,
            issued_at: now,
            name: name.to_owned(),
            bytes: b,
        })
    }

    /// Strict decode + `verify_strict` under the embedded device id.
    pub fn parse_verified(bytes: &[u8]) -> Result<DeviceCert, RejectReason> {
        if bytes.len() < CERT_FIXED_LEN + 1 + 64 || bytes.len() > CERT_FIXED_LEN + 64 + 64 {
            return Err(RejectReason::MalformedFrame);
        }
        if bytes[..4] != CERT_MAGIC {
            return Err(if bytes[..2] == CERT_MAGIC[..2] {
                RejectReason::UnsupportedVersion
            } else {
                RejectReason::MalformedFrame
            });
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes[4..36]);
        let device = DeviceId::from_bytes(id)?;
        let mut rk = [0u8; 32];
        rk.copy_from_slice(&bytes[36..68]);
        let platform = Platform::from_u8(bytes[68]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&bytes[69..77]);
        let name_len = bytes[77] as usize;
        if bytes.len() != CERT_FIXED_LEN + name_len + 64 {
            return Err(RejectReason::MalformedFrame);
        }
        let name = std::str::from_utf8(&bytes[CERT_FIXED_LEN..CERT_FIXED_LEN + name_len])
            .map_err(|_| RejectReason::MalformedFrame)?;
        if !valid_device_name(name) {
            return Err(RejectReason::BadDeviceName);
        }
        let signed = &bytes[..CERT_FIXED_LEN + name_len];
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes[CERT_FIXED_LEN + name_len..]);
        let mut input = TAG_DEVICE_CERT.to_vec();
        input.extend_from_slice(signed);
        device
            .verifying_key()
            .ok_or(RejectReason::BadSignature)?
            .verify_strict(&input, &Signature::from_bytes(&sig))
            .map_err(|_| RejectReason::BadSignature)?;
        let receive = ReceivePublicKey(rk);
        receive.to_hpke()?;
        Ok(DeviceCert {
            device,
            receive,
            platform,
            issued_at: UnixMillis(u64::from_be_bytes(ts)),
            name: name.to_owned(),
            bytes: bytes.to_vec(),
        })
    }

    pub fn device(&self) -> DeviceId {
        self.device
    }
    pub fn receive_key(&self) -> ReceivePublicKey {
        self.receive
    }
    pub fn platform(&self) -> Platform {
        self.platform
    }
    pub fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    /// The signed encoding (sent on the wire, stored, hashed into transcripts).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Secret key types wipe themselves on drop (QA M1 nit): ed25519-dalek's
/// `SigningKey` implements `ZeroizeOnDrop`; x25519-dalek's `StaticSecret`
/// (inside hpke's X25519 `PrivateKey`) gets a zeroizing `Drop` from its
/// `zeroize` feature, turned on in core/Cargo.toml. Compile-time checks, so a
/// feature change can't silently drop either.
const _: () = {
    // Without the feature StaticSecret is a plain [u8; 32] with no Drop.
    assert!(std::mem::needs_drop::<x25519_dalek::StaticSecret>());
    assert!(std::mem::needs_drop::<<HpkeKem as hpke::Kem>::PrivateKey>());
};

#[allow(dead_code)]
fn _secret_types_zeroize() {
    fn zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    fn zeroize<T: zeroize::Zeroize>() {}
    zeroize_on_drop::<ed25519_dalek::SigningKey>();
    zeroize::<x25519_dalek::StaticSecret>();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_key_roundtrip() {
        let k = ReceiveKeypair::generate();
        let k2 = ReceiveKeypair::from_secret_bytes(&k.secret_bytes()).unwrap();
        assert_eq!(k.public(), k2.public());
    }

    #[test]
    fn device_cert_sign_parse_and_tamper() {
        let id = DeviceKeypair::generate();
        let rk = ReceiveKeypair::generate();
        let c = DeviceCert::issue(
            &id,
            rk.public(),
            "Pixel 8",
            Platform::Android,
            UnixMillis(5),
        )
        .unwrap();
        let p = DeviceCert::parse_verified(c.as_bytes()).unwrap();
        assert_eq!(p, c);
        assert_eq!(p.name(), "Pixel 8");
        assert_eq!(p.receive_key(), rk.public());
        for i in 0..c.as_bytes().len() {
            let mut b = c.as_bytes().to_vec();
            b[i] ^= 1;
            assert!(DeviceCert::parse_verified(&b).is_err(), "byte {i}");
        }
        let mut longer = c.as_bytes().to_vec();
        longer.push(0);
        assert!(DeviceCert::parse_verified(&longer).is_err());
        for bad in ["", " ", "a\u{202E}b", "x\ny", &"n".repeat(65)] {
            assert_eq!(
                DeviceCert::issue(&id, rk.public(), bad, Platform::Android, UnixMillis(5)),
                Err(RejectReason::BadDeviceName)
            );
        }
    }
}
