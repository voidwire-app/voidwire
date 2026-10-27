#![forbid(unsafe_code)]
//! Encryption envelope (docs/PROTOCOL.md §3).
//!
//! HPKE (RFC 9180) **base mode**, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
//! ChaCha20-Poly1305, sealed to the recipient device's receive key, using the
//! `hpke` crate (rust-hpke, audited by NCC Group). No other suite, no fallback.
//!
//! ```text
//! envelope = header(4) || enc(32) || ciphertext(padded_len + 16)
//! header   = 'V' 'W' version(=1) suite(=1)        (also the HPKE aad)
//! info     = "voidwire/v1/envelope\0" || recipient DeviceId
//! padded   = u32 BE body_len || body || zero padding to a bucket (PAD_BUCKETS)
//! ```
//!
//! HPKE base mode is **not** sender authentication: anyone with the receive
//! public key can seal. Authentication is the inner Ed25519 signature
//! (`wire`) plus the transport binding (`Inbox::receive` step 3).
//!
//! **Release gate (ENV-16).** `ENCRYPTION_IMPLEMENTED` is `true` since M1 and
//! the crate refuses to compile if it is ever set back to `false`; the M0
//! unencrypted preview feature is retired. `seal` output never contains the
//! plaintext (`sealed_bytes_never_contain_the_url_env_16`).

use crate::ids::DeviceId;
use crate::keys::{HpkeKem, ReceiveKeypair, ReceivePublicKey};
use crate::reject::RejectReason;
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, Deserializable, OpModeR, OpModeS, Serializable,
};
use rand_core::CryptoRngCore;

/// HPKE envelope encryption is implemented (M1). Must stay `true`.
pub const ENCRYPTION_IMPLEMENTED: bool = true;

const _ENCRYPTION_GATE: () = assert!(
    ENCRYPTION_IMPLEMENTED,
    "voidwire-core: envelope encryption must be on; there is no unencrypted build"
);

/// Domain separation for the HPKE `info` parameter.
pub(crate) const TAG_ENVELOPE: &[u8] = b"voidwire/v1/envelope\0";

/// Envelope format version and the only HPKE suite we accept.
pub const ENVELOPE_VERSION: u8 = crate::protocol::PROTOCOL_VERSION;
pub const SUITE_X25519_SHA256_CHACHA: u8 = 1;
pub const HEADER: [u8; 4] = [b'V', b'W', ENVELOPE_VERSION, SUITE_X25519_SHA256_CHACHA];

const ENC_LEN: usize = 32;
const TAG_LEN: usize = 16;
/// Bytes an envelope adds on top of the padded plaintext.
pub const OVERHEAD: usize = HEADER.len() + ENC_LEN + TAG_LEN;

/// Size of the 4-byte length prefix inside the padded plaintext.
const FRAME_PREFIX: usize = 4;

/// Padded plaintext sizes (decision: 512/1K/2K/4K/8K). The last bucket is
/// "8K + fixed header" so that a full 8 KiB URL (MAX_URL_BYTES) plus the
/// 222-byte header/signature and 4-byte prefix still fits.
pub const PAD_BUCKETS: [usize; 6] = [512, 1024, 2048, 4096, 8192, 8192 + 256];

/// Largest padded plaintext.
pub const MAX_PADDED_LEN: usize = PAD_BUCKETS[PAD_BUCKETS.len() - 1];
/// Largest envelope on the wire.
pub const MAX_ENVELOPE_LEN: usize = MAX_PADDED_LEN + OVERHEAD;

const _: () = assert!(FRAME_PREFIX + crate::wire::MAX_BODY_LEN <= MAX_PADDED_LEN);

/// Smallest bucket that holds `n` bytes, or `None` if larger than the top bucket.
pub const fn padded_len(n: usize) -> Option<usize> {
    let mut i = 0;
    while i < PAD_BUCKETS.len() {
        if n <= PAD_BUCKETS[i] {
            return Some(PAD_BUCKETS[i]);
        }
        i += 1;
    }
    None
}

fn info_for(recipient: &DeviceId) -> Vec<u8> {
    let mut info = Vec::with_capacity(TAG_ENVELOPE.len() + 32);
    info.extend_from_slice(TAG_ENVELOPE);
    info.extend_from_slice(recipient.as_bytes());
    info
}

/// Frame + pad `body` (strict format, see module docs).
pub fn pad(body: &[u8]) -> Result<Vec<u8>, RejectReason> {
    let total = padded_len(FRAME_PREFIX + body.len()).ok_or(RejectReason::UrlTooLong)?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out.resize(total, 0);
    Ok(out)
}

/// Strict unpad + unframe.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, RejectReason> {
    if padded.len() > MAX_PADDED_LEN || padded_len(padded.len()) != Some(padded.len()) {
        return Err(RejectReason::MalformedFrame);
    }
    let n = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if n > padded.len() - FRAME_PREFIX || padded_len(FRAME_PREFIX + n) != Some(padded.len()) {
        return Err(RejectReason::MalformedFrame);
    }
    if padded[FRAME_PREFIX + n..].iter().any(|&b| b != 0) {
        return Err(RejectReason::MalformedFrame);
    }
    Ok(padded[FRAME_PREFIX..FRAME_PREFIX + n].to_vec())
}

/// Pad `body` and HPKE-seal it to `recipient` (its device id and receive key).
pub fn seal(
    recipient: &DeviceId,
    recipient_key: &ReceivePublicKey,
    body: &[u8],
) -> Result<Vec<u8>, RejectReason> {
    seal_with(recipient, recipient_key, body, &mut rand_core::OsRng)
}

/// [`seal`] with an injectable RNG (tests).
pub fn seal_with(
    recipient: &DeviceId,
    recipient_key: &ReceivePublicKey,
    body: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>, RejectReason> {
    let padded = pad(body)?;
    let pk = recipient_key.to_hpke()?;
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, HpkeKem, _>(
        &OpModeS::Base,
        &pk,
        &info_for(recipient),
        &padded,
        &HEADER,
        &mut crate::keys::HpkeRng(rng),
    )
    .map_err(|_| RejectReason::Internal)?;
    let mut out = Vec::with_capacity(OVERHEAD + padded.len());
    out.extend_from_slice(&HEADER);
    out.extend_from_slice(&enc.to_bytes());
    out.extend_from_slice(&ct);
    debug_assert_eq!(out.len(), OVERHEAD + padded.len());
    Ok(out)
}

/// Check the envelope's outer shape without any crypto: known header and a
/// length that is exactly one bucket plus overhead. Cheap; run before `open`.
pub fn check_shape(envelope: &[u8]) -> Result<(), RejectReason> {
    if envelope.len() < OVERHEAD + PAD_BUCKETS[0] || envelope.len() > MAX_ENVELOPE_LEN {
        return Err(RejectReason::MalformedFrame);
    }
    if envelope[..2] != HEADER[..2] {
        return Err(RejectReason::MalformedFrame);
    }
    if envelope[2] != ENVELOPE_VERSION || envelope[3] != SUITE_X25519_SHA256_CHACHA {
        return Err(RejectReason::UnsupportedVersion);
    }
    let padded = envelope.len() - OVERHEAD;
    if padded_len(padded) != Some(padded) {
        return Err(RejectReason::MalformedFrame);
    }
    Ok(())
}

/// Open an envelope addressed to `self_id` with our receive key, then strictly
/// unpad. Shape errors → `MalformedFrame` / `UnsupportedVersion`; any HPKE
/// failure (wrong key, wrong recipient id, any flipped bit) → `DecryptFailed`.
pub fn open(
    receive: &ReceiveKeypair,
    self_id: &DeviceId,
    envelope: &[u8],
) -> Result<Vec<u8>, RejectReason> {
    check_shape(envelope)?;
    let enc = <HpkeKem as hpke::Kem>::EncappedKey::from_bytes(&envelope[4..4 + ENC_LEN])
        .map_err(|_| RejectReason::DecryptFailed)?;
    let padded = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, HpkeKem>(
        &OpModeR::Base,
        receive.hpke_secret(),
        &enc,
        &info_for(self_id),
        &envelope[4 + ENC_LEN..],
        &HEADER,
    )
    .map_err(|_| RejectReason::DecryptFailed)?;
    unpad(&padded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceKeypair;

    fn pair() -> (DeviceId, ReceiveKeypair) {
        (
            DeviceKeypair::generate().device_id(),
            ReceiveKeypair::generate(),
        )
    }

    #[test]
    fn padding_buckets() {
        assert_eq!(padded_len(1), Some(512));
        assert_eq!(padded_len(513), Some(1024));
        assert_eq!(padded_len(4096), Some(4096));
        assert_eq!(padded_len(4097), Some(8192));
        assert_eq!(padded_len(8193), Some(8448));
        assert_eq!(padded_len(8449), None);
    }

    #[test]
    fn strict_unpad() {
        let e = pad(b"hello").unwrap();
        assert_eq!(e.len(), 512);
        assert_eq!(unpad(&e).unwrap(), b"hello");
        let mut nonzero_pad = e.clone();
        nonzero_pad[100] = 1;
        assert_eq!(unpad(&nonzero_pad), Err(RejectReason::MalformedFrame));
        assert_eq!(unpad(&e[..511]), Err(RejectReason::MalformedFrame));
        assert_eq!(unpad(&[]), Err(RejectReason::MalformedFrame));
        let mut long_len = e.clone();
        long_len[..4].copy_from_slice(&600u32.to_be_bytes());
        assert_eq!(unpad(&long_len), Err(RejectReason::MalformedFrame));
        let mut wrong_bucket = pad(b"hi").unwrap();
        wrong_bucket.resize(1024, 0);
        assert_eq!(unpad(&wrong_bucket), Err(RejectReason::MalformedFrame));
        assert_eq!(
            unpad(&vec![0u8; MAX_PADDED_LEN + 1]),
            Err(RejectReason::MalformedFrame)
        );
    }

    #[test]
    fn roundtrip_and_sizes_are_bucketed() {
        let (id, rk) = pair();
        for (n, padded) in [
            (1, 512),
            (508, 512),
            (509, 1024),
            (8000, 8192),
            (8300, 8448),
        ] {
            let body = vec![7u8; n];
            let e = seal(&id, &rk.public(), &body).unwrap();
            assert_eq!(e.len(), padded + OVERHEAD, "body {n}");
            assert_eq!(open(&rk, &id, &e).unwrap(), body);
        }
        assert_eq!(
            seal(&id, &rk.public(), &vec![0u8; 8445]),
            Err(RejectReason::UrlTooLong)
        );
    }

    #[test]
    fn sealed_bytes_never_contain_the_url_env_16() {
        let (id, rk) = pair();
        let marker = b"https://marker.example/ENV-16-PLAINTEXT-MARKER";
        let e = seal(&id, &rk.public(), marker).unwrap();
        assert!(!e.windows(marker.len()).any(|w| w == marker));
        assert!(!e.windows(12).any(|w| w == &marker[..12]));
        // Two seals of the same body differ (fresh ephemeral key each time).
        assert_ne!(e, seal(&id, &rk.public(), marker).unwrap());
    }

    #[test]
    fn tamper_anywhere_is_rejected_env_08() {
        let (id, rk) = pair();
        let e = seal(&id, &rk.public(), b"https://example.com/").unwrap();
        for bit in 0..e.len() * 8 {
            let mut t = e.clone();
            t[bit / 8] ^= 1 << (bit % 8);
            let r = open(&rk, &id, &t);
            let expect_header = bit < 32;
            match r {
                Err(RejectReason::DecryptFailed) => assert!(!expect_header, "bit {bit}"),
                Err(RejectReason::MalformedFrame) | Err(RejectReason::UnsupportedVersion) => {
                    assert!(expect_header, "bit {bit}")
                }
                other => panic!("bit {bit}: {other:?}"),
            }
        }
    }

    #[test]
    fn truncation_and_extension_rejected_env_09() {
        let (id, rk) = pair();
        let e = seal(&id, &rk.public(), b"https://example.com/").unwrap();
        for cut in 0..e.len() {
            assert!(open(&rk, &id, &e[..cut]).is_err());
        }
        for extra in [1usize, 1024, 1 << 20] {
            let mut x = e.clone();
            x.resize(e.len() + extra, 0);
            assert!(open(&rk, &id, &x).is_err());
        }
    }

    #[test]
    fn wrong_recipient_key_or_id_fails_env_10() {
        let (id, rk) = pair();
        let (other_id, other_rk) = pair();
        let e = seal(&id, &rk.public(), b"https://example.com/").unwrap();
        // Another device's key.
        assert_eq!(open(&other_rk, &id, &e), Err(RejectReason::DecryptFailed));
        // Right key, but the envelope was bound to a different recipient id.
        assert_eq!(open(&rk, &other_id, &e), Err(RejectReason::DecryptFailed));
    }

    #[test]
    fn version_and_suite_downgrade_rejected_env_12() {
        let (id, rk) = pair();
        let e = seal(&id, &rk.public(), b"https://example.com/").unwrap();
        for (i, v) in [(2usize, 0u8), (2, 2), (2, 255), (3, 0), (3, 2), (3, 255)] {
            let mut t = e.clone();
            t[i] = v;
            assert_eq!(open(&rk, &id, &t), Err(RejectReason::UnsupportedVersion));
        }
    }
}
