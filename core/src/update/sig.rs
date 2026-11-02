//! Update signatures (U1): Ed25519 over a domain-separated manifest.
//!
//! Text formats, one line each, lowercase hex:
//!
//! * public key: `voidwire-update-pub-v1 <32-byte key>`
//! * signature:  `voidwire-update-sig-v1 <8-byte key id> <64-byte signature>`
//!
//! The key id is the first 8 bytes of SHA-256 over the public key; it picks
//! the key from the pinned list, it is not trusted on its own. The signed
//! message is [`DOMAIN`] followed by the manifest bytes exactly as served.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Prefix of every signed message, so an update key never signs anything
/// that means something elsewhere.
pub const DOMAIN: &[u8] = b"voidwire-update-v1\0";
pub const PUB_PREFIX: &str = "voidwire-update-pub-v1";
pub const SIG_PREFIX: &str = "voidwire-update-sig-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SigError {
    #[error("not a voidwire update signature")]
    Format,
    #[error("signed by a key this app does not trust")]
    UnknownKey,
    #[error("signature does not match")]
    Bad,
}

/// A trusted update public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", crate::hex::encode(&self.key_id()))
    }
}

impl PublicKey {
    /// Parse a `voidwire-update-pub-v1 <hex>` line.
    pub fn parse(line: &str) -> Option<PublicKey> {
        let mut it = line.split_ascii_whitespace();
        if it.next()? != PUB_PREFIX {
            return None;
        }
        let bytes = crate::hex::decode_array::<32>(it.next()?)?;
        if it.next().is_some() {
            return None;
        }
        VerifyingKey::from_bytes(&bytes).ok().map(PublicKey)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Option<PublicKey> {
        VerifyingKey::from_bytes(bytes).ok().map(PublicKey)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn to_line(&self) -> String {
        format!("{PUB_PREFIX} {}", crate::hex::encode(&self.0.to_bytes()))
    }

    pub fn key_id(&self) -> [u8; 8] {
        let d = Sha256::digest(self.0.as_bytes());
        let mut id = [0u8; 8];
        id.copy_from_slice(&d[..8]);
        id
    }
}

/// The public key of a 32-byte Ed25519 seed.
pub fn public_key(seed: &[u8; 32]) -> PublicKey {
    PublicKey(SigningKey::from_bytes(seed).verifying_key())
}

/// Sign `msg` (the manifest bytes) with a 32-byte seed; returns the
/// signature line, newline terminated.
pub fn sign(seed: &[u8; 32], msg: &[u8]) -> String {
    let sk = SigningKey::from_bytes(seed);
    let pk = PublicKey(sk.verifying_key());
    let mut m = Vec::with_capacity(DOMAIN.len() + msg.len());
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(msg);
    let sig = sk.sign(&m);
    format!(
        "{SIG_PREFIX} {} {}\n",
        crate::hex::encode(&pk.key_id()),
        crate::hex::encode(&sig.to_bytes())
    )
}

/// Check `sig_text` over `msg` against the pinned `keys`; returns the key
/// that signed.
pub fn verify(keys: &[PublicKey], msg: &[u8], sig_text: &str) -> Result<PublicKey, SigError> {
    let mut it = sig_text.split_ascii_whitespace();
    if it.next() != Some(SIG_PREFIX) {
        return Err(SigError::Format);
    }
    let id = it
        .next()
        .and_then(crate::hex::decode_array::<8>)
        .ok_or(SigError::Format)?;
    let sig = it
        .next()
        .and_then(crate::hex::decode_array::<64>)
        .ok_or(SigError::Format)?;
    if it.next().is_some() {
        return Err(SigError::Format);
    }
    let key = keys
        .iter()
        .find(|k| k.key_id() == id)
        .ok_or(SigError::UnknownKey)?;
    let mut m = Vec::with_capacity(DOMAIN.len() + msg.len());
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(msg);
    key.0
        .verify_strict(&m, &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| SigError::Bad)?;
    Ok(*key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [7; 32];
    const B: [u8; 32] = [9; 32];

    #[test]
    fn round_trip_and_key_list() {
        let (a, b) = (public_key(&A), public_key(&B));
        let s = sign(&A, b"manifest");
        assert_eq!(verify(&[a], b"manifest", &s), Ok(a));
        // Any key in the pinned list verifies (rotation, D3).
        assert_eq!(verify(&[b, a], b"manifest", &s), Ok(a));
        assert_eq!(verify(&[b], b"manifest", &s), Err(SigError::UnknownKey));
        assert_eq!(verify(&[], b"manifest", &s), Err(SigError::UnknownKey));
        assert_eq!(verify(&[a], b"manifesT", &s), Err(SigError::Bad));
    }

    #[test]
    fn domain_separated() {
        let a = public_key(&A);
        let raw = SigningKey::from_bytes(&A).sign(b"manifest");
        let forged = format!(
            "{SIG_PREFIX} {} {}",
            crate::hex::encode(&a.key_id()),
            crate::hex::encode(&raw.to_bytes())
        );
        assert_eq!(verify(&[a], b"manifest", &forged), Err(SigError::Bad));
    }

    #[test]
    fn formats() {
        let a = public_key(&A);
        assert_eq!(PublicKey::parse(&a.to_line()), Some(a));
        assert_eq!(PublicKey::parse(&format!("  {}  ", a.to_line())), Some(a));
        assert_eq!(PublicKey::parse("voidwire-update-pub-v1 00"), None);
        assert_eq!(PublicKey::parse(&a.to_line().replace("-v1", "-v2")), None);
        let s = sign(&A, b"x");
        assert!(s.ends_with('\n'));
        assert_eq!(verify(&[a], b"x", s.trim()), Ok(a));
        assert_eq!(verify(&[a], b"x", ""), Err(SigError::Format));
        assert_eq!(
            verify(&[a], b"x", &format!("{s} extra")),
            Err(SigError::Format)
        );
        // Flip a bit in the signature itself.
        let mut bad = s.trim().to_owned();
        let last = bad.pop().unwrap();
        bad.push(if last == '0' { '1' } else { '0' });
        assert_eq!(verify(&[a], b"x", &bad), Err(SigError::Bad));
    }
}
