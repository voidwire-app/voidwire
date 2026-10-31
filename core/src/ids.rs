#![forbid(unsafe_code)]
//! Identifiers. Public values, not secrets.

use crate::reject::RejectReason;
use ed25519_dalek::VerifyingKey;
use std::fmt;

/// A device's Ed25519 identity public key (in M1+ also its iroh EndpointId).
///
/// The bytes are private and only [`DeviceId::from_bytes`] constructs one, which
/// rejects encodings that are not valid curve points and **weak (small-order)
/// keys** (AUTH-10). So every `DeviceId` in the program is a usable, strong key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, RejectReason> {
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| RejectReason::BadSignature)?;
        if key.is_weak() {
            return Err(RejectReason::BadSignature);
        }
        Ok(DeviceId(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        crate::hex::encode(&self.0)
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        crate::hex::decode_array::<32>(s).and_then(|b| DeviceId::from_bytes(b).ok())
    }

    /// Short id for logs/UI ("a1b2c3d4"); never the whole key.
    pub fn short(&self) -> String {
        crate::hex::encode(&self.0[..4])
    }

    pub(crate) fn verifying_key(&self) -> Option<VerifyingKey> {
        VerifyingKey::from_bytes(&self.0).ok()
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({}…)", self.short())
    }
}

/// Group (one person's device set). In M4 this is the hash of the genesis op.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupId(pub [u8; 32]);

impl GroupId {
    pub fn to_hex(&self) -> String {
        crate::hex::encode(&self.0)
    }
    pub fn from_hex(s: &str) -> Option<Self> {
        crate::hex::decode_array::<32>(s).map(GroupId)
    }
}

impl fmt::Debug for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GroupId({}…)", crate::hex::encode(&self.0[..4]))
    }
}

/// Hash of the newest group-log op a device knows (its "head"). Carried in
/// every message so receivers can refuse senders that are behind (revocation).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogHead(pub [u8; 32]);

impl fmt::Debug for LogHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LogHead({}…)", crate::hex::encode(&self.0[..4]))
    }
}

/// 128-bit random message id (replay protection).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct MsgId(pub [u8; 16]);

impl MsgId {
    pub fn random() -> Self {
        Self::random_with(&mut rand_core::OsRng)
    }

    pub fn random_with(rng: &mut impl rand_core::CryptoRngCore) -> Self {
        let mut b = [0u8; 16];
        rng.fill_bytes(&mut b);
        MsgId(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_and_invalid_keys_rejected_at_parse() {
        // Identity point (small order).
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            DeviceId::from_bytes(identity),
            Err(RejectReason::BadSignature)
        );
        // All zeros: small-order point.
        assert_eq!(
            DeviceId::from_bytes([0u8; 32]),
            Err(RejectReason::BadSignature)
        );
        // Order-2 point (y = -1).
        let mut order2 = [0xffu8; 32];
        order2[0] = 0xec;
        order2[31] = 0x7f;
        assert_eq!(
            DeviceId::from_bytes(order2),
            Err(RejectReason::BadSignature)
        );
        // A real key parses.
        let k = crate::keys::DeviceKeypair::generate().device_id();
        assert_eq!(DeviceId::from_bytes(*k.as_bytes()), Ok(k));
        assert_eq!(DeviceId::from_hex(&k.to_hex()), Some(k));
    }
}
