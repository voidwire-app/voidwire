#![forbid(unsafe_code)]
//! M2 blind group-log mailbox crypto, epoch secrets (`gs_e`), owner seal root,
//! record padding/encryption, tombstones, and signed `voidwire-config` v1
//! (`docs/PROTOCOL.md` §7.1, `docs/M2-PLAN.md` rev. 3 §2.3 & §6b).
//!
//! All domain-separation tags are registered in [`crate::protocol::DOMAIN_TAGS`]
//! and checked against the source by `domain_tag_list_matches_the_source`.

use std::fmt;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hpke::{
    aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305, kdf::HkdfSha256, Deserializable, OpModeR,
    OpModeS, Serializable,
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::ids::{DeviceId, GroupId};
use crate::keys::{HpkeKem, HpkeRng, ReceiveKeypair, ReceivePublicKey};
use crate::reject::RejectReason;

/// Domain tag for deriving `k_mb_enc` from `gs_e` (and sealing state secrets).
pub const TAG_MAILBOX_ENC: &[u8] = b"voidwire/v1/mailbox-enc\0";
/// Domain tag for per-device wrapping of `gs_{e+1}` in a `rekey` op / `WELCOME`.
pub const TAG_EPOCH_KEY: &[u8] = b"voidwire/v1/epoch-key\0";
/// Domain tag for signed `voidwire-config` v1 (`docs/M2-PLAN.md` §6b).
pub const TAG_CONFIG: &[u8] = b"voidwire/v1/config\0";
/// Domain tag prefix for the per-device blind RAM inbox HKDF info (`M3-PLAN.md` §1.3.1).
pub const TAG_DEVICE_INBOX_INFO: &[u8] = b"voidwire/v1/device-inbox\0";
/// Domain tag (HKDF salt) for deriving `DeviceInboxId` (`M3-PLAN.md` §1.3.1).
pub const TAG_DEVICE_INBOX_ID: &[u8] = b"voidwire/v1/device-inbox-id\0";
/// Domain tag (HKDF salt) for deriving the device-inbox write signing seed (`M3-PLAN.md` §1.3.1).
pub const TAG_DEVICE_INBOX_WRITE: &[u8] = b"voidwire/v1/device-inbox-write\0";
/// Domain tag for hashing the device-inbox write verifying key (`M3-PLAN.md` §1.3.1).
pub const TAG_DEVICE_INBOX_WRITE_VERIFIER: &[u8] = b"voidwire/v1/device-inbox-write-verifier\0";
/// Domain tag (HKDF salt) for deriving the device-inbox read/ack signing seed (`M3-PLAN.md` §1.3.1).
pub const TAG_DEVICE_INBOX_READ: &[u8] = b"voidwire/v1/device-inbox-read\0";
/// Domain tag for hashing the device-inbox read/ack verifying key (`M3-PLAN.md` §1.3.1).
pub const TAG_DEVICE_INBOX_READ_VERIFIER: &[u8] = b"voidwire/v1/device-inbox-read-verifier\0";
/// Domain tag for `INBOX_PUT` write signatures (`M3-PLAN.md` §1.3.1).
pub const TAG_DEVICE_INBOX_PUT: &[u8] = b"voidwire/v1/device-inbox-put\0";
/// Domain tag for `INBOX_PULL` read signatures (`M3-PLAN.md` §1.3.1).
pub const TAG_DEVICE_INBOX_PULL: &[u8] = b"voidwire/v1/device-inbox-pull\0";
/// Domain tag for `INBOX_ACK` ack signatures (`M3-PLAN.md` §1.3.1).
pub const TAG_DEVICE_INBOX_ACK: &[u8] = b"voidwire/v1/device-inbox-ack\0";

/// Maximum wire frame payload on `voidwire/v1/mailbox` (`5 MiB`), large enough
/// to carry a full 512-record `CREATE` or `ROTATE` re-seed frame (`M2-L1`).
pub const MAX_MAILBOX_WIRE_FRAME: usize = 5 * 1024 * 1024;
/// Fixed size of a HPKE-wrapped `EpochSecret` (`enc[32] || ct[32 + 16]`).
pub const WRAPPED_EPOCH_SECRET_LEN: usize = 32 + 32 + 16;

/// Opaque 32-byte mailbox handle (`HKDF-Expand(gs_e, TAG_MAILBOX_ID, 32)`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MailboxId(pub [u8; 32]);

impl MailboxId {
    pub fn to_hex(&self) -> String {
        crate::hex::encode(&self.0)
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        crate::hex::decode_array::<32>(s).map(MailboxId)
    }
}

impl fmt::Debug for MailboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MailboxId({})", crate::hex::encode(&self.0[..4]))
    }
}

/// 256-bit group epoch secret (`gs_e`). Held by active group members in epoch `e`.
/// Zeroized on drop and redacted in `Debug`.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EpochSecret([u8; 32]);

impl EpochSecret {
    pub fn generate() -> Self {
        Self::generate_with(&mut rand_core::OsRng)
    }

    pub fn generate_with(rng: &mut impl CryptoRngCore) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        EpochSecret(b)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        EpochSecret(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive the group-bound epoch key `HKDF-Expand(gs_e, TAG_EPOCH_KEY || group_id || u64_be(epoch), 32)`.
    pub fn derive_group_epoch_key(&self, group: &GroupId, epoch: u64) -> Zeroizing<[u8; 32]> {
        derive_epoch_key(&self.0, group, epoch)
    }

    /// Derive the unlinkable per-device blind RAM inbox identifier, write signing keypair,
    /// and read/ack signing keypair for `(group, epoch, recipient_id, recipient_receive_pk)`
    /// (`M3-PLAN.md` §1.3.2).
    pub fn derive_device_inbox_keys(
        &self,
        group: &GroupId,
        epoch: u64,
        recipient_id: &DeviceId,
        recipient_receive_pk: &ReceivePublicKey,
    ) -> DeviceInboxKeys {
        let mut info = Vec::with_capacity(TAG_DEVICE_INBOX_INFO.len() + 32 + 8 + 32 + 32);
        info.extend_from_slice(TAG_DEVICE_INBOX_INFO);
        info.extend_from_slice(&group.0);
        info.extend_from_slice(&epoch.to_be_bytes());
        info.extend_from_slice(recipient_id.as_bytes());
        info.extend_from_slice(&recipient_receive_pk.0);

        let hk_id = Hkdf::<Sha256>::new(Some(TAG_DEVICE_INBOX_ID), &self.0);
        let mut id_bytes = [0u8; 32];
        hk_id
            .expand(&info, &mut id_bytes)
            .expect("32 bytes is valid HKDF output");

        let hk_write = Hkdf::<Sha256>::new(Some(TAG_DEVICE_INBOX_WRITE), &self.0);
        let mut write_seed = Zeroizing::new([0u8; 32]);
        hk_write
            .expand(&info, &mut write_seed[..])
            .expect("32 bytes is valid HKDF output");
        let write_signing_key = SigningKey::from_bytes(&write_seed);
        let write_verifying_key = write_signing_key.verifying_key().to_bytes();
        let write_verifier = compute_device_inbox_write_verifier(&write_verifying_key);

        let hk_read = Hkdf::<Sha256>::new(Some(TAG_DEVICE_INBOX_READ), &self.0);
        let mut read_seed = Zeroizing::new([0u8; 32]);
        hk_read
            .expand(&info, &mut read_seed[..])
            .expect("32 bytes is valid HKDF output");
        let read_signing_key = SigningKey::from_bytes(&read_seed);
        let read_verifying_key = read_signing_key.verifying_key().to_bytes();
        let read_verifier = compute_device_inbox_read_verifier(&read_verifying_key);

        DeviceInboxKeys {
            inbox_id: DeviceInboxId(id_bytes),
            write_signing_key,
            write_verifying_key,
            write_verifier,
            read_signing_key,
            read_verifying_key,
            read_verifier,
        }
    }
}

impl fmt::Debug for EpochSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EpochSecret(<redacted>)")
    }
}

/// `SHA-256(TAG_DEVICE_INBOX_WRITE_VERIFIER || write_verifying_key)` stored in RAM by `voidwire-mailbox`.
pub fn compute_device_inbox_write_verifier(write_verifying_key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TAG_DEVICE_INBOX_WRITE_VERIFIER);
    h.update(write_verifying_key);
    h.finalize().into()
}

/// `SHA-256(TAG_DEVICE_INBOX_READ_VERIFIER || read_verifying_key)` stored in RAM by `voidwire-mailbox`.
pub fn compute_device_inbox_read_verifier(read_verifying_key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TAG_DEVICE_INBOX_READ_VERIFIER);
    h.update(read_verifying_key);
    h.finalize().into()
}

/// Unlinkable 32-byte per-device blind RAM inbox identifier (`M3-PLAN.md` §1.3.2).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceInboxId(pub [u8; 32]);

impl DeviceInboxId {
    pub fn to_hex(&self) -> String {
        crate::hex::encode(&self.0)
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        crate::hex::decode_array::<32>(s).map(DeviceInboxId)
    }
}

impl fmt::Debug for DeviceInboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceInboxId({})", crate::hex::encode(&self.0[..4]))
    }
}

/// Per-device blind RAM inbox capabilities derived from [`EpochSecret`] (`M3-PLAN.md` §1.3.2).
pub struct DeviceInboxKeys {
    pub inbox_id: DeviceInboxId,
    write_signing_key: SigningKey,
    pub write_verifying_key: [u8; 32],
    pub write_verifier: [u8; 32],
    read_signing_key: SigningKey,
    pub read_verifying_key: [u8; 32],
    pub read_verifier: [u8; 32],
}

impl DeviceInboxKeys {
    pub fn sign_put(&self, item_id: &[u8; 16], envelope: &[u8]) -> [u8; 64] {
        let msg = inbox_put_sig_input(
            &self.inbox_id,
            item_id,
            &self.write_verifying_key,
            &self.read_verifier,
            envelope,
        );
        self.write_signing_key.sign(&msg).to_bytes()
    }

    pub fn sign_pull(&self, nonce: &[u8; 16]) -> [u8; 64] {
        let msg = inbox_pull_sig_input(&self.inbox_id, nonce, &self.read_verifying_key);
        self.read_signing_key.sign(&msg).to_bytes()
    }

    pub fn sign_ack(&self, item_ids: &[[u8; 16]]) -> [u8; 64] {
        let msg = inbox_ack_sig_input(&self.inbox_id, &self.read_verifying_key, item_ids);
        self.read_signing_key.sign(&msg).to_bytes()
    }

    pub fn build_put_req(
        &self,
        item_id: [u8; 16],
        envelope: Vec<u8>,
    ) -> Result<InboxPutReq, RejectReason> {
        crate::envelope::check_shape(&envelope)?;
        let sig_write = self.sign_put(&item_id, &envelope);
        Ok(InboxPutReq {
            inbox_id: self.inbox_id,
            item_id,
            write_verifying_key: self.write_verifying_key,
            read_verifier: self.read_verifier,
            envelope: Zeroizing::new(envelope),
            sig_write,
        })
    }

    pub fn build_pull_req(&self, nonce: [u8; 16]) -> InboxPullReq {
        let sig_read = self.sign_pull(&nonce);
        InboxPullReq {
            inbox_id: self.inbox_id,
            nonce,
            read_verifying_key: self.read_verifying_key,
            sig_read,
        }
    }

    pub fn build_ack_req(&self, item_ids: Vec<[u8; 16]>) -> Result<InboxAckReq, RejectReason> {
        if item_ids.is_empty() || item_ids.len() > 64 {
            return Err(RejectReason::MalformedFrame);
        }
        let sig_read = self.sign_ack(&item_ids);
        Ok(InboxAckReq {
            inbox_id: self.inbox_id,
            read_verifying_key: self.read_verifying_key,
            item_ids,
            sig_read,
        })
    }
}

impl fmt::Debug for DeviceInboxKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceInboxKeys")
            .field("inbox_id", &self.inbox_id)
            .finish_non_exhaustive()
    }
}

/// HKDF-Expand helper for deriving a 32-byte key from a shared secret under
/// `TAG_EPOCH_KEY || group_id || u64_be(epoch)` (`docs/PROTOCOL.md` §7.1(a)).
pub fn derive_epoch_key(
    shared_secret: &[u8; 32],
    group: &GroupId,
    epoch: u64,
) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::from_prk(shared_secret).expect("32-byte PRK");
    let info = epoch_key_info(group, epoch);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut out[..]).expect("32-byte HKDF output");
    out
}

fn epoch_key_info(group: &GroupId, epoch: u64) -> Vec<u8> {
    let mut info = Vec::with_capacity(TAG_EPOCH_KEY.len() + 32 + 8);
    info.extend_from_slice(TAG_EPOCH_KEY);
    info.extend_from_slice(&group.0);
    info.extend_from_slice(&epoch.to_be_bytes());
    info
}

/// One device's HPKE-wrapped `gs_e` entry in a `rekey` op or `WELCOME`.
#[derive(Clone, PartialEq, Eq)]
pub struct WrappedEpochKey {
    pub recipient: DeviceId,
    pub sealed: [u8; WRAPPED_EPOCH_SECRET_LEN],
}

impl fmt::Debug for WrappedEpochKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WrappedEpochKey")
            .field("recipient", &self.recipient)
            .finish_non_exhaustive()
    }
}

/// Seal `gs` to `recipient` (`recipient_pk`) for `(group, epoch)` using HPKE
/// base mode (`DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305`).
pub fn wrap_epoch_secret(
    recipient: &DeviceId,
    recipient_pk: &ReceivePublicKey,
    group: &GroupId,
    epoch: u64,
    gs: &EpochSecret,
) -> Result<WrappedEpochKey, RejectReason> {
    wrap_epoch_secret_with(
        recipient,
        recipient_pk,
        group,
        epoch,
        gs,
        &mut rand_core::OsRng,
    )
}

/// [`wrap_epoch_secret`] with an injectable CSPRNG (for deterministic KATs).
pub fn wrap_epoch_secret_with(
    recipient: &DeviceId,
    recipient_pk: &ReceivePublicKey,
    group: &GroupId,
    epoch: u64,
    gs: &EpochSecret,
    rng: &mut impl CryptoRngCore,
) -> Result<WrappedEpochKey, RejectReason> {
    let pk = recipient_pk.to_hpke()?;
    let info = epoch_key_info(group, epoch);
    let (enc, ct) = hpke::single_shot_seal::<HpkeChaCha20Poly1305, HkdfSha256, HpkeKem, _>(
        &OpModeS::Base,
        &pk,
        &info,
        gs.as_bytes(),
        recipient.as_bytes(),
        &mut HpkeRng(rng),
    )
    .map_err(|_| RejectReason::Internal)?;
    let mut sealed = [0u8; WRAPPED_EPOCH_SECRET_LEN];
    sealed[..32].copy_from_slice(&enc.to_bytes());
    sealed[32..].copy_from_slice(&ct);
    Ok(WrappedEpochKey {
        recipient: *recipient,
        sealed,
    })
}

/// Open a [`WrappedEpochKey`] addressed to `self_id` using `receive`.
pub fn unwrap_epoch_secret(
    receive: &ReceiveKeypair,
    self_id: &DeviceId,
    group: &GroupId,
    epoch: u64,
    sealed: &[u8],
) -> Result<EpochSecret, RejectReason> {
    if sealed.len() != WRAPPED_EPOCH_SECRET_LEN {
        return Err(RejectReason::MalformedFrame);
    }
    let enc = <HpkeKem as hpke::Kem>::EncappedKey::from_bytes(&sealed[..32])
        .map_err(|_| RejectReason::DecryptFailed)?;
    let info = epoch_key_info(group, epoch);
    let pt = Zeroizing::new(
        hpke::single_shot_open::<HpkeChaCha20Poly1305, HkdfSha256, HpkeKem>(
            &OpModeR::Base,
            receive.hpke_secret(),
            &enc,
            &info,
            &sealed[32..],
            self_id.as_bytes(),
        )
        .map_err(|_| RejectReason::DecryptFailed)?,
    );
    let arr: [u8; 32] = pt[..].try_into().map_err(|_| RejectReason::DecryptFailed)?;
    Ok(EpochSecret::from_bytes(arr))
}

/// Payload carried inside a `SignedOp` of kind `OpKind::Rekey` (`docs/PROTOCOL.md` §7.1(c)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyPayload {
    pub new_epoch: u64,
    pub removed: DeviceId,
    pub wrapped_keys: Vec<WrappedEpochKey>,
}

/// Maximum number of active member wrapped keys in one `RekeyPayload`.
pub const MAX_REKEY_WRAPPED_KEYS: usize = 16;

impl RekeyPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            8 + 32 + 2 + self.wrapped_keys.len() * (32 + WRAPPED_EPOCH_SECRET_LEN),
        );
        out.extend_from_slice(&self.new_epoch.to_be_bytes());
        out.extend_from_slice(self.removed.as_bytes());
        out.extend_from_slice(&(self.wrapped_keys.len() as u16).to_be_bytes());
        for w in &self.wrapped_keys {
            out.extend_from_slice(w.recipient.as_bytes());
            out.extend_from_slice(&w.sealed);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, RejectReason> {
        if b.len() < 8 + 32 + 2 {
            return Err(RejectReason::BadLogOp);
        }
        let new_epoch = u64::from_be_bytes(b[..8].try_into().expect("8"));
        let removed = DeviceId::from_bytes(b[8..40].try_into().expect("32"))
            .map_err(|_| RejectReason::BadLogOp)?;
        let count = u16::from_be_bytes([b[40], b[41]]) as usize;
        if count > MAX_REKEY_WRAPPED_KEYS {
            return Err(RejectReason::BadLogOp);
        }
        let item_len = 32 + WRAPPED_EPOCH_SECRET_LEN;
        if b.len() != 42 + count * item_len {
            return Err(RejectReason::BadLogOp);
        }
        let mut wrapped_keys = Vec::with_capacity(count);
        let mut o = 42;
        for _ in 0..count {
            let recipient = DeviceId::from_bytes(b[o..o + 32].try_into().expect("32"))
                .map_err(|_| RejectReason::BadLogOp)?;
            let sealed: [u8; WRAPPED_EPOCH_SECRET_LEN] =
                b[o + 32..o + item_len].try_into().expect("80");
            wrapped_keys.push(WrappedEpochKey { recipient, sealed });
            o += item_len;
        }
        Ok(RekeyPayload {
            new_epoch,
            removed,
            wrapped_keys,
        })
    }

    /// Find and unwrap the new epoch secret for `self_id`.
    pub fn unwrap_for(
        &self,
        receive: &ReceiveKeypair,
        self_id: &DeviceId,
        group: &GroupId,
    ) -> Result<Option<EpochSecret>, RejectReason> {
        let Some(w) = self.wrapped_keys.iter().find(|w| w.recipient == *self_id) else {
            return Ok(None);
        };
        unwrap_epoch_secret(receive, self_id, group, self.new_epoch, &w.sealed).map(Some)
    }
}

// ---------------------------------------------------------------------------
// Signed `voidwire-config` v1 (`docs/M2-PLAN.md` rev. 3 §6b)
// ---------------------------------------------------------------------------

/// Version of the signed server configuration document.
pub const CONFIG_VERSION: u8 = 1;
/// Default relay-fallback file cap (`25 MiB`, `docs/M2-PLAN.md` §6b).
pub const DEFAULT_RELAY_FILE_CAP_BYTES: u64 = 25 * 1024 * 1024;
/// Maximum allowed validity window of a signed config (`30 days`).
pub const MAX_CONFIG_TTL_DAYS: u32 = 30;
/// Legacy M2 encoded length of a [`SignedConfig`] (`1 + 4 + 4 + 8 + 64 = 81` bytes).
pub const SIGNED_CONFIG_V1_LEN: usize = 1 + 4 + 4 + 8 + 64;
/// Encoded length of a [`SignedConfig`] with M3.1 device-inbox limits (`1 + 4 + 4 + 8 + 2 + 4 + 64 = 87` bytes).
pub const SIGNED_CONFIG_LEN: usize = 1 + 4 + 4 + 8 + 2 + 4 + 64;

/// Signed `voidwire-config` served by `voidwire-mailbox` on `CONFIG_GET` (`M3-PLAN.md` §1.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedConfig {
    pub version: u8,
    pub issued_at_day: u32,
    pub expires_at_day: u32,
    pub relay_file_cap_bytes: u64,
    pub inbox_max_items: u16,
    pub inbox_ttl_secs: u32,
    pub signature: [u8; 64],
}

fn config_sig_input_v1(
    version: u8,
    issued_at_day: u32,
    expires_at_day: u32,
    relay_file_cap_bytes: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(TAG_CONFIG.len() + 1 + 4 + 4 + 8);
    msg.extend_from_slice(TAG_CONFIG);
    msg.push(version);
    msg.extend_from_slice(&issued_at_day.to_be_bytes());
    msg.extend_from_slice(&expires_at_day.to_be_bytes());
    msg.extend_from_slice(&relay_file_cap_bytes.to_be_bytes());
    msg
}

fn config_sig_input_v2(
    version: u8,
    issued_at_day: u32,
    expires_at_day: u32,
    relay_file_cap_bytes: u64,
    inbox_max_items: u16,
    inbox_ttl_secs: u32,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(TAG_CONFIG.len() + 1 + 4 + 4 + 8 + 2 + 4);
    msg.extend_from_slice(TAG_CONFIG);
    msg.push(version);
    msg.extend_from_slice(&issued_at_day.to_be_bytes());
    msg.extend_from_slice(&expires_at_day.to_be_bytes());
    msg.extend_from_slice(&relay_file_cap_bytes.to_be_bytes());
    msg.extend_from_slice(&inbox_max_items.to_be_bytes());
    msg.extend_from_slice(&inbox_ttl_secs.to_be_bytes());
    msg
}

impl SignedConfig {
    /// Sign a `voidwire-config` with default M3.1 device-inbox limits (`4` items, `3600`s TTL).
    pub fn sign(
        signing_key_bytes: &[u8; 32],
        issued_at_day: u32,
        expires_at_day: u32,
        relay_file_cap_bytes: u64,
    ) -> Result<Self, RejectReason> {
        Self::sign_with_inbox(
            signing_key_bytes,
            issued_at_day,
            expires_at_day,
            relay_file_cap_bytes,
            crate::limits::DEFAULT_INBOX_MAX_ITEMS as u16,
            crate::limits::DEFAULT_INBOX_TTL_SECS as u32,
        )
    }

    /// Sign a `voidwire-config` including explicit `inbox_max_items` and `inbox_ttl_secs` (`M3-PLAN.md` §1.4.3).
    pub fn sign_with_inbox(
        signing_key_bytes: &[u8; 32],
        issued_at_day: u32,
        expires_at_day: u32,
        relay_file_cap_bytes: u64,
        inbox_max_items: u16,
        inbox_ttl_secs: u32,
    ) -> Result<Self, RejectReason> {
        if expires_at_day < issued_at_day || expires_at_day - issued_at_day > MAX_CONFIG_TTL_DAYS {
            return Err(RejectReason::MalformedFrame);
        }
        if !(crate::limits::INBOX_MAX_ITEMS_MIN as u16..=crate::limits::INBOX_MAX_ITEMS_MAX as u16)
            .contains(&inbox_max_items)
        {
            return Err(RejectReason::MalformedFrame);
        }
        if !(crate::limits::INBOX_TTL_SECS_MIN as u32..=crate::limits::MAX_INBOX_TTL_SECS as u32)
            .contains(&inbox_ttl_secs)
        {
            return Err(RejectReason::MalformedFrame);
        }
        let sk = SigningKey::from_bytes(signing_key_bytes);
        let msg = config_sig_input_v2(
            CONFIG_VERSION,
            issued_at_day,
            expires_at_day,
            relay_file_cap_bytes,
            inbox_max_items,
            inbox_ttl_secs,
        );
        let signature = sk.sign(&msg).to_bytes();
        Ok(SignedConfig {
            version: CONFIG_VERSION,
            issued_at_day,
            expires_at_day,
            relay_file_cap_bytes,
            inbox_max_items,
            inbox_ttl_secs,
            signature,
        })
    }

    /// Verify signature, version, and TTL window (`<= 30` days), and check
    /// freshness against `current_day` (`unix_secs / 86_400`) when provided.
    pub fn verify(
        &self,
        verifying_key_bytes: &[u8; 32],
        current_day: Option<u32>,
    ) -> Result<(), RejectReason> {
        if self.version != CONFIG_VERSION {
            return Err(RejectReason::UnsupportedVersion);
        }
        if self.expires_at_day < self.issued_at_day
            || self.expires_at_day - self.issued_at_day > MAX_CONFIG_TTL_DAYS
        {
            return Err(RejectReason::MalformedFrame);
        }
        if !(crate::limits::INBOX_MAX_ITEMS_MIN as u16..=crate::limits::INBOX_MAX_ITEMS_MAX as u16)
            .contains(&self.inbox_max_items)
        {
            return Err(RejectReason::MalformedFrame);
        }
        if !(crate::limits::INBOX_TTL_SECS_MIN as u32..=crate::limits::MAX_INBOX_TTL_SECS as u32)
            .contains(&self.inbox_ttl_secs)
        {
            return Err(RejectReason::MalformedFrame);
        }
        if let Some(today) = current_day {
            if today < self.issued_at_day || today > self.expires_at_day {
                return Err(RejectReason::StaleTimestamp);
            }
        }
        let vk = VerifyingKey::from_bytes(verifying_key_bytes)
            .map_err(|_| RejectReason::BadSignature)?;
        let sig = Signature::from_bytes(&self.signature);
        let msg_v2 = config_sig_input_v2(
            self.version,
            self.issued_at_day,
            self.expires_at_day,
            self.relay_file_cap_bytes,
            self.inbox_max_items,
            self.inbox_ttl_secs,
        );
        if vk.verify_strict(&msg_v2, &sig).is_ok() {
            return Ok(());
        }
        // Backwards compatibility with 81-byte v1 configs that used default inbox limits.
        if self.inbox_max_items == crate::limits::DEFAULT_INBOX_MAX_ITEMS as u16
            && self.inbox_ttl_secs == crate::limits::DEFAULT_INBOX_TTL_SECS as u32
        {
            let msg_v1 = config_sig_input_v1(
                self.version,
                self.issued_at_day,
                self.expires_at_day,
                self.relay_file_cap_bytes,
            );
            return vk
                .verify_strict(&msg_v1, &sig)
                .map_err(|_| RejectReason::BadSignature);
        }
        Err(RejectReason::BadSignature)
    }

    pub fn encode(&self) -> [u8; SIGNED_CONFIG_LEN] {
        let mut out = [0u8; SIGNED_CONFIG_LEN];
        out[0] = self.version;
        out[1..5].copy_from_slice(&self.issued_at_day.to_be_bytes());
        out[5..9].copy_from_slice(&self.expires_at_day.to_be_bytes());
        out[9..17].copy_from_slice(&self.relay_file_cap_bytes.to_be_bytes());
        out[17..19].copy_from_slice(&self.inbox_max_items.to_be_bytes());
        out[19..23].copy_from_slice(&self.inbox_ttl_secs.to_be_bytes());
        out[23..87].copy_from_slice(&self.signature);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, RejectReason> {
        if b.len() != SIGNED_CONFIG_LEN && b.len() != SIGNED_CONFIG_V1_LEN {
            return Err(RejectReason::MalformedFrame);
        }
        let version = b[0];
        if version != CONFIG_VERSION {
            return Err(RejectReason::UnsupportedVersion);
        }
        let issued_at_day = u32::from_be_bytes(b[1..5].try_into().expect("4"));
        let expires_at_day = u32::from_be_bytes(b[5..9].try_into().expect("4"));
        let relay_file_cap_bytes = u64::from_be_bytes(b[9..17].try_into().expect("8"));
        if b.len() == SIGNED_CONFIG_V1_LEN {
            let signature: [u8; 64] = b[17..81].try_into().expect("64");
            Ok(SignedConfig {
                version,
                issued_at_day,
                expires_at_day,
                relay_file_cap_bytes,
                inbox_max_items: crate::limits::DEFAULT_INBOX_MAX_ITEMS as u16,
                inbox_ttl_secs: crate::limits::DEFAULT_INBOX_TTL_SECS as u32,
                signature,
            })
        } else {
            let inbox_max_items = u16::from_be_bytes([b[17], b[18]]);
            let inbox_ttl_secs = u32::from_be_bytes(b[19..23].try_into().expect("4"));
            let signature: [u8; 64] = b[23..87].try_into().expect("64");
            Ok(SignedConfig {
                version,
                issued_at_day,
                expires_at_day,
                relay_file_cap_bytes,
                inbox_max_items,
                inbox_ttl_secs,
                signature,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// State envelope sealing for `gs_e` and `owner_seal_root` (`state.bin`)
// ---------------------------------------------------------------------------

/// Seal a 32-byte secret (`gs_e` or `owner_seal_root`) before writing it into
/// `state.bin` so `gs_e` and `owner_seal_root` are never stored in clear on disk
/// on any platform (`docs/M2-PLAN.md` §10 item 7).
pub const SEALED_STATE_SECRET_LEN: usize = 24 + 32 + 16;

pub fn seal_secret_for_state(
    identity_secret: &[u8; 32],
    secret: &[u8; 32],
) -> [u8; SEALED_STATE_SECRET_LEN] {
    let hk = Hkdf::<Sha256>::from_prk(identity_secret).expect("32-byte PRK");
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(TAG_MAILBOX_ENC, &mut key[..])
        .expect("32-byte HKDF output");
    let mut nonce = [0u8; 24];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: secret,
                aad: TAG_MAILBOX_ENC,
            },
        )
        .expect("32-byte seal");
    let mut out = [0u8; 24 + 32 + 16];
    out[..24].copy_from_slice(&nonce);
    out[24..].copy_from_slice(&ct);
    out
}

/// Open a 32-byte secret sealed with [`seal_secret_for_state`].
pub fn open_secret_from_state(
    identity_secret: &[u8; 32],
    sealed: &[u8; 24 + 32 + 16],
) -> Option<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::from_prk(identity_secret).ok()?;
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(TAG_MAILBOX_ENC, &mut key[..]).ok()?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let pt = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&sealed[..24]),
                Payload {
                    msg: &sealed[24..],
                    aad: TAG_MAILBOX_ENC,
                },
            )
            .ok()?,
    );
    let arr: [u8; 32] = pt[..].try_into().ok()?;
    Some(Zeroizing::new(arr))
}

// ---------------------------------------------------------------------------
// Wire protocol frames for ALPN `voidwire/v1/mailbox` (`docs/PROTOCOL.md` §7.1)
// ---------------------------------------------------------------------------

/// Frame type bytes for ALPN `voidwire/v1/mailbox`.
pub mod mb_frame {
    /// Fetch signed `voidwire-config` (`empty` -> `CONFIG` or `STATUS`).
    pub const CONFIG_GET: u8 = 0x06;
    /// Enqueue a padded HPKE envelope into a RAM-only per-device blind inbox (`InboxPutReq` -> `STATUS`, `M3-PLAN.md` §1.3.3).
    pub const INBOX_PUT: u8 = 0x07;
    /// Pull queued envelopes from a RAM-only per-device blind inbox (`InboxPullReq` -> `INBOX_PULL_OK` or `STATUS`, `M3-PLAN.md` §1.3.3).
    pub const INBOX_PULL: u8 = 0x08;
    /// Acknowledge and zeroize delivered envelopes in a RAM-only per-device blind inbox (`InboxAckReq` -> `STATUS`, `M3-PLAN.md` §1.3.3).
    pub const INBOX_ACK: u8 = 0x09;

    /// Status response (`1 byte status code`).
    pub const STATUS: u8 = 0x80;
    /// Signed config response (`SignedConfig`).
    pub const CONFIG: u8 = 0x82;
    /// Device inbox pull response (`InboxPullResp`, `M3-PLAN.md` §1.3.3).
    pub const INBOX_PULL_OK: u8 = 0x83;
}

/// 1-byte status codes returned in `mb_frame::STATUS`.
pub mod mb_status {
    pub const OK: u8 = 0x00;
    pub const NOT_FOUND: u8 = 0x01;
    pub const ALREADY_EXISTS: u8 = 0x02;
    pub const SEALED: u8 = 0x03;
    pub const BAD_AUTH: u8 = 0x04;
    pub const BAD_SEQ: u8 = 0x05;
    pub const QUOTA_EXCEEDED: u8 = 0x06;
    pub const RATE_LIMITED: u8 = 0x07;
    pub const MALFORMED: u8 = 0x08;
}

// ---------------------------------------------------------------------------
// RAM-only per-device blind inbox wire frames (`M3-PLAN.md` §1.3.3)
// ---------------------------------------------------------------------------

fn inbox_put_sig_input(
    inbox_id: &DeviceInboxId,
    item_id: &[u8; 16],
    write_verifying_key: &[u8; 32],
    read_verifier: &[u8; 32],
    envelope: &[u8],
) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(TAG_DEVICE_INBOX_PUT.len() + 32 + 16 + 32 + 32 + 2 + envelope.len());
    msg.extend_from_slice(TAG_DEVICE_INBOX_PUT);
    msg.extend_from_slice(&inbox_id.0);
    msg.extend_from_slice(item_id);
    msg.extend_from_slice(write_verifying_key);
    msg.extend_from_slice(read_verifier);
    msg.extend_from_slice(&(envelope.len() as u16).to_be_bytes());
    msg.extend_from_slice(envelope);
    msg
}

fn inbox_pull_sig_input(
    inbox_id: &DeviceInboxId,
    nonce: &[u8; 16],
    read_verifying_key: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(TAG_DEVICE_INBOX_PULL.len() + 32 + 16 + 32);
    msg.extend_from_slice(TAG_DEVICE_INBOX_PULL);
    msg.extend_from_slice(&inbox_id.0);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(read_verifying_key);
    msg
}

fn inbox_ack_sig_input(
    inbox_id: &DeviceInboxId,
    read_verifying_key: &[u8; 32],
    item_ids: &[[u8; 16]],
) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(TAG_DEVICE_INBOX_ACK.len() + 32 + 32 + 2 + item_ids.len() * 16);
    msg.extend_from_slice(TAG_DEVICE_INBOX_ACK);
    msg.extend_from_slice(&inbox_id.0);
    msg.extend_from_slice(read_verifying_key);
    msg.extend_from_slice(&(item_ids.len() as u16).to_be_bytes());
    for id in item_ids {
        msg.extend_from_slice(id);
    }
    msg
}

/// Request payload for `mb_frame::INBOX_PUT` (`0x07`, `M3-PLAN.md` §1.3.3).
#[derive(Clone, PartialEq, Eq)]
pub struct InboxPutReq {
    pub inbox_id: DeviceInboxId,
    pub item_id: [u8; 16],
    pub write_verifying_key: [u8; 32],
    pub read_verifier: [u8; 32],
    pub envelope: Zeroizing<Vec<u8>>,
    pub sig_write: [u8; 64],
}

impl fmt::Debug for InboxPutReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboxPutReq")
            .field("inbox_id", &self.inbox_id)
            .field("item_id", &self.item_id)
            .field("envelope_len", &self.envelope.len())
            .finish_non_exhaustive()
    }
}

impl InboxPutReq {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 16 + 32 + 32 + 2 + self.envelope.len() + 64);
        out.extend_from_slice(&self.inbox_id.0);
        out.extend_from_slice(&self.item_id);
        out.extend_from_slice(&self.write_verifying_key);
        out.extend_from_slice(&self.read_verifier);
        out.extend_from_slice(&(self.envelope.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.envelope);
        out.extend_from_slice(&self.sig_write);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, RejectReason> {
        if b.len() < 32 + 16 + 32 + 32 + 2 + 64 {
            return Err(RejectReason::MalformedFrame);
        }
        let inbox_id = DeviceInboxId(b[..32].try_into().expect("32"));
        let item_id: [u8; 16] = b[32..48].try_into().expect("16");
        let write_verifying_key: [u8; 32] = b[48..80].try_into().expect("32");
        let read_verifier: [u8; 32] = b[80..112].try_into().expect("32");
        let env_len = u16::from_be_bytes([b[112], b[113]]) as usize;
        if b.len() != 114 + env_len + 64 {
            return Err(RejectReason::MalformedFrame);
        }
        let env_slice = &b[114..114 + env_len];
        crate::envelope::check_shape(env_slice)?;
        let sig_write: [u8; 64] = b[114 + env_len..].try_into().expect("64");
        Ok(InboxPutReq {
            inbox_id,
            item_id,
            write_verifying_key,
            read_verifier,
            envelope: Zeroizing::new(env_slice.to_vec()),
            sig_write,
        })
    }

    /// Verify the write signature and optionally match against an existing inbox's
    /// `expected_write_verifier` and `expected_read_verifier`.
    pub fn verify_write(
        &self,
        expected_write_verifier: Option<&[u8; 32]>,
        expected_read_verifier: Option<&[u8; 32]>,
    ) -> Result<[u8; 32], RejectReason> {
        crate::envelope::check_shape(&self.envelope)?;
        let computed_wv = compute_device_inbox_write_verifier(&self.write_verifying_key);
        if let Some(exp_wv) = expected_write_verifier {
            if computed_wv != *exp_wv {
                return Err(RejectReason::BadSignature);
            }
        }
        if let Some(exp_rv) = expected_read_verifier {
            if self.read_verifier != *exp_rv {
                return Err(RejectReason::BadSignature);
            }
        }
        let vk = VerifyingKey::from_bytes(&self.write_verifying_key)
            .map_err(|_| RejectReason::BadSignature)?;
        let sig = Signature::from_bytes(&self.sig_write);
        let msg = inbox_put_sig_input(
            &self.inbox_id,
            &self.item_id,
            &self.write_verifying_key,
            &self.read_verifier,
            &self.envelope,
        );
        vk.verify_strict(&msg, &sig)
            .map_err(|_| RejectReason::BadSignature)?;
        Ok(computed_wv)
    }
}

/// Request payload for `mb_frame::INBOX_PULL` (`0x08`, `M3-PLAN.md` §1.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxPullReq {
    pub inbox_id: DeviceInboxId,
    pub nonce: [u8; 16],
    pub read_verifying_key: [u8; 32],
    pub sig_read: [u8; 64],
}

impl InboxPullReq {
    pub fn encode(&self) -> [u8; 32 + 16 + 32 + 64] {
        let mut out = [0u8; 32 + 16 + 32 + 64];
        out[..32].copy_from_slice(&self.inbox_id.0);
        out[32..48].copy_from_slice(&self.nonce);
        out[48..80].copy_from_slice(&self.read_verifying_key);
        out[80..144].copy_from_slice(&self.sig_read);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, RejectReason> {
        if b.len() != 32 + 16 + 32 + 64 {
            return Err(RejectReason::MalformedFrame);
        }
        Ok(InboxPullReq {
            inbox_id: DeviceInboxId(b[..32].try_into().expect("32")),
            nonce: b[32..48].try_into().expect("16"),
            read_verifying_key: b[48..80].try_into().expect("32"),
            sig_read: b[80..144].try_into().expect("64"),
        })
    }

    pub fn verify_read(&self, expected_read_verifier: &[u8; 32]) -> Result<(), RejectReason> {
        let computed = compute_device_inbox_read_verifier(&self.read_verifying_key);
        if computed != *expected_read_verifier {
            return Err(RejectReason::BadSignature);
        }
        let vk = VerifyingKey::from_bytes(&self.read_verifying_key)
            .map_err(|_| RejectReason::BadSignature)?;
        let sig = Signature::from_bytes(&self.sig_read);
        let msg = inbox_pull_sig_input(&self.inbox_id, &self.nonce, &self.read_verifying_key);
        vk.verify_strict(&msg, &sig)
            .map_err(|_| RejectReason::BadSignature)
    }

    /// Verify signature syntax alone (used when an inbox does not exist in RAM yet so
    /// a valid empty pull returns `InboxPullResp { items: vec![] }` while a forged
    /// signature is rejected with `BAD_AUTH`).
    pub fn verify_signature_self(&self) -> Result<[u8; 32], RejectReason> {
        let vk = VerifyingKey::from_bytes(&self.read_verifying_key)
            .map_err(|_| RejectReason::BadSignature)?;
        let sig = Signature::from_bytes(&self.sig_read);
        let msg = inbox_pull_sig_input(&self.inbox_id, &self.nonce, &self.read_verifying_key);
        vk.verify_strict(&msg, &sig)
            .map_err(|_| RejectReason::BadSignature)?;
        Ok(compute_device_inbox_read_verifier(&self.read_verifying_key))
    }
}

/// One queued item returned in [`InboxPullResp`] (`M3-PLAN.md` §1.3.3).
#[derive(Clone, PartialEq, Eq)]
pub struct InboxPullItem {
    pub item_id: [u8; 16],
    pub remaining_ttl_secs: u32,
    pub envelope: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for InboxPullItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboxPullItem")
            .field("item_id", &self.item_id)
            .field("remaining_ttl_secs", &self.remaining_ttl_secs)
            .field("envelope_len", &self.envelope.len())
            .finish()
    }
}

/// Response payload for `mb_frame::INBOX_PULL_OK` (`0x83`, `M3-PLAN.md` §1.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxPullResp {
    pub items: Vec<InboxPullItem>,
}

/// Server limits optionally advertised as a trailing 14-byte trailer on `INBOX_PULL_OK`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvertisedInboxCaps {
    pub max_relay_file_bytes: u64,
    pub inbox_max_items: u16,
    pub inbox_ttl_secs: u32,
}

impl InboxPullResp {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.items.len() as u16).to_be_bytes());
        for item in &self.items {
            out.extend_from_slice(&item.item_id);
            out.extend_from_slice(&item.remaining_ttl_secs.to_be_bytes());
            out.extend_from_slice(&(item.envelope.len() as u16).to_be_bytes());
            out.extend_from_slice(&item.envelope);
        }
        out
    }

    pub fn encode_with_caps(&self, caps: AdvertisedInboxCaps) -> Vec<u8> {
        let mut out = self.encode();
        out.extend_from_slice(&caps.max_relay_file_bytes.to_be_bytes());
        out.extend_from_slice(&caps.inbox_max_items.to_be_bytes());
        out.extend_from_slice(&caps.inbox_ttl_secs.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, RejectReason> {
        Self::decode_with_caps(b).map(|(r, _)| r)
    }

    pub fn decode_with_caps(b: &[u8]) -> Result<(Self, Option<AdvertisedInboxCaps>), RejectReason> {
        if b.len() < 2 {
            return Err(RejectReason::MalformedFrame);
        }
        let count = u16::from_be_bytes([b[0], b[1]]) as usize;
        if count > crate::limits::INBOX_MAX_ITEMS_MAX {
            return Err(RejectReason::MalformedFrame);
        }
        let mut o = 2;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            if o + 16 + 4 + 2 > b.len() {
                return Err(RejectReason::MalformedFrame);
            }
            let item_id: [u8; 16] = b[o..o + 16].try_into().expect("16");
            o += 16;
            let remaining_ttl_secs = u32::from_be_bytes(b[o..o + 4].try_into().expect("4"));
            o += 4;
            let env_len = u16::from_be_bytes([b[o], b[o + 1]]) as usize;
            o += 2;
            if o + env_len > b.len() {
                return Err(RejectReason::MalformedFrame);
            }
            let env_slice = &b[o..o + env_len];
            crate::envelope::check_shape(env_slice)?;
            o += env_len;
            items.push(InboxPullItem {
                item_id,
                remaining_ttl_secs,
                envelope: Zeroizing::new(env_slice.to_vec()),
            });
        }
        let caps = match b.len() - o {
            0 => None,
            14 => {
                let max_relay_file_bytes = u64::from_be_bytes(b[o..o + 8].try_into().expect("8"));
                let inbox_max_items = u16::from_be_bytes([b[o + 8], b[o + 9]]);
                let inbox_ttl_secs = u32::from_be_bytes(b[o + 10..o + 14].try_into().expect("4"));
                Some(AdvertisedInboxCaps {
                    max_relay_file_bytes,
                    inbox_max_items,
                    inbox_ttl_secs,
                })
            }
            _ => return Err(RejectReason::MalformedFrame),
        };
        Ok((InboxPullResp { items }, caps))
    }
}

/// Request payload for `mb_frame::INBOX_ACK` (`0x09`, `M3-PLAN.md` §1.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxAckReq {
    pub inbox_id: DeviceInboxId,
    pub read_verifying_key: [u8; 32],
    pub item_ids: Vec<[u8; 16]>,
    pub sig_read: [u8; 64],
}

impl InboxAckReq {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 2 + self.item_ids.len() * 16 + 64);
        out.extend_from_slice(&self.inbox_id.0);
        out.extend_from_slice(&self.read_verifying_key);
        out.extend_from_slice(&(self.item_ids.len() as u16).to_be_bytes());
        for id in &self.item_ids {
            out.extend_from_slice(id);
        }
        out.extend_from_slice(&self.sig_read);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, RejectReason> {
        if b.len() < 32 + 32 + 2 + 16 + 64 {
            return Err(RejectReason::MalformedFrame);
        }
        let inbox_id = DeviceInboxId(b[..32].try_into().expect("32"));
        let read_verifying_key: [u8; 32] = b[32..64].try_into().expect("32");
        let count = u16::from_be_bytes([b[64], b[65]]) as usize;
        if count == 0 || count > 64 {
            return Err(RejectReason::MalformedFrame);
        }
        if b.len() != 66 + count * 16 + 64 {
            return Err(RejectReason::MalformedFrame);
        }
        let mut item_ids = Vec::with_capacity(count);
        let mut o = 66;
        for _ in 0..count {
            item_ids.push(b[o..o + 16].try_into().expect("16"));
            o += 16;
        }
        let sig_read: [u8; 64] = b[o..o + 64].try_into().expect("64");
        Ok(InboxAckReq {
            inbox_id,
            read_verifying_key,
            item_ids,
            sig_read,
        })
    }

    pub fn verify_ack(&self, expected_read_verifier: &[u8; 32]) -> Result<(), RejectReason> {
        let computed = compute_device_inbox_read_verifier(&self.read_verifying_key);
        if computed != *expected_read_verifier {
            return Err(RejectReason::BadSignature);
        }
        self.verify_signature_self().map(|_| ())
    }

    pub fn verify_signature_self(&self) -> Result<[u8; 32], RejectReason> {
        let vk = VerifyingKey::from_bytes(&self.read_verifying_key)
            .map_err(|_| RejectReason::BadSignature)?;
        let sig = Signature::from_bytes(&self.sig_read);
        let msg = inbox_ack_sig_input(&self.inbox_id, &self.read_verifying_key, &self.item_ids);
        vk.verify_strict(&msg, &sig)
            .map_err(|_| RejectReason::BadSignature)?;
        Ok(compute_device_inbox_read_verifier(&self.read_verifying_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceKeypair;

    #[test]
    fn kat_epoch_key_derivation() {
        // Epoch key HKDF KAT:
        let ek0 = derive_epoch_key(&[0x11; 32], &GroupId([0x22; 32]), 0);
        let ek1 = derive_epoch_key(&[0x11; 32], &GroupId([0x22; 32]), 1);
        assert_eq!(
            crate::hex::encode(&*ek0),
            "6fd8abb23c96ea96e18634b151f3f87394d95fabac2dd93327b6385c9900bded"
        );
        assert_eq!(
            &*EpochSecret::from_bytes([0x11; 32]).derive_group_epoch_key(&GroupId([0x22; 32]), 0),
            &*ek0
        );
        assert_ne!(&*ek0, &*ek1);
    }

    #[test]
    fn wrap_and_unwrap_epoch_secret_and_rekey_payload() {
        let group = GroupId([7; 32]);
        let dev1 = DeviceKeypair::generate().device_id();
        let rk1 = ReceiveKeypair::generate();
        let dev2 = DeviceKeypair::generate().device_id();
        let rk2 = ReceiveKeypair::generate();
        let removed_dev = DeviceKeypair::generate().device_id();
        let rk_removed = ReceiveKeypair::generate();

        let gs1 = EpochSecret::generate();
        let w1 = wrap_epoch_secret(&dev1, &rk1.public(), &group, 1, &gs1).unwrap();
        let w2 = wrap_epoch_secret(&dev2, &rk2.public(), &group, 1, &gs1).unwrap();

        let payload = RekeyPayload {
            new_epoch: 1,
            removed: removed_dev,
            wrapped_keys: vec![w1, w2],
        };
        let encoded = payload.encode();
        let decoded = RekeyPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);

        // Remaining members unwrap gs1:
        assert_eq!(
            decoded.unwrap_for(&rk1, &dev1, &group).unwrap().as_ref(),
            Some(&gs1)
        );
        assert_eq!(
            decoded.unwrap_for(&rk2, &dev2, &group).unwrap().as_ref(),
            Some(&gs1)
        );
        // Removed member is not in wrapped_keys and cannot unwrap dev1's entry:
        assert_eq!(
            decoded
                .unwrap_for(&rk_removed, &removed_dev, &group)
                .unwrap(),
            None
        );
        assert_eq!(
            unwrap_epoch_secret(
                &rk_removed,
                &dev1,
                &group,
                1,
                &decoded.wrapped_keys[0].sealed
            ),
            Err(RejectReason::DecryptFailed)
        );
    }

    #[test]
    fn signed_config_v1_roundtrip_and_ttl_enforcement() {
        let sk = [0x55u8; 32];
        let vk = SigningKey::from_bytes(&sk).verifying_key().to_bytes();
        let cfg = SignedConfig::sign(&sk, 20_750, 20_780, DEFAULT_RELAY_FILE_CAP_BYTES).unwrap();
        let wire = cfg.encode();
        let parsed = SignedConfig::decode(&wire).unwrap();
        parsed.verify(&vk, Some(20_760)).unwrap();
        assert_eq!(parsed.relay_file_cap_bytes, DEFAULT_RELAY_FILE_CAP_BYTES);

        // Expired or future day rejected:
        assert_eq!(
            parsed.verify(&vk, Some(20_781)),
            Err(RejectReason::StaleTimestamp)
        );
        // TTL > 30 days rejected:
        assert_eq!(
            SignedConfig::sign(&sk, 20_750, 20_781, DEFAULT_RELAY_FILE_CAP_BYTES),
            Err(RejectReason::MalformedFrame)
        );
    }
    #[test]
    fn device_inbox_keys_unlinkability_and_frame_roundtrips() {
        let gs0 = EpochSecret::from_bytes([0x33; 32]);
        let gs1 = EpochSecret::from_bytes([0x44; 32]);
        let group = GroupId([0x11; 32]);
        let dev_a = DeviceKeypair::generate().device_id();
        let rk_a = ReceiveKeypair::generate();
        let dev_b = DeviceKeypair::generate().device_id();
        let rk_b = ReceiveKeypair::generate();

        let keys_a0 = gs0.derive_device_inbox_keys(&group, 0, &dev_a, &rk_a.public());
        let keys_a0_again = gs0.derive_device_inbox_keys(&group, 0, &dev_a, &rk_a.public());
        let keys_b0 = gs0.derive_device_inbox_keys(&group, 0, &dev_b, &rk_b.public());
        let keys_a1 = gs1.derive_device_inbox_keys(&group, 1, &dev_a, &rk_a.public());

        // Deterministic for identical inputs:
        assert_eq!(keys_a0.inbox_id, keys_a0_again.inbox_id);
        assert_eq!(keys_a0.write_verifier, keys_a0_again.write_verifier);
        assert_eq!(keys_a0.read_verifier, keys_a0_again.read_verifier);

        // Unlinkable across devices and epochs:
        assert_ne!(keys_a0.inbox_id, keys_b0.inbox_id);
        assert_ne!(keys_a0.inbox_id, keys_a1.inbox_id);
        assert_ne!(keys_a0.write_verifier, keys_a0.read_verifier);

        // Build a valid padded HPKE envelope (564 bytes = 52 header + 512 bucket):
        let padded = crate::envelope::pad(b"hello-blind-inbox").unwrap();
        let env = crate::envelope::seal(&dev_a, &rk_a.public(), &padded).unwrap();

        let item_id = [0xAA; 16];
        let put_req = keys_a0.build_put_req(item_id, env.clone()).unwrap();
        let put_wire = put_req.encode();
        let decoded_put = InboxPutReq::decode(&put_wire).unwrap();
        assert_eq!(decoded_put, put_req);
        decoded_put
            .verify_write(Some(&keys_a0.write_verifier), Some(&keys_a0.read_verifier))
            .unwrap();
        // Wrong verifier rejected:
        assert_eq!(
            decoded_put.verify_write(Some(&keys_b0.write_verifier), Some(&keys_a0.read_verifier)),
            Err(RejectReason::BadSignature)
        );

        // Pull request roundtrip & verification:
        let pull_req = keys_a0.build_pull_req([0xBB; 16]);
        let pull_wire = pull_req.encode();
        let decoded_pull = InboxPullReq::decode(&pull_wire).unwrap();
        decoded_pull.verify_read(&keys_a0.read_verifier).unwrap();
        assert_eq!(
            decoded_pull.verify_read(&keys_b0.read_verifier),
            Err(RejectReason::BadSignature)
        );

        // Pull response with caps roundtrip:
        let resp = InboxPullResp {
            items: vec![InboxPullItem {
                item_id,
                remaining_ttl_secs: 3599,
                envelope: Zeroizing::new(env),
            }],
        };
        let caps = AdvertisedInboxCaps {
            max_relay_file_bytes: 26_214_400,
            inbox_max_items: 4,
            inbox_ttl_secs: 3600,
        };
        let resp_wire = resp.encode_with_caps(caps);
        let (decoded_resp, decoded_caps) = InboxPullResp::decode_with_caps(&resp_wire).unwrap();
        assert_eq!(decoded_resp, resp);
        assert_eq!(decoded_caps, Some(caps));

        // Ack request roundtrip & verification:
        let ack_req = keys_a0.build_ack_req(vec![item_id]).unwrap();
        let ack_wire = ack_req.encode();
        let decoded_ack = InboxAckReq::decode(&ack_wire).unwrap();
        decoded_ack.verify_ack(&keys_a0.read_verifier).unwrap();
        assert_eq!(
            decoded_ack.verify_ack(&keys_b0.read_verifier),
            Err(RejectReason::BadSignature)
        );
    }
}
