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

use crate::envelope::{pad, unpad};
use crate::ids::{DeviceId, GroupId};
use crate::keys::{HpkeKem, HpkeRng, ReceiveKeypair, ReceivePublicKey};
use crate::reject::RejectReason;

/// Domain tag for deriving `mailbox_id` from `gs_e`.
pub const TAG_MAILBOX_ID: &[u8] = b"voidwire/v1/mailbox-id\0";
/// Domain tag for deriving `k_mb_enc` from `gs_e` (and sealing state secrets).
pub const TAG_MAILBOX_ENC: &[u8] = b"voidwire/v1/mailbox-enc\0";
/// Domain tag for deriving `k_mb_write_seed` from `gs_e`.
pub const TAG_MAILBOX_WRITE: &[u8] = b"voidwire/v1/mailbox-write\0";
/// Domain tag for hashing `pk_mb_write` into the server-stored verifier.
pub const TAG_MAILBOX_WRITE_VERIFIER: &[u8] = b"voidwire/v1/mailbox-write-verifier\0";
/// Domain tag for deriving `k_mb_seal_seed` from `owner_seal_root` and signing seals.
pub const TAG_MAILBOX_SEAL: &[u8] = b"voidwire/v1/mailbox-seal\0";
/// Domain tag for hashing `pk_mb_seal` into the server-stored seal verifier.
pub const TAG_MAILBOX_SEAL_VERIFIER: &[u8] = b"voidwire/v1/mailbox-seal-verifier\0";
/// Domain tag for per-device wrapping of `gs_{e+1}` in a `rekey` op / `WELCOME`.
pub const TAG_EPOCH_KEY: &[u8] = b"voidwire/v1/epoch-key\0";
/// Domain tag for mailbox record AEAD AAD and write signature.
pub const TAG_MAILBOX_REC: &[u8] = b"voidwire/v1/mailbox-rec\0";
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

/// Maximum serialized size of one mailbox record (matches the largest `PAD_BUCKETS` bucket).
pub const MAX_MAILBOX_RECORD_BYTES: usize = 8448;
/// Maximum records in a single mailbox before compaction/rekey.
pub const MAX_MAILBOX_RECORDS: usize = 512;
/// Maximum total bytes in a single mailbox (`1 MiB`).
pub const MAX_MAILBOX_TOTAL_BYTES: usize = 1024 * 1024;
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

    /// Derive the mailbox identifier, record encryption key, and write signing key
    /// for this epoch (`docs/PROTOCOL.md` §7.1(a)).
    pub fn derive_keys(&self) -> EpochKeys {
        let hk = Hkdf::<Sha256>::from_prk(&self.0).expect("32-byte PRK is valid for HKDF-SHA256");

        let mut mb_id = [0u8; 32];
        hk.expand(TAG_MAILBOX_ID, &mut mb_id)
            .expect("32 bytes is valid HKDF output");

        let mut enc = [0u8; 32];
        hk.expand(TAG_MAILBOX_ENC, &mut enc)
            .expect("32 bytes is valid HKDF output");

        let mut write_seed = Zeroizing::new([0u8; 32]);
        hk.expand(TAG_MAILBOX_WRITE, &mut write_seed[..])
            .expect("32 bytes is valid HKDF output");
        let write_signing = SigningKey::from_bytes(&write_seed);
        let write_verifying = write_signing.verifying_key().to_bytes();
        let write_verifier = compute_write_verifier(&write_verifying);

        EpochKeys {
            mailbox_id: MailboxId(mb_id),
            enc_key: MailboxEncKey(enc),
            write_signing,
            write_verifying,
            write_verifier,
        }
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

/// 256-bit owner-only root secret (`owner_seal_root`). Never shared with members;
/// used to derive per-epoch seal keys `k_mb_seal(e)` so only the owner can seal
/// a retired epoch's mailbox.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct OwnerSealRoot([u8; 32]);

impl OwnerSealRoot {
    pub fn generate() -> Self {
        Self::generate_with(&mut rand_core::OsRng)
    }

    pub fn generate_with(rng: &mut impl CryptoRngCore) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        OwnerSealRoot(b)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        OwnerSealRoot(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive the seal signing keypair and server verifier for `epoch`.
    pub fn derive_seal_key(&self, epoch: u64) -> OwnerEpochSealKey {
        let hk = Hkdf::<Sha256>::from_prk(&self.0).expect("32-byte PRK is valid for HKDF-SHA256");
        let mut info = Vec::with_capacity(TAG_MAILBOX_SEAL.len() + 8);
        info.extend_from_slice(TAG_MAILBOX_SEAL);
        info.extend_from_slice(&epoch.to_be_bytes());
        let mut seed = Zeroizing::new([0u8; 32]);
        hk.expand(&info, &mut seed[..])
            .expect("32 bytes is valid HKDF output");
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key().to_bytes();
        let verifier = compute_seal_verifier(&verifying);
        OwnerEpochSealKey {
            epoch,
            signing,
            verifying,
            verifier,
        }
    }
}

impl fmt::Debug for OwnerSealRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnerSealRoot(<redacted>)")
    }
}

/// Symmetric record encryption key (`k_mb_enc`).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MailboxEncKey(pub [u8; 32]);

impl fmt::Debug for MailboxEncKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MailboxEncKey(<redacted>)")
    }
}

/// Keys derived from an [`EpochSecret`] (`gs_e`).
pub struct EpochKeys {
    pub mailbox_id: MailboxId,
    pub enc_key: MailboxEncKey,
    write_signing: SigningKey,
    pub write_verifying: [u8; 32],
    pub write_verifier: [u8; 32],
}

impl EpochKeys {
    pub fn sign_write(&self, msg: &[u8]) -> [u8; 64] {
        self.write_signing.sign(msg).to_bytes()
    }
}

impl fmt::Debug for EpochKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EpochKeys")
            .field("mailbox_id", &self.mailbox_id)
            .finish_non_exhaustive()
    }
}

/// Per-epoch seal key derived from [`OwnerSealRoot`].
pub struct OwnerEpochSealKey {
    pub epoch: u64,
    signing: SigningKey,
    pub verifying: [u8; 32],
    pub verifier: [u8; 32],
}

impl OwnerEpochSealKey {
    pub fn sign_seal(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }
}

impl fmt::Debug for OwnerEpochSealKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnerEpochSealKey")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// `SHA-256(TAG_MAILBOX_WRITE_VERIFIER || pk_mb_write)` stored by the mailbox server.
pub fn compute_write_verifier(pk_mb_write: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TAG_MAILBOX_WRITE_VERIFIER);
    h.update(pk_mb_write);
    h.finalize().into()
}

/// `SHA-256(TAG_MAILBOX_SEAL_VERIFIER || pk_mb_seal)` stored by the mailbox server.
pub fn compute_seal_verifier(pk_mb_seal: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TAG_MAILBOX_SEAL_VERIFIER);
    h.update(pk_mb_seal);
    h.finalize().into()
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
// Mailbox records (padded, XChaCha20-Poly1305 encrypted, Ed25519 write-signed)
// ---------------------------------------------------------------------------

/// Wire header overhead of a [`MailboxRecord`] around the padded ciphertext:
/// `seq(8) + nonce(24) + pk_mb_write(32) + sig_write(64) + ct_len(2) = 130` bytes,
/// plus 16-byte Poly1305 tag inside `ct`.
pub const RECORD_HEADER_OVERHEAD: usize = 8 + 24 + 32 + 64 + 2;

/// One encrypted, authenticated record stored in an epoch mailbox.
#[derive(Clone, PartialEq, Eq)]
pub struct MailboxRecord {
    pub seq: u64,
    pub nonce: [u8; 24],
    pub pk_mb_write: [u8; 32],
    pub sig_write: [u8; 64],
    pub ct: Vec<u8>,
}

impl fmt::Debug for MailboxRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailboxRecord")
            .field("seq", &self.seq)
            .field("ct_len", &self.ct.len())
            .finish_non_exhaustive()
    }
}

fn record_aad(mailbox_id: &MailboxId, seq: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(TAG_MAILBOX_REC.len() + 32 + 8);
    aad.extend_from_slice(TAG_MAILBOX_REC);
    aad.extend_from_slice(&mailbox_id.0);
    aad.extend_from_slice(&seq.to_be_bytes());
    aad
}

fn record_sig_input(mailbox_id: &MailboxId, seq: u64, nonce: &[u8; 24], ct: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(TAG_MAILBOX_REC.len() + 32 + 8 + 24 + ct.len());
    msg.extend_from_slice(TAG_MAILBOX_REC);
    msg.extend_from_slice(&mailbox_id.0);
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(ct);
    msg
}

impl MailboxRecord {
    /// Pad `plaintext` to a `PAD_BUCKETS` size, encrypt with `XChaCha20-Poly1305`
    /// under `keys.enc_key`, and sign with `keys.write_signing`.
    pub fn seal(keys: &EpochKeys, seq: u64, plaintext: &[u8]) -> Result<Self, RejectReason> {
        Self::seal_with(keys, seq, plaintext, &mut rand_core::OsRng)
    }

    /// [`MailboxRecord::seal`] with an injectable CSPRNG (for deterministic KATs).
    pub fn seal_with(
        keys: &EpochKeys,
        seq: u64,
        plaintext: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, RejectReason> {
        let padded = pad(plaintext)?;
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new((&keys.enc_key.0).into());
        let aad = record_aad(&keys.mailbox_id, seq);
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &padded,
                    aad: &aad,
                },
            )
            .map_err(|_| RejectReason::Internal)?;
        let sig_input = record_sig_input(&keys.mailbox_id, seq, &nonce, &ct);
        let sig_write = keys.sign_write(&sig_input);
        let rec = MailboxRecord {
            seq,
            nonce,
            pk_mb_write: keys.write_verifying,
            sig_write,
            ct,
        };
        if rec.encoded_len() > MAX_MAILBOX_RECORD_BYTES {
            return Err(RejectReason::MalformedFrame);
        }
        Ok(rec)
    }

    /// Verify the outer write capability signature and `write_verifier` without
    /// holding `gs_e` (run by the blind mailbox server on `append`, and by clients).
    pub fn verify_write(
        &self,
        mailbox_id: &MailboxId,
        expected_write_verifier: &[u8; 32],
    ) -> Result<(), RejectReason> {
        if self.encoded_len() > MAX_MAILBOX_RECORD_BYTES || self.ct.len() < 16 + 512 {
            return Err(RejectReason::MalformedFrame);
        }
        if &compute_write_verifier(&self.pk_mb_write) != expected_write_verifier {
            return Err(RejectReason::BadSignature);
        }
        let vk =
            VerifyingKey::from_bytes(&self.pk_mb_write).map_err(|_| RejectReason::BadSignature)?;
        let sig = Signature::from_bytes(&self.sig_write);
        let sig_input = record_sig_input(mailbox_id, self.seq, &self.nonce, &self.ct);
        vk.verify_strict(&sig_input, &sig)
            .map_err(|_| RejectReason::BadSignature)
    }

    /// Verify signature, decrypt with `keys.enc_key`, and strictly unpad.
    pub fn open(&self, keys: &EpochKeys) -> Result<Vec<u8>, RejectReason> {
        self.verify_write(&keys.mailbox_id, &keys.write_verifier)?;
        let cipher = XChaCha20Poly1305::new((&keys.enc_key.0).into());
        let aad = record_aad(&keys.mailbox_id, self.seq);
        let padded = cipher
            .decrypt(
                XNonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ct,
                    aad: &aad,
                },
            )
            .map_err(|_| RejectReason::DecryptFailed)?;
        unpad(&padded)
    }

    pub fn encoded_len(&self) -> usize {
        RECORD_HEADER_OVERHEAD + self.ct.len()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.pk_mb_write);
        out.extend_from_slice(&self.sig_write);
        out.extend_from_slice(&(self.ct.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ct);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, RejectReason> {
        if b.len() < RECORD_HEADER_OVERHEAD + 16 + 512 || b.len() > MAX_MAILBOX_RECORD_BYTES {
            return Err(RejectReason::MalformedFrame);
        }
        let seq = u64::from_be_bytes(b[..8].try_into().expect("8"));
        let nonce: [u8; 24] = b[8..32].try_into().expect("24");
        let pk_mb_write: [u8; 32] = b[32..64].try_into().expect("32");
        let sig_write: [u8; 64] = b[64..128].try_into().expect("64");
        let ct_len = u16::from_be_bytes([b[128], b[129]]) as usize;
        if b.len() != RECORD_HEADER_OVERHEAD + ct_len {
            return Err(RejectReason::MalformedFrame);
        }
        Ok(MailboxRecord {
            seq,
            nonce,
            pk_mb_write,
            sig_write,
            ct: b[130..].to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// Mailbox seal tombstone (owner-signed, links retired epoch e -> e + 1)
// ---------------------------------------------------------------------------

/// Sequence number reserved for the encrypted `rekey` op inside a [`MailboxSeal`].
pub const SEAL_REKEY_SEQ: u64 = u64::MAX;

/// Tombstone sealing a retired epoch mailbox (`docs/PROTOCOL.md` §7.1(c)).
#[derive(Clone, PartialEq, Eq)]
pub struct MailboxSeal {
    pub epoch: u64,
    pub next_mailbox_id: MailboxId,
    pub encrypted_rekey_record: Vec<u8>,
    pub pk_mb_seal: [u8; 32],
    pub sig_seal: [u8; 64],
}

impl fmt::Debug for MailboxSeal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailboxSeal")
            .field("epoch", &self.epoch)
            .field("next_mailbox_id", &self.next_mailbox_id)
            .finish_non_exhaustive()
    }
}

fn seal_sig_input(
    mailbox_id: &MailboxId,
    epoch: u64,
    next_mailbox_id: &MailboxId,
    encrypted_rekey_record: &[u8],
) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(TAG_MAILBOX_SEAL.len() + 32 + 8 + 32 + encrypted_rekey_record.len());
    msg.extend_from_slice(TAG_MAILBOX_SEAL);
    msg.extend_from_slice(&mailbox_id.0);
    msg.extend_from_slice(&epoch.to_be_bytes());
    msg.extend_from_slice(&next_mailbox_id.0);
    msg.extend_from_slice(encrypted_rekey_record);
    msg
}

impl MailboxSeal {
    /// Seal `epoch` (`old_keys`) pointing to `next_mailbox_id`, embedding the
    /// encoded `rekey` op encrypted under `old_keys` at [`SEAL_REKEY_SEQ`].
    pub fn create(
        old_keys: &EpochKeys,
        seal_key: &OwnerEpochSealKey,
        next_mailbox_id: MailboxId,
        rekey_op_bytes: &[u8],
    ) -> Result<Self, RejectReason> {
        Self::create_with(
            old_keys,
            seal_key,
            next_mailbox_id,
            rekey_op_bytes,
            &mut rand_core::OsRng,
        )
    }

    pub fn create_with(
        old_keys: &EpochKeys,
        seal_key: &OwnerEpochSealKey,
        next_mailbox_id: MailboxId,
        rekey_op_bytes: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, RejectReason> {
        let rec = MailboxRecord::seal_with(old_keys, SEAL_REKEY_SEQ, rekey_op_bytes, rng)?;
        let encrypted_rekey_record = rec.encode();
        let sig_input = seal_sig_input(
            &old_keys.mailbox_id,
            seal_key.epoch,
            &next_mailbox_id,
            &encrypted_rekey_record,
        );
        let sig_seal = seal_key.sign_seal(&sig_input);
        Ok(MailboxSeal {
            epoch: seal_key.epoch,
            next_mailbox_id,
            encrypted_rekey_record,
            pk_mb_seal: seal_key.verifying,
            sig_seal,
        })
    }

    /// Verify the seal against `mailbox_id` and `expected_seal_verifier`
    /// (run by the blind mailbox server before freezing the mailbox).
    pub fn verify(
        &self,
        mailbox_id: &MailboxId,
        expected_seal_verifier: &[u8; 32],
    ) -> Result<(), RejectReason> {
        if self.encrypted_rekey_record.len() > MAX_MAILBOX_RECORD_BYTES {
            return Err(RejectReason::MalformedFrame);
        }
        if &compute_seal_verifier(&self.pk_mb_seal) != expected_seal_verifier {
            return Err(RejectReason::BadSignature);
        }
        let vk =
            VerifyingKey::from_bytes(&self.pk_mb_seal).map_err(|_| RejectReason::BadSignature)?;
        let sig = Signature::from_bytes(&self.sig_seal);
        let sig_input = seal_sig_input(
            mailbox_id,
            self.epoch,
            &self.next_mailbox_id,
            &self.encrypted_rekey_record,
        );
        vk.verify_strict(&sig_input, &sig)
            .map_err(|_| RejectReason::BadSignature)
    }

    /// Decrypt the embedded `rekey` op bytes using `old_keys` (`gs_e`).
    pub fn open_rekey_op(&self, old_keys: &EpochKeys) -> Result<Vec<u8>, RejectReason> {
        let rec = MailboxRecord::decode(&self.encrypted_rekey_record)?;
        if rec.seq != SEAL_REKEY_SEQ {
            return Err(RejectReason::MalformedFrame);
        }
        rec.open(old_keys)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 32 + 64 + 2 + self.encrypted_rekey_record.len());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.next_mailbox_id.0);
        out.extend_from_slice(&self.pk_mb_seal);
        out.extend_from_slice(&self.sig_seal);
        out.extend_from_slice(&(self.encrypted_rekey_record.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.encrypted_rekey_record);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, RejectReason> {
        if b.len() < 8 + 32 + 32 + 64 + 2 {
            return Err(RejectReason::MalformedFrame);
        }
        let epoch = u64::from_be_bytes(b[..8].try_into().expect("8"));
        let next_mailbox_id = MailboxId(b[8..40].try_into().expect("32"));
        let pk_mb_seal: [u8; 32] = b[40..72].try_into().expect("32");
        let sig_seal: [u8; 64] = b[72..136].try_into().expect("64");
        let rec_len = u16::from_be_bytes([b[136], b[137]]) as usize;
        if rec_len > MAX_MAILBOX_RECORD_BYTES || b.len() != 138 + rec_len {
            return Err(RejectReason::MalformedFrame);
        }
        Ok(MailboxSeal {
            epoch,
            next_mailbox_id,
            encrypted_rekey_record: b[138..].to_vec(),
            pk_mb_seal,
            sig_seal,
        })
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
    /// Create or ensure an epoch mailbox exists (`CreateMailboxReq` -> `STATUS`).
    pub const CREATE: u8 = 0x01;
    /// Append an encrypted, write-signed record (`AppendMailboxReq` -> `STATUS`).
    pub const APPEND: u8 = 0x02;
    /// Read records from `from_seq` (`ReadMailboxReq` -> `READ_OK` or `STATUS`).
    pub const READ: u8 = 0x03;
    /// Seal an epoch mailbox (`SealMailboxReq` -> `STATUS`).
    pub const SEAL: u8 = 0x04;
    /// Atomic `remove + rekey + seal old + create new` (`RotateMailboxReq` -> `STATUS`).
    pub const ROTATE: u8 = 0x05;
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
    /// Read response (`ReadMailboxResp`).
    pub const READ_OK: u8 = 0x81;
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

/// Request payload for `mb_frame::CREATE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateMailboxReq {
    pub mailbox_id: MailboxId,
    pub epoch: u64,
    pub write_verifier: [u8; 32],
    pub seal_verifier: [u8; 32],
    pub initial_records: Vec<MailboxRecord>,
}

impl CreateMailboxReq {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 8 + 32 + 32 + 2);
        out.extend_from_slice(&self.mailbox_id.0);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.write_verifier);
        out.extend_from_slice(&self.seal_verifier);
        out.extend_from_slice(&(self.initial_records.len() as u16).to_be_bytes());
        for rec in &self.initial_records {
            let b = rec.encode();
            out.extend_from_slice(&(b.len() as u16).to_be_bytes());
            out.extend_from_slice(&b);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, RejectReason> {
        if b.len() < 32 + 8 + 32 + 32 + 2 {
            return Err(RejectReason::MalformedFrame);
        }
        let mailbox_id = MailboxId(b[..32].try_into().expect("32"));
        let epoch = u64::from_be_bytes(b[32..40].try_into().expect("8"));
        let write_verifier: [u8; 32] = b[40..72].try_into().expect("32");
        let seal_verifier: [u8; 32] = b[72..104].try_into().expect("32");
        let count = u16::from_be_bytes([b[104], b[105]]) as usize;
        if count > MAX_MAILBOX_RECORDS {
            return Err(RejectReason::MalformedFrame);
        }
        let mut o = 106;
        let mut initial_records = Vec::with_capacity(count);
        for _ in 0..count {
            if o + 2 > b.len() {
                return Err(RejectReason::MalformedFrame);
            }
            let rlen = u16::from_be_bytes([b[o], b[o + 1]]) as usize;
            o += 2;
            if o + rlen > b.len() {
                return Err(RejectReason::MalformedFrame);
            }
            initial_records.push(MailboxRecord::decode(&b[o..o + rlen])?);
            o += rlen;
        }
        if o != b.len() {
            return Err(RejectReason::MalformedFrame);
        }
        Ok(CreateMailboxReq {
            mailbox_id,
            epoch,
            write_verifier,
            seal_verifier,
            initial_records,
        })
    }
}

/// Request payload for `mb_frame::APPEND`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendMailboxReq {
    pub mailbox_id: MailboxId,
    pub record: MailboxRecord,
}

impl AppendMailboxReq {
    pub fn encode(&self) -> Vec<u8> {
        let rb = self.record.encode();
        let mut out = Vec::with_capacity(32 + rb.len());
        out.extend_from_slice(&self.mailbox_id.0);
        out.extend_from_slice(&rb);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, RejectReason> {
        if b.len() < 32 {
            return Err(RejectReason::MalformedFrame);
        }
        let mailbox_id = MailboxId(b[..32].try_into().expect("32"));
        let record = MailboxRecord::decode(&b[32..])?;
        Ok(AppendMailboxReq { mailbox_id, record })
    }
}

/// Request payload for `mb_frame::READ`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadMailboxReq {
    pub mailbox_id: MailboxId,
    pub from_seq: u64,
}

impl ReadMailboxReq {
    pub fn encode(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.mailbox_id.0);
        out[32..40].copy_from_slice(&self.from_seq.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, RejectReason> {
        if b.len() != 40 {
            return Err(RejectReason::MalformedFrame);
        }
        let mailbox_id = MailboxId(b[..32].try_into().expect("32"));
        let from_seq = u64::from_be_bytes(b[32..40].try_into().expect("8"));
        Ok(ReadMailboxReq {
            mailbox_id,
            from_seq,
        })
    }
}

/// Response payload for `mb_frame::READ_OK`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadMailboxResp {
    pub epoch: u64,
    pub records: Vec<MailboxRecord>,
    pub seal: Option<MailboxSeal>,
}

impl ReadMailboxResp {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&(self.records.len() as u16).to_be_bytes());
        for rec in &self.records {
            let b = rec.encode();
            out.extend_from_slice(&(b.len() as u16).to_be_bytes());
            out.extend_from_slice(&b);
        }
        match &self.seal {
            Some(seal) => {
                out.push(1);
                let sb = seal.encode();
                out.extend_from_slice(&(sb.len() as u16).to_be_bytes());
                out.extend_from_slice(&sb);
            }
            None => {
                out.push(0);
            }
        }
        out
    }

    /// Encode `READ_OK` (`PULL_RESP`) with a trailing 8-byte big-endian `max_relay_file_bytes`
    /// advertisement (`M2.9`). Fully backwards-compatible with [`Self::decode_with_cap`].
    pub fn encode_with_cap(&self, max_relay_file_bytes: u64) -> Vec<u8> {
        let mut out = self.encode();
        out.extend_from_slice(&max_relay_file_bytes.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, RejectReason> {
        Self::decode_with_cap(b).map(|(resp, _)| resp)
    }

    /// Decode `READ_OK` (`PULL_RESP`) and optional trailing 8-byte big-endian
    /// `max_relay_file_bytes` advertised by the mailbox server (`M2.9`).
    /// Returns `(resp, None)` when talking to an older `voidwire-mailbox` that
    /// omits the 8-byte trailer.
    pub fn decode_with_cap(b: &[u8]) -> Result<(Self, Option<u64>), RejectReason> {
        if b.len() < 8 + 2 + 1 {
            return Err(RejectReason::MalformedFrame);
        }
        let epoch = u64::from_be_bytes(b[..8].try_into().expect("8"));
        let count = u16::from_be_bytes([b[8], b[9]]) as usize;
        if count > MAX_MAILBOX_RECORDS {
            return Err(RejectReason::MalformedFrame);
        }
        let mut o = 10;
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            if o + 2 > b.len() {
                return Err(RejectReason::MalformedFrame);
            }
            let rlen = u16::from_be_bytes([b[o], b[o + 1]]) as usize;
            o += 2;
            if o + rlen > b.len() {
                return Err(RejectReason::MalformedFrame);
            }
            records.push(MailboxRecord::decode(&b[o..o + rlen])?);
            o += rlen;
        }
        if o >= b.len() {
            return Err(RejectReason::MalformedFrame);
        }
        let has_seal = b[o];
        o += 1;
        let seal = match has_seal {
            0 => None,
            1 => {
                if o + 2 > b.len() {
                    return Err(RejectReason::MalformedFrame);
                }
                let slen = u16::from_be_bytes([b[o], b[o + 1]]) as usize;
                o += 2;
                if o + slen > b.len() {
                    return Err(RejectReason::MalformedFrame);
                }
                let s = MailboxSeal::decode(&b[o..o + slen])?;
                o += slen;
                Some(s)
            }
            _ => return Err(RejectReason::MalformedFrame),
        };
        let advertised_cap = match b.len() - o {
            0 => None,
            8 => Some(u64::from_be_bytes(b[o..o + 8].try_into().expect("8"))),
            _ => return Err(RejectReason::MalformedFrame),
        };
        Ok((
            ReadMailboxResp {
                epoch,
                records,
                seal,
            },
            advertised_cap,
        ))
    }
}

/// Request payload for `mb_frame::SEAL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealMailboxReq {
    pub mailbox_id: MailboxId,
    pub seal: MailboxSeal,
}

impl SealMailboxReq {
    pub fn encode(&self) -> Vec<u8> {
        let sb = self.seal.encode();
        let mut out = Vec::with_capacity(32 + sb.len());
        out.extend_from_slice(&self.mailbox_id.0);
        out.extend_from_slice(&sb);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, RejectReason> {
        if b.len() < 32 {
            return Err(RejectReason::MalformedFrame);
        }
        let mailbox_id = MailboxId(b[..32].try_into().expect("32"));
        let seal = MailboxSeal::decode(&b[32..])?;
        Ok(SealMailboxReq { mailbox_id, seal })
    }
}

/// Request payload for `mb_frame::ROTATE` (atomic remove + rekey + seal old + create new).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateMailboxReq {
    pub old_mailbox_id: MailboxId,
    pub final_old_record: Option<MailboxRecord>,
    pub seal: MailboxSeal,
    pub create_new: CreateMailboxReq,
}

impl RotateMailboxReq {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.old_mailbox_id.0);
        match &self.final_old_record {
            Some(rec) => {
                out.push(1);
                let rb = rec.encode();
                out.extend_from_slice(&(rb.len() as u16).to_be_bytes());
                out.extend_from_slice(&rb);
            }
            None => out.push(0),
        }
        let sb = self.seal.encode();
        out.extend_from_slice(&(sb.len() as u16).to_be_bytes());
        out.extend_from_slice(&sb);
        let cb = self.create_new.encode();
        out.extend_from_slice(&(cb.len() as u32).to_be_bytes());
        out.extend_from_slice(&cb);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, RejectReason> {
        if b.len() < 32 + 1 + 2 + 4 {
            return Err(RejectReason::MalformedFrame);
        }
        let old_mailbox_id = MailboxId(b[..32].try_into().expect("32"));
        let mut o = 32;
        let has_rec = b[o];
        o += 1;
        let final_old_record = match has_rec {
            0 => None,
            1 => {
                if o + 2 > b.len() {
                    return Err(RejectReason::MalformedFrame);
                }
                let rlen = u16::from_be_bytes([b[o], b[o + 1]]) as usize;
                o += 2;
                if o + rlen > b.len() {
                    return Err(RejectReason::MalformedFrame);
                }
                let rec = MailboxRecord::decode(&b[o..o + rlen])?;
                o += rlen;
                Some(rec)
            }
            _ => return Err(RejectReason::MalformedFrame),
        };
        if o + 2 > b.len() {
            return Err(RejectReason::MalformedFrame);
        }
        let slen = u16::from_be_bytes([b[o], b[o + 1]]) as usize;
        o += 2;
        if o + slen > b.len() {
            return Err(RejectReason::MalformedFrame);
        }
        let seal = MailboxSeal::decode(&b[o..o + slen])?;
        o += slen;
        if o + 4 > b.len() {
            return Err(RejectReason::MalformedFrame);
        }
        let clen = u32::from_be_bytes(b[o..o + 4].try_into().expect("4")) as usize;
        o += 4;
        if o + clen != b.len() {
            return Err(RejectReason::MalformedFrame);
        }
        let create_new = CreateMailboxReq::decode(&b[o..o + clen])?;
        Ok(RotateMailboxReq {
            old_mailbox_id,
            final_old_record,
            seal,
            create_new,
        })
    }
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
    fn kat_epoch_and_owner_seal_derivations() {
        let gs = EpochSecret::from_bytes([0x42; 32]);
        let keys = gs.derive_keys();
        // Deterministic KAT vectors for gs = [0x42; 32]:
        assert_eq!(
            keys.mailbox_id.to_hex(),
            "bf360ef8e114c6d70ea20785d397abc7f820fc4646b264116f887b248b0812ae"
        );
        assert_eq!(
            crate::hex::encode(&keys.enc_key.0),
            "776eec45c2d1f01e45e50374bef4cad095533a7b9482a4ab8b5f3d48fb1a1900"
        );
        assert_eq!(crate::hex::encode(&keys.write_verifying).len(), 64);
        assert_eq!(
            keys.write_verifier,
            compute_write_verifier(&keys.write_verifying)
        );

        // Domain separation: mailbox_id, enc_key, write_verifying, write_verifier are all distinct.
        assert_ne!(keys.mailbox_id.0, keys.enc_key.0);
        assert_ne!(keys.mailbox_id.0, keys.write_verifying);

        // Owner seal root KAT for epoch 0 and epoch 1:
        let root = OwnerSealRoot::from_bytes([0x99; 32]);
        let seal0 = root.derive_seal_key(0);
        let seal1 = root.derive_seal_key(1);
        assert_eq!(seal0.verifier, compute_seal_verifier(&seal0.verifying));
        assert_eq!(seal1.verifier, compute_seal_verifier(&seal1.verifying));
        assert_ne!(seal0.verifying, seal1.verifying);
        assert_ne!(seal0.verifier, seal1.verifier);

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
    fn mailbox_record_and_seal_roundtrip_and_tamper_rejection() {
        let gs0 = EpochSecret::generate();
        let keys0 = gs0.derive_keys();
        let gs1 = EpochSecret::generate();
        let keys1 = gs1.derive_keys();
        let root = OwnerSealRoot::generate();
        let seal_key0 = root.derive_seal_key(0);

        let rec = MailboxRecord::seal(&keys0, 0, b"op-0-bytes").unwrap();
        // Padded to 512 bucket + 16 tag + 130 header = 658 bytes:
        assert_eq!(rec.ct.len(), 512 + 16);
        assert!(rec.encoded_len() <= MAX_MAILBOX_RECORD_BYTES);

        let wire = rec.encode();
        let parsed = MailboxRecord::decode(&wire).unwrap();
        parsed
            .verify_write(&keys0.mailbox_id, &keys0.write_verifier)
            .unwrap();
        assert_eq!(parsed.open(&keys0).unwrap(), b"op-0-bytes");

        // Wrong epoch key fails verification:
        assert_eq!(
            parsed.verify_write(&keys1.mailbox_id, &keys1.write_verifier),
            Err(RejectReason::BadSignature)
        );

        // Seal epoch 0 -> epoch 1:
        let seal =
            MailboxSeal::create(&keys0, &seal_key0, keys1.mailbox_id, b"rekey-op-bytes").unwrap();
        let seal_wire = seal.encode();
        let parsed_seal = MailboxSeal::decode(&seal_wire).unwrap();
        parsed_seal
            .verify(&keys0.mailbox_id, &seal_key0.verifier)
            .unwrap();
        assert_eq!(parsed_seal.next_mailbox_id, keys1.mailbox_id);
        assert_eq!(
            parsed_seal.open_rekey_op(&keys0).unwrap(),
            b"rekey-op-bytes"
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
        let group_keys0 = gs0.derive_keys();

        // Deterministic for identical inputs:
        assert_eq!(keys_a0.inbox_id, keys_a0_again.inbox_id);
        assert_eq!(keys_a0.write_verifier, keys_a0_again.write_verifier);
        assert_eq!(keys_a0.read_verifier, keys_a0_again.read_verifier);

        // Unlinkable across devices, epochs, and group mailbox_id:
        assert_ne!(keys_a0.inbox_id.0, group_keys0.mailbox_id.0);
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
