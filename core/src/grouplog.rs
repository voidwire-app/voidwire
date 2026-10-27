//! Signed group log (M1 subset of PROTOCOL §7).
//!
//! In M1 the PC is the group owner and the only author: every roster change
//! (genesis, add after a typed-SAS pairing, remove via "Forget this device")
//! becomes a [`SignedOp`] signed with the PC identity key. Phones keep a
//! [`GroupReplica`] built only from ops that verify under the PC key they
//! pinned at pairing (the QR `id`, checked by the TLS handshake). The head
//! chain is the same as [`crate::roster`]'s, so the phone's head is what the
//! PC compares in step 4 of `Inbox::receive` (not behind).
//!
//! Remove ops reach members on their next sync (each app connection starts
//! with one). Queue/retry through the relay for offline members is M2; see
//! `docs/PROTOCOL.md` §7.3.
//!
//! ```text
//! op = "VW" 01 'L' | kind u8 | group[32] | author[32] | prev[32] | subject[32]
//!      | ts u64 BE | name_len u8 | name | cert_len u16 BE | cert | sig[64]
//! sig = Ed25519(author, TAG_LOG_SIG || op-without-sig)
//! ```

use ed25519_dalek::Signature;

use crate::ids::{DeviceId, GroupId, LogHead};
use crate::keys::{DeviceCert, DeviceKeypair};
use crate::reject::RejectReason;
use crate::roster::{LogEntry, OpKind, Roster};
use crate::time::UnixMillis;

/// Domain tag for group-log op signatures.
pub const TAG_LOG_SIG: &[u8] = b"voidwire/v1/log-sig\0";

const OP_MAGIC: [u8; 4] = [b'V', b'W', 1, b'L'];
const OP_FIXED: usize = 4 + 1 + 32 * 4 + 8 + 1;
/// Upper bound on one encoded op (name ≤ 64, cert ≤ 206 or rekey payload ≤ 42 + 16*112).
pub const MAX_OP_LEN: usize = OP_FIXED + 64 + 2 + (42 + 16 * 112) + 64;
/// Upper bound on ops in one log (M1: a household, not an enterprise).
pub const MAX_LOG_OPS: usize = 512;

/// One verified, signed log operation.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedOp {
    pub kind: OpKind,
    pub group: GroupId,
    pub author: DeviceId,
    pub prev: LogHead,
    pub subject: DeviceId,
    pub ts: UnixMillis,
    pub name: String,
    pub cert: Option<DeviceCert>,
    pub rekey: Option<crate::mailbox::RekeyPayload>,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for SignedOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedOp")
            .field("kind", &self.kind)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

impl SignedOp {
    /// Sign one roster log entry.
    pub fn sign(author: &DeviceKeypair, group: GroupId, e: &LogEntry, ts: UnixMillis) -> SignedOp {
        let rekey_bytes = e.rekey.as_ref().map(|r| r.encode());
        let cert = if e.kind == OpKind::Rekey {
            rekey_bytes.as_deref().unwrap_or(&[])
        } else {
            e.cert.as_ref().map(|c| c.as_bytes()).unwrap_or(&[])
        };
        let name = &e.name.as_bytes()[..e.name.len().min(64)];
        let mut b = Vec::with_capacity(OP_FIXED + name.len() + 2 + cert.len() + 64);
        b.extend_from_slice(&OP_MAGIC);
        b.push(e.kind as u8);
        b.extend_from_slice(&group.0);
        b.extend_from_slice(author.device_id().as_bytes());
        b.extend_from_slice(&e.prev.0);
        b.extend_from_slice(e.subject.as_bytes());
        b.extend_from_slice(&ts.0.to_be_bytes());
        b.push(name.len() as u8);
        b.extend_from_slice(name);
        b.extend_from_slice(&(cert.len() as u16).to_be_bytes());
        b.extend_from_slice(cert);
        let mut input = TAG_LOG_SIG.to_vec();
        input.extend_from_slice(&b);
        b.extend_from_slice(&author.sign(&input).to_bytes());
        SignedOp::parse_verified(&b).expect("freshly signed op parses")
    }

    /// Strict decode + `verify_strict` under the embedded author key.
    pub fn parse_verified(b: &[u8]) -> Result<SignedOp, RejectReason> {
        if b.len() < OP_FIXED + 2 + 64 || b.len() > MAX_OP_LEN {
            return Err(RejectReason::BadLogOp);
        }
        if b[..4] != OP_MAGIC {
            return Err(RejectReason::BadLogOp);
        }
        let kind = OpKind::from_u8(b[4]).ok_or(RejectReason::BadLogOp)?;
        let arr = |o: usize| -> [u8; 32] { b[o..o + 32].try_into().expect("32") };
        let group = GroupId(arr(5));
        let author = DeviceId::from_bytes(arr(37)).map_err(|_| RejectReason::BadLogOp)?;
        let prev = LogHead(arr(69));
        let subject = DeviceId::from_bytes(arr(101)).map_err(|_| RejectReason::BadLogOp)?;
        let ts = UnixMillis(u64::from_be_bytes(b[133..141].try_into().expect("8")));
        let name_len = b[141] as usize;
        let mut o = OP_FIXED;
        if b.len() < o + name_len + 2 + 64 {
            return Err(RejectReason::BadLogOp);
        }
        let name = std::str::from_utf8(&b[o..o + name_len])
            .map_err(|_| RejectReason::BadLogOp)?
            .to_owned();
        o += name_len;
        let cert_len = u16::from_be_bytes([b[o], b[o + 1]]) as usize;
        o += 2;
        if b.len() != o + cert_len + 64 {
            return Err(RejectReason::BadLogOp);
        }
        let (cert, rekey) = if kind == OpKind::Rekey {
            let rk = crate::mailbox::RekeyPayload::decode(&b[o..o + cert_len])?;
            if rk.removed != subject {
                return Err(RejectReason::BadLogOp);
            }
            (None, Some(rk))
        } else if cert_len == 0 {
            (None, None)
        } else {
            let c = DeviceCert::parse_verified(&b[o..o + cert_len])?;
            if c.device() != subject {
                return Err(RejectReason::BadLogOp);
            }
            (Some(c), None)
        };
        o += cert_len;
        let mut input = TAG_LOG_SIG.to_vec();
        input.extend_from_slice(&b[..o]);
        let sig = Signature::from_bytes(b[o..].try_into().expect("64"));
        author
            .verifying_key()
            .ok_or(RejectReason::BadSignature)?
            .verify_strict(&input, &sig)
            .map_err(|_| RejectReason::BadSignature)?;
        Ok(SignedOp {
            kind,
            group,
            author,
            prev,
            subject,
            ts,
            name,
            cert,
            rekey,
            bytes: b.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Sign every roster entry from `signed.len()` on and append them (the owner
/// calls this after each roster change, then persists `signed`).
pub fn sign_new_entries(
    roster: &Roster,
    author: &DeviceKeypair,
    signed: &mut Vec<SignedOp>,
    now: UnixMillis,
) {
    for e in &roster.log()[signed.len().min(roster.log().len())..] {
        signed.push(SignedOp::sign(author, roster.group(), e, now));
    }
}

/// Rebuild a roster from a log signed by `author` (owner restart, or a
/// phone's replica of the owner). Verifies authorship, the genesis subject,
/// and the head chain op by op.
pub fn replay(author: &DeviceId, ops: &[SignedOp]) -> Result<Roster, RejectReason> {
    if ops.is_empty() || ops.len() > MAX_LOG_OPS {
        return Err(RejectReason::BadLogOp);
    }
    let g = &ops[0];
    if g.kind != OpKind::Genesis || g.subject != *author || g.prev != LogHead(g.group.0) {
        return Err(RejectReason::BadLogOp);
    }
    let mut roster = match &g.cert {
        Some(c) => Roster::genesis_with_cert(g.group, c.clone()),
        None => Roster::genesis(g.group, *author, g.name.clone()),
    };
    for op in ops {
        if op.author != *author || op.group != g.group {
            return Err(RejectReason::BadLogOp);
        }
    }
    for op in &ops[1..] {
        if op.prev != roster.head() {
            return Err(RejectReason::BadLogOp);
        }
        let applied = if op.kind == OpKind::Rekey {
            match &op.rekey {
                Some(rk) => roster.rekey(rk.clone()),
                None => false,
            }
        } else {
            roster.apply(op.kind, op.subject, op.name.clone(), op.cert.clone())
        };
        if !applied {
            return Err(RejectReason::BadLogOp);
        }
    }
    Ok(roster)
}

/// Parse a list of encoded ops (each verified).
pub fn parse_ops<'a>(
    encoded: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<SignedOp>, RejectReason> {
    encoded.into_iter().map(SignedOp::parse_verified).collect()
}

/// Membership of `me` as seen by a replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Membership {
    Member,
    Removed,
    NotYetAdded,
}

/// A member's (phone's) verified copy of the owner's log.
#[derive(Debug)]
pub struct GroupReplica {
    owner: DeviceId,
    ops: Vec<SignedOp>,
    roster: Roster,
}

impl GroupReplica {
    /// Build from a full log signed by `owner` (the pinned PC id).
    pub fn new(owner: DeviceId, ops: Vec<SignedOp>) -> Result<Self, RejectReason> {
        let roster = replay(&owner, &ops)?;
        Ok(GroupReplica { owner, ops, roster })
    }

    /// Replace with a newer full log. It must extend the current one (no
    /// rollback, no fork); an identical log is accepted as a no-op.
    pub fn update(&mut self, ops: Vec<SignedOp>) -> Result<bool, RejectReason> {
        if ops.len() < self.ops.len() || ops[..self.ops.len()] != self.ops[..] {
            return Err(RejectReason::BadLogOp);
        }
        if ops.len() == self.ops.len() {
            return Ok(false);
        }
        let roster = replay(&self.owner, &ops)?;
        self.ops = ops;
        self.roster = roster;
        Ok(true)
    }

    pub fn owner(&self) -> DeviceId {
        self.owner
    }
    pub fn head(&self) -> LogHead {
        self.roster.head()
    }
    pub fn epoch(&self) -> u64 {
        self.roster.epoch()
    }
    /// Append a single verified op (e.g. pulled from the blind mailbox or seal).
    /// Returns `Ok(true)` if applied, `Ok(false)` if already in our log.
    pub fn apply_op(&mut self, op: SignedOp) -> Result<bool, RejectReason> {
        if self.ops.contains(&op) {
            return Ok(false);
        }
        let mut next = self.ops.clone();
        next.push(op);
        self.update(next)
    }
    pub fn group(&self) -> GroupId {
        self.roster.group()
    }
    pub fn ops(&self) -> &[SignedOp] {
        &self.ops
    }
    pub fn roster(&self) -> &Roster {
        &self.roster
    }
    /// The owner's certificate (its HPKE receive key and display name).
    pub fn owner_cert(&self) -> Option<&DeviceCert> {
        self.roster
            .device(&self.owner)
            .and_then(|e| e.cert.as_ref())
    }
    pub fn membership(&self, me: &DeviceId) -> Membership {
        match self.roster.device(me) {
            Some(e) if e.is_removed() => Membership::Removed,
            Some(_) => Membership::Member,
            None => Membership::NotYetAdded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Platform, ReceiveKeypair};

    fn cert(kp: &DeviceKeypair, name: &str) -> DeviceCert {
        DeviceCert::issue(
            kp,
            ReceiveKeypair::generate().public(),
            name,
            Platform::Linux,
            UnixMillis(1),
        )
        .unwrap()
    }

    fn owner_log() -> (DeviceKeypair, DeviceKeypair, Roster, Vec<SignedOp>) {
        let pc = DeviceKeypair::generate();
        let phone = DeviceKeypair::generate();
        let mut r = Roster::genesis_with_cert(GroupId([7; 32]), cert(&pc, "PC"));
        r.apply(
            OpKind::AddDevice,
            phone.device_id(),
            "Phone".into(),
            Some(cert(&phone, "Phone")),
        );
        let mut signed = Vec::new();
        sign_new_entries(&r, &pc, &mut signed, UnixMillis(5));
        (pc, phone, r, signed)
    }

    #[test]
    fn replay_matches_owner_head_and_membership() {
        let (pc, phone, r, signed) = owner_log();
        let rep = GroupReplica::new(pc.device_id(), signed.clone()).unwrap();
        assert_eq!(rep.head(), r.head());
        assert_eq!(rep.membership(&phone.device_id()), Membership::Member);
        assert_eq!(rep.owner_cert().unwrap().name(), "PC");
        // Round-trip through bytes.
        let parsed = parse_ops(signed.iter().map(|o| o.as_bytes())).unwrap();
        assert_eq!(parsed, signed);
    }

    #[test]
    fn signed_remove_reaches_replica() {
        let (pc, phone, mut r, mut signed) = owner_log();
        let mut rep = GroupReplica::new(pc.device_id(), signed.clone()).unwrap();
        assert!(r.remove_device(&phone.device_id()));
        sign_new_entries(&r, &pc, &mut signed, UnixMillis(9));
        assert!(rep.update(signed.clone()).unwrap());
        assert_eq!(rep.membership(&phone.device_id()), Membership::Removed);
        assert_eq!(rep.head(), r.head());
        // Rollback to the shorter log is refused.
        assert_eq!(
            rep.update(signed[..2].to_vec()).unwrap_err(),
            RejectReason::BadLogOp
        );
    }

    #[test]
    fn forged_or_reordered_ops_rejected() {
        let (pc, _phone, _r, signed) = owner_log();
        // Signed by someone else.
        let mallory = DeviceKeypair::generate();
        assert!(GroupReplica::new(mallory.device_id(), signed.clone()).is_err());
        // Bit flip anywhere breaks the signature or the framing.
        let bytes = signed[1].as_bytes();
        for i in (0..bytes.len()).step_by(7) {
            let mut b = bytes.to_vec();
            b[i] ^= 0x01;
            assert!(SignedOp::parse_verified(&b).is_err(), "flip at {i}");
        }
        // Out of order.
        let mut swapped = signed.clone();
        swapped.swap(0, 1);
        assert!(GroupReplica::new(pc.device_id(), swapped).is_err());
        // An add signed by a member (not the owner) is refused.
        let (_, phone, r, _) = owner_log();
        let e = r.log()[1].clone();
        let forged = SignedOp::sign(&phone, r.group(), &e, UnixMillis(1));
        let mut ops = signed[..1].to_vec();
        ops.push(forged);
        assert!(replay(&pc.device_id(), &ops).is_err());
    }
}
