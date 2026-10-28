#![forbid(unsafe_code)]
//! The owner's device group.
//!
//! M0: an in-memory stand-in for the signed group log (plan §4, M4). Shaped
//! for the decisions in docs/PROTOCOL.md §7:
//! * a device is only *added* by consuming a [`ConfirmedPairing`];
//! * "Forget this device" ([`Roster::remove_device`]) takes effect locally and
//!   immediately (ships in M1);
//! * every op advances a hash-chained **log head**; every message carries the
//!   sender's head and receivers refuse senders whose head is behind theirs.

use crate::ids::{DeviceId, GroupId, LogHead};
use crate::keys::DeviceCert;
use crate::pairing::ConfirmedPairing;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    Member,
    Guest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberStatus {
    Active,
    Removed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadStatus {
    /// Same head as ours.
    Current,
    /// A head we have already moved past: the sender missed ops (e.g. a removal).
    Behind,
    /// Not in our history: the sender knows ops we don't. M1: sync first.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct DeviceEntry {
    pub id: DeviceId,
    pub name: String,
    pub role: Role,
    removed: bool,
    /// Signed device certificate (receive key, platform). `None` only for
    /// rosters built by tests without certificates.
    pub cert: Option<DeviceCert>,
}

impl DeviceEntry {
    pub fn is_removed(&self) -> bool {
        self.removed
    }
}

/// Kinds of group-log operation (M1 subset of the M4 DAG, PROTOCOL §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    Genesis = 1,
    AddDevice = 2,
    RemoveDevice = 3,
    Rekey = 4,
    RenameDevice = 5,
}

impl OpKind {
    pub(crate) fn from_u8(b: u8) -> Option<OpKind> {
        match b {
            1 => Some(OpKind::Genesis),
            2 => Some(OpKind::AddDevice),
            3 => Some(OpKind::RemoveDevice),
            4 => Some(OpKind::Rekey),
            5 => Some(OpKind::RenameDevice),
            _ => None,
        }
    }
    fn chain_label(self) -> &'static [u8] {
        match self {
            OpKind::Genesis => b"genesis",
            OpKind::AddDevice => b"add_device",
            OpKind::RemoveDevice => b"remove_device",
            OpKind::Rekey => b"rekey",
            OpKind::RenameDevice => b"rename_device",
        }
    }
}

/// One applied roster operation, in order. `grouplog` signs these; the
/// head chain is the same on every replica.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub kind: OpKind,
    pub subject: DeviceId,
    pub name: String,
    pub cert: Option<DeviceCert>,
    pub rekey: Option<crate::mailbox::RekeyPayload>,
    pub prev: LogHead,
    pub head: LogHead,
}

#[derive(Debug, Clone)]
pub struct Roster {
    group: GroupId,
    self_id: DeviceId,
    devices: HashMap<DeviceId, DeviceEntry>,
    head: LogHead,
    prior_heads: HashSet<LogHead>,
    log: Vec<LogEntry>,
    epoch: u64,
}

pub(crate) const TAG_LOG_OP: &[u8] = b"voidwire/v1/log-op\0";

fn chain(prev: &[u8; 32], op: &[u8], id: &DeviceId) -> LogHead {
    let mut h = Sha256::new();
    h.update(TAG_LOG_OP);
    h.update(prev);
    h.update(op);
    h.update(id.as_bytes());
    LogHead(h.finalize().into())
}

impl Roster {
    /// Start a new group containing only this device.
    pub fn genesis(group: GroupId, self_id: DeviceId, self_name: impl Into<String>) -> Self {
        Self::genesis_inner(group, self_id, self_name.into(), None)
    }

    /// Start a new group with this device's signed certificate (apps).
    pub fn genesis_with_cert(group: GroupId, cert: DeviceCert) -> Self {
        Self::genesis_inner(group, cert.device(), cert.name().to_owned(), Some(cert))
    }

    fn genesis_inner(
        group: GroupId,
        self_id: DeviceId,
        name: String,
        cert: Option<DeviceCert>,
    ) -> Self {
        let mut devices = HashMap::new();
        devices.insert(
            self_id,
            DeviceEntry {
                id: self_id,
                name: name.clone(),
                role: Role::Owner,
                removed: false,
                cert: cert.clone(),
            },
        );
        let head = chain(&group.0, OpKind::Genesis.chain_label(), &self_id);
        Roster {
            group,
            self_id,
            devices,
            head,
            prior_heads: HashSet::new(),
            log: vec![LogEntry {
                kind: OpKind::Genesis,
                subject: self_id,
                name,
                cert,
                rekey: None,
                prev: LogHead(group.0),
                head,
            }],
            epoch: 0,
        }
    }

    /// Every applied operation, oldest first (genesis at index 0).
    pub fn log(&self) -> &[LogEntry] {
        &self.log
    }

    /// Apply an operation that was already authorized: by a typed-SAS
    /// `ConfirmedPairing` / local forget, or by a signature check in
    /// `grouplog` (our own persisted log, or the owner's log on a replica).
    pub fn apply(
        &mut self,
        kind: OpKind,
        subject: DeviceId,
        name: String,
        cert: Option<DeviceCert>,
    ) -> bool {
        match kind {
            OpKind::Genesis => false,
            OpKind::AddDevice => {
                if subject == self.self_id {
                    return false;
                }
                self.devices.insert(
                    subject,
                    DeviceEntry {
                        id: subject,
                        name: name.clone(),
                        role: Role::Owner,
                        removed: false,
                        cert: cert.clone(),
                    },
                );
                self.advance(kind, &subject, name, cert);
                true
            }
            OpKind::RemoveDevice => {
                let changed = match self.devices.get_mut(&subject) {
                    Some(e) if subject != self.self_id && !e.removed => {
                        e.removed = true;
                        true
                    }
                    _ => false,
                };
                if changed {
                    let name = self.devices[&subject].name.clone();
                    self.advance(kind, &subject, name, None);
                }
                changed
            }
            OpKind::Rekey => false,
            OpKind::RenameDevice => {
                if name.is_empty() {
                    return false;
                }
                if let Some(ref c) = cert {
                    if c.device() != subject || c.name() != name {
                        return false;
                    }
                }
                let changed = match self.devices.get_mut(&subject) {
                    Some(e) if !e.removed => {
                        e.name = name.clone();
                        if cert.is_some() {
                            e.cert = cert.clone();
                        }
                        true
                    }
                    _ => false,
                };
                if changed {
                    self.advance(kind, &subject, name, cert);
                }
                changed
            }
        }
    }

    /// Apply an epoch rotation (`OpKind::Rekey`, `docs/PROTOCOL.md` §7.1(c)).
    /// Also ensures `payload.removed` is marked `Removed`.
    pub fn rekey(&mut self, payload: crate::mailbox::RekeyPayload) -> bool {
        if payload.new_epoch != self.epoch + 1 || payload.removed == self.self_id {
            return false;
        }
        let Some(dev) = self.devices.get_mut(&payload.removed) else {
            return false;
        };
        dev.removed = true;
        let removed = payload.removed;
        let name = dev.name.clone();
        self.epoch = payload.new_epoch;
        let prev = self.head;
        self.prior_heads.insert(prev);
        self.head = chain(&prev.0, OpKind::Rekey.chain_label(), &removed);
        self.log.push(LogEntry {
            kind: OpKind::Rekey,
            subject: removed,
            name,
            cert: None,
            rekey: Some(payload),
            prev,
            head: self.head,
        });
        true
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn group(&self) -> GroupId {
        self.group
    }

    pub fn self_id(&self) -> DeviceId {
        self.self_id
    }

    /// Rebind the local receiver identity on a phone's replica of the owner's roster (`M3.1`).
    pub(crate) fn set_self_id(&mut self, self_id: DeviceId) {
        self.self_id = self_id;
    }

    pub fn head(&self) -> LogHead {
        self.head
    }

    fn advance(&mut self, kind: OpKind, id: &DeviceId, name: String, cert: Option<DeviceCert>) {
        let prev = self.head;
        self.prior_heads.insert(prev);
        self.head = chain(&prev.0, kind.chain_label(), id);
        self.log.push(LogEntry {
            kind,
            subject: *id,
            name,
            cert,
            rekey: None,
            prev,
            head: self.head,
        });
    }

    pub fn head_status(&self, h: &LogHead) -> HeadStatus {
        if *h == self.head {
            HeadStatus::Current
        } else if self.prior_heads.contains(h) {
            HeadStatus::Behind
        } else {
            HeadStatus::Unknown
        }
    }

    /// The only way to add a device. In v1 every device is `Owner` (plan §4).
    pub fn add_paired_device(&mut self, pairing: ConfirmedPairing, role: Role) -> DeviceId {
        let (id, name, cert) = pairing.into_parts();
        self.apply(OpKind::AddDevice, id, name, cert);
        if let Some(e) = self.devices.get_mut(&id) {
            e.role = role;
        }
        id
    }

    /// "Forget this device": local, immediate, and a removal wins. The entry is
    /// kept as a tombstone so the device stays rejected (`Removed`).
    pub fn remove_device(&mut self, id: &DeviceId) -> bool {
        self.apply(OpKind::RemoveDevice, *id, String::new(), None)
    }

    /// Rename an active device (such as the owner PC) and update its signed `DeviceCert`.
    pub fn rename_device(&mut self, id: &DeviceId, name: String, cert: Option<DeviceCert>) -> bool {
        self.apply(OpKind::RenameDevice, *id, name, cert)
    }

    /// Roll back a [`Roster::remove_device`] that could not be persisted
    /// (the caller's save failed). Only undoes the newest log entry, and only
    /// when it is the removal of `id`; returns whether anything changed.
    #[cfg_attr(not(feature = "net"), allow(dead_code))]
    pub(crate) fn undo_last_remove(&mut self, id: &DeviceId) -> bool {
        if matches!(self.log.last(), Some(e) if e.kind == OpKind::Rekey && e.subject == *id) {
            let e = self.log.pop().expect("checked");
            self.head = e.prev;
            self.prior_heads.remove(&e.prev);
            self.epoch = self.epoch.saturating_sub(1);
        }
        match self.log.last() {
            Some(e) if e.kind == OpKind::RemoveDevice && e.subject == *id => {}
            _ => return false,
        }
        let Some(e) = self.log.pop() else {
            return false;
        };
        self.head = e.prev;
        self.prior_heads.remove(&e.prev);
        if let Some(d) = self.devices.get_mut(id) {
            d.removed = false;
        }
        true
    }

    pub fn status(&self, id: &DeviceId) -> MemberStatus {
        match self.devices.get(id) {
            Some(e) if e.removed => MemberStatus::Removed,
            Some(_) => MemberStatus::Active,
            None => MemberStatus::Unknown,
        }
    }

    pub fn device(&self, id: &DeviceId) -> Option<&DeviceEntry> {
        self.devices.get(id)
    }

    pub fn active_devices(&self) -> impl Iterator<Item = &DeviceEntry> {
        self.devices.values().filter(|e| !e.removed)
    }

    /// Every device ever added, removed ones included (tombstones).
    pub fn all_devices(&self) -> impl Iterator<Item = &DeviceEntry> {
        self.devices.values()
    }

    /// Index in [`Roster::log`] of the entry whose head is `h`.
    pub fn log_position(&self, h: &LogHead) -> Option<usize> {
        self.log.iter().position(|e| e.head == *h)
    }
}
