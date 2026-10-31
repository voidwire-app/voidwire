//! Test harness (TEST-PLAN H-1..H-6). Behind the `test-util` feature, which
//! **cannot be enabled in release-profile or shipping builds** (compile_error!
//! below; cfgs from core/build.rs, independent of `debug_assertions`).
//!
//! * [`FakeClock`]: injectable wall + monotonic clock.
//! * [`seeded_rng`] / [`keypair_from_label`]: deterministic RNG and keys.
//! * [`SpyOpener`]: records opens, never spawns anything.
//! * [`FakePeer`]: fake malicious peer that crafts raw/forged frames.
//! * [`pair_device`]: runs the real pairing flow to put a peer in a roster.

#![forbid(unsafe_code)]

#[cfg(any(voidwire_release_profile, voidwire_shipping))]
compile_error!(
    "the `test-util` feature is for tests only and must not be enabled in release or shipping builds"
);

use crate::envelope;
use crate::ids::{DeviceId, GroupId, MsgId};
use crate::keys::{DeviceKeypair, ReceiveKeypair, ReceivePublicKey};
use crate::opener::{OpenApproval, OpenError, UrlOpener};
use crate::pairing::{PairingRegistry, PairingRequest, ScannedInvite};
use crate::replay::NoPersistence;
use crate::roster::{Role, Roster};
use crate::time::{Clock, MonoMillis, Now, UnixMillis};
use crate::verify::{Inbox, InboxConfig};
use crate::wire::{RawBody, MAGIC};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};

/// Deterministic CSPRNG for test vectors.
pub fn seeded_rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

/// Same label → same key, on every platform.
pub fn keypair_from_label(label: &str) -> DeviceKeypair {
    let mut h = Sha256::new();
    h.update(b"voidwire/test-key\0");
    h.update(label.as_bytes());
    DeviceKeypair::from_secret_bytes(&h.finalize().into())
}

/// Same label → same receive (X25519) key.
pub fn receive_keypair_from_label(label: &str) -> ReceiveKeypair {
    let mut h = Sha256::new();
    h.update(b"voidwire/test-receive-key\0");
    h.update(label.as_bytes());
    let mut b: [u8; 32] = h.finalize().into();
    // X25519 clamping makes any 32 bytes a valid secret.
    b[0] &= 248;
    b[31] &= 127;
    b[31] |= 64;
    ReceiveKeypair::from_secret_bytes(&b).expect("clamped scalar")
}

/// An `Inbox` for tests, in-memory replay cache.
pub fn test_inbox(roster: Roster, config: InboxConfig) -> Inbox {
    let rk = receive_keypair_from_label(&format!("inbox-{:?}", roster.self_id()));
    Inbox::with_store(roster, rk, config, Box::new(NoPersistence)).expect("valid test config")
}

/// A settable clock. `advance` moves both clocks; `set_wall` simulates jumps.
#[derive(Debug)]
pub struct FakeClock(Cell<Now>);

impl FakeClock {
    pub fn new(wall_ms: u64) -> Self {
        FakeClock(Cell::new(Now {
            wall: UnixMillis(wall_ms),
            mono: MonoMillis(1_000),
        }))
    }
    pub fn advance(&self, ms: u64) {
        self.0.set(self.0.get().plus(ms));
    }
    pub fn set_wall(&self, wall_ms: u64) {
        let n = self.0.get();
        self.0.set(Now {
            wall: UnixMillis(wall_ms),
            mono: n.mono,
        });
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Now {
        self.0.get()
    }
}

/// Records every URL it's asked to open. Never spawns anything.
#[derive(Debug, Default)]
pub struct SpyOpener {
    calls: RefCell<Vec<String>>,
}

impl SpyOpener {
    pub fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
    pub fn count(&self) -> usize {
        self.calls.borrow().len()
    }
}

impl UrlOpener for SpyOpener {
    fn open(&self, approval: OpenApproval) -> Result<(), OpenError> {
        self.calls.borrow_mut().push(approval.as_str().to_owned());
        Ok(())
    }
}

/// Thread-safe [`SpyOpener`] for the networked node (shared across threads).
#[derive(Debug, Default)]
pub struct SharedSpyOpener {
    calls: std::sync::Mutex<Vec<String>>,
}

impl SharedSpyOpener {
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
    pub fn count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl UrlOpener for SharedSpyOpener {
    fn open(&self, approval: OpenApproval) -> Result<(), OpenError> {
        self.calls
            .lock()
            .unwrap()
            .push(approval.as_str().to_owned());
        Ok(())
    }
}

/// Put `joiner` into the inbox's roster via the real QR + proof + typed-SAS flow.
pub fn pair_device(
    inbox: &mut Inbox,
    inviter_registry: &mut PairingRegistry,
    joiner: &DeviceKeypair,
    name: &str,
    now: Now,
) -> DeviceId {
    let invite = inviter_registry
        .issue(now, &mut rand_core::OsRng)
        .expect("issue");
    let scanned = ScannedInvite::parse(&invite.qr_uri(""), now).expect("scan");
    let req = PairingRequest::create(&scanned, joiner.device_id(), name, b"test-handshake");
    let grant = inviter_registry
        .redeem(&req, b"test-handshake", now)
        .expect("redeem");
    let typed = scanned.sas_code(&joiner.device_id(), name, b"test-handshake");
    let confirmed = grant.confirm_typed_code(&typed, now).expect("confirm");
    inbox.add_paired_device(confirmed, Role::Owner)
}

/// Fake malicious peer (TEST-PLAN H-5). Holds a key (fresh, stolen or paired)
/// and builds envelopes with any field forged.
pub struct FakePeer {
    pub key: DeviceKeypair,
    pub group: GroupId,
    pub recipient: DeviceId,
    /// The receive key envelopes are sealed to (the target's, unless a test
    /// swaps it to simulate a wrong-recipient seal).
    pub seal_to: ReceivePublicKey,
}

impl FakePeer {
    pub fn new(key: DeviceKeypair, target: &Inbox) -> Self {
        FakePeer {
            key,
            group: target.group(),
            recipient: target.self_id(),
            seal_to: target.receive_public(),
        }
    }

    pub fn id(&self) -> DeviceId {
        self.key.device_id()
    }

    /// An honest body for `url` at `ts` with a fresh random msg_id.
    pub fn body(&self, url: &str, ts: UnixMillis) -> RawBody {
        RawBody {
            magic: MAGIC,
            group: self.group.0,
            sender: *self.key.device_id().as_bytes(),
            recipient: *self.recipient.as_bytes(),
            msg_id: MsgId::random().0,
            timestamp: ts.0,
            url: url.as_bytes().to_vec(),
        }
    }

    /// Sign `body` with this peer's key and seal it (whatever the fields say).
    pub fn seal(&self, body: &RawBody) -> Vec<u8> {
        self.seal_raw(&body.sign_with(&self.key))
    }

    /// HPKE-seal arbitrary body bytes to the target (raw frame injection).
    pub fn seal_raw(&self, body_bytes: &[u8]) -> Vec<u8> {
        envelope::seal(&self.recipient, &self.seal_to, body_bytes).expect("fits")
    }

    /// Honest frame.
    pub fn frame(&self, url: &str, ts: UnixMillis) -> Vec<u8> {
        self.seal(&self.body(url, ts))
    }

    /// Honest body with a caller-supplied mutation applied *before* signing.
    pub fn forged(&self, url: &str, ts: UnixMillis, f: impl FnOnce(&mut RawBody)) -> Vec<u8> {
        let mut b = self.body(url, ts);
        f(&mut b);
        self.seal(&b)
    }

    /// Flip one bit of a frame.
    pub fn bit_flip(frame: &[u8], bit: usize) -> Vec<u8> {
        let mut f = frame.to_vec();
        f[bit / 8] ^= 1 << (bit % 8);
        f
    }
}
