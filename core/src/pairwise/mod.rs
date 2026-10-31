#![forbid(unsafe_code)]
//! Pairwise pairings (M4).
//!
//! Every relationship is a two-device group ("pairing") with its own
//! co-signed log ([`log`]), receive keys, relay and offline inbox
//! ([`record`]). v0.4.x PC-hosted groups are split into one pairing per
//! peer when the state loads ([`PairingSet::sync_legacy`]); their traffic
//! stays on the legacy group until both sides agree on v2 (version gating).

mod codec;
pub mod log;
pub mod record;
pub mod v2;

pub use log::{
    genesis_prev, Caps, PairBody, PairError, PairLog, PairOp, PairingKind, Proposed, Received,
    RelayRef, COMPACT_AT_OPS, FEAT_PAIRWISE, MAX_PAIR_LOG_OPS,
};
pub use record::{
    legacy_pairing_id, LegacyLink, MyRx, Pairing, PairingOrigin, PairingSet, PeerInfo, RelayEntry,
    RelaySettings, RelaySource, RelayToken, MAX_PAIRINGS, MAX_RELAYS_IN_USE, MAX_SAVED_RELAYS,
};

#[cfg(test)]
mod tests;
