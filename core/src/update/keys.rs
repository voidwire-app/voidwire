//! The pinned update keys (U1, D3). A list per channel: a manifest signed by
//! any key in its channel's list is accepted, so a key can be added by one
//! release and the old one dropped by a later one (rotation), or the stable
//! key can later move into CI.
//!
//! * test: signed in CI by the release workflow (repo secret
//!   `VOIDWIRE_UPDATE_TEST_KEY`).
//! * stable: signed offline by the maintainer (`voidwire-sign sign`); empty
//!   until that key exists, which means stable builds accept no update.
//!
//! Only public keys live here (docs/UPDATES.md).

use super::policy::Channel;
use super::sig::PublicKey;

pub const TEST_KEYS: &[&str] = &[
    // CI key (repo secret VOIDWIRE_UPDATE_TEST_KEY).
    "voidwire-update-pub-v1 ee2f09fe77be5f4729a30c09a821f895c1c0b721bedcef530930a2175fec4aad",
];

pub const STABLE_KEYS: &[&str] = &[
    // The maintainer's offline key goes here (docs/UPDATES.md, "One-time
    // setup"). Until then stable builds see "up to date".
];

/// The keys trusted for `channel`.
pub fn pinned(channel: Channel) -> Vec<PublicKey> {
    let lines = match channel {
        Channel::Test => TEST_KEYS,
        Channel::Stable => STABLE_KEYS,
    };
    lines.iter().filter_map(|l| PublicKey::parse(l)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pinned_key_parses_and_is_unique() {
        for (ch, lines) in [(Channel::Test, TEST_KEYS), (Channel::Stable, STABLE_KEYS)] {
            let keys = pinned(ch);
            assert_eq!(
                keys.len(),
                lines.len(),
                "a pinned {ch:?} key does not parse"
            );
            let mut ids: Vec<_> = keys.iter().map(|k| k.key_id()).collect();
            ids.sort();
            ids.dedup();
            assert_eq!(ids.len(), keys.len());
        }
        // A key is trusted for one channel only.
        for t in pinned(Channel::Test) {
            assert!(!pinned(Channel::Stable).contains(&t));
        }
    }
}
