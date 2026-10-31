//! User settings, kept apart from identity and pairing state.
//!
//! `settings.bin` sits next to the state file and holds only what the user
//! chose (relay list, preferences). It has its own version and is only ever
//! migrated forward: a pairing or identity reset (an old state format, a
//! damaged state file) replaces the state file and never touches this one.
//!
//! Format: `VWSET\n`, a version byte, then `(tag u8, len u32, value)`
//! entries. Entries with a tag this build doesn't know are kept as they are
//! and written back, so a newer file read by this build loses nothing.

use super::state::{Reader, StateStore, Writer};
use std::collections::BTreeMap;

const MAGIC: &[u8] = b"VWSET\n";
/// Current version. Add a step to [`migrate`] when this goes up.
pub(crate) const VERSION: u8 = 1;

/// PC: the PREFS blob (relay URL, download folder, shortcut, ...).
pub(crate) const PC_PREFS: u8 = 1;
/// The saved relay list ([`crate::pairwise::RelaySettings`]).
pub(crate) const RELAYS: u8 = 2;
/// PC: auto-open links without asking (1) or ask first (0).
pub(crate) const PC_NO_PROMPT: u8 = 3;
/// The user's relay file-size cap (u64, big endian).
pub(crate) const USER_CAP: u8 = 4;
/// PC: the name the user gave this PC (a reset issues the new identity's
/// certificate with it).
pub(crate) const PC_NAME: u8 = 5;
/// On-device connection stats on (1) or off (0); the counters themselves
/// stay in the state file.
pub(crate) const CONN_STATS_ON: u8 = 6;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Settings {
    entries: BTreeMap<u8, Vec<u8>>,
}

impl Settings {
    pub(crate) fn get(&self, tag: u8) -> Option<&[u8]> {
        self.entries.get(&tag).map(Vec::as_slice)
    }

    pub(crate) fn set(&mut self, tag: u8, value: Vec<u8>) {
        self.entries.insert(tag, value);
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new(MAGIC);
        w.u8(VERSION);
        for (tag, v) in &self.entries {
            w.u8(*tag);
            w.bytes32(v);
        }
        w.0
    }

    /// `None` when the bytes aren't a settings file at all.
    pub(crate) fn decode(b: &[u8]) -> Option<Settings> {
        let mut r = Reader::new(b);
        if r.take(MAGIC.len())? != MAGIC {
            return None;
        }
        let version = r.u8()?;
        let mut entries = BTreeMap::new();
        while !r.is_empty() {
            let tag = r.u8()?;
            entries.insert(tag, r.bytes32()?.to_vec());
        }
        Some(migrate(version, Settings { entries }))
    }
}

/// Bring an older file up to [`VERSION`], one step at a time. Never drops a
/// setting: a step may only rename or reshape entries.
fn migrate(version: u8, s: Settings) -> Settings {
    // v1 is the first version: nothing to do yet.
    let _ = version;
    s
}

/// The settings saved next to `state`. `None`: no settings file (first run
/// of this version), or a store without one. A file that doesn't parse is
/// reported and treated as missing; the caller falls back to the copies in
/// the state file, so nothing is reset on purpose.
pub(crate) fn load(state: &dyn StateStore) -> Option<Settings> {
    let store = state.settings()?;
    match store.load() {
        Ok(Some(b)) => {
            let s = Settings::decode(&b);
            if s.is_none() {
                eprintln!("voidwire: settings file unreadable; using the copies in the state file");
            }
            s
        }
        Ok(None) => None,
        Err(e) => {
            eprintln!("voidwire: couldn't read the settings file: {e}");
            None
        }
    }
}

/// Save `s` next to `state` (no-op for a store without a settings file).
pub(crate) fn save(state: &dyn StateStore, s: &Settings) -> Result<(), String> {
    match state.settings() {
        Some(store) => store.save(&s.encode()),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keeps_unknown_entries() {
        let mut s = Settings::default();
        s.set(RELAYS, vec![1, 2, 3]);
        s.set(200, b"from a newer build".to_vec());
        let back = Settings::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.get(200), Some(&b"from a newer build"[..]));
    }

    #[test]
    fn not_a_settings_file() {
        assert!(Settings::decode(b"VWPC3\nxxxx").is_none());
        let mut b = Settings::default().encode();
        b.extend_from_slice(&[RELAYS, 0, 0]);
        assert!(Settings::decode(&b).is_none(), "truncated entry");
    }
}
