#![forbid(unsafe_code)]
//! Replay cache: seen (sender, msg_id) hashes, kept for
//! [`REPLAY_RETENTION_MS`], bounded, fail-closed when full.
//!
//! Decision (docs/PROTOCOL.md §5): the cache is **persisted to disk and fsync'd**
//! so a restart doesn't reopen the replay window (ENV-05): [`FileSeenIdStore`]
//! appends each key and `fsync`s it **before** `Inbox::receive` returns Ok, and
//! the cache is re-seeded from the file at startup. A failed persist rejects the
//! message (`Internal`, fail closed).
//!
//! If the file is lost or damaged, the cache fails closed for one replay
//! window: only messages timestamped after startup are accepted
//! ([`StartupGuard`]).
//!
//! An entry is evicted only after **both** its wall-clock and monotonic expiry
//! have passed, so a wall-clock jump backwards can't resurrect a replay
//! window (CLK-03) and a forward jump can't evict early.

use crate::ids::{DeviceId, MsgId};
pub(crate) const TAG_REPLAY: &[u8] = b"voidwire/v1/replay\0";

use crate::limits::{REPLAY_CACHE_MAX_ENTRIES, REPLAY_RETENTION_MS};
use crate::time::{MonoMillis, Now, UnixMillis};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub type SeenKey = [u8; 16];

/// Persistence seam: [`FileSeenIdStore`] in the apps, [`NoPersistence`] in tests.
pub trait SeenIdStore {
    /// Durably record a key. An error makes the message rejected.
    fn persist(&mut self, key: &SeenKey, forget_after: UnixMillis) -> std::io::Result<()>;

    /// Keys recorded by an earlier run that are still within their retention.
    fn load(&mut self) -> Vec<(SeenKey, UnixMillis)> {
        Vec::new()
    }

    /// Set when the persisted cache was lost or damaged (fail closed).
    fn startup_guard(&self) -> Option<StartupGuard> {
        None
    }

    /// L2: the newest durable record, for the app to keep in its state blob
    /// (state.bin) and hand back to the next [`FileSeenIdStore::open_checked`].
    fn high_water(&self) -> Option<HighWater> {
        None
    }
}

/// QA M1 re-check L2: a high-water mark for the seen-id file, kept *outside*
/// it (in the PC's state.bin), so losing the tail of seen.bin is detected.
///
/// `last_*` is the newest record in the file. Records are only pruned when
/// the file is rewritten (at open and during compaction), and both times the
/// app re-saves the mark right away, so the record it names is always in the
/// file unless the file lost its tail: a truncation at a record boundary, a
/// header-only file, or a damaged last record (dropped as torn). Then the
/// store fails closed (`Corrupt` + startup guard), unless every record ever
/// written has expired anyway (`max_forget_after` is in the past), in which
/// case nothing could be replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HighWater {
    pub last_key: SeenKey,
    pub last_forget_after: UnixMillis,
    pub max_forget_after: UnixMillis,
}

impl HighWater {
    pub const ENCODED_LEN: usize = 16 + 8 + 8;

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut b = [0u8; Self::ENCODED_LEN];
        b[..16].copy_from_slice(&self.last_key);
        b[16..24].copy_from_slice(&self.last_forget_after.0.to_be_bytes());
        b[24..].copy_from_slice(&self.max_forget_after.0.to_be_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != Self::ENCODED_LEN {
            return None;
        }
        let mut last_key = [0u8; 16];
        last_key.copy_from_slice(&b[..16]);
        Some(HighWater {
            last_key,
            last_forget_after: UnixMillis(u64::from_be_bytes(b[16..24].try_into().ok()?)),
            max_forget_after: UnixMillis(u64::from_be_bytes(b[24..].try_into().ok()?)),
        })
    }
}

/// M0 default: nothing persisted (documented gap until M1).
#[derive(Debug, Default)]
pub struct NoPersistence;

impl SeenIdStore for NoPersistence {
    fn persist(&mut self, _key: &SeenKey, _forget_after: UnixMillis) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayVerdict {
    Fresh,
    Replay,
    /// Cache full: fail closed.
    Full,
    /// Persisting failed: fail closed.
    PersistFailed,
    /// The persisted cache was lost; the message predates startup.
    StartupGuard,
}

pub struct ReplayCache {
    seen: HashMap<SeenKey, (UnixMillis, MonoMillis)>,
    max_entries: usize,
    store: Box<dyn SeenIdStore + Send>,
    guard: Option<StartupGuard>,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new(REPLAY_CACHE_MAX_ENTRIES, Box::new(NoPersistence))
    }
}

impl ReplayCache {
    pub fn new(max_entries: usize, mut store: Box<dyn SeenIdStore + Send>) -> Self {
        // Entries from an earlier run: monotonic expiry 0 (our monotonic clock
        // restarted), so only their wall-clock expiry decides. A forward wall
        // jump that evicts them early also makes their messages stale.
        let seen = store
            .load()
            .into_iter()
            .map(|(k, w)| (k, (w, MonoMillis(0))))
            .collect();
        let guard = store.startup_guard();
        ReplayCache {
            seen,
            max_entries,
            store,
            guard,
        }
    }

    /// L2: the store's high-water mark (see [`HighWater`]).
    pub fn high_water(&self) -> Option<HighWater> {
        self.store.high_water()
    }

    pub fn key(sender: &DeviceId, id: &MsgId) -> SeenKey {
        let mut h = Sha256::new();
        h.update(TAG_REPLAY);
        h.update(sender.as_bytes());
        h.update(id.0);
        let d = h.finalize();
        let mut k = [0u8; 16];
        k.copy_from_slice(&d[..16]);
        k
    }

    fn evict(&mut self, now: Now) {
        self.seen
            .retain(|_, (w, m)| !(now.wall > *w && now.mono > *m));
    }

    pub fn check_and_insert(
        &mut self,
        sender: &DeviceId,
        id: &MsgId,
        msg_time: UnixMillis,
        now: Now,
    ) -> ReplayVerdict {
        if let Some(g) = self.guard {
            if now.mono >= g.until {
                self.guard = None;
            } else if msg_time <= g.after {
                return ReplayVerdict::StartupGuard;
            }
        }
        let key = Self::key(sender, id);
        if self.seen.contains_key(&key) {
            return ReplayVerdict::Replay;
        }
        if self.seen.len() >= self.max_entries {
            self.evict(now);
            if self.seen.len() >= self.max_entries {
                return ReplayVerdict::Full;
            }
        }
        let forget_wall = msg_time.max(now.wall).saturating_add(REPLAY_RETENTION_MS);
        let forget_mono = now.mono.saturating_add(REPLAY_RETENTION_MS);
        if self.store.persist(&key, forget_wall).is_err() {
            return ReplayVerdict::PersistFailed;
        }
        self.seen.insert(key, (forget_wall, forget_mono));
        ReplayVerdict::Fresh
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// ENV-05: append-only seen-id file (format 2).
///
/// * Header `VWSEEN2\n`, then records `len u16 BE (= 24) || key(16) ||
///   forget_after u64 BE (unix ms) || check(4)`, where `check` is the first 4
///   bytes of SHA-256 over `len || key || forget_after`. Each record is
///   appended and `fsync`ed (`File::sync_data`) before the message is accepted.
/// * **Truncation recovery:** an incomplete record at the end (crash or full
///   disk mid-append) is dropped, and so is a complete-length last record
///   whose check fails (a torn sector). The file is then rewritten atomically
///   (temp file + fsync + rename) with only the valid live records, so the
///   next append starts aligned.
/// * **Fail closed on loss:** if the file is missing although the app was
///   already initialised, or is damaged (unknown header, bad length, a failed
///   check before the last record), the store reports a [`StartupGuard`]: for
///   one replay window after startup only messages timestamped **after**
///   startup are accepted (`ReplayStartupGuard`).
/// * Unix: the file is created `0600`. Windows: it lives in the per-user
///   data dir that `net::state::private_dir` restricts to the current user
///   (and SYSTEM) with a protected DACL, and inherits that ACL.
/// * While running, the file is compacted when it holds more than twice the
///   live records.
pub struct FileSeenIdStore {
    path: std::path::PathBuf,
    file: std::fs::File,
    live: HashMap<SeenKey, UnixMillis>,
    records: usize,
    loaded: Vec<(SeenKey, UnixMillis)>,
    health: StoreHealth,
    guard: Option<StartupGuard>,
    hw: Option<HighWater>,
}

const PAYLOAD: usize = 16 + 8;
const RECORD: usize = 2 + PAYLOAD + 4;
const FILE_MAGIC: &[u8; 8] = b"VWSEEN2\n";

/// What [`FileSeenIdStore::open`] found on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreHealth {
    /// Valid file (possibly with `torn_bytes` of an incomplete tail dropped).
    Intact { torn_bytes: usize },
    /// No file, and none was expected (first run).
    FirstRun,
    /// No file although the app was initialised: fail closed.
    Missing,
    /// Damaged or unknown content: valid leading records kept, fail closed.
    Corrupt,
}

/// While active, only messages timestamped after `after` are accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupGuard {
    /// Wall-clock time of startup.
    pub after: UnixMillis,
    /// Monotonic deadline (one replay window after startup).
    pub until: MonoMillis,
}

impl std::fmt::Debug for FileSeenIdStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSeenIdStore")
            .field("path", &self.path)
            .field("live", &self.live.len())
            .field("health", &self.health)
            .finish()
    }
}

fn record_check(payload: &[u8; PAYLOAD]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update((PAYLOAD as u16).to_be_bytes());
    h.update(payload);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

fn encode_record(key: &SeenKey, forget_after: UnixMillis) -> [u8; RECORD] {
    let mut payload = [0u8; PAYLOAD];
    payload[..16].copy_from_slice(key);
    payload[16..].copy_from_slice(&forget_after.0.to_be_bytes());
    let mut rec = [0u8; RECORD];
    rec[..2].copy_from_slice(&(PAYLOAD as u16).to_be_bytes());
    rec[2..2 + PAYLOAD].copy_from_slice(&payload);
    rec[2 + PAYLOAD..].copy_from_slice(&record_check(&payload));
    rec
}

/// Parse the body after the header. Returns the valid records and the
/// health (`Intact { torn_bytes }` or `Corrupt`).
fn parse_records(body: &[u8]) -> (Vec<(SeenKey, UnixMillis)>, StoreHealth) {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < body.len() {
        let rest = &body[pos..];
        if rest.len() < 2 {
            return (
                out,
                StoreHealth::Intact {
                    torn_bytes: rest.len(),
                },
            );
        }
        let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        if len != PAYLOAD {
            // A torn tail can't have a full bad header followed by nothing
            // only if it is the very end; anything else is damage.
            return if rest.len() < RECORD {
                (
                    out,
                    StoreHealth::Intact {
                        torn_bytes: rest.len(),
                    },
                )
            } else {
                (out, StoreHealth::Corrupt)
            };
        }
        if rest.len() < RECORD {
            return (
                out,
                StoreHealth::Intact {
                    torn_bytes: rest.len(),
                },
            );
        }
        let payload: [u8; PAYLOAD] = rest[2..2 + PAYLOAD].try_into().expect("24");
        if rest[2 + PAYLOAD..RECORD] != record_check(&payload) {
            return if rest.len() == RECORD {
                // Last record, full length but bad: a torn write.
                (out, StoreHealth::Intact { torn_bytes: RECORD })
            } else {
                (out, StoreHealth::Corrupt)
            };
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(&payload[..16]);
        let w = UnixMillis(u64::from_be_bytes(payload[16..].try_into().expect("8")));
        out.push((k, w));
        pos += RECORD;
    }
    (out, StoreHealth::Intact { torn_bytes: 0 })
}

fn create_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

impl FileSeenIdStore {
    /// Open (or create) the store at `path`, keeping records whose
    /// `forget_after` is later than `now.wall`. `initialised`: the app has
    /// run before (its state exists), so a missing file means lost data and
    /// turns on the [`StartupGuard`].
    pub fn open(
        path: impl Into<std::path::PathBuf>,
        now: Now,
        initialised: bool,
    ) -> std::io::Result<Self> {
        Self::open_checked(path, now, initialised, None)
    }

    /// [`open`](Self::open), also checking the file against the high-water
    /// mark the app saved last time (L2). A file that lost its tail is
    /// `Corrupt` (fail closed).
    pub fn open_checked(
        path: impl Into<std::path::PathBuf>,
        now: Now,
        initialised: bool,
        expected: Option<HighWater>,
    ) -> std::io::Result<Self> {
        use std::io::Read;
        let path = path.into();
        let mut live = HashMap::new();
        let mut max_seen = UnixMillis(0);
        let health = match std::fs::File::open(&path) {
            Ok(mut f) => {
                let mut buf = Vec::new();
                f.read_to_end(&mut buf)?;
                if buf.len() >= FILE_MAGIC.len() && &buf[..FILE_MAGIC.len()] == FILE_MAGIC {
                    let (recs, mut health) = parse_records(&buf[FILE_MAGIC.len()..]);
                    if let Some(hw) = expected {
                        let present = recs
                            .iter()
                            .any(|(k, w)| *k == hw.last_key && *w == hw.last_forget_after);
                        if !present && hw.max_forget_after > now.wall {
                            // Lost tail (boundary truncation, header only,
                            // or a damaged last record): fail closed.
                            health = StoreHealth::Corrupt;
                        }
                    }
                    for (k, w) in recs {
                        max_seen = max_seen.max(w);
                        if w > now.wall {
                            live.insert(k, w);
                        }
                    }
                    health
                } else if buf.is_empty() && !initialised {
                    StoreHealth::FirstRun
                } else {
                    // Unknown header, an empty file after init, or an older
                    // format: nothing trustworthy to load.
                    StoreHealth::Corrupt
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if initialised {
                    StoreHealth::Missing
                } else {
                    StoreHealth::FirstRun
                }
            }
            Err(e) => return Err(e),
        };
        let guard =
            matches!(health, StoreHealth::Missing | StoreHealth::Corrupt).then(|| StartupGuard {
                after: now.wall,
                until: now.mono.saturating_add(REPLAY_RETENTION_MS),
            });
        let (file, last) = Self::rewrite(&path, &live)?;
        let loaded = live.iter().map(|(k, w)| (*k, *w)).collect();
        let max = expected
            .map(|h| h.max_forget_after)
            .unwrap_or(UnixMillis(0))
            .max(max_seen);
        let hw = last.map(|(k, w)| HighWater {
            last_key: k,
            last_forget_after: w,
            max_forget_after: max,
        });
        Ok(FileSeenIdStore {
            path,
            file,
            records: live.len(),
            live,
            loaded,
            health,
            guard,
            hw,
        })
    }

    /// Atomically replace the file with exactly `live`, return it for
    /// appending, plus the record written last (the new high-water record).
    fn rewrite(
        path: &std::path::Path,
        live: &HashMap<SeenKey, UnixMillis>,
    ) -> std::io::Result<(std::fs::File, Option<(SeenKey, UnixMillis)>)> {
        use std::io::Write;
        let tmp = path.with_extension("tmp");
        let mut last = None;
        {
            let mut f = create_private(&tmp)?;
            let mut buf = Vec::with_capacity(FILE_MAGIC.len() + live.len() * RECORD);
            buf.extend_from_slice(FILE_MAGIC);
            for (k, w) in live {
                buf.extend_from_slice(&encode_record(k, *w));
                last = Some((*k, *w));
            }
            f.write_all(&buf)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent() {
            // Make the rename durable (no-op where directories can't be opened).
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok((std::fs::OpenOptions::new().append(true).open(path)?, last))
    }

    /// Number of live records (diagnostics/tests).
    pub fn live_len(&self) -> usize {
        self.live.len()
    }

    /// What was found on disk at open.
    pub fn health(&self) -> StoreHealth {
        self.health
    }
}

impl SeenIdStore for FileSeenIdStore {
    fn persist(&mut self, key: &SeenKey, forget_after: UnixMillis) -> std::io::Result<()> {
        use std::io::Write;
        self.file.write_all(&encode_record(key, forget_after))?;
        self.file.sync_data()?;
        self.records += 1;
        self.live.insert(*key, forget_after);
        let max = self
            .hw
            .map_or(forget_after, |h| h.max_forget_after.max(forget_after));
        self.hw = Some(HighWater {
            last_key: *key,
            last_forget_after: forget_after,
            max_forget_after: max,
        });
        if self.records.is_multiple_of(256) {
            // `forget_after` = max(ts, now) + retention, so this is <= now.
            let now_lower_bound = UnixMillis(forget_after.0.saturating_sub(REPLAY_RETENTION_MS));
            self.live.retain(|_, w| *w > now_lower_bound);
            if self.records > 2 * self.live.len() + 1024 {
                let (file, last) = Self::rewrite(&self.path, &self.live)?;
                self.file = file;
                self.records = self.live.len();
                if let (Some((k, w)), Some(h)) = (last, self.hw.as_mut()) {
                    h.last_key = k;
                    h.last_forget_after = w;
                }
            }
        }
        Ok(())
    }

    fn load(&mut self) -> Vec<(SeenKey, UnixMillis)> {
        std::mem::take(&mut self.loaded)
    }

    fn startup_guard(&self) -> Option<StartupGuard> {
        self.guard
    }

    fn high_water(&self) -> Option<HighWater> {
        self.hw
    }
}

#[cfg(test)]
mod file_store_tests {
    use super::*;
    use crate::keys::DeviceKeypair;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "voidwire-seen-{tag}-{:x}",
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn now(wall: u64) -> Now {
        now_m(wall, 5)
    }

    fn now_m(wall: u64, mono: u64) -> Now {
        Now {
            wall: UnixMillis(wall),
            mono: MonoMillis(mono),
        }
    }

    const T: u64 = 1_800_000_000_000;

    #[test]
    fn replay_survives_restart_env_05() {
        let dir = tmpdir("restart");
        let p = dir.join("seen.bin");
        let sender = DeviceKeypair::generate().device_id();
        let id = MsgId::random();
        {
            let store = FileSeenIdStore::open(&p, now(T), false).unwrap();
            assert_eq!(store.health(), StoreHealth::FirstRun);
            let mut c = ReplayCache::new(100, Box::new(store));
            assert_eq!(
                c.check_and_insert(&sender, &id, UnixMillis(T), now(T)),
                ReplayVerdict::Fresh
            );
            // "kill -9": dropped without any shutdown hook.
        }
        let store = FileSeenIdStore::open(&p, now(T + 60_000), true).unwrap();
        assert_eq!(store.health(), StoreHealth::Intact { torn_bytes: 0 });
        assert_eq!(store.live_len(), 1);
        let mut c = ReplayCache::new(100, Box::new(store));
        assert_eq!(
            c.check_and_insert(&sender, &id, UnixMillis(T), now(T + 60_000)),
            ReplayVerdict::Replay
        );
        // After retention the record is dropped at open.
        let store = FileSeenIdStore::open(&p, now(T + REPLAY_RETENTION_MS + 1), true).unwrap();
        assert_eq!(store.live_len(), 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn torn_tail_is_recovered_and_appends_stay_aligned() {
        let dir = tmpdir("torn");
        let p = dir.join("seen.bin");
        {
            let mut s = FileSeenIdStore::open(&p, now(T), false).unwrap();
            s.persist(&[1; 16], UnixMillis(T + 1000)).unwrap();
            s.persist(&[2; 16], UnixMillis(T + 1000)).unwrap();
        }
        // Crash (or full disk) mid-append: part of a third record.
        let full = std::fs::read(&p).unwrap();
        let mut torn = full.clone();
        torn.extend_from_slice(&encode_record(&[3; 16], UnixMillis(T + 1000))[..11]);
        std::fs::write(&p, &torn).unwrap();
        {
            let mut s = FileSeenIdStore::open(&p, now(T), true).unwrap();
            assert_eq!(s.health(), StoreHealth::Intact { torn_bytes: 11 });
            assert_eq!(s.live_len(), 2);
            assert!(s.guard.is_none(), "a torn tail is not data loss");
            // The tail was cut at open, so this record is read back intact.
            s.persist(&[4; 16], UnixMillis(T + 1000)).unwrap();
        }
        let s = FileSeenIdStore::open(&p, now(T), true).unwrap();
        assert_eq!(s.health(), StoreHealth::Intact { torn_bytes: 0 });
        assert_eq!(s.live_len(), 3);
        assert!(s.live.contains_key(&[4; 16]));
        drop(s);

        // A full-length last record with a bad check (torn sector) is a
        // torn tail too.
        let mut bad = std::fs::read(&p).unwrap();
        let n = bad.len();
        bad[n - 1] ^= 0xff;
        std::fs::write(&p, &bad).unwrap();
        let s = FileSeenIdStore::open(&p, now(T), true).unwrap();
        assert_eq!(s.health(), StoreHealth::Intact { torn_bytes: RECORD });
        assert_eq!(s.live_len(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// L2 helper: write 3 records, return the file bytes and the mark the
    /// app would have saved in state.bin.
    fn three_records(p: &std::path::Path) -> (Vec<u8>, HighWater) {
        let hw = {
            let mut s = FileSeenIdStore::open(p, now(T), false).unwrap();
            for i in 1..=3u8 {
                s.persist(&[i; 16], UnixMillis(T + 1000 * i as u64))
                    .unwrap();
            }
            s.high_water().unwrap()
        };
        assert_eq!(hw.last_key, [3; 16]);
        assert_eq!(hw.max_forget_after, UnixMillis(T + 3000));
        (std::fs::read(p).unwrap(), hw)
    }

    fn reopen(p: &std::path::Path, bytes: &[u8], hw: HighWater) -> FileSeenIdStore {
        std::fs::write(p, bytes).unwrap();
        FileSeenIdStore::open_checked(p, now(T), true, Some(hw)).unwrap()
    }

    /// QA M1 re-check L2: losing the tail of seen.bin is detected through
    /// the high-water mark kept in state.bin, and fails closed.
    #[test]
    fn lost_tail_against_high_water_fails_closed_l2() {
        let dir = tmpdir("hw");
        let p = dir.join("seen.bin");
        let (full, hw) = three_records(&p);

        // Control: intact file, no guard; the mark names a record that's in
        // the rewritten file, so a restart without new messages is clean.
        let s = reopen(&p, &full, hw);
        assert_eq!(s.health(), StoreHealth::Intact { torn_bytes: 0 });
        assert!(s.guard.is_none());
        let hw2 = s.high_water().unwrap();
        drop(s);
        let s = FileSeenIdStore::open_checked(&p, now(T), true, Some(hw2)).unwrap();
        assert_eq!(s.health(), StoreHealth::Intact { torn_bytes: 0 });
        drop(s);

        // 1. Truncated at a record boundary (last record gone).
        let s = reopen(&p, &full[..full.len() - RECORD], hw);
        assert_eq!(s.health(), StoreHealth::Corrupt);
        assert!(s.guard.is_some(), "boundary truncation must fail closed");
        drop(s);
        // 2. Header only.
        let s = reopen(&p, &full[..FILE_MAGIC.len()], hw);
        assert_eq!(s.health(), StoreHealth::Corrupt);
        assert!(s.guard.is_some(), "header-only file must fail closed");
        drop(s);
        // 3. Last record tampered (looks like a torn write without the mark).
        let mut t = full.clone();
        let n = t.len();
        t[n - RECORD + 4] ^= 0x40;
        let s = reopen(&p, &t, hw);
        assert_eq!(s.health(), StoreHealth::Corrupt);
        assert!(s.guard.is_some(), "tampered last record must fail closed");
        drop(s);
        // 3b. Last record replaced by a valid record with another key.
        let mut t = full[..full.len() - RECORD].to_vec();
        t.extend_from_slice(&encode_record(&[9; 16], UnixMillis(T + 3000)));
        let s = reopen(&p, &t, hw);
        assert_eq!(s.health(), StoreHealth::Corrupt);
        drop(s);

        // A torn partial record after the mark (crash mid-append of an
        // unacknowledged message) is still fine.
        let mut t = full.clone();
        t.extend_from_slice(&encode_record(&[4; 16], UnixMillis(T + 4000))[..9]);
        let s = reopen(&p, &t, hw);
        assert_eq!(s.health(), StoreHealth::Intact { torn_bytes: 9 });
        assert!(s.guard.is_none());
        drop(s);

        // Everything ever written has expired: nothing to replay, no guard.
        std::fs::write(&p, &full[..FILE_MAGIC.len()]).unwrap();
        let later = now(T + 3001);
        let s = FileSeenIdStore::open_checked(&p, later, true, Some(hw)).unwrap();
        assert_eq!(s.health(), StoreHealth::Intact { torn_bytes: 0 });
        assert!(s.guard.is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn high_water_round_trips() {
        let hw = HighWater {
            last_key: [7; 16],
            last_forget_after: UnixMillis(42),
            max_forget_after: UnixMillis(u64::MAX),
        };
        assert_eq!(HighWater::decode(&hw.encode()), Some(hw));
        assert_eq!(HighWater::decode(&hw.encode()[..31]), None);
    }

    #[test]
    fn damage_before_the_tail_fails_closed() {
        let dir = tmpdir("corrupt");
        let p = dir.join("seen.bin");
        {
            let mut s = FileSeenIdStore::open(&p, now(T), false).unwrap();
            for i in 0..3u8 {
                s.persist(&[i; 16], UnixMillis(T + 1000)).unwrap();
            }
        }
        // Flip a bit inside the second record (bad check, not the last one).
        let mut b = std::fs::read(&p).unwrap();
        b[FILE_MAGIC.len() + RECORD + 5] ^= 1;
        std::fs::write(&p, &b).unwrap();
        let s = FileSeenIdStore::open(&p, now_m(T, 7), true).unwrap();
        assert_eq!(s.health(), StoreHealth::Corrupt);
        assert_eq!(s.live_len(), 1, "valid records before the damage are kept");
        assert_eq!(
            s.startup_guard(),
            Some(StartupGuard {
                after: UnixMillis(T),
                until: MonoMillis(7 + REPLAY_RETENTION_MS)
            })
        );
        drop(s);
        // A bad length field mid-file is damage too.
        let mut b = std::fs::read(&p).unwrap();
        b.extend_from_slice(&encode_record(&[9; 16], UnixMillis(T + 1000)));
        b[FILE_MAGIC.len()] = 0xff;
        std::fs::write(&p, &b).unwrap();
        assert_eq!(
            FileSeenIdStore::open(&p, now(T), true).unwrap().health(),
            StoreHealth::Corrupt
        );
        // Unknown content (or the old format) no longer stops the app; it
        // fails closed instead.
        std::fs::write(&p, b"not a seen-id file").unwrap();
        let s = FileSeenIdStore::open(&p, now(T), true).unwrap();
        assert_eq!(s.health(), StoreHealth::Corrupt);
        assert!(s.startup_guard().is_some());
        drop(s);
        // ... and the file is valid again afterwards.
        assert_eq!(
            FileSeenIdStore::open(&p, now(T), true).unwrap().health(),
            StoreHealth::Intact { torn_bytes: 0 }
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_file_after_init_fails_closed_first_run_does_not() {
        let dir = tmpdir("missing");
        let p = dir.join("seen.bin");
        let s = FileSeenIdStore::open(&p, now(T), false).unwrap();
        assert_eq!(s.health(), StoreHealth::FirstRun);
        assert!(s.startup_guard().is_none());
        drop(s);
        std::fs::remove_file(&p).unwrap();
        let s = FileSeenIdStore::open(&p, now(T), true).unwrap();
        assert_eq!(s.health(), StoreHealth::Missing);
        assert!(s.startup_guard().is_some());
        drop(s);
        // An empty file after init is lost data as well.
        std::fs::write(&p, b"").unwrap();
        assert_eq!(
            FileSeenIdStore::open(&p, now(T), true).unwrap().health(),
            StoreHealth::Corrupt
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn startup_guard_accepts_only_messages_after_startup_for_one_window() {
        let dir = tmpdir("guard");
        let p = dir.join("seen.bin");
        let start = now_m(T, 1_000);
        let store = FileSeenIdStore::open(&p, start, true).unwrap(); // missing
        let mut c = ReplayCache::new(100, Box::new(store));
        let sender = DeviceKeypair::generate().device_id();
        let later = now_m(T + 5_000, 6_000);
        // Captured before the restart (or exactly at it): refused.
        for ts in [T - 60_000, T - 1, T] {
            assert_eq!(
                c.check_and_insert(&sender, &MsgId::random(), UnixMillis(ts), later),
                ReplayVerdict::StartupGuard
            );
        }
        // Sent after startup: fine.
        assert_eq!(
            c.check_and_insert(&sender, &MsgId::random(), UnixMillis(T + 1), later),
            ReplayVerdict::Fresh
        );
        // One replay window later (monotonic), the guard is off. A wall
        // clock set back doesn't extend or shorten it.
        let after = now_m(T - 3_600_000, 1_000 + REPLAY_RETENTION_MS);
        assert_eq!(
            c.check_and_insert(&sender, &MsgId::random(), UnixMillis(T - 1), after),
            ReplayVerdict::Fresh
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_is_private_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("mode");
        let p = dir.join("seen.bin");
        let mut s = FileSeenIdStore::open(&p, now(T), false).unwrap();
        s.persist(&[1; 16], UnixMillis(T + 1)).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // Also after a reopen (rewrite) of a file that was world-readable.
        drop(s);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o664)).unwrap();
        let _s = FileSeenIdStore::open(&p, now(T), true).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn persist_failure_fails_closed() {
        struct Broken;
        impl SeenIdStore for Broken {
            fn persist(&mut self, _: &SeenKey, _: UnixMillis) -> std::io::Result<()> {
                Err(std::io::Error::other("disk full"))
            }
        }
        let mut c = ReplayCache::new(10, Box::new(Broken));
        let sender = DeviceKeypair::generate().device_id();
        assert_eq!(
            c.check_and_insert(&sender, &MsgId::random(), UnixMillis(1), now(1)),
            ReplayVerdict::PersistFailed
        );
        assert!(c.is_empty());
    }

    #[test]
    fn file_is_compacted_while_running() {
        let dir = tmpdir("compact");
        let p = dir.join("seen.bin");
        let mut s = FileSeenIdStore::open(&p, now(0), false).unwrap();
        let mut wall = 1_000_000u64;
        for i in 0..3000u32 {
            let mut k = [0u8; 16];
            k[..4].copy_from_slice(&i.to_be_bytes());
            wall += 10_000; // 10 s per message: older records expire
            s.persist(&k, UnixMillis(wall + REPLAY_RETENTION_MS))
                .unwrap();
        }
        let len = std::fs::metadata(&p).unwrap().len() as usize;
        assert!(len < (FILE_MAGIC.len() + 3000 * RECORD), "compacted: {len}");
        assert!(s.live_len() <= 2 * (REPLAY_RETENTION_MS as usize / 10_000) + 1024);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
