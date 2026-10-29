//! Durable outbox for unpair notices (M4.3).
//!
//! An unpair erases the pairing at once, so the notice to the peer can't be
//! rebuilt later. Before the erase is saved, the notice is signed into a
//! ready-to-send `INBOX_PUT` for the peer's inbox and stored here, in the
//! encrypted state file. It leaves the outbox when the peer got it live or
//! the relay took the PUT. Otherwise it is retried on the next event that
//! talks to a relay anyway (start, inbox pulls, network change), never on a
//! timer, with the relay supervisor's backoff between tries, and dropped
//! after [`GIVE_UP_AFTER`] failed tries.
//!
//! Only the sealed request is kept: no inbox keys, no device names.

use crate::ids::DeviceId;
use crate::relay_supervisor::SupervisorConfig;
use crate::time::UnixMillis;

use super::links::InboxTarget;
use super::state::{Reader, Writer};

/// Failed tries before a notice is dropped: the supervisor's backoff from
/// 30 s up to its 30 min cap, then a few more tries at the cap.
pub(crate) const GIVE_UP_AFTER: u32 = 12;
/// At most this many notices wait (16 pairings, each unpaired at most once,
/// with room for re-pairs).
pub(crate) const OUTBOX_MAX: usize = 32;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OutboxItem {
    pub relay_url: String,
    pub mailbox: DeviceId,
    /// Encoded, signed `INBOX_PUT` (inbox id, item id, sealed notice).
    pub put: Vec<u8>,
    pub attempts: u32,
    pub next_try: UnixMillis,
}

impl std::fmt::Debug for OutboxItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxItem")
            .field("attempts", &self.attempts)
            .finish_non_exhaustive()
    }
}

impl OutboxItem {
    /// A notice for `target`'s inbox, due now.
    pub fn new(target: &InboxTarget, env: Vec<u8>, now: UnixMillis) -> Option<OutboxItem> {
        let mut item_id = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut item_id);
        let req = target.keys.build_put_req(item_id, env).ok()?;
        Some(OutboxItem {
            relay_url: target.relay_url.clone(),
            mailbox: target.mailbox,
            put: req.encode(),
            attempts: 0,
            next_try: now,
        })
    }

    /// Inbox id + item id: unique per notice.
    fn key(&self) -> &[u8] {
        &self.put[..self.put.len().min(48)]
    }
}

/// The supervisor's retry delay before try `attempt + 1`, without jitter.
pub(crate) fn backoff_ms(attempt: u32) -> u64 {
    let c = SupervisorConfig::DEFAULT;
    c.base_retry_ms
        .saturating_mul(1u64 << attempt.min(32))
        .min(c.max_retry_ms)
}

#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub(crate) struct Outbox {
    items: Vec<OutboxItem>,
}

impl Outbox {
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn push(&mut self, item: OutboxItem) {
        if self.items.len() >= OUTBOX_MAX {
            self.items.remove(0);
        }
        self.items.push(item);
    }

    /// Notices due at `now` (all of them when `force`).
    pub fn due(&self, now: UnixMillis, force: bool) -> Vec<OutboxItem> {
        self.items
            .iter()
            .filter(|i| force || i.next_try <= now)
            .cloned()
            .collect()
    }

    /// Delivered: drop it.
    pub fn delivered(&mut self, item: &OutboxItem) {
        self.items.retain(|i| i.key() != item.key());
    }

    /// One more failed try: back off, or give up.
    pub fn failed(&mut self, item: &OutboxItem, now: UnixMillis) {
        if let Some(i) = self.items.iter_mut().find(|i| i.key() == item.key()) {
            i.attempts += 1;
            i.next_try = now.saturating_add(backoff_ms(i.attempts - 1));
        }
        self.items.retain(|i| i.attempts < GIVE_UP_AFTER);
    }

    pub fn encode(&self, w: &mut Writer) {
        w.u16(self.items.len() as u16);
        for i in &self.items {
            w.bytes16(i.relay_url.as_bytes());
            w.raw(i.mailbox.as_bytes());
            w.bytes32(&i.put);
            w.raw(&i.attempts.to_be_bytes());
            w.raw(&i.next_try.0.to_be_bytes());
        }
    }

    pub fn decode(r: &mut Reader<'_>) -> Option<Outbox> {
        let n = r.u16()? as usize;
        let mut items = Vec::with_capacity(n.min(OUTBOX_MAX));
        for _ in 0..n {
            let relay_url = std::str::from_utf8(r.bytes16()?).ok()?.to_owned();
            let mailbox = DeviceId::from_bytes(r.arr32()?).ok()?;
            let put = r.bytes32()?.to_vec();
            let attempts = u32::from_be_bytes(r.take(4)?.try_into().ok()?);
            let next_try = UnixMillis(u64::from_be_bytes(r.take(8)?.try_into().ok()?));
            items.push(OutboxItem {
                relay_url,
                mailbox,
                put,
                attempts,
                next_try,
            });
        }
        Some(Outbox { items })
    }
}

/// Send `items`, one throwaway session per relay. Returns each item with
/// whether the relay took it.
pub(crate) async fn send(items: Vec<OutboxItem>) -> Vec<(OutboxItem, bool)> {
    let mut by_relay: Vec<((String, DeviceId), Vec<OutboxItem>)> = Vec::new();
    for i in items {
        let k = (i.relay_url.clone(), i.mailbox);
        match by_relay.iter_mut().find(|(key, _)| *key == k) {
            Some((_, v)) => v.push(i),
            None => by_relay.push((k, vec![i])),
        }
    }
    let mut out = Vec::new();
    for ((url, mailbox), group) in by_relay {
        match super::mailbox_client::ThrowawaySession::connect(&mailbox, &url).await {
            Ok(sess) => {
                for i in group {
                    let ok = sess.put_device_inbox_raw(&i.put).await.is_ok();
                    out.push((i, ok));
                }
                sess.close().await;
            }
            Err(_) => out.extend(group.into_iter().map(|i| (i, false))),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(n: u8) -> OutboxItem {
        OutboxItem {
            relay_url: "https://relay.example".into(),
            mailbox: crate::keys::DeviceKeypair::generate().device_id(),
            put: vec![n; 80],
            attempts: 0,
            next_try: UnixMillis(1_000),
        }
    }

    #[test]
    fn round_trips() {
        let mut o = Outbox::default();
        o.push(item(1));
        o.push(item(2));
        let mut w = Writer(Vec::new());
        o.encode(&mut w);
        let mut r = Reader::new(&w.0);
        assert_eq!(Outbox::decode(&mut r).unwrap(), o);
        assert!(r.is_empty());
    }

    #[test]
    fn backs_off_on_the_supervisor_schedule_then_gives_up() {
        let mut o = Outbox::default();
        let it = item(1);
        o.push(it.clone());
        let mut t = UnixMillis(1_000);
        let mut waits = Vec::new();
        for _ in 0..GIVE_UP_AFTER - 1 {
            assert_eq!(o.due(t, false).len(), 1);
            o.failed(&it, t);
            let next = o.items[0].next_try;
            assert!(o.due(UnixMillis(next.0 - 1), false).is_empty());
            waits.push(next.0 - t.0);
            t = next;
        }
        assert_eq!(&waits[..3], &[30_000, 60_000, 120_000]);
        assert_eq!(*waits.last().unwrap(), 30 * 60_000);
        o.failed(&it, t);
        assert!(o.is_empty(), "dropped after {GIVE_UP_AFTER} failed tries");
    }

    #[test]
    fn delivered_removes_only_that_notice_and_size_is_capped() {
        let mut o = Outbox::default();
        for n in 0..(OUTBOX_MAX as u8 + 3) {
            o.push(item(n));
        }
        assert_eq!(o.len(), OUTBOX_MAX);
        let first = o.items[0].clone();
        o.delivered(&first);
        assert_eq!(o.len(), OUTBOX_MAX - 1);
        assert!(!o.items.contains(&first));
    }
}
